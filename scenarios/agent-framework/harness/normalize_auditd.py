#!/usr/bin/env python3
"""SBOB-EXAMPLES DEMO WATERMARK — scenario A harness: auditd → sbob.* JSONL normalizer.

Issue #3 (M2 Gate C): converts the canary-observer.sh captured auditd
window into the normalized sbob.* event stream sbobctl profile consumes
(SBoB docs M9 profiler contract: one JSON object per line with ts /
workload / source / kind / sbob fields; comments with # allowed).

Record shapes are the recorded-corpus shapes proven live by the php2shell
lane (SYSCALL + contiguous EXECVE / PATH / SOCKADDR records). Decoding:

  open    SYSCALL(syscall=2 open | 257 openat, arch=b64) + its PATH record
          (name=). Flags map from the numeric a1 (open) / a2 (openat) argument
          to the SBoB open-flag vocabulary {O_RDONLY, O_WRONLY, O_RDWR,
          O_CREAT, O_EXCL}; volatile bits (O_TRUNC, O_APPEND, O_NONBLOCK,
          O_CLOEXEC, ...) are dropped by design — the profile candidate and
          the canary baseline both go through this same vocabulary, so the
          delta compares like with like (stated in supply-chain-evidence.md).
  connect SYSCALL(syscall=42) + its SOCKADDR record: saddr hex, AF_INET
          family 0x02, port big-endian, then IPv4 address.
  exec    SYSCALL(syscall=59) + its EXE record (exe=) and EXECVE record
          (a0=, a1=, ... argument vector, quoted by the kernel).

OBSERVER SCOPE (the honest rules, all stated in docs/supply-chain-evidence.md):
  - opens   only paths under the canary fixture roots (AF_HOME /
            AF_PROC_ROOT) count as canary behavior; everything else the
            canary interpreter does (stdlib reads, wheel/site dirs, receipts,
            guard logs, __pycache__) is excluded. The fixture tree is the
            declared blast radius of the demo (TDS §4). Paths are emitted
            ROOT-RELATIVE with the stable markers AF-HOME/AF-PROC: each
            disposable canary stages the identical fixture tree under its
            own out-dir (work/clean, work/clean2, work/mal1...), so the
            literal out-dir prefix is the observation equivalent of an
            inode number — it carries no behavior signal and would make
            identical staging rows look like drift. Canonicalizing BOTH
            sides of every diff keeps the baseline→candidate comparison
            root-relative without filtering a single row.
  - connect only loopback (127.0.0.1) destinations count: the demo's hard
            rule is loopback-only networking; the sink and the declared
            memcache stand-in are the only peers that can legally appear.
  - exec    every execve by the dedicated canary uid counts. Same shape in
            every canary window (driver, sink, guarded interpreter starts),
            so these rows self-cancel in the baseline→candidate delta.
  - fixture staging (make_fixtures writing the synthetic tree) is part of
            every window equally and self-cancels in the delta; the
            candidates carry it as declared open entries (full transparency,
            no hidden filtering).

stdlib only (org lesson: no pip in CI lanes).
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone

SYSCALL_NR = {"open": 2, "openat": 257, "connect": 42, "execve": 59}

# open(2) flag bits kept in the SBoB vocabulary
O_ACCMODE = 0o3
O_CREAT = 0o100
O_EXCL = 0o200


def fields_of(line: str) -> dict[str, str]:
    """Parse auditd `key=value` fields (quoted values with spaces)."""
    out: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
        out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def flags_of(bits: int) -> list[str]:
    acc = bits & O_ACCMODE
    out = ["O_RDONLY", "O_WRONLY", "O_RDWR"][acc] if acc < 3 else "O_RDWR"
    flags = [out]
    if bits & O_CREAT:
        flags.append("O_CREAT")
    if bits & O_EXCL:
        flags.append("O_EXCL")
    return flags


def decode_saddr(hexstr: str) -> tuple[str, int] | None:
    """AF_INET saddr: family(2) port(2 BE) ipv4(4). Returns (ip, port) or None."""
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if len(raw) < 8 or raw[0] != 0x02 or raw[1] != 0x00:
        return None
    port = (raw[2] << 8) | raw[3]
    ip = ".".join(str(b) for b in raw[4:8])
    return (ip, port)


def iso_z(epoch_ms: str) -> str:
    sec = float(epoch_ms)
    return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize(lines: list[str], home: str, proc_root: str,
             workload: str) -> tuple[list[str], list[str]]:
    """Return (events, diagnostics)."""
    events: list[str] = list()
    diag: list[str] = list()

    # group an event: keyed SYSCALL + following aux records until next SYSCALL
    groups: list[tuple[dict[str, str], list[dict[str, str]], float]] = []
    cur: tuple[dict[str, str], list[dict[str, str]], float] | None = None
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("type=SYSCALL "):
            f = fields_of(ln)
            try:
                ts = float(f.get("msg", "audit(0):").split("(")[1].split(":")[0])
            except (ValueError, IndexError):
                continue
            cur = (f, [], ts)
            groups.append(cur)
        elif cur is not None:
            cur[1].append(fields_of(ln) if " " in ln else {})

    for f, aux, ts in groups:
        nr = f.get("syscall", "")
        call = next((n for n, v in SYSCALL_NR.items() if nr == str(v)),
                    nr if nr in SYSCALL_NR else "")
        key = f.get("key", "")
        if not key.startswith("sbob-canary-"):
            continue
        iso = iso_z(str(ts))
        base = {"ts": iso, "workload": workload, "source": "auditd"}

        if call in ("open", "openat"):
            # the PATH record carries the resolved name
            path = next((a.get("name", "") for a in aux if a.get("name")), "")
            if not path:
                continue
            # observer scope: only the declared fixture roots count, and the
            # emitted path is root-relative (AF-HOME/AF-PROC markers) so the
            # per-canary out-dir prefix cannot masquerade as behavior drift
            if path == home or path.startswith(home + "/"):
                canonical = "AF-HOME" + path[len(home):]
            elif path == proc_root or path.startswith(proc_root + "/"):
                canonical = "AF-PROC" + path[len(proc_root):]
            else:
                continue
            bits = int(f.get("a2", "0"), 16) if call == "openat" else int(f.get("a1", "0"), 16)
            ev = dict(base, kind="open", sbob={"path": canonical, "flags": flags_of(bits)})
            events.append(json.dumps(ev))

        elif call == "connect":
            saddr = next((a.get("saddr", "") for a in aux if a.get("saddr")), "")
            dec = decode_saddr(saddr)
            if dec is None:
                diag.append(f"undecodable saddr: {saddr!r}")
                continue
            ip, port = dec
            if ip != "127.0.0.1":
                diag.append(f"non-loopback connect dropped by scope rule: {ip}:{port}")
                continue
            ev = dict(base, kind="connect", sbob={"dst_ip": ip, "dst_port": port})
            events.append(json.dumps(ev))

        elif call == "execve":
            exe = f.get("exe", "") or next((a.get("exe", "") for a in aux if a.get("exe")), "")
            if not exe:
                continue
            args = []
            execve = next((a for a in aux if any(k.startswith("a") and k[1:].isdigit() for k in a)), {})
            i = 0
            while f"a{i}" in execve:
                args.append(execve[f"a{i}"])
                i += 1
            comm = f.get("comm", exe.rsplit("/", 1)[-1])
            ev = dict(base, kind="exec", sbob={"exe": exe, "comm": comm, "args": args})
            events.append(json.dumps(ev))

    return events, diag


def main() -> int:
    if len(sys.argv) < 6:
        print(
            "usage: normalize_auditd.py <captured.audit> <af-home> <af-proc-root> "
            "<workload> <events.jsonl>", file=sys.stderr)
        return 2
    src, home, proc_root, workload, out = sys.argv[1:6]
    lines = open(src, "r", encoding="utf-8", errors="replace").read().splitlines()
    events, diag = normalize(lines, home.rstrip("/"), proc_root.rstrip("/"), workload)
    for d in diag:
        print(f"[normalize] {d}", file=sys.stderr)
    if not events:
        print("[normalize] FAIL: empty event window — nothing survived the "
              "observer scope (capture, fixture tree or scope bug)", file=sys.stderr)
        return 1
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(events) + "\n")
    kinds: dict[str, int] = {}
    for e in events:
        k = json.loads(e)["kind"]
        kinds[k] = kinds.get(k, 0) + 1
    print(f"[normalize] wrote {len(events)} events to {out}: {kinds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
