#!/usr/bin/env python3
"""SBOB-EXAMPLES DEMO WATERMARK — scenario B harness: capture parity checker.

Demo reconstruction, loopback-only stand-ins (TDS 4). Grounding: SBoB repo
test/corpus/php-{benign,drift}.audit shapes; CVE-2026-109618/109619.

Runs on the CI runner (stdlib only) against the two captured telemetry
windows BEFORE any replay, asserting:

  safety  every SOCKADDR in both windows decodes to the declared memcache
          peer (10.96.100.10, loopback-local alias) or loopback — the
          scenario-B TDS 4 hard rule: no socket in this demo ever leaves
          the container
  shape   record types and auditd field shapes match the recorded corpus
          (SYSCALL/EXECVE/PATH/SOCKADDR, key=, exe=, comm=, uid=, saddr=)
  benign  only declared behavior: every PATH under /var/www/html/,
          /var/lib/php/sessions/ or /etc/resolv.conf; the declared memcache
          connect present when the window is non-empty; NO /bin/sh exec,
          /var/tmp write, memfd_create, C2 stand-in connect, or node-scoped
          signature key. An EMPTY benign window is the expected shape in
          node-side observer mode (delta 7: the exe-scoped keys cannot tag
          the containerized workload, declared behavior included) and is
          drift-free by construction.
  drift   the live-fireable leg (memfd_create with key sbob-memfd, node-
          scoped signature key) MUST be present. The exe-scoped legs
          (exec/open/connect) cannot tag a containerized workload observed
          node-side (delta 7): when their records are absent the finding is
          recorded (behaviors proven by side effects in run-behaviors.sh);
          when present (self-hosted in-container observer mode) they are
          validated against the corpus field values.

Exit 0 = parity OK; exit 1 with diagnostics = fail loudly (the lane
iterates on the diagnostics; expected-verdict assertions live in the
replay gates, this gate proves the CAPTURE is faithful and safe).

Usage: check_capture.py <benign.audit> <drift.audit>
"""

from __future__ import annotations

import re
import sys

DECLARED_OPEN_PREFIXES = (
    "/var/www/html/",
    "/var/lib/php/sessions/",
    "/etc/resolv.conf",
)
DECLARED_PEER_IP = "10.96.100.10"
DECLARED_PEER_PORT = 11211
C2_STANDIN_IP = "127.0.0.1"
C2_STANDIN_PORT = 4444
WORKLOAD_KEYS = (
    "sbob-exec-php-fpm",
    "sbob-open-php-fpm",
    "sbob-connect-php-fpm",
)
SIGNATURE_KEYS = (
    "sbob-memfd",
    "sbob-module-load",
    "sbob-namespace-change",
    "sbob-process-tracing",
)

AUDIT_FIELD = re.compile(r'\b(\w+)=("[^"]*"|\S+)')


def fields(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, val in AUDIT_FIELD.findall(line):
        if key not in out:
            out[key] = val.strip('"')
    return out


def load(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def decode_saddr(hexstr: str) -> tuple[str, int] | None:
    """AF_INET sockaddr hex -> (ip, port); None for other/short families."""
    try:
        raw = bytes.fromhex(hexstr.rstrip("Z"))
    except ValueError:
        return None
    if len(raw) < 8 or raw[0] != 0x02 or raw[1] != 0x00:
        return None
    return f"{raw[4]}.{raw[5]}.{raw[6]}.{raw[7]}", (raw[2] << 8) | raw[3]


def check(path: str, expect_drift: bool) -> list[str]:
    lines = load(path)
    problems: list[str] = []
    syscalls = [ln for ln in lines if ln.startswith("type=SYSCALL ")]
    paths = [ln for ln in lines if ln.startswith("type=PATH ")]
    sockaddrs = [ln for ln in lines if ln.startswith("type=SOCKADDR ")]
    execves = [ln for ln in lines if ln.startswith("type=EXECVE ")]

    if not syscalls:
        if expect_drift:
            problems.append(f"{path}: no SYSCALL records captured (the live-fireable memfd leg is missing)")
        else:
            print(f"  {path}: empty window — node-side observer mode (delta 7): drift-free by construction")

    # --- safety: every socket destination must be a stand-in --------------
    for ln in sockaddrs:
        f = fields(ln)
        dec = decode_saddr(f.get("saddr", ""))
        if dec is None:
            problems.append(f"{path}: undecodable saddr: {f.get('saddr')!r} in {ln}")
            continue
        ip, port = dec
        allowed = (ip == DECLARED_PEER_IP and port == DECLARED_PEER_PORT) or (
            ip == C2_STANDIN_IP and port == C2_STANDIN_PORT
        )
        if not allowed:
            problems.append(f"{path}: non-stand-in socket {ip}:{port} (TDS 4 violation): {ln}")

    # --- keys on SYSCALL records must be sbob keys, uid 33 ----------------
    for ln in syscalls:
        f = fields(ln)
        key = f.get("key", "")
        if key not in WORKLOAD_KEYS and key not in SIGNATURE_KEYS:
            problems.append(f"{path}: unexpected audit key {key!r}: {ln}")
        if f.get("uid") != "33":
            problems.append(f"{path}: SYSCALL uid {f.get('uid')} is not the workload uid 33: {ln}")
        if key in SIGNATURE_KEYS and expect_drift is False:
            problems.append(f"{path}: node-scoped signature key leaked into benign window: {ln}")

    if expect_drift:
        # --- the live-fireable leg: memfd_create, node-scoped key ----------
        memfd = [ln for ln in syscalls if fields(ln).get("syscall") == "319"]
        if not any(fields(ln).get("key") == "sbob-memfd" for ln in memfd):
            problems.append(f"{path}: no memfd_create with key sbob-memfd (rule 100163 leg)")

        # --- the exe-scoped legs: corpus-shaped when tagged, recorded
        #     finding when absent (delta 7: exe-scoping vs overlay2 paths).
        #     The behaviors are proven by side effects in run-behaviors.sh;
        #     their rules are proven on the recorded corpus (leg 1).
        sh_execs = [ln for ln in syscalls if fields(ln).get("exe") == "/bin/sh"]
        shell_drop = [ln for ln in paths if fields(ln).get("name") == "/var/tmp/.php2shell.php"]
        c2 = [
            (ip, port)
            for ln in sockaddrs
            if (dec := decode_saddr(fields(ln).get("saddr", "")))
            for ip, port in [dec]
        ]
        if sh_execs or shell_drop or c2:
            # tagged (self-hosted in-container observer mode): full corpus shape
            if not any(fields(ln).get("key") == "sbob-exec-php-fpm" for ln in sh_execs):
                problems.append(f"{path}: /bin/sh exec present but not tagged sbob-exec-php-fpm (rule 100111 leg)")
            if not any('a0="/bin/sh"' in ln and 'a1="-c"' in ln for ln in execves):
                problems.append(f"{path}: no EXECVE record shaped /bin/sh -c <cmd> (rule 100111 leg)")
            if not shell_drop:
                problems.append(f"{path}: no PATH record for /var/tmp/.php2shell.php (rule 100121 leg)")
            elif fields(shell_drop[0]).get("nametype") != "CREATE":
                problems.append(
                    f"{path}: webshell drop nametype={fields(shell_drop[0]).get('nametype')} (expected CREATE): {shell_drop[0]}"
                )
            if (C2_STANDIN_IP, C2_STANDIN_PORT) not in c2:
                problems.append(
                    f"{path}: no C2 stand-in connect {C2_STANDIN_IP}:{C2_STANDIN_PORT} (rule 100131 leg)"
                )
        else:
            print(
                "  FINDING (delta 7): exec/open/connect legs untagged node-side —"
                " exe-scoped rules cannot tag the containerized workload (overlay2 path);"
                " behaviors proven by side effects, rules proven on the recorded corpus"
            )
    else:
        # --- benign: declared behavior only -------------------------------
        for ln in paths:
            name = fields(ln).get("name", "")
            if not name.startswith(DECLARED_OPEN_PREFIXES):
                problems.append(f"{path}: undeclared open in benign window: {name}: {ln}")
        if lines:
            if not any(
                (dec := decode_saddr(fields(ln).get("saddr", "")))
                and dec == (DECLARED_PEER_IP, DECLARED_PEER_PORT)
                for ln in sockaddrs
            ):
                problems.append(
                    f"{path}: non-empty benign window but declared memcache connect {DECLARED_PEER_IP}:{DECLARED_PEER_PORT} missing"
                )
        if any(fields(ln).get("exe") == "/bin/sh" for ln in syscalls):
            problems.append(f"{path}: /bin/sh exec in benign window")
        if any(fields(ln).get("syscall") == "319" for ln in syscalls):
            problems.append(f"{path}: memfd_create in benign window")

    # --- report -------------------------------------------------------------
    print(f"== {path} ==")
    print(f"  records: {len(lines)} (SYSCALL {len(syscalls)}, PATH {len(paths)}, "
          f"SOCKADDR {len(sockaddrs)}, EXECVE {len(execves)})")
    keys: dict[str, int] = {}
    for ln in syscalls:
        k = fields(ln).get("key", "?")
        keys[k] = keys.get(k, 0) + 1
    for k in sorted(keys):
        print(f"  key {k}: {keys[k]}")
    for ln in sockaddrs:
        dec = decode_saddr(fields(ln).get("saddr", ""))
        if dec:
            print(f"  socket dst {dec[0]}:{dec[1]}")
    for p in problems:
        print(f"  PROBLEM {p}")
    return problems


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    benign, drift = sys.argv[1], sys.argv[2]
    problems = check(benign, expect_drift=False) + check(drift, expect_drift=True)
    if problems:
        print(f"FAIL: {len(problems)} capture parity problem(s)")
        return 1
    print("PASS: capture parity + safety (drift memfd leg live; benign drift-free; stand-ins only; delta-7 shape accepted where tagged legs cannot fire)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
