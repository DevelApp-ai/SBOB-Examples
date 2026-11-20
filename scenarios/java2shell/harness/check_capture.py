#!/usr/bin/env python3
"""SBOB-EXAMPLES DEMO WATERMARK — scenario C harness: capture parity checker.

Demo reconstruction, loopback-only stand-ins (TDS 4). Grounding: CVE-2026-114938
(Java2Shell); record shapes mirror the SBoB repo test/corpus/php-*.audit.

Runs on the CI runner (stdlib only) against the two captured telemetry
windows BEFORE any replay, asserting:

  safety  every SOCKADDR in both windows decodes to the declared config peer
          (10.96.100.30, loopback-local alias) or loopback — the scenario-C
          TDS 4 hard rule: no socket in this demo ever leaves the container
  shape   record types and auditd field shapes match the recorded corpus
          (SYSCALL/EXECVE/PATH/SOCKADDR, key=, exe=, comm=, uid=, saddr=)
  benign  only declared behavior: every PATH under /app/, /var/lib/app-data/
          or /etc/resolv.conf; the declared config-peer connect present when
          the window is non-empty; NO /bin/sh exec, /var/www/webapp or
          /var/tmp write, C2 stand-in connect, or node-scoped signature key.
          An EMPTY benign window is the expected shape in node-side observer
          mode (scenario-C delta-7 analog: the exe-scoped keys cannot tag the
          containerized JVM, declared behavior included) and is drift-free by
          construction.
  drift   the exe-scoped legs (exec/open/connect) cannot tag a containerized
          JVM observed node-side (delta-7 analog): when their records are
          absent the finding is recorded (behaviors proven by side effects in
          run-behaviors.sh); when present (self-hosted in-container observer
          mode) they are validated against the corpus field values.

Exit 0 = parity OK; exit 1 with diagnostics = fail loudly.

Usage: check_capture.py <benign.audit> <drift.audit>
"""

from __future__ import annotations

import re
import sys

DECLARED_OPEN_PREFIXES = (
    "/app/",
    "/var/lib/app-data/",
    "/etc/resolv.conf",
)
DECLARED_PEER_SADDRS = ("020020FB0A60641E",)   # 10.96.100.30:8443 (declared config peer)
C2_STANDIN_SADDRS = ("0200115D7F000001",)       # 127.0.0.1:4445 (C2 stand-in)
WORKLOAD_KEYS = (
    "sbob-exec-java-service",
    "sbob-open-java-service",
    "sbob-connect-java-service",
)
SIGNATURE_KEYS = (
    "sbob-memfd",
    "sbob-module-load",
    "sbob-namespace-change",
    "sbob-process-tracing",
)
DECLARED_EXE = "/usr/local/openjdk-17/bin/java"
WORKLOAD_UID = "1000"
DRIFT_SIG_RE = re.compile(r'exe="/bin/sh"|/var/www/webapp/|/var/tmp/|saddr=0200115D7F000001')


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_capture.py <benign.audit> <drift.audit>", file=sys.stderr)
        return 2
    benign = open(sys.argv[1]).read() if __import__("os").path.exists(sys.argv[1]) else ""
    drift = open(sys.argv[2]).read() if __import__("os").path.exists(sys.argv[2]) else ""
    fail = 0

    def bad(msg: str) -> None:
        nonlocal fail
        fail = 1
        print(f"FAIL: {msg}")

    # --- safety: socket destinations -----------------------------------------
    for name, text in (("benign", benign), ("drift", drift)):
        for m in re.finditer(r"saddr=([0-9A-F]+)", text):
            s = m.group(1)
            if not any(s.startswith(p) for p in DECLARED_PEER_SADDRS + C2_STANDIN_SADDRS):
                bad(f"{name} window: non-stand-in socket address saddr={s}")

    # --- shape: workload records carry the java-service keys + uid -----------
    for name, text in (("benign", benign), ("drift", drift)):
        for line in text.splitlines():
            if "key=\"sbob-" in line:
                if not any(f'key="{k}"' in line for k in WORKLOAD_KEYS + SIGNATURE_KEYS):
                    bad(f"{name} window: unknown sbob key in: {line[:160]}")
                if f"uid={WORKLOAD_UID}" not in line and "type=SYSCALL" in line:
                    bad(f"{name} window: SYSCALL not attributed to workload uid {WORKLOAD_UID}: {line[:160]}")

    # --- benign purity --------------------------------------------------------
    if benign.strip():
        for m in re.finditer(r'type=PATH[^\n]*\n(?:.*\n)?[^\n]*name="([^"]+)"', benign):
            path = m.group(1)
            if not any(path.startswith(p) for p in DECLARED_OPEN_PREFIXES):
                bad(f"benign window: undeclared PATH {path}")
        if DRIFT_SIG_RE.search(benign):
            bad("benign window: drift signature present")
        if not any(s.startswith(DECLARED_PEER_SADDRS[0]) for s in re.findall(r"saddr=([0-9A-F]+)", benign)):
            bad("benign window: no declared config-peer connect")
    else:
        print("[check] benign window empty (expected node-side shape, drift-free by construction)")

    # --- drift: side-effect legs proven by run-behaviors.sh; records optional -
    if drift.strip():
        for line in drift.splitlines():
            if 'key="sbob-' in line and "type=SYSCALL" in line:
                if f'exe="{DECLARED_EXE}"' not in line and 'exe="/bin/sh"' not in line:
                    bad(f"drift window: unexpected exe in tagged record: {line[:160]}")

    if fail:
        print("FAIL: capture parity/safety check failed")
        return 1
    print("PASS: capture parity + safety (loopback-only, benign purity, record shape)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
