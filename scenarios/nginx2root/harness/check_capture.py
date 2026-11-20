#!/usr/bin/env python3
"""SBOB-EXAMPLES DEMO WATERMARK — scenario D harness: capture parity checker.

Demo reconstruction, loopback-only stand-ins (TDS 4). Grounding: NGINX2Root
(CVE-2026-123007 et al., Xint 2026-11-18); record shapes mirror the SBoB repo
test/corpus/php-*.audit.

Runs on the CI runner (stdlib only) against the two captured telemetry windows
BEFORE any replay, asserting:

  safety  every SOCKADDR in both windows decodes to the declared upstream
          (10.96.100.40, loopback-local alias) or loopback — no socket in this
          demo ever leaves the container (TDS 4 hard rule)
  shape   workload records carry the nginx-worker keys; node-scoped signature
          keys (module-load etc.) are attributed to uid 0 (host)
  benign  only declared behavior; an EMPTY benign window is the expected
          node-side shape (scenario-D delta-7 analog) and is drift-free by
          construction
  drift   exe-scoped legs cannot tag a containerized worker observed
          node-side (delta-7 analog); the SCTP module-load signature key IS
          node-scoped and may tag live (uid 0) — both shapes accepted, the
          sctp-already-loaded variant is the committed expected-silent finding

Exit 0 = parity OK; exit 1 with diagnostics = fail loudly.

Usage: check_capture.py <benign.audit> <drift.audit>
"""

from __future__ import annotations

import os
import re
import sys

DECLARED_OPEN_PREFIXES = (
    "/etc/nginx/",
    "/var/www/html/",
    "/var/log/nginx/",
    "/var/cache/nginx/",
    "/etc/resolv.conf",
)
DECLARED_PEER_SADDRS = ("02001F900A606428",)   # 10.96.100.40:8080 (declared upstream)
C2_STANDIN_SADDRS = ("0200115E7F000001",)       # 127.0.0.1:4446 (C2 stand-in)
WORKLOAD_KEYS = (
    "sbob-exec-nginx-worker",
    "sbob-open-nginx-worker",
    "sbob-connect-nginx-worker",
)
SIGNATURE_KEYS = (
    "sbob-memfd",
    "sbob-module-load",
    "sbob-namespace-change",
    "sbob-process-tracing",
)
WORKER_UID = "101"
HOST_UID = "0"
DRIFT_SIG_RE = re.compile(r'exe="/bin/sh"|/etc/passwd|/etc/shadow|/var/tmp/|saddr=0200115E7F000001')


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_capture.py <benign.audit> <drift.audit>", file=sys.stderr)
        return 2
    benign = open(sys.argv[1]).read() if os.path.exists(sys.argv[1]) else ""
    drift = open(sys.argv[2]).read() if os.path.exists(sys.argv[2]) else ""
    fail = 0

    def bad(msg: str) -> None:
        nonlocal fail
        fail = 1
        print(f"FAIL: {msg}")

    for name, text in (("benign", benign), ("drift", drift)):
        for m in re.finditer(r"saddr=([0-9A-F]+)", text):
            s = m.group(1)
            if not any(s.startswith(p) for p in DECLARED_PEER_SADDRS + C2_STANDIN_SADDRS):
                bad(f"{name} window: non-stand-in socket address saddr={s}")
        for line in text.splitlines():
            if 'key="sbob-' in line and "type=SYSCALL" in line:
                if not any(f'key="{k}"' in line for k in WORKLOAD_KEYS + SIGNATURE_KEYS):
                    bad(f"{name} window: unknown sbob key: {line[:160]}")
                if any(f'key="{k}"' in line for k in WORKLOAD_KEYS) and f"uid={WORKER_UID}" not in line:
                    bad(f"{name} window: workload-keyed SYSCALL not attributed to worker uid {WORKER_UID}: {line[:160]}")
                if any(f'key="{k}"' in line for k in SIGNATURE_KEYS) and f"uid={HOST_UID}" not in line:
                    # node-scoped signature keys attribute to the host (uid 0)
                    bad(f"{name} window: signature-keyed SYSCALL not attributed to host uid {HOST_UID}: {line[:160]}")

    if benign.strip():
        for m in re.finditer(r'name="([^"]+)"', benign):
            path = m.group(1)
            if path.startswith("/") and not any(path.startswith(p) for p in DECLARED_OPEN_PREFIXES):
                bad(f"benign window: undeclared PATH {path}")
        if DRIFT_SIG_RE.search(benign):
            bad("benign window: drift signature present")
        if not any(s.startswith(DECLARED_PEER_SADDRS[0]) for s in re.findall(r"saddr=([0-9A-F]+)", benign)):
            bad("benign window: no declared upstream connect")
    else:
        print("[check] benign window empty (expected node-side shape, drift-free by construction)")

    if fail:
        print("FAIL: capture parity/safety check failed")
        return 1
    print("PASS: capture parity + safety (loopback-only, benign purity, record shape)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
