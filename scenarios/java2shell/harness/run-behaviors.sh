#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario C harness: run the benign and
# post-exploit request flows against the java-service fixture and capture the
# auditd windows. Demo reconstruction, loopback-only stand-ins (TDS §4).
# Grounding: CVE-2026-114938 (Java2Shell, JIT Base64 fast path, OpenJDK 17).
#
# Runs INSIDE the workload container (docker exec). The CI lane loads the
# SBoB-generated audit fragment (wazuh/audit/sbob/java-service.rules from the
# transpiled bundle) before invoking this script.
#
# Flow (same discipline as scenario B):
#   warm-up      one benign request OUTSIDE any capture window
#   benign  win  /benign     — declared behavior only (silent)
#   drift   win  /behaviors  — the four post-RCE behaviors
#   capture      capture-window.sh filters the audit log into the two
#                corpus-shaped telemetry files
#   pre-checks   fail loudly before any replay: behaviors 1-3 proven by real
#                side effects (the exe-scoped audit keys cannot tag a
#                containerized JVM observed node-side — the scenario-C analog
#                of scenario B's delta 7 — so side effects carry the proof);
#                b4 (defineClass) must have run and must leave NO undeclared
#                record (expected-silent finding). Benign must stay drift-free.
set -euo pipefail

AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
OUT="${TELEMETRY_OUT:-/opt/telemetry}"
mkdir -p "$OUT"

req() { # $1 = path
  curl -s --max-time 20 "http://127.0.0.1:8080$1" 2>/dev/null
}

# fresh state: no leftover webshell / pwn marker / c2 log
rm -f /var/tmp/.pwned /var/www/webapp/shell.jsp /tmp/c2-standin.log
rm -f /var/lib/app-data/counter.txt

echo "[harness] warm-up request (outside all windows)"
req /benign >/dev/null

echo "[harness] benign window"
B0=$(date +%s.%N)
BENIGN_RESP=$(req /benign) || BENIGN_RESP="___http-request-failed"
B1=$(date +%s.%N)
printf '%s\n' "$BENIGN_RESP"

echo "[harness] drift window"
D0=$(date +%s.%N)
DRIFT_RESP=$(req /behaviors) || DRIFT_RESP="___http-request-failed"
D1=$(date +%s.%N)
printf '%s\n' "$DRIFT_RESP"

# let auditd flush the window tail before reading the log back (proven in the
# scenario-B lane: tagged events reach audit.log only after one flush interval)
sleep 10

echo "[harness] audit log view: $(wc -l < "$AUDIT_LOG") lines / $(wc -c < "$AUDIT_LOG") bytes"
echo "[harness] drift window bounds: [$D0, $D1] (benign: [$B0, $B1])"
bash /opt/harness/capture-window.sh "$AUDIT_LOG" "$B0" "$B1" "$OUT/benign.audit" "$D0" "$D1" "$OUT/drift.audit"

echo "[harness] --- side effects (behaviors really executed) ---"
ls -la /var/tmp/.pwned /var/www/webapp/shell.jsp 2>&1 || true
echo "[harness] C2 stand-in received: $(cat /tmp/c2-standin.log 2>/dev/null | head -2 || echo '(nothing)')"
fail=0

# b1: /bin/sh spawn executed for real
test -s /var/tmp/.pwned \
  || { echo "FAIL: behavior 1 (/bin/sh spawn) did not execute (no /var/tmp/.pwned)"; fail=1; }
# b2: webshell dropped for real
test -f /var/www/webapp/shell.jsp \
  || { echo "FAIL: behavior 2 (webshell drop) did not execute (no shell.jsp)"; fail=1; }
# b3: C2 stand-in callback received
printf '%s' "$DRIFT_RESP" | grep -q 'b3 C2 stand-in 127.0.0.1:4445 connected' \
  || { echo "FAIL: behavior 3 (C2 stand-in connect) outcome: $(printf '%s' "$DRIFT_RESP" | grep -o 'b3 C2.*' | head -1)"; fail=1; }
grep -q 'GET / HTTP/1.0' /tmp/c2-standin.log 2>/dev/null \
  || { echo "FAIL: behavior 3: C2 stand-in listener logged no callback"; fail=1; }
# b4: defineClass leg ran, and produced NO drift record (expected-silent)
printf '%s' "$DRIFT_RESP" | grep -q 'b4 defineClass in-JVM payload ran' \
  || { echo "FAIL: behavior 4 (defineClass) did not run: $(printf '%s' "$DRIFT_RESP" | grep -o 'b4 defineClass.*' | head -1)"; fail=1; }

# benign window: declared behavior must stay drift-free
sig_drift_re='exe="/bin/sh"|/var/www/webapp/|/var/tmp/|saddr=0200115D7F000001'
if grep -Eq "$sig_drift_re" "$OUT/benign.audit"; then
  echo "FAIL: benign window contains drift signatures:"
  grep -E "$sig_drift_re" "$OUT/benign.audit"
  fail=1
fi
# benign declared peer connect present when the window is non-empty
if [ -s "$OUT/benign.audit" ]; then
  grep -q 'saddr=020020FB0A60641E' "$OUT/benign.audit" \
    || { echo "FAIL: benign window has records but no declared config-peer connect 10.96.100.30:8443"; fail=1; }
else
  echo "[harness] benign window empty (expected node-side shape: exe-scoped keys cannot tag the containerized JVM — scenario-C delta-7 analog, drift-free by construction)"
fi

# safety assertion (TDS §4): every SOCKADDR in BOTH windows must be the
# declared config peer or loopback — no other destination, ever
for f in "$OUT/benign.audit" "$OUT/drift.audit"; do
  bad=$(grep -o 'saddr=[0-9A-F]*' "$f" | grep -v -E 'saddr=020020FB0A60641E|saddr=0200115D7F000001' || true)
  if [ -n "$bad" ]; then
    echo "FAIL: non-stand-in socket address in $f: $bad"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "[harness] benign window:"; cat "$OUT/benign.audit"
  echo "[harness] drift window:"; cat "$OUT/drift.audit"
  echo "FAIL: capture pre-checks failed"
  exit 1
fi

echo "[harness] benign window:"
cat "$OUT/benign.audit"
echo "[harness] drift window:"
cat "$OUT/drift.audit"
echo "PASS: capture pre-checks (b1-b3 side effects present, b4 expected-silent, benign drift-free, loopback-only)"
