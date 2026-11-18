#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario B harness: run the benign and
# post-exploit request flows and capture the auditd windows.
# Demo reconstruction, loopback-only stand-ins (TDS §4). Grounding: SBoB repo
# docs/php2shell-scenario.md; CVE-2026-109618 / CVE-2026-109619.
#
# Runs INSIDE the workload container (docker exec). The CI lane loads the
# SBoB-generated audit fragment (wazuh/audit/sbob/php-fpm.rules from the
# transpiled bundle) before invoking this script.
#
# Flow:
#   warm-up      one benign request OUTSIDE any capture window (workers fully
#                initialized; any runtime file opens the first request makes
#                happen here, unrecorded)
#   benign  win  benign.php  — declared behavior only (base chain, silent)
#   drift   win  behaviors.php — the four post-exploit behaviors
#   capture      capture-window.sh filters the audit log into the two corpus-
#                shaped telemetry files
#   pre-checks  hard-fail inside the container if a signature is missing or
#                the benign window contains drift signatures
set -euo pipefail

AUDIT_LOG="${AUDIT_LOG:-/var/log/audit/audit.log}"
OUT="${TELEMETRY_OUT:-/opt/telemetry}"
mkdir -p "$OUT"

fcgi() { # $1 = script basename under /var/www/html
  SCRIPT_NAME="/$1" SCRIPT_FILENAME="/var/www/html/$1" REQUEST_METHOD=GET \
    QUERY_STRING="" CONTENT_TYPE="" CONTENT_LENGTH="" \
    cgi-fcgi -bind -connect 127.0.0.1:9000 2>/dev/null
}

# fresh state: no leftover session files, webshell or pwn marker
rm -f /var/lib/php/sessions/sess_* /var/tmp/.php2shell.php /var/tmp/.pwned

echo "[harness] warm-up request (outside all windows)"
fcgi benign.php >/dev/null

echo "[harness] benign window"
B0=$(date +%s.%N)
fcgi benign.php
B1=$(date +%s.%N)

echo "[harness] drift window"
rm -f /var/tmp/.php2shell.php /var/tmp/.pwned
D0=$(date +%s.%N)
fcgi behaviors.php
D1=$(date +%s.%N)

# let auditd flush the window tail
sleep 2

bash /opt/harness/capture-window.sh "$AUDIT_LOG" "$B0" "$B1" "$OUT/benign.audit" "$D0" "$D1" "$OUT/drift.audit"

echo "[harness] --- in-container pre-checks (fail loudly, before any replay) ---"
echo "[harness] drift side effects (behaviors really executed, audit aside):"
ls -la /var/tmp/.pwned /var/tmp/.php2shell.php 2>&1 || true
fail=0

sig_drift_re='exe="/bin/sh"|/var/tmp/\.|syscall=319|saddr=0200115C7F000001'

grep -q 'exe="/bin/sh"' "$OUT/drift.audit" || { echo "FAIL: drift window has no /bin/sh exec (rule 100111 leg)"; fail=1; }
grep -q '/var/tmp/.php2shell.php' "$OUT/drift.audit" || { echo "FAIL: drift window has no webshell drop (rule 100121 leg)"; fail=1; }
grep -q 'saddr=0200115C7F000001' "$OUT/drift.audit" || { echo "FAIL: drift window has no C2 stand-in connect 127.0.0.1:4444 (rule 100131 leg)"; fail=1; }
grep -q 'syscall=319' "$OUT/drift.audit" || { echo "FAIL: drift window has no memfd_create (rule 100163 leg)"; fail=1; }
grep -q 'saddr=02002BCB0A60640A' "$OUT/benign.audit" || { echo "FAIL: benign window has no declared memcache connect 10.96.100.10:11211"; fail=1; }

if grep -Eq "$sig_drift_re" "$OUT/benign.audit"; then
  echo "FAIL: benign window contains drift signatures:"
  grep -E "$sig_drift_re" "$OUT/benign.audit"
  fail=1
fi

if grep -q 'sbob-namespace-change\|sbob-process-tracing\|sbob-module-load' "$OUT/benign.audit"; then
  echo "FAIL: benign window contains node-scoped signature keys (attribution leak):"
  grep -E 'sbob-namespace-change|sbob-process-tracing|sbob-module-load' "$OUT/benign.audit"
  fail=1
fi

# safety assertion (TDS §4): every SOCKADDR in BOTH windows must be the
# declared memcache peer alias or loopback — no other destination, ever
for f in "$OUT/benign.audit" "$OUT/drift.audit"; do
  bad=$(grep -o 'saddr=[0-9A-F]*' "$f" | grep -v -E 'saddr=02002BCB0A60640A|saddr=0200115C7F000001' || true)
  if [ -n "$bad" ]; then
    echo "FAIL: non-stand-in socket address in $f: $bad"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "[harness] benign window:"
  cat "$OUT/benign.audit"
  echo "[harness] drift window:"
  cat "$OUT/drift.audit"
  echo "FAIL: capture pre-checks failed"
  exit 1
fi

echo "[harness] benign window:"
cat "$OUT/benign.audit"
echo "[harness] drift window:"
cat "$OUT/drift.audit"
echo "PASS: capture pre-checks (both windows captured, drift signatures present, benign clean)"
