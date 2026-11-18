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
#   pre-checks   fail loudly before any replay. Live-fireable leg (memfd,
#                node-scoped key) must be tagged. The exe-scoped legs
#                (exec/open/connect) cannot tag a containerized workload
#                observed node-side (delta 7, the recorded finding): their
#                behaviors are proven by real side effects instead. With an
#                in-container observer (self-hosted mode) the corpus-shaped
#                pre-checks apply instead. Benign must stay drift-free in
#                both modes.
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
DRIFT_RESP=$(fcgi behaviors.php) || DRIFT_RESP="___fcgi-request-failed"
D1=$(date +%s.%N)
printf '%s\n' "$DRIFT_RESP"

# let auditd flush the window tail
sleep 2

bash /opt/harness/capture-window.sh "$AUDIT_LOG" "$B0" "$B1" "$OUT/benign.audit" "$D0" "$D1" "$OUT/drift.audit"

echo "[harness] --- in-container pre-checks (fail loudly, before any replay) ---"
echo "[harness] drift side effects (behaviors 1-3 really executed, audit aside):"
ls -la /var/tmp/.pwned /var/tmp/.php2shell.php 2>&1 || true
fail=0

# --- the one live-fireable drift leg: memfd_create (node-scoped key, uid 33).
# The signature rule has no exe filter, so the node-side observer tags it.
grep -q 'syscall=319' "$OUT/drift.audit" \
  || { echo "FAIL: drift window has no memfd_create (rule 100163 leg)"; fail=1; }
grep -q 'key="sbob-memfd"' "$OUT/drift.audit" \
  || { echo "FAIL: drift memfd_create is not tagged sbob-memfd (rule 100163 leg)"; fail=1; }

# --- behaviors 1-3: FINDING (delta 7), not a harness defect -----------------
# The generated fragment is exe-scoped (Mode A) to /usr/local/sbin/php-fpm,
# the path as the workload sees it in its own mount namespace. A node-side
# auditd resolves the containerized binary through the overlay2 merged path,
# so sbob-exec/-open/-connect-php-fpm cannot tag this containerized workload:
# behaviors 1-3 execute for real (side effects above) but produce no tagged
# records. That is the honest SBoB finding this scenario records
# (docs/php2shell/detection-evidence.md, delta 7); their rules are proven on
# the recorded corpus (leg 1). On a self-hosted node with the in-container
# observer the keys tag normally and the corpus-shaped pre-checks apply.
if grep -q 'exe="/bin/sh"' "$OUT/drift.audit"; then
  echo "[harness] exe-scoped keys tag the workload (in-container observer mode): corpus-shaped pre-checks apply"
  grep -q '/var/tmp/.php2shell.php' "$OUT/drift.audit" \
    || { echo "FAIL: /bin/sh exec tagged but webshell drop missing (inconsistent window)"; fail=1; }
  grep -q 'saddr=0200115C7F000001' "$OUT/drift.audit" \
    || { echo "FAIL: /bin/sh exec tagged but C2 connect missing (inconsistent window)"; fail=1; }
else
  echo "[harness] FINDING (delta 7): exec/open/connect legs untagged node-side (exe-scoping vs overlay2 paths)"
  test -s /var/tmp/.pwned \
    || { echo "FAIL: behavior 1 (/bin/sh spawn) did not execute (no /var/tmp/.pwned side effect)"; fail=1; }
  test -f /var/tmp/.php2shell.php \
    || { echo "FAIL: behavior 2 (webshell drop) did not execute (no /var/tmp/.php2shell.php side effect)"; fail=1; }
  case "$DRIFT_RESP" in
    *"b3 C2 stand-in 127.0.0.1:4444 connected"*) : ;;
    *"b3 C2 connect failed"*)
      echo "FAIL: behavior 3 (C2 stand-in connect) failed: $(printf '%s' "$DRIFT_RESP" | grep -o 'b3 C2 connect failed.*' | head -1)"; fail=1 ;;
    *)
      echo "FAIL: behavior 3 (C2 stand-in connect) outcome unknown (no behaviors.php response)"; fail=1 ;;
  esac
fi

# --- benign window: declared behavior must stay drift-free -----------------
# Same finding, benign side: the exe-scoped keys cannot tag the benign
# declared behavior either, so an EMPTY benign window is the expected
# node-side shape and is drift-free by construction. When the observer does
# tag (self-hosted in-container mode) the declared memcache connect must be
# present and the window must be declared-only.
if [ -s "$OUT/benign.audit" ]; then
  grep -q 'saddr=02002BCB0A60640A' "$OUT/benign.audit" \
    || { echo "FAIL: benign window has records but no declared memcache connect 10.96.100.10:11211"; fail=1; }
else
  echo "[harness] benign window empty (delta 7 shape: declared behavior untagged node-side, drift-free by construction)"
fi

sig_drift_re='exe="/bin/sh"|/var/tmp/\.|syscall=319|saddr=0200115C7F000001'

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
echo "PASS: capture pre-checks (live-fireable memfd leg tagged, delta-7 shape recorded, benign drift-free)"
