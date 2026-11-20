#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# SBOB-EXAMPLES DEMO WATERMARK — scenario A (agent-framework) M3 corpus gate
# (issue #4, layer-2 runtime detection).
#
# Feeds the synthetic scenario-A corpora (scenarios/agent-framework/
# telemetry/{benign,drift,sustained}.audit) through a live Wazuh manager
# running the bundle generated from the committed consumer workload
# (sbobs/workload/python-ci-runner.yaml, slot 2 -> rule band 1002xx), and
# asserts the expected-verdict shape (TDS §7: never a permanently red lane;
# verdicts recorded, then asserted):
#
#   benign     -> ZERO drift/alerting rules fire (level-0 base chains only)
#   drift      -> 100221 (open drift: /proc/*/environ + credential reads) and
#                 100231 (connect drift: the single exfil POST to the sink)
#                 fire; the honest absences 100211 (exec drift: the stealer
#                 lives inside the DECLARED interpreter), 100201 (cloud
#                 credentials are not on the sensitive-file watchlist),
#                 100222/100232 (single-POST semantics: no repetition) stay
#                 quiet and are asserted so
#   sustained  -> 100222 + 100232 fire (synthetic 8x repetition capability
#                 proof); 100212 (sustained exec) and 100209 (sustained
#                 sensitive) stay quiet and are asserted so
#
# Corpus->rule expectations were verified on a local wazuh-manager 4.14.6
# replica before the first lane run; the lane re-proves them against the
# pinned container image on every run.
#
# Designed to run INSIDE the wazuh-manager container via docker exec, where
# wazuh-logtest reads the manager's live ruleset. Mirrors the proven
# logtest-corpus.sh mechanics from the pinned SBoB repo (both 4.14 and older
# matched-rule output spellings are accepted).
#
# Usage: logtest-gate.sh <telemetry-dir>  (corpora: benign/drift/sustained.audit)
# Exit: 0 all gates pass, 1 assertion failed.
# ---------------------------------------------------------------------------
set -euo pipefail

TDIR="${1:?usage: logtest-gate.sh <telemetry-dir>}"
command -v wazuh-logtest >/dev/null 2>&1 || {
  echo "FAIL: wazuh-logtest not found — run this inside the manager container" >&2
  exit 1
}

ALERTING_IDS=(100221 100231 100222 100232 100211 100212 100201 100202 100209 100260 100261 100262 100263)
DRIFT_IDS=(100221 100231)
DRIFT_ABSENT_IDS=(100211 100201 100222 100232)
SUSTAINED_IDS=(100222 100232)
SUSTAINED_ABSENT_IDS=(100212 100209)

# matched-rule grep: accepts the 4.14 spelling (id: 'NNNNNN') and the older
# "Rule id: NNNNNN" spelling; analysis goes to stderr in 4.14 -> capture 2>&1
fired_grep() { grep -qE "(Rule id: |[[:space:]]id: ')$1'|id=$1([^0-9]|$)" "$2"; }

replay() { cat "$1" | wazuh-logtest 2>&1; }

RC=0

echo "== [scenario A] benign corpus: expecting ZERO drift/alerting rules =="
replay "$TDIR/benign.audit" | tee /tmp/sbob-af-benign.out || true
fired_any=0
for id in "${ALERTING_IDS[@]}"; do
  if fired_grep "$id" /tmp/sbob-af-benign.out; then
    echo "FAIL: benign corpus fired $id — see /tmp/sbob-af-benign.out" >&2
    fired_any=1
  fi
done
if [ "$fired_any" -eq 0 ]; then
  echo "OK: benign corpus fired no drift/alerting rules (level-0 base chains only)"
else
  RC=1
  echo "      check the opens/execs/egress contract in sbobs/workload/ vs the corpus paths" >&2
fi

echo "== [scenario A] drift corpus: expecting ${DRIFT_IDS[*]}; honest absences: ${DRIFT_ABSENT_IDS[*]} =="
replay "$TDIR/drift.audit" | tee /tmp/sbob-af-drift.out || true
for id in "${DRIFT_IDS[@]}"; do
  if ! fired_grep "$id" /tmp/sbob-af-drift.out; then
    echo "FAIL: drift rule $id did not fire — see /tmp/sbob-af-drift.out" >&2
    RC=1
  else
    echo "OK: drift rule $id fired"
  fi
done
for id in "${DRIFT_ABSENT_IDS[@]}"; do
  if fired_grep "$id" /tmp/sbob-af-drift.out; then
    echo "FAIL: rule $id fired on the single-pass drift corpus — UNEXPECTED verdict (see the honest-absence design in the corpus header)" >&2
    RC=1
  else
    echo "OK: honest absence held — $id quiet on the single pass"
  fi
done

echo "== [scenario A] sustained corpus: expecting ${SUSTAINED_IDS[*]} (8/120s, one session); honest absences: ${SUSTAINED_ABSENT_IDS[*]} =="
replay "$TDIR/sustained.audit" | tee /tmp/sbob-af-sustained.out || true
for id in "${SUSTAINED_IDS[@]}"; do
  if ! fired_grep "$id" /tmp/sbob-af-sustained.out; then
    echo "FAIL: sustained rule $id did not fire — see /tmp/sbob-af-sustained.out" >&2
    echo "      frequency children need 8 parent matches within 120s in ONE logtest session (wazuh 4.14: the parent must also WIN the matched-rule selection)" >&2
    RC=1
  else
    echo "OK: sustained rule $id fired"
  fi
done
for id in "${SUSTAINED_ABSENT_IDS[@]}"; do
  if fired_grep "$id" /tmp/sbob-af-sustained.out; then
    echo "FAIL: sustained rule $id fired — UNEXPECTED (no exec drift / no watchlist path in this scenario)" >&2
    RC=1
  else
    echo "OK: honest absence held — $id quiet"
  fi
done

if [ "$RC" -eq 0 ]; then
  echo
  echo "PASS (scenario A M3): benign quiet; drift 100221+100231; sustained 100222+100232"
else
  echo
  echo "FAIL (scenario A M3): see the per-leg messages above" >&2
fi
exit "$RC"
