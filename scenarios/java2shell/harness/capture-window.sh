#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario C harness: the capture-window filter.
# Demo reconstruction, loopback-only stand-ins (TDS §4). Grounding: SBoB repo
# docs/php2shell-scenario.md, test/corpus/php-{benign,drift}.audit shapes.
#
# Extracts the two capture windows from the kernel audit log and writes them
# in the recorded-corpus record shape:
#   - SYSCALL records with workload-scoped keys
#     (sbob-exec-java-service / sbob-open-java-service / sbob-connect-java-service): the
#     generated audit fragment is exe-scoped to /usr/local/openjdk-17/bin/java and
#     the kernel resolves a task's exe path against the TASK ROOT (an
#     exe="/usr/local/openjdk-17/bin/java" record for this containerized worker
#     appears in the node-side log, proven live in this lane), so the keys
#     tag this workload from the node vantage too
#   - SYSCALL records with node-scoped signature keys
#     (sbob-memfd / sbob-module-load / sbob-namespace-change /
#     sbob-process-tracing) attributed to the workload by uid=1000: those keys
#     are node-wide by design (Mode B, TDS 7.4) and a CI runner node is a
#     shared node — the harness attributes windows to the workload, exactly
#     what rulePolicies.processAllowed exemptions do in a real deployment
#   - the EXECVE / PATH / SOCKADDR records belonging to a selected SYSCALL
#     event (auditd writes an event's records contiguously, SYSCALL first,
#     so a single print flag replaces id bookkeeping)
# CWD / PROCTITLE records are dropped: they are not part of the sbob decoder
# chain (no rule consumes them), and the recorded corpus carries the same
# four record types.
#
# Implementation note (proven live in this lane): an earlier two-pass
# selector (id collection into a shell pipeline, then a second awk keyed on
# the serial numbers) produced empty windows on the runner container in ways
# that never reproduced with the same mawk binary offline. This selector is
# single-pass and uses ONLY constructs the memfd-trace proved live on the
# runner container awk with the exact records: regex-on-$0 key checks,
# sub()-based timestamp parse, `+ 0` numeric window bounds (bare -v
# comparisons degrade to string compares on mawk 1.3.4-20200120), and the
# uid == "1000" string test.
#
# Field parsing is POSIX awk (mawk-safe: no gawk match() arrays).
#
# Usage: capture-window.sh <audit.log> <b0> <b1> <benign.out> <d0> <d1> <drift.out>
set -euo pipefail

AUDIT_LOG="$1"; B0="$2"; B1="$3"; BENIGN_OUT="$4"; D0="$5"; D1="$6"; DRIFT_OUT="$7"

# --- single-pass window selector -------------------------------------------
# One awk pass per window. `printing` carries "current SYSCALL event is
# selected" across the event's contiguous aux records; a new type=SYSCALL
# record always re-decides (untagged SYSCALLs reset it through the last
# pattern). Class checks are regexes against $0; window bounds are forced
# numeric with `+ 0`.
cap() { # $1=t0 $2=t1 -> selected records on stdout
  awk -v t0="$1" -v t1="$2" '
    $1 == "type=SYSCALL" && /key="sbob-/ {
      printing = 0
      ts = $2
      sub(/^msg=audit\(/, "", ts)
      sub(/\):$/, "", ts)
      split(ts, p, ":")
      tsv = p[1] + 0
      uid = ""
      for (i = 3; i <= NF; i++) {
        if (uid == "" && $i ~ /^uid=/) { uid = substr($i, 5) }
      }
      if (tsv >= t0 + 0 && tsv <= t1 + 0) {
        if (/key="sbob-exec-java-service"/ || /key="sbob-open-java-service"/ || /key="sbob-connect-java-service"/) printing = 1
        else if ((/key="sbob-memfd"/ || /key="sbob-module-load"/ || /key="sbob-namespace-change"/ || /key="sbob-process-tracing"/) && uid == "1000") printing = 1
      }
      if (printing) print
      next
    }
    ($1 == "type=EXECVE" || $1 == "type=PATH" || $1 == "type=SOCKADDR") {
      if (printing) print
      next
    }
    $1 == "type=SYSCALL" { printing = 0 }
  ' "$AUDIT_LOG"
}

# selector decision trace for the live-fireable leg (rule 100163): one line
# per sbob-memfd SYSCALL record — timestamp, uid, window verdict, and whether
# the selector picks it. Debug channel for the node-side attribution model
# (uid=1000 attribution is what ties a node-scoped key to this workload).
awk -v b0="$B0" -v b1="$B1" -v d0="$D0" -v d1="$D1" '
  $1 == "type=SYSCALL" && /key="sbob-memfd"/ {
    ts = $2
    sub(/^msg=audit\(/, "", ts)
    sub(/\):$/, "", ts)
    split(ts, p, ":")
    tsv = p[1] + 0
    uid = ""
    for (i = 3; i <= NF; i++) {
      if (uid == "" && $i ~ /^uid=/) { uid = substr($i, 5) }
    }
    w = "outside"
    if (tsv >= b0 + 0 && tsv <= b1 + 0) w = "benign"
    if (tsv >= d0 + 0 && tsv <= d1 + 0) w = "drift"
    v = (w == "drift" && uid == "1000") ? "selected" : "NOT-selected"
    print "[capture] memfd-trace " ts " uid=" uid " window=" w " " v
  }' "$AUDIT_LOG"

echo "[capture] benign window: [$B0, $B1]"
cap "$B0" "$B1" > "$BENIGN_OUT"
echo "[capture] drift window: [$D0, $D1]"
cap "$D0" "$D1" > "$DRIFT_OUT"

echo "[capture] benign records: $(wc -l < "$BENIGN_OUT"), drift records: $(wc -l < "$DRIFT_OUT")"
echo "[capture] benign key histogram: $(grep -o 'key="sbob-[a-z0-9-]*"' "$BENIGN_OUT" | sort | uniq -c | tr '\n' ' ')"
echo "[capture] drift key histogram: $(grep -o 'key="sbob-[a-z0-9-]*"' "$DRIFT_OUT" | sort | uniq -c | tr '\n' ' ')"
