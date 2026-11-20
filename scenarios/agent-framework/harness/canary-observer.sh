#!/bin/bash
# ============================================================================
# SBOB-EXAMPLES DEMO WATERMARK — scenario A harness: canary auditd observer.
# Issue #3 (M2 Gate C): node-side uid-scoped kernel observer for the canary.
#
# DESIGN DEVIATION FROM TDS DRAFT (recorded in docs/supply-chain-evidence.md):
# the TDS draft says "disposable canary container with auditd"; the M6 lane
# proved live on GitHub-hosted runners that auditd INSIDE a runner container
# cannot load rules (EPERM on the shared kernel audit interface). This
# observer therefore runs NODE-SIDE — the proven M6 shape — and scopes by a
# DEDICATED CANARY UID instead of a container boundary: every rule carries
# -F uid=$CANARY_UID, so the window contains exactly what the disposable
# canary identity did. The canary itself is disposable: fresh work dirs, no
# real credentials (synthetic fixture tree), loopback-only sink (TDS §4).
#
# Usage:
#   canary-observer.sh setup   <canary_uid>        # install/start auditd, load rules
#   canary-observer.sh mark                        # print epoch seconds (window start marker)
#   canary-observer.sh capture  <canary_uid> <t0> <out.audit>   # flush-waited keyed window
#   canary-observer.sh teardown                    # delete our rules (disposable node hygiene)
#
# Rules loaded (b64 syscall ids: open=2, openat=257, connect=42, execve=59):
#   -a always,exit -F arch=b64 -S open,openat     -F uid=$CANARY_UID -F key=sbob-canary-open
#   -a always,exit -F arch=b64 -S connect         -F uid=$CANARY_UID -F key=sbob-canary-connect
#   -a always,exit -F arch=b64 -S execve          -F uid=$CANARY_UID -F key=sbob-canary-exec
#
# Capture follows the live-proven php2shell capture rules: auditd writes the
# node log in flush batches, so capture sleeps well past one flush interval
# before reading (M6 lesson: a tagged event sat in the kernel queue at
# capture time and reached the log only after the grep). The selector is the
# single-pass mawk-safe shape from scenarios/php2shell/harness/capture-
# window.sh: a keyed type=SYSCALL record prints, its contiguous type=EXECVE/
# type=PATH/type=SOCKADDR records follow, a new type=SYSCALL re-decides;
# window bounds are forced numeric (`+ 0`, the mawk 1.3.4 lesson).
# ============================================================================
set -euo pipefail

AUDIT_LOG="/var/log/audit/audit.log"

case "${1:-}" in

  setup)
    CANARY_UID="$2"
    if ! command -v auditctl >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null
      apt-get install -y -qq auditd >/dev/null
    fi
    # GH runner images ship auditd sometimes stopped but usable via sudo.
    if ! pgrep -x auditd >/dev/null 2>&1; then
      service auditd start >/dev/null 2>&1 || systemctl start auditd >/dev/null 2>&1 || true
    fi
    # sleep past the first flush so a fresh log tail cannot miss early canary events
    sleep 2
    # disposable runner: clearing the ruleset is safe (no other audit policy
    # runs on an ephemeral job node; teardown restores by deleting our rules)
    auditctl -D >/dev/null
    auditctl -a always,exit -F arch=b64 -S open,openat  -F uid="$CANARY_UID" -F key=sbob-canary-open
    auditctl -a always,exit -F arch=b64 -S connect      -F uid="$CANARY_UID" -F key=sbob-canary-connect
    auditctl -a always,exit -F arch=b64 -S execve       -F uid="$CANARY_UID" -F key=sbob-canary-exec
    echo "[observer] rules loaded for uid $CANARY_UID:"
    auditctl -l | sed 's/^/[observer]   /'
    ;;

  mark)
    date +%s
    ;;

  capture)
    CANARY_UID="$2"; T0="$3"; OUT="$4"
    # let auditd flush the canary workload (live-proven M6 timing)
    sleep 10
    awk -v t0="$T0" -v uid0="$CANARY_UID" '
      $1 == "type=SYSCALL" && /key="sbob-canary-/ {
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
        if (tsv >= t0 + 0 && uid == uid0) printing = 1
        if (printing) print
        next
      }
      ($1 == "type=EXECVE" || $1 == "type=PATH" || $1 == "type=SOCKADDR") {
        if (printing) print
        next
      }
      $1 == "type=SYSCALL" { printing = 0 }
    ' "$AUDIT_LOG" > "$OUT.tmp" || true
    mv "$OUT.tmp" "$OUT"
    echo "[observer] captured $(wc -l < "$OUT") records since $T0 to $OUT"
    echo "[observer] key histogram: $(grep -o 'key=\"sbob-canary-[a-z]*\"' "$OUT" | sort | uniq -c | tr '\n' ' ')"
    ;;

  teardown)
    auditctl -D >/dev/null 2>&1 || true
    echo "[observer] rules deleted (disposable node hygiene)"
    ;;

  *)
    echo "usage: canary-observer.sh setup <uid> | mark | capture <uid> <t0> <out> | teardown" >&2
    exit 2
    ;;
esac
