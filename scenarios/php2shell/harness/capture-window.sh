#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario B harness: the capture-window filter.
# Demo reconstruction, loopback-only stand-ins (TDS §4). Grounding: SBoB repo
# docs/php2shell-scenario.md, test/corpus/php-{benign,drift}.audit shapes.
#
# Extracts the two capture windows from the kernel audit log and writes them
# in the recorded-corpus record shape:
#   - SYSCALL records whose key is one of the workload-scoped keys
#     (sbob-exec-php-fpm / sbob-open-php-fpm / sbob-connect-php-fpm):
#     the generated audit fragment is exe-scoped to /usr/local/sbin/php-fpm,
#     so by construction only this container's php-fpm trips them — FROM THE
#     IN-CONTAINER VANTAGE. From the node-side observer these keys never
#     match the containerized workload (the node auditd resolves the binary
#     through the overlay2 path): delta 7 in docs/php2shell/detection-
#     evidence.md, the finding this scenario records
#   - SYSCALL records with node-scoped signature keys
#     (sbob-memfd / sbob-module-load / sbob-namespace-change /
#     sbob-process-tracing) attributed to the workload by uid=33: those keys
#     are node-wide by design (Mode B, TDS 7.4) and a CI runner node is a
#     shared node — the harness attributes windows to the workload, exactly
#     what rulePolicies.processAllowed exemptions do in a real deployment
#   - the EXECVE / PATH / SOCKADDR records belonging to a selected SYSCALL
#     event id (same msg=audit(<ts>:<serial>))
# CWD / PROCTITLE records are dropped: they are not part of the sbob decoder
# chain (no rule consumes them), and the recorded corpus carries the same
# four record types.
#
# Field parsing is POSIX awk (mawk-safe: no gawk match() arrays).
#
# Usage: capture-window.sh <audit.log> <b0> <b1> <benign.out> <d0> <d1> <drift.out>
set -euo pipefail

AUDIT_LOG="$1"; B0="$2"; B1="$3"; BENIGN_OUT="$4"; D0="$5"; D1="$6"; DRIFT_OUT="$7"

# --- shared selector: SYSCALL records in [t0,t1] with allowed keys -> ids ---
sel() { # $1=t0 $2=t1 -> selected event ids on stdout
  awk -v t0="$1" -v t1="$2" '
    $1 == "type=SYSCALL" && $2 ~ /^msg=audit\([0-9]/ {
      ts = $2
      sub(/^msg=audit\(/, "", ts)
      sub(/\):$/, "", ts)
      split(ts, p, ":")
      tsv = p[1] + 0
      if (tsv < t0 || tsv > t1) next
      key = ""; uid = ""
      for (i = 3; i <= NF; i++) {
        if (key == "" && $i ~ /^key="sbob-/) {
          key = $i
          sub(/^key="/, "", key)
          sub(/"$/, "", key)
        }
        if (uid == "" && $i ~ /^uid=/) { uid = substr($i, 5) }
      }
      if (key == "") next
      work = (key == "sbob-exec-php-fpm" || key == "sbob-open-php-fpm" || key == "sbob-connect-php-fpm")
      sig = (key == "sbob-memfd" || key == "sbob-module-load" || \
             key == "sbob-namespace-change" || key == "sbob-process-tracing")
      if (work) print p[2]
      else if (sig && uid == "33") print p[2]
    }' "$AUDIT_LOG"
}

ids_for_window() { # $1=t0 $2=t1 $3=outfile — write full event records
  local t0="$1" t1="$2" out="$3" ids
  ids=$(sel "$t0" "$t1" | sort -u | tr '\n' ' ')
  if [ -z "$ids" ]; then
    : > "$out"
    return
  fi
  awk -v ids="$ids" '
    BEGIN { n = split(ids, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
    $2 ~ /^msg=audit\([0-9]/ {
      ts = $2
      sub(/^msg=audit\(/, "", ts)
      sub(/\):$/, "", ts)
      split(ts, p, ":")
      if ($1 == "type=SYSCALL") { if (want[p[2]]) print; next }
      if ($1 == "type=EXECVE" || $1 == "type=PATH" || $1 == "type=SOCKADDR") {
        if (want[p[2]]) print
      }
    }' "$AUDIT_LOG" > "$out"
}

echo "[capture] benign window: [$B0, $B1]"
ids_for_window "$B0" "$B1" "$BENIGN_OUT"
echo "[capture] drift window: [$D0, $D1]"
ids_for_window "$D0" "$D1" "$DRIFT_OUT"

echo "[capture] benign records: $(wc -l < "$BENIGN_OUT"), drift records: $(wc -l < "$DRIFT_OUT")"
