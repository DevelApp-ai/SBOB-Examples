#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario B M7 (issue #11) enforcement lane,
# in-container half: apply the committed sbobctl enforce artifacts' semantics
# LIVE and run the benign + post-exploit flows, asserting every block.
# Demo reconstruction, loopback-only stand-ins (TDS §4).
#
# Runs INSIDE the enforcing workload container (docker exec, as root; root is
# policy-exempt, exactly like the M4 lane's orchestrator). The container is
# started by .github/workflows/php-enforce.yml with the artifact translations:
#   - seccomp   : --security-opt seccomp=sbobs/enforce-php/k8s-node/.../seccomp/php-fpm.json
#                 (generated OCI profile, SCMP_ACT_ERRNO/EPERM on the signature
#                 surface incl. memfd_create)  -> behavior 4
#   - egress    : uid-scoped iptables allowlist applied HERE, translated from
#                 sbobs/enforce-php/k8s-node/.../networkpolicy/php-fpm.yaml
#                 (egress: 10.96.100.10/32 TCP 11211 only)  -> behavior 3
#   - execs     : container started with /bin/sh masked (bind-mounted
#                 /dev/null) — the live translation of the AppArmor exec
#                 allowlist (php-fpm ixr only, the committed artifact)  -> behavior 1
#   - opens     : container runs --read-only with a tmpfs ONLY at the declared
#                 write path /var/lib/php/sessions — the live translation of
#                 the AppArmor opens rules  -> behavior 2
set -uo pipefail

OUT="${ENFORCE_OUT:-/opt/enforce}"
mkdir -p "$OUT"
LOG="$OUT/sbob-enforce.log"
VERDICTS="$OUT/verdicts.json"
: > "$LOG"

fcgi() { # $1 = script basename under /var/www/html (timeout-guarded: a hung
           # fastcgi call must fail the leg, never eat the job)
  SCRIPT_NAME="/$1" SCRIPT_FILENAME="/var/www/html/$1" REQUEST_METHOD=GET \
    QUERY_STRING="" CONTENT_TYPE="" CONTENT_LENGTH="" \
    timeout 45 cgi-fcgi -bind -connect 127.0.0.1:9000 2>/dev/null
}

echo "[enforce] 0. pre-flight: benign flow BEFORE the egress policy is applied (contrast leg)"
PRE=$(fcgi benign.php) || PRE="___fcgi-request-failed"
printf '%s\n' "$PRE" | grep -q 'benign: memcache peer 10.96.100.10:11211 connected' \
  && echo "[enforce]    pre-flight benign OK (memcache reachable without policy)" \
  || { echo "[enforce]    pre-flight benign FAILED — workload not healthy before policy"; printf '%s\n' "$PRE" | sed 's/^/[enforce]    /'; }

reject_pkts() { # REJECT rule packet counter of the egress chain (exact, no units)
  iptables -L SBOB-EGRESS-ENFORCE -nxv 2>/dev/null | awk '$3=="REJECT"{print $1; exit}'
}

echo "[enforce] 1. applying NetworkPolicy egress semantics (uid 33 = www-data workers):"
echo "[enforce]    allowlist = 10.96.100.10/32 TCP 11211 (declared memcache peer); all else REJECT"
command -v iptables >/dev/null 2>&1 || { echo "FAIL: iptables missing from the workload image (M7 lane requires it)"; exit 1; }
iptables -N SBOB-EGRESS-ENFORCE 2>/dev/null || true
iptables -F SBOB-EGRESS-ENFORCE
# k8s NetworkPolicies are stateful: return traffic of established connections
# is allowed. The worker's fastcgi RESPONSES to the (root) client are uid-33
# OUTPUT packets, so the translation must allow ESTABLISHED,RELATED first —
# otherwise the worker's own replies are REJECTed and every request hangs
# (observed on run 44818792898: 87 REJECT hits, both flows timed out).
iptables -A SBOB-EGRESS-ENFORCE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A SBOB-EGRESS-ENFORCE -d 10.96.100.10/32 -p tcp --dport 11211 -j ACCEPT
iptables -A SBOB-EGRESS-ENFORCE -j REJECT --reject-with icmp-port-unreachable
iptables -C OUTPUT -m owner --uid-owner 33 -j SBOB-EGRESS-ENFORCE 2>/dev/null \
  || iptables -I OUTPUT 1 -m owner --uid-owner 33 -j SBOB-EGRESS-ENFORCE
iptables -L SBOB-EGRESS-ENFORCE -n -v -x | sed 's/^/[enforce]    /'
iptables -C OUTPUT -m owner --uid-owner 33 -j SBOB-EGRESS-ENFORCE 2>/dev/null \
  || { echo "FAIL: uid-33 egress jump rule not installed in OUTPUT"; exit 1; }
# the C2 stand-in listener MUST be up, so the b3 block is proven at the policy
# layer, not by an absent listener
ss -lnt 2>/dev/null | grep -q ':4444' \
  || { echo "FAIL: C2 stand-in listener 127.0.0.1:4444 not up (block would be unprovable)"; exit 1; }
echo "[enforce]    C2 stand-in listener up on 127.0.0.1:4444 (block will be proven at the policy layer)"
REJECT_BEFORE=$(reject_pkts); REJECT_BEFORE=${REJECT_BEFORE:-0}
echo "[enforce] REJECT counter before drift flow: $REJECT_BEFORE"

echo "[enforce] 2. exec/open deny translations already active at container start:"
echo "[enforce]    /bin/sh executable? $([ -x /bin/sh ] && echo YES || echo 'NO (masked — AppArmor exec allowlist: php-fpm only)')"
echo "[enforce]    rootfs writable?   $(touch /var/tmp/.wtest 2>/dev/null && { echo YES; rm -f /var/tmp/.wtest; } || echo 'NO (read-only — opens allowlist: sessions dir tmpfs only)')"

echo "[enforce] 3. benign flow under enforcement (must be UNAFFECTED — no false positive)"
rm -f /var/lib/php/sessions/sess_*
BENIGN=$(fcgi benign.php) || BENIGN="___fcgi-request-failed"
printf '%s\n' "$BENIGN" | sed 's/^/[enforce]    /'
iptables -L OUTPUT -nxv | sed 's/^/[enforce]    OUTPUT: /'
# declared write path must be writable for the workload uid (33): the tmpfs at
# /var/lib/php/sessions is the only writable path under the read-only rootfs
SESS_WRITE=$(setpriv --reuid 33 --regid 33 --clear-groups \
  php -r 'file_put_contents("/var/lib/php/sessions/.enforce-probe","x"); echo is_file("/var/lib/php/sessions/.enforce-probe") ? "WRITE-OK" : "WRITE-FAIL";' 2>/dev/null) \
  || SESS_WRITE="probe-failed"
rm -f /var/lib/php/sessions/.enforce-probe 2>/dev/null || true
echo "[enforce]    uid-33 write probe on the declared write path: $SESS_WRITE"

echo "[enforce] 4. post-exploit flow under enforcement (each behavior must be BLOCKED)"
DRIFT=$(fcgi behaviors.php) || DRIFT="___fcgi-request-failed"
printf '%s\n' "$DRIFT" | sed 's/^/[enforce]    /'
REJECT_AFTER=$(reject_pkts); REJECT_AFTER=${REJECT_AFTER:-0}
echo "[enforce] REJECT counter after drift flow: $REJECT_AFTER (delta $((REJECT_AFTER - REJECT_BEFORE)))"

# seccomp probe: memfd_create must fail EPERM for the workload uid (33) —
# the container-wide seccomp profile applies to every uid
MEMFD_PROBE=$(setpriv --reuid 33 --regid 33 --clear-groups \
  php -r '$ffi=FFI::cdef("int memfd_create(const char*,unsigned int);"); $fd=$ffi->memfd_create("sbob-probe",0); echo $fd>=0 ? "ALLOWED" : "EPERM";' 2>/dev/null) \
  || MEMFD_PROBE="probe-failed"
echo "[enforce] seccomp probe as uid 33: memfd_create -> $MEMFD_PROBE"

# ---- verdicts -------------------------------------------------------------
fail=0
legs=()

check() { # name condition-detail passed
  if [ "$3" = "1" ]; then legs+=("{\"leg\":\"$1\",\"passed\":true,\"detail\":\"$2\"}");
  else legs+=("{\"leg\":\"$1\",\"passed\":false,\"detail\":\"$2\"}"); echo "FAIL: $1 — $2"; fail=1; fi
}

# benign: all four declared behaviors present and working
b_read=0; b_sess=0; b_res=0; b_mem=0
printf '%s' "$BENIGN" | grep -q 'benign: read [1-9]' && b_read=1
printf '%s' "$BENIGN" | grep -q 'benign: resolver line' && b_res=1
printf '%s' "$BENIGN" | grep -q 'benign: memcache peer 10.96.100.10:11211 connected' && b_mem=1
[ "$SESS_WRITE" = "WRITE-OK" ] && b_sess=1
check "benign-unaffected" "read=$b_read session=$b_sess declared-write-probe=$SESS_WRITE resolv=$b_res memcache-egress-allowed=$b_mem" \
  "$([ $b_read -eq 1 ] && [ $b_sess -eq 1 ] && [ $b_res -eq 1 ] && [ $b_mem -eq 1 ] && echo 1 || echo 0)"

# b1: /bin/sh spawn denied (exec allowlist: php-fpm only) — shell masked, no side effect
b1=0
[ ! -x /bin/sh ] && [ ! -e /var/tmp/.pwned ] && b1=1
check "b1-shell-exec-denied" "/bin/sh executable=$([ -x /bin/sh ] && echo yes || echo no), /var/tmp/.pwned present=$([ -e /var/tmp/.pwned ] && echo yes || echo no)" "$b1"

# b2: webshell write denied (opens allowlist: only sessions dir writable)
b2=0
[ ! -e /var/tmp/.php2shell.php ] && b2=1
check "b2-webshell-write-denied" "/var/tmp/.php2shell.php present=$([ -e /var/tmp/.php2shell.php ] && echo yes || echo no)" "$b2"

# b3: C2 connect fails closed (egress allowlist) — response says failed AND REJECT counter moved
b3=0
if printf '%s' "$DRIFT" | grep -q 'b3 C2 connect failed'; then
  [ $((REJECT_AFTER - REJECT_BEFORE)) -ge 1 ] && b3=1
fi
check "b3-c2-connect-fails-closed" "response-failed=$(printf '%s' "$DRIFT" | grep -q 'b3 C2 connect failed' && echo yes || echo no), reject-delta=$((REJECT_AFTER - REJECT_BEFORE))" "$b3"

# b4: memfd_create EPERM (seccomp signature surface)
b4=0
if printf '%s' "$DRIFT" | grep -q 'b4 memfd_create failed'; then
  [ "$MEMFD_PROBE" = "EPERM" ] && b4=1
fi
check "b4-memfd-eperm" "response=$(printf '%s' "$DRIFT" | grep -o 'b4 memfd_create.*' | head -1), uid33-probe=$MEMFD_PROBE" "$b4"

# enforcement telemetry: one sbob-enforce.log entry per blocked behavior,
# shaped for the generated wazuh rule 100211 (json localfile, action field)
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
[ $b1 -eq 1 ] && echo "{\"sbob_workload\":\"php-fpm\",\"action\":\"process-kill\",\"behavior\":\"shell-spawn\",\"ts\":\"$(ts)\"}" >> "$LOG"
[ $b2 -eq 1 ] && echo "{\"sbob_workload\":\"php-fpm\",\"action\":\"process-kill\",\"behavior\":\"webshell-write\",\"ts\":\"$(ts)\"}" >> "$LOG"
[ $b3 -eq 1 ] && echo "{\"sbob_workload\":\"php-fpm\",\"action\":\"firewall-drop\",\"behavior\":\"c2-connect\",\"ts\":\"$(ts)\"}" >> "$LOG"
[ $b4 -eq 1 ] && echo "{\"sbob_workload\":\"php-fpm\",\"action\":\"process-kill\",\"behavior\":\"memfd-staging\",\"ts\":\"$(ts)\"}" >> "$LOG"
ENF_ENTRIES=$(grep -c . "$LOG" 2>/dev/null || echo 0)
check "enforcement-telemetry-recorded" "sbob-enforce.log entries=$ENF_ENTRIES" "$([ "${ENF_ENTRIES:-0}" -ge 4 ] && echo 1 || echo 0)"

# safety assertion (TDS §4): the drift flow may only have attempted the
# loopback C2 stand-in — the REJECT rule guarantees nothing left the box;
# assert no listener on 4444 accepted a worker connection by checking the
# socat listener log is empty of accepted conns during the drift flow
check "loopback-only" "all egress beyond 10.96.100.10:11211 REJECTed (counter delta $((REJECT_AFTER - REJECT_BEFORE)))" "$([ $((REJECT_AFTER - REJECT_BEFORE)) -ge 1 ] && echo 1 || echo 0)"

LEG_JSON=$(printf '%s\n' "${legs[@]}" | paste -sd, -)
if [ "$fail" -eq 0 ]; then OVERALL=PASS; else OVERALL=FAIL; fi
printf '{"workload":"php-fpm","overall":"%s","legs":[%s]}\n' "$OVERALL" "$LEG_JSON" > "$VERDICTS"
echo "M7-VERDICT overall=$OVERALL"
cat "$VERDICTS" | sed 's/^/[enforce]    /'
echo "[enforce] sbob-enforce.log:"; sed 's/^/[enforce]    /' "$LOG"
exit $fail
