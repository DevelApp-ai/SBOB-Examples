#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario C workload fixture entrypoint.
# Demo reconstruction, loopback-only stand-ins (TDS §4). See Dockerfile header.
#
# Boot order matters for telemetry cleanliness (same discipline as scenario B):
#   1. declared config-service peer aliased onto `lo` (traffic never leaves
#      the container)
#   2. stand-in listeners up (declared peer + loopback C2 stand-in; the C2
#      stand-in logs what it receives so the harness can prove the callback)
#   3. auditd attempt (functional only on self-hosted runners; on
#      GitHub-hosted runners the lane runs auditd node-side and mounts the
#      node audit log read-only as /host-audit)
#   4. the JVM service as the dedicated workload uid 1000 (appuser)
#   5. stay alive
set -euo pipefail

echo "[entrypoint] 1. loopback-local alias for the declared config peer (10.96.100.30)"
ip addr add 10.96.100.30/32 dev lo 2>/dev/null || echo "[entrypoint] alias already present"

echo "[entrypoint] 2. stand-in listeners (root; not part of the workload)"
socat TCP-LISTEN:8443,bind=10.96.100.30,fork /dev/null &
socat TCP-LISTEN:4445,bind=127.0.0.1,fork /tmp/c2-standin.log &

echo "[entrypoint] 3. auditd (optional, self-hosted observer mode only)"
if ! service auditd start; then
  if ! auditd; then
    auditd --foreground > /tmp/auditd-fg.log 2>&1 &
  fi
fi
sleep 1
auditctl -l >/dev/null 2>&1 \
  && echo "[entrypoint] in-container auditd functional" \
  || echo "[entrypoint] in-container auditd not functional — node-side observer expected (/host-audit)"

echo "[entrypoint] 4. java service as uid 1000 (appuser)"
setpriv --reuid 1000 --regid 1000 --clear-groups \
  /usr/local/openjdk-17/bin/java -cp /app App &

echo "[entrypoint] 5. waiting for the service on 127.0.0.1:8080"
for i in $(seq 1 60); do
  if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then
    exec 3>&- 3<&- || true
    echo "[entrypoint] java-service ready"
    if [ -f /host-audit/audit.log ]; then
      exec tail -f /host-audit/audit.log
    fi
    exec tail -f /dev/null
  fi
  sleep 0.5
done
echo "FAIL: java-service did not come up on 127.0.0.1:8080" >&2
exit 1
