#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario D workload fixture entrypoint.
# Demo reconstruction, loopback-only stand-ins (TDS §4). See Dockerfile header.
set -euo pipefail

echo "[entrypoint] 1. loopback-local alias for the declared upstream (10.96.100.40)"
ip addr add 10.96.100.40/32 dev lo 2>/dev/null || echo "[entrypoint] alias already present"

echo "[entrypoint] 2. stand-in listeners (root; not part of the workload)"
socat TCP-LISTEN:8080,bind=10.96.100.40,fork /dev/null &
socat TCP-LISTEN:4446,bind=127.0.0.1,fork /tmp/c2-standin.log &

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

echo "[entrypoint] 4. nginx (master root, workers as the nginx user, uid 101)"
nginx -g 'daemon off;' &

echo "[entrypoint] 5. waiting for nginx on 127.0.0.1:80"
for i in $(seq 1 60); do
  if curl -s --max-time 3 -o /dev/null http://127.0.0.1:80/ 2>/dev/null; then
    echo "[entrypoint] nginx ready"
    if [ -f /host-audit/audit.log ]; then
      exec tail -f /host-audit/audit.log
    fi
    exec tail -f /dev/null
  fi
  sleep 0.5
done
echo "FAIL: nginx did not come up on 127.0.0.1:80" >&2
exit 1
