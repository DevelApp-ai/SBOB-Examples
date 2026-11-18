#!/bin/bash
# SBOB-EXAMPLES DEMO WATERMARK — scenario B workload fixture entrypoint.
# Demo reconstruction, loopback-only stand-ins (TDS §4). See Dockerfile header.
#
# Boot order matters for telemetry cleanliness:
#   1. declared memcache peer aliased onto `lo` (traffic never leaves the container)
#   2. stand-in listeners up (declared memcache peer + loopback C2 stand-in)
#   3. auditd up (the CI lane loads the SBoB-generated audit fragment AFTER
#      this entrypoint returns control, so php-fpm master startup opens land
#      BEFORE any rules exist and are never captured; capture windows contain
#      request-time worker behavior only)
#   4. php-fpm master (root) + workers (www-data, uid 33)
#   5. stay alive tailing the audit log (also keeps it flushed)
set -euo pipefail

echo "[entrypoint] 1. loopback-local alias for the declared memcache peer (10.96.100.10)"
ip addr add 10.96.100.10/32 dev lo 2>/dev/null || echo "[entrypoint] alias already present"

echo "[entrypoint] 2. stand-in listeners (root; never inside capture windows: the sbob audit rules are exe-scoped to php-fpm)"
socat TCP-LISTEN:11211,bind=10.96.100.10,fork /dev/null &
socat TCP-LISTEN:4444,bind=127.0.0.1,fork /dev/null &

echo "[entrypoint] 3. auditd"
if ! service auditd start; then
  echo "[entrypoint] service auditd start failed, trying the daemon directly"
  if ! auditd; then
    echo "[entrypoint] auditd daemonize failed, trying foreground mode"
    auditd --foreground &
  fi
fi
sleep 1
if ! auditctl -l >/dev/null 2>&1; then
  echo "FAIL: auditctl not functional — the container must run --privileged (CAP_AUDIT_CONTROL)" >&2
  exit 1
fi
auditctl -l || true

echo "[entrypoint] 4. php-fpm master (workers as www-data, uid 33)"
php-fpm --nodaemonize --fpm-config /usr/local/etc/php-fpm.conf &

echo "[entrypoint] 5. waiting for the fastcgi endpoint on 127.0.0.1:9000"
for i in $(seq 1 60); do
  if (exec 3<>/dev/tcp/127.0.0.1/9000) 2>/dev/null; then
    exec 3>&- 3<&- || true
    echo "[entrypoint] php-fpm ready"
    touch /var/log/audit/audit.log
    exec tail -f /var/log/audit/audit.log
  fi
  sleep 0.5
done
echo "FAIL: php-fpm did not come up on 127.0.0.1:9000" >&2
exit 1
