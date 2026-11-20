#!/bin/sh
# sbobctl generated process-kill active response — workload: python-ci-runner (TDS 14.1, M7)
# Deploy to the agent's /var/ossec/active-response/bin/ (runbook §9).
# Invoked by Wazuh with: <script> <action> <user> <ip> <alert-id> <rule-id> <agent-id> <filename>
ACTION=$1
ALERT=$(echo "$9" | sed 's/^ *//;s/ *$//')   # JSON alert payload

# telemetry first: every enforcement event is itself a Wazuh alert (TDS 14.6)
pid=$(printf '%s' "$ALERT" | grep -o '"syscall.process.id":"[0-9]*"' | head -1 | grep -o '[0-9]*')
exe=$(printf '%s' "$ALERT" | grep -o '"syscall.exe":"[^"]*"' | head -1 | sed 's/"syscall.exe":"//;s/"$//')
if [ "${ACTION}" = "delete" ]; then
  echo '{"sbob_workload":"python-ci-runner","action":"process-kill-revert","pid":'${pid}'}' >> /var/ossec/logs/sbob-enforce.log
  exit 0
fi
if [ -n "${pid}" ] && kill -9 "${pid}" 2>/dev/null; then
  echo '{"sbob_workload":"python-ci-runner","action":"process-kill","pid":'${pid}',"exe":"'${exe}'"}' >> /var/ossec/logs/sbob-enforce.log
  exit 0
fi
echo '{"sbob_workload":"python-ci-runner","action":"process-kill-failed","pid":'${pid:-null}'}' >> /var/ossec/logs/sbob-enforce.log
exit 1
