# Enforcement setup for workload python-ci-runner (TDS 14, M7)

State file default: **audit**; enforcing sections: egress.

## Manager ossec.conf — AR command definition

The shipped `firewall-drop` command is predefined. The custom process-kill
command must be defined once on the manager:

```xml
<command>
  <name>sbob-python-ci-runner-process-kill</name>
  <executable>sbob-python-ci-runner-process-kill.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

Deploy `sbob-python-ci-runner-process-kill.sh` to the agent's
`/var/ossec/active-response/bin/` (config management; runbook §9).

## Telemetry

The script writes JSON lines to `/var/ossec/logs/sbob-enforce.log`,
ingested by the `python-ci-runner-enforce-localfile.xml` agent-conf block and
alerted by rule (11,1). Every block/revert/failure event is visible
(TDS 14.6).

## Kill-switch

Per agent group: flip `<disabled>` to `yes` in the group's agent.conf
AR block (or remove the `python-ci-runner-ar.xml` fragment and re-sync).
The detection bundle stays active — the kill-switch only disables
active responses.
