# Scenario C telemetry contract

SBOB-EXAMPLES DEMO WATERMARK — recorded harness corpus for the java-service
workload (slot 3), in the same record shape as the SBoB repo's
`test/corpus/php-*.audit` (SYSCALL + EXECVE/PATH/SOCKADDR aux records per
event, serial-grouped).

| file | content |
|---|---|
| `java-benign.audit` | one full benign request: JVM exec (declared), `/app/index.html` read, `/var/lib/app-data/counter.txt` write, `/etc/resolv.conf` read, declared config-peer connect `10.96.100.30:8443` (saddr `020020FB0A60641E`) |
| `java-drift.audit` | the three OS-visible post-RCE behaviors: `/bin/sh` execve, `/var/www/webapp/shell.jsp` create, C2 stand-in connect `127.0.0.1:4445` (saddr `0200115D7F000001`) |

The fourth behavior (defineClass fully in-JVM) is deliberately absent from the
drift corpus: it has no OS-visible record — the committed expected-silent
finding in `docs/java2shell/detection-evidence.md`.

Per-run captured windows land in the `java2shell-telemetry` CI artifact
(`benign.audit`, `drift.audit`, `audit-tail.log`); the live windows carry the
honest node-side shape (exe-scoped keys cannot tag the containerized JVM —
the scenario-C delta-7 analog), so rule firing is proven on the recorded
corpus above and side effects are proven live.
