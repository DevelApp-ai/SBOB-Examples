# Scenario C: Java2Shell — live post-exploit behavior vs SBoB detection

SBOB-EXAMPLES DEMO WATERMARK — scenario C harness (M8, issue #14). Demo
reconstruction, loopback-only stand-ins (TDS §4).

The question (TDS §1, scenario C): **CVE-2026-114938** ("Java2Shell",
disclosed 2026-11-17) — an unauthenticated RCE via the JIT-compiled Base64
decode fast path in OpenJDK 17 (x86-64 AVX-512 VBMI), demonstrated pre-auth on
default Keycloak, Jenkins, Jira, Confluence, Artifactory and PingFederate
(JFrog, Qualys, SecureLayer7 research). Like scenario B there is no release to
gate — the entry vector is a CVE in a widely deployed runtime. What SBoB
offers is the declared-contract defense: the workload's own behavior is the
baseline (`sbobs/workload/java-service.yaml`, slot 3), so post-exploit behavior
is drift **by definition**.

## Layout

| path | role |
|---|---|
| `workload/` | the Java 17 service fixture (eclipse-temurin:17-jdk): Dockerfile, `src/App.java` + `src/Payload.java`, entrypoint, `www/index.html` |
| `harness/run-behaviors.sh` | in-container orchestration: warm-up, benign window, drift window, capture, pre-checks |
| `harness/capture-window.sh` | audit-log window extraction (corpus-shaped; uid-1000 attribution for node-scoped keys) |
| `harness/check_capture.py` | runner-side capture parity + safety checker (loopback-only, benign purity, delta-7-analog shape) |
| `harness/logtest-replay.ts` | file-driven logtest-API replay (vendored from scenario B; session-based, `--repeats` for sustained children) |
| `telemetry/` | recorded harness corpus (`java-benign.audit`, `java-drift.audit`) + capture contract |
| `.github/workflows/java-detection.yml` | the M8 CI lane |

## The four post-RCE behaviors (drift window)

| # | behavior (executed for real, in-JVM) | contract violation | rule (slot 3) |
|---|---|---|---|
| 1 | `ProcessBuilder("/bin/sh","-c","id > /var/tmp/.pwned")` → execve `/bin/sh` from the JVM | `execs[]` declares only the JVM | 100311 (sustained 100312) |
| 2 | JSP drop to `/var/www/webapp/shell.jsp` (inert watermark content, never served) | `opens[]`: only `/var/lib/app-data/*` is a declared write | 100321 (sustained 100322) |
| 3 | C2 callback to the loopback stand-in `127.0.0.1:4445` | `egress[]`: only `10.96.100.30:8443` | 100331 (sustained 100332) |
| 4 | `defineClass` staging fully in-JVM (bytes read via the **declared** `/app` read) | **none observable** — no exec, no undeclared open, no socket | expected-silent (committed finding) |

## The defineClass blind spot (scenario C's honest finding)

Behavior 4 performs no OS-level syscall beyond the declared `/app` read while
the payload stays inside the JVM, so no drift rule can fire — the scenario-C
analog of scenario B's delta 7. The lane asserts b4 ran (response) and that
the drift window carries no record for it; the moment the payload touches the
OS (exec, file, socket), behaviors 1-3 show drift fires. Recorded in
`docs/java2shell/detection-evidence.md`.

## Safety boundary (TDS §4 applies in full)

- The C2 stand-in binds `127.0.0.1:4445` only and logs what it receives; the
  real C2 is never contacted. The declared config peer `10.96.100.30` is
  aliased onto the container's `lo`, so benign declared egress never leaves
  the container either. Capture-level and lane-level assertions reject any
  other destination.
- The dropped JSP is inert watermark content under `/var/www/webapp`, which is
  not routed; nothing serves it.
- Everything runs in disposable CI containers on a recycled runner (TDS §7);
  audit rules exist only for the lifetime of the job.

## How to run

```sh
# locally (assumes docker; observer is node-side — see workload/CONTRACT notes in scenario B):
docker build -f scenarios/java2shell/workload/Dockerfile -t sbob-java2shell:local scenarios/java2shell
sudo auditctl -R dist/java/wazuh/audit/sbob/java-service.rules   # node kernel, node auditd
docker run --cap-add=NET_ADMIN -v /var/log/audit:/host-audit:ro -d --name sbob-java sbob-java2shell:local
docker exec -e AUDIT_LOG=/host-audit/audit.log sbob-java bash /opt/harness/run-behaviors.sh
```

The full flow (transpile → workload capture → containerized wazuh-manager →
corpus + live replay gates) runs in CI: `.github/workflows/java-detection.yml`.
Committed evidence: `docs/java2shell/detection-evidence.md`.
