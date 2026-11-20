# Scenario C detection evidence — Java2Shell (CVE-2026-114938) vs SBoB detection

**Milestone:** M8 (issue #14) — Java2Shell detection replay.
**Lane:** `.github/workflows/java-detection.yml` · **Harness:** `scenarios/java2shell/`
**Workload contract:** `sbobs/workload/java-service.yaml` (slot 3, band `1003xx`, registry `sbobs/registry.yaml`)

SBOB-EXAMPLES DEMO WATERMARK — demo reconstruction, loopback-only stand-ins
(TDS §4).

## The real timeline vs the demo timeline

| Real event (Java2Shell) | Demo counterpart |
|---|---|
| 2026-11-17: CVE-2026-114938 disclosed — unauthenticated RCE via the JIT-compiled Base64 decode fast path in OpenJDK 17 (x86-64 AVX-512 VBMI) | The RCE itself is **not** simulated: the demo starts at the post-RCE stage, because SBoB makes no claim about the exploit. The harness executes the post-RCE behaviors for real inside the disposable openjdk:17 fixture. |
| Demonstrated pre-auth against default Keycloak, Jenkins, Jira, Confluence, Artifactory, PingFederate (JFrog, Qualys, SecureLayer7 research) | The fixture is a Java 17 service behind the same contract shape those products share: one JVM exec, app dir read, one write dir, declared service peer. |
| Post-RCE chain: shell spawn, webshell drop, C2 callback, fileless in-JVM staging | The four behaviors, executed for real in-worker-equivalent (`/behaviors`), loopback stand-ins only. |

## Why there is no supply-chain row

No release ever shipped: the entry vector is a CVE in the runtime. There is no
artifact to gate, canary or profile — the same honest asymmetry scenario B
records (TDS §9.0). What SBoB offers is the declared-contract defense:
post-exploit behavior is drift by definition, whatever the CVE.

## What the lane proves, rule for rule (slot 3, band 1003xx)

Recorded corpus (`scenarios/java2shell/telemetry/java-drift.audit`, replayed
through the pinned wazuh-manager 4.14.6 via the session-based logtest API):

| behavior (executed for real live; corpus replayed) | contract violation | rule | sustained child |
|---|---|---|---|
| b1 `/bin/sh` spawn from the JVM (`ProcessBuilder`) | `execs[]` = JVM only | **100311** | 100312 (8/120s) |
| b2 JSP drop to `/var/www/webapp/shell.jsp` | `opens[]` write = `/var/lib/app-data/*` only | **100321** | 100322 (8/120s) |
| b3 C2 callback (loopback stand-in `127.0.0.1:4445`) | `egress[]` = `10.96.100.30:8443` only | **100331** | 100332 (8/120s) |
| b4 `defineClass` fully in-JVM | none observable | **expected-silent** (finding below) | — |

Gates in the lane:

- **corpus-benign** — `java-benign.audit` ×8 in one session: ZERO alerts.
- **corpus-drift** — `java-drift.audit`: 100311, 100321, 100331 all fire;
  signature/overlay rules (100301, 100302, 100360-100363) stay absent;
  repeated ×8 in ONE session: 100312, 100322, 100332 fire (sustained children
  via the session-based API replay).
- **live gates** — the live-captured windows replay with the honest node-side
  shape: behaviors 1-3 are proven by real side effects (`.pwned`, `shell.jsp`,
  the C2 stand-in's received callback) because the exe-scoped audit keys cannot
  tag a containerized JVM observed node-side (the scenario-C analog of
  scenario B's delta 7 — the rules are proven on the corpus; the live windows
  assert zero drift alerts rather than claiming tagging that does not happen).
- **safety** — every SOCKADDR in both windows is the declared peer or loopback
  (parity checker + TDS §4 assertion).

## The defineClass blind spot (committed finding, not a superhero claim)

Behavior 4 stages the payload via `ClassLoader.defineClass` from bytes read
through the **declared** `/app` read — no exec, no undeclared open, no socket.
No rule can fire while the payload stays inside the JVM: the lane asserts b4
ran (HTTP response) and that the drift window carries no record for it. The
moment the payload touches the OS — exec, file, socket — behaviors 1-3 show
that drift fires within seconds. This is the scenario-C analog of delta 7 and
is stated, not hidden.

## Honest limitations

1. **Containerized workload + node-side observer (delta-7 analog):** the
   generated audit fragment is exe-scoped (Mode A) to
   `/opt/java/openjdk/bin/java`; a node-side auditd resolves the
   container binary through the overlay2 path, so exe-scoped keys do not tag
   live. Rule firing is proven on the recorded harness corpus; live behavior
   is proven by side effects. On a self-hosted node with the in-container
   observer the keys tag normally.
2. **DNS-blind egress** (same as scenario A/B, TDS §9.3): the declared peer is
   used numerically in the fixture, so no resolver leg exists here at all.
3. **Sustained children are proven on the corpus replay** (8/120s in one
   logtest session), not on a single live window — the real C2 callback is a
   single connect; the sustained shape is a capability proof, same caveat as
   scenario B's 100232.

## Run evidence

<!-- STAMP: record the first fully green java-detection run here on merge,
     with the run URL, in the same pattern as the other evidence docs:
     | gate | verdict | run |
     (local pre-push proof: java-service.yaml transpiles at pin 4bf2eb1d —
     slot 3, rules 100300/100311/100312/100320/100321/100322/100330/100331/
     100332/…/100363, audit keys sbob-{exec,open,connect}-java-service +
     node-scoped signature keys; harness scripts syntax-checked) -->

Lane artifacts on every run: `java2shell-telemetry` (transpile log, build log,
workload run log, parity check, captured windows, gate logs).
