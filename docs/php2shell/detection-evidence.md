# Scenario B detection evidence — PHP2Shell, live behaviors vs SBoB detection

**Milestone:** M6 (issue #10) — PHP2Shell post-exploit behavior harness + detection replay.
**Status:** first delivery. Run evidence: see "Run evidence" at the bottom.
**Lane:** `.github/workflows/php-detection.yml` · **Harness:** `scenarios/php2shell/`

## The real timeline vs the demo timeline

| Real event (PHP2Shell campaign) | Demo counterpart |
|---|---|
| 2026-10-21: CVE-2026-109618 (OOM corruption/longjmp RCE) and CVE-2026-109619 (stale global state RCE) disclosed; both CVSS v4.0 9.2 | The RCEs are **not** simulated: the demo starts at the post-exploit stage, because SBoB makes no claim about the exploit itself. The harness executes the four post-exploit behaviors for real inside the php-fpm worker. |
| Exploited in the wild since 2026-10-21 | The behaviors executed in the drift window are the campaign's documented follow-ons: in-worker `/bin/sh` spawn, webshell drop, C2 callback, fileless memfd staging. |
| 2026-10-26: added to the CISA KEV | Recorded as the reference anchor; no live-actor infrastructure is touched — every stand-in is loopback-only (TDS §4). |

## Why there is no supply-chain row (TDS §9.0)

No release ever shipped: the entry vector is a CVE against an already-deployed
php-fpm. There is no artifact to gate, canary or profile. What SBoB offers is
the declared-contract defense: the workload's own behavior is the baseline,
so post-exploit behavior is drift by definition, whatever the CVE — and the
same contract graduates to enforcement (M7) where each behavior is blocked
outright.

## What the lane proves, rule for rule

The bundle is transpiled from the SHA-pinned SBoB repo
(`DevelApp-ai/Software-Bill-of-Behavior` at
`1e7c0db71049f950160234804eca301dc6ce3977`, `sbobs/php-fpm.yaml`, slot 1,
band `1001xx`), installed into a disposable `wazuh/wazuh-manager:4.14.6`
(the proven lab-validate pattern), and exercised on two legs:

**Leg 1 — recorded-corpus parity (the proven Stage 1).** The pinned repo's
own `scripts/logtest-corpus.sh php` and `scripts/logtest-api.ts --target php`
replay `test/corpus/php-{benign,drift}.audit`: benign silent, drift fires
every mapped rule, sustained children fire at 8 matches / 120s in one
logtest session. Running the upstream scripts unmodified from the pinned SHA
is the parity claim.

**Leg 2 — live-captured telemetry (the M6 contribution).** The four
post-exploit behaviors run for real in the php-fpm workload container under
the bundle's own generated audit fragment; the kernel-observed windows are
captured (`harness/capture-window.sh`), parity- and safety-checked
(`harness/check_capture.py`), and replayed through the same logtest API
(`harness/logtest-replay.ts`). The observer runs node-side (auditd on the
CI node, its log bind-mounted read-only into the container) — see delta 6.

Live firing is honest, not staged: the lane fires what this observer model
can fire and records what it cannot. The node-scoped signature rule
(100163, memfd) tags the containerized workload and fires live. The three
exe-scoped rules cannot tag a containerized workload observed node-side
(delta 7, the finding this scenario exists to produce): their behaviors
execute for real and are proven by their side effects, their rules are
proven on the recorded corpus (leg 1), and the live replay asserts they
correctly stay absent.

| # | Live behavior (in-worker, executed for real) | Rule | Live verdict |
|---|---|---|---|
| 1 | `shell_exec()` → execve `/bin/sh -c "id > /var/tmp/.pwned"` from the php-fpm worker (uid 33) — the CVE-2026-109618 follow-on | **100111** undeclared process execution (T1059, level 9) | executes for real, side-effect-proven; untagged node-side (delta 7); proven on corpus (leg 1) |
| 2 | `file_put_contents('/var/tmp/.php2shell.php', …)` — inert watermarked webshell, the undeclared write | **100121** undeclared file open (T1005, level 9) | executes for real, side-effect-proven; untagged node-side (delta 7); proven on corpus (leg 1) |
| 3 | `fsockopen('127.0.0.1', 4444)` — loopback stand-in for the C2 callback (CVE-2026-109619) | **100131** undeclared outbound connect (T1071, level 9) | executes for real, response-proven; untagged node-side (delta 7); proven on corpus (leg 1) |
| 4 | `FFI` memfd_create staging — the fileless variant | **100163** execution-from-memory signature (T1620, level 10) | **fires on live telemetry** (node-scoped key, uid 33 attribution; replayed and JSON-asserted via the logtest API) |
| — | sustained drift (8 live passes in one logtest session) | **100112 / 100122 / 100132** (level 12) | proven on corpus (leg 1); the live window carries no exe-scoped events to sustain them from |
| — | benign window: app read, session write, resolver read, declared memcache connect — replayed 8x | base chain only (`100100/…` level 0) | empty live window (the delta-7 shape): the exe-scoped keys cannot tag the benign declared behavior either, so nothing is captured and nothing fires; benign silence on tagged content is proven by leg 1 |

## Live-vs-corpus deltas (honest shape differences, verdicts proven on the corpus)

The recorded corpus is synthetic; the live capture is what the kernel
actually emits from this observer model. Verdicts for every mapped rule are
proven by the recorded-corpus replay (leg 1); the live leg fires what this
observer model can fire and records what it cannot. These shape deltas are
committed as findings, not papered over:

1. **The benign master-exec line is not observable live.** The generated
   audit fragment is exe-scoped (Mode A): the exec rule matches the
   *caller's* exe, so from the workload's own vantage it records processes
   that php-fpm execs (the `/bin/sh` catch), not the master's own exec
   (whose caller is the container init). The corpus's benign master-exec
   line is an idealized event; its base-chain parity is proven by the
   recorded corpus (leg 1). In production this is the intended semantics:
   the exec declaration constrains what the workload may spawn. (From the
   node-side observer even the `/bin/sh` catch cannot tag — see delta 7.)
2. **The live C2 connect is in-worker (`comm="php-fpm"`), not post-shell
   (`comm="sh"`).** The connect rule is also exe-scoped, so only connects by
   php-fpm itself carry the key — which matches the in-worker RCE variant of
   CVE-2026-109619. Both shapes are undeclared-peer drift and fire 100131.
3. **The declared memcache peer is a loopback-local alias.**
   `10.96.100.10` is added to the container's `lo`, so the benign
   declared-egress connect is a real socket that never leaves the container
   (TDS §4). Byte-parity bonus: the live benign SOCKADDR is
   `02002BCB0A60640A…` — identical to the corpus line.
4. **Node-scoped signature keys need workload attribution on a shared
   node.** `sbob-memfd` (Mode B) trips for every process on the node; the
   capture attributes signature-key events to the workload by uid 33 (the
   worker uid the corpus itself carries). This is the same attribution
   `rulePolicies.processAllowed` provides in a real deployment.
5. **Real auditd emits more record types than the corpus.** The capture keeps
   only the record types the sbob decoder chain consumes
   (SYSCALL/EXECVE/PATH/SOCKADDR); CWD/PROCTITLE records are dropped. Live
   SYSCALL records also carry argument-pointer fields the synthetic corpus
   omits on some lines — the decoder chain is unaffected.
6. **The observer runs node-side, not in-container.** GitHub-hosted runner
   containers cannot hold the audit netlink: in-container `auditctl`
   returns EPERM even under `--privileged`, and in-container `auditd` fails
   to start (proven live while developing this lane). The lane therefore
   runs auditd on the CI node, loads the SBoB-generated fragment with node
   `auditctl -R`, and bind-mounts the node audit log read-only into the
   workload container. This is not a compromise: it is exactly the
   production SBoB deployment model, where the agent observes the node and
   the workload runs in a container. Its consequences for exe-scoped rules
   are delta 7 — the finding this scenario exists to produce.
7. **The exe-scoped rules cannot tag a containerized workload observed
   node-side (the honest SBoB finding).** The generated fragment is Mode A:
   `sbob-exec/-open/-connect-php-fpm` filter on
   `exe=/usr/local/sbin/php-fpm`, the path as the workload sees it in its
   own mount namespace. A node-side auditd resolves the containerized
   binary through the host mount (the overlay2 merged path), so those
   three rules never match the containerized php-fpm: the benign declared
   behavior AND drift behaviors 1-3 execute for real but produce no
   tagged records (proven live in this lane: both windows empty of
   exe-scoped keys while the behaviors' side effects exist). The live lane
   therefore fires what can fire — 100163 (node-scoped signature key,
   attributed by uid 33) — proves behaviors 1-3 by their side effects,
   asserts their rules stay correctly absent on the live replay, and
   proves them on the recorded corpus (leg 1), whose `exe=` fields model
   the in-container vantage. This is a real SBoB boundary, not a harness
   defect: any node-scoped agent observing a containerized workload
   through `exe=` filters has the same blind spot on k8s nodes. Closing it
   is a toolchain work item (cgroup/pod-aware scoping or container-path
   normalization in the generated fragment), not an SBOB-Examples fix —
   recorded here as the honest answer this repo exists to give: SBoB
   detects the post-exploit behavior model, and the scoping mechanism
   needs container awareness to deliver it from a node vantage.

## Safety boundary (TDS §4, asserted twice per run)

- The C2 stand-in binds `127.0.0.1:4444` only; the real C2 address is never
  contacted, and `check_capture.py` rejects any captured socket that is not
  the declared memcache alias or loopback.
- No real credentials, no real victims, disposable containers on a recycled
  runner; audit rules live only for the job's lifetime.
- Every reconstructed file carries the demo watermark header.

## Run evidence

| item | value |
|---|---|
| First green lane run | (stamped after merge — see the run linked on the merging PR) |
| SBoB toolchain pin | `1e7c0db71049f950160234804eca301dc6ce3977` |
| Manager | `wazuh/wazuh-manager:4.14.6` (disposable, per run) |
| Telemetry artifacts | `php2shell-telemetry` workflow artifact (benign/drift windows, gate logs) |
| Follow-ups | M7 (issue #11): the same four behaviors blocked under Enforce (AppArmor/seccomp/NetworkPolicy), `docs/php2shell/enforce-evidence.md` |
