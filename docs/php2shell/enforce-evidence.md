# Scenario B enforcement evidence — PHP2Shell blocked under Enforce (M7, issue #11)

**Milestone:** M7 (issue #11) — PHP2Shell enforcement in anger (Stage 3).
**Lane:** `.github/workflows/php-enforce.yml` · **Harness:** `scenarios/php2shell/harness/run-enforce.sh`
**Workload contract:** `sbobs/php-fpm.yaml` (slot 1, pinned SBoB repo `Software-Bill-of-Behavior` @ `4bf2eb1d`) ·
**Rollout state:** `sbobs/enforce-state-php-fpm.yaml` · **Committed artifacts:** `sbobs/enforce-php/{linux,k8s-node}`

SBOB-EXAMPLES DEMO WATERMARK — demo reconstruction, loopback-only stand-ins
(TDS §4). The four post-exploit behaviors are executed FOR REAL in the
disposable php-fpm container (same harness pages as M6, `behaviors.php`) and
each is asserted BLOCKED under enforcement — asserted in the lane, not
eyeballed.

## Monitor → Audit → Enforce: the state-file progression (no skipped rungs)

`sbobs/enforce-state-php-fpm.yaml` is validated by the pinned sbobctl on every
lane run (drift gate): `ERR_ENFORCE_LADDER` on a skipped rung,
`ERR_ENFORCE_NOT_AUDITED` when a section enforces without an incident-free
audit record.

| rung | evidence |
|---|---|
| Monitor | profile ships detection only (M1–M2 pattern) |
| Audit | M6 lane `php-detection.yml`, first green run [44591553822](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44591553822): benign window silent, recorded corpus fires 100111/100121/100131/100163, live capture fires 100163 (delta-7 exe-scoping finding recorded) — see `detection-evidence.md` |
| Enforce | this lane: all four sections (`execs`, `opens`, `egress`, `ingress`) at `enforce`, each with an `auditRecords` entry citing the M6 clean window (`incidents: 0`) |

## Per-behavior block table

| # | post-exploit behavior (executed for real) | contract violation | artifact of record (committed, drift-gated) | live translation in the CI lane (M4 pattern) | asserted result |
|---|---|---|---|---|---|
| 1 | `/bin/sh` spawn from the worker (`shell_exec`) | `execs[]` = `/usr/local/sbin/php-fpm` only | AppArmor profile `sbobs/enforce-php/linux/.../apparmor/php-fpm.profile` (`/usr/local/sbin/php-fpm ixr,`, blocking mode) | `/bin/sh` masked (bind-mounted `/dev/null`) at container start | exec denied: `/bin/sh` not executable, `/var/tmp/.pwned` absent |
| 2 | webshell drop to `/var/tmp` | `opens[]`: only `/var/lib/php/sessions/*` writable | same AppArmor profile (opens rules) | container `--read-only` + tmpfs only at `/var/lib/php/sessions` (plus `/run`, `/tmp` scratch) | write denied: `/var/tmp/.php2shell.php` absent; benign session write works |
| 3 | C2 connect (loopback stand-in `127.0.0.1:4444`) | `egress[]` = `10.96.100.10:11211` only | NetworkPolicy `sbobs/enforce-php/k8s-node/.../networkpolicy/php-fpm.yaml` (`mode: "enforce"`, egress ipBlock `10.96.100.10/32` TCP 11211) | uid-scoped (uid 33) iptables allowlist in the NET_ADMIN container: ACCEPT `10.96.100.10/32` tcp/11211, REJECT all else | connect fails closed: response `b3 C2 connect failed`, REJECT counter +1 |
| 4 | `memfd_create` staging via FFI | signature surface (T1620 execution-from-memory) | OCI seccomp `sbobs/enforce-php/k8s-node/.../seccomp/php-fpm.json` (`SCMP_ACT_ERRNO`, errnoRet 1 = EPERM, on memfd_create + the 8 other signature syscalls) | `docker run --security-opt seccomp=<that generated profile>` | `memfd_create` → EPERM: `b4 memfd_create failed` in the response; uid-33 probe returns EPERM |

Benign workload under enforcement (no false positive): app-file read, session
write, resolver read, and the declared memcache egress all work — the benign
flow is asserted line-by-line in the lane (`benign-unaffected` leg).

Enforcement telemetry: every block is recorded as a JSON entry in
`sbob-enforce.log` inside the workload (`action: process-kill|firewall-drop`,
`sbob_workload: php-fpm`) — the exact ingestion shape of the generated wazuh
rule `100100_php-fpm_enforce.xml` (rule **100211**, json localfile
`php-fpm-enforce-localfile.xml`). The lane asserts ≥ 1 entry per blocked
behavior (4 total).

## Honest limitations (stated, not papered over)

1. **The live lane translates the artifacts; the artifacts of record are the
   generated files.** k8s NetworkPolicies cannot run in GitHub CI, so the
   egress semantics run as a uid-scoped iptables allowlist (the M4-proven
   translation); the AppArmor profile is the production artifact while the
   lane proves the exec/open deny semantics via the shell mask + read-only
   rootfs (a naive live AppArmor enforce false-positives on interpreter
   stdlib paths — the M4 finding, recorded in
   `docs/agent-framework/enforce-evidence.md` limitation 3). Declared-peer
   *delivery* is untestable from CI (10.96.100.10 is a lab-cluster IP aliased
   onto `lo`); the lane proves the ruleset ADMITS the declared peer and
   REJECTs everything else.
2. **The seccomp profile is a default-allow deny-list on the signature
   surface** (that is what the generator emits); production layers it on top
   of the container runtime's default profile, not instead of it.
3. **Ingress enforcement is not translated live**: the fastcgi client
   stand-in runs as root and is policy-exempt (same podSelector→uid
   translation as M4); the ingress half of the NetworkPolicy artifact
   (`10.244.0.0/16` → TCP 9000) is committed but exercised only as an
   artifact, which is why the state file graduates ingress on the same M6
   audit record.
4. **`labValidation: "pending"` stays on the generated manifests** — that
   field flips in the SBoB repo's own lab flow; the drift gate pins the
   generated bytes, so this lane commits them as generated.
5. Delta 7 from M6 still applies to *detection* attribution (exe-scoped rules
   vs overlay2 paths); enforcement here is policy-layer (seccomp/iptables/fs),
   which does not depend on exe attribution — that is exactly why Enforce
   closes the detection gap for containerized workloads.

## Run evidence

<!-- STAMP: record the first fully green php-enforce run here on merge, with
     the run URL, in the same pattern as docs/supply-chain-evidence.md:
     | leg | verdict | run |
     (local pre-push proof: both targets regenerate byte-identical from pin
     4bf2eb1d + sbobs/enforce-state-php-fpm.yaml; ladder guard verified:
     enforce without audit record -> ERR_ENFORCE_NOT_AUDITED) -->

Lane artifacts on every run: `php-enforce-evidence` (drift diffs, demo log,
verdicts.json, sbob-enforce.log, manifests).
