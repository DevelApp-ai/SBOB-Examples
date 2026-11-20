# Scenario D detection evidence — NGINX2Root (CVE-2026-123007 + kernel SCTP LPE chain) vs SBoB detection

**Milestone:** M9 (issue #15) — NGINX2Root detection replay, worker + host scope.
**Lane:** `.github/workflows/nginx-detection.yml` · **Harness:** `scenarios/nginx2root/`
**Workload contracts:** `sbobs/workload/nginx-worker.yaml` (slot 4, band `1004xx`) · `sbobs/workload/node-host.yaml` (slot 5, band `1005xx`)

SBOB-EXAMPLES DEMO WATERMARK — demo reconstruction, loopback-only stand-ins
(TDS §4). The RCE/LPE entry vectors are NOT simulated; the post-RCE behaviors
run for real (worker activity as the nginx worker uid 101 inside the
disposable container; the escape phase as a benign root-shell shape on the
recycled CI node).

## The real timeline vs the demo timeline

| Real event (NGINX2Root, Xint 2026-11-18) | Demo counterpart |
|---|---|
| 2026-11-18: five unauthenticated nginx RCEs disclosed (CVE-2026-123007 on HTTP/2, CVE-2026-123634, CVE-2026-123633, CVE-2026-121810, CVE-2026-113425); every release 1.9.5–1.31.8 affected; fix in 1.31.9 | The RCE is not simulated — SBoB makes no claim about the exploit. The demo starts at the post-RCE worker stage and executes the chain's behaviors for real. |
| Commands run with the privileges of the nginx worker process | Worker-scope behaviors executed as uid 101 (the nginx worker user) inside the disposable container. |
| Chained with a kernel SCTP-subsystem LPE to root on the host, including Docker-container escape (AWS/GCP/Azure/bare metal) | The SCTP socket open (module autoload) is executed for real; the kernel exploit work itself is invisible to userspace audit (finding below). The escape phase is a root-shell *shape* on the CI node, observed via the host-scope corpus + live node record. |

## What the lane proves, rule for rule

Worker scope (slot 4), recorded corpus `nginx-drift.audit` replayed through the
pinned wazuh-manager 4.14.6:

| behavior | rule | sustained child |
|---|---|---|
| worker shell spawn (`execve /bin/sh`) | **100411** | 100412 (8/120s) |
| recon open `/etc/passwd` | **100421** | 100422 |
| recon open `/etc/shadow` | 100421 + sensitive-file overlay **100401** (level 12) | 100422 / 100409 |
| first SCTP socket → sctp module autoload (uid-0 modprobe, node-scoped key) | host-scope **100460** | — |
| C2 callback (loopback stand-in) | **100431** | 100432 (8/120s) |

Host scope (slot 5), recorded corpus `host-escape.audit`:

| post-escape behavior (uid 0) | rule | sustained child |
|---|---|---|
| root `/bin/sh` execve on the host | **100511** | 100512 |
| uid-0 read `/etc/passwd` | **100521** | 100522 |
| uid-0 read `/etc/shadow` | 100521 + overlay **100501** (level 12) | 100522 / 100509 |

Gates: corpus-benign silent (×8, one session); corpus-drift expects
100411/100421/100431/100401/100460 with sustained 100412/100422/100432;
corpus-escape expects 100511/100521/100501 with sustained 100512/100522; live
benign silent; live drift fires 100460 iff the sctp autoload actually happened
on the runner (see findings). Safety: every SOCKADDR in every window is the
declared upstream or loopback (parity checker + TDS §4).

## Committed findings (honest gaps, not superhero claims)

1. **The kernel LPE is invisible to userspace audit.** Only the module-load
   *event* is observable. On hosts where the sctp module is already loaded
   there is no event at all — the lane records that variant as
   expected-silent when the runner kernel already has sctp (live gate falls
   back to the zero-alert assertion and the finding is logged).
2. **delta-7 analog:** exe-scoped audit keys cannot tag the containerized
   nginx worker observed node-side (overlay2 paths), so worker-scope rules
   are proven on the recorded corpus while the behaviors are proven live by
   side effects (`.pwned`, the C2 stand-in's logged callback). The host-scope
   escape rules are proven on the host-escape corpus; the live node record of
   the escape-sim root shell is captured but not exe-tagged (same boundary).
3. **DNS-blind egress** (TDS §9.3) applies as in the other scenarios; the
   fixture uses numeric literals, so no resolver leg exists here.

## Run evidence

<!-- STAMP: recorded from the lane's fully green run
     https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44834477759
     (nginx-detection):
| gate | verdict | detail |
|------|---------|--------|
| workload capture + parity/safety | PASS | b1/b5 side effects present, benign drift-free, loopback-only sockets |
| corpus-benign | PASS | nginx-benign.audit ×8 one session: zero alerts |
| corpus-drift (worker) | PASS | 100411 + 100421 + 100431 + overlay 100401 + host module-load 100460 all fired; sustained 100412/100422/100432 fired on the ×8 session replay |
| live gates | PASS | live drift window fired 100460 LIVE — the sctp module autoloaded on this runner (first SCTP socket); exe-scoped worker legs correctly absent (delta-7 analog); benign live silent |
| corpus-escape (host, host-only ruleset) | PASS | 100511 + 100521 + overlay 100501 fired; sustained 100512/100522 fired |

Recorded lane finding: with both bundles installed, the opens base rules match
on record type (not key), so the lowest-slot open rule shadowed the host one —
the escape gate therefore runs against the host-only ruleset (production
shape: one workload's rules per agent group). Lane iterations recorded:
44833195857 / 44833913061 (that shadowing, then the flattened sbob_* rule
filename in the swap). Local pre-push proof: both workloads transpile at pin
4bf2eb1d with the expected rule ids; harness scripts syntax-checked. -->

Lane artifacts on every run: `nginx2root-telemetry` (transpile logs, build
log, workload run log, escape-sim log, parity check, captured windows, gate
logs).
