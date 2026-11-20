# Scenario D: NGINX2Root — live post-RCE behavior vs SBoB detection (worker + host scope)

SBOB-EXAMPLES DEMO WATERMARK — scenario D harness (M9, issue #15). Demo
reconstruction, loopback-only stand-ins (TDS §4).

The question (TDS §1, scenario D): **NGINX2Root** (Xint, disclosed 2026-11-18) —
five unauthenticated nginx RCEs (CVE-2026-123007 on HTTP/2, plus
CVE-2026-123634 / CVE-2026-123633 / CVE-2026-121810 / CVE-2026-113425; every
release 1.9.5–1.31.8 affected, fix in 1.31.9), chained with a Linux-kernel
SCTP-subsystem LPE to root on the host, including escaping a Docker container
running nginx. Like scenarios B/C there is no release to gate — the entry
vector is a CVE in a widely deployed server. Post-exploit behavior is the
catchable surface, at TWO scopes: the nginx worker (container) and the host
(node).

## Layout

| path | role |
|---|---|
| `workload/` | the nginx fixture (official nginx image): Dockerfile, nginx.conf, entrypoint, `www/index.html` |
| `harness/run-behaviors.sh` | in-container orchestration: warm-up, benign window, post-RCE drift window (executed as worker uid 101), capture, pre-checks |
| `harness/capture-window.sh` | audit-log window extraction (worker keys uid=101; node-scoped signature keys uid=0) |
| `harness/check_capture.py` | runner-side parity + safety checker |
| `harness/logtest-replay.ts` | file-driven logtest-API replay (vendored; session-based, `--repeats` for sustained children) |
| `telemetry/` | recorded corpus: `nginx-benign.audit`, `nginx-drift.audit`, `host-escape.audit` |
| `.github/workflows/nginx-detection.yml` | the M9 CI lane |
| `sbobs/workload/nginx-worker.yaml` / `sbobs/workload/node-host.yaml` | the worker (slot 4) and host (slot 5) SBoB contracts |

## The post-RCE chain, mapped rule-for-rule

| # | behavior | scope | contract violation | rule (slot) |
|---|---|---|---|---|
| 1 | worker shell spawn (execve `/bin/sh` from the worker) | worker | `execs[]` = `/usr/sbin/nginx` only | 100411 (sustained 100412) |
| 2 | recon reads `/etc/passwd`, `/etc/shadow` | worker | not in `opens[]`; shadow trips the sensitive-file overlay | 100421 + **100401** (100422 sustained) |
| 3 | first SCTP socket → `request_module` autoloads the sctp kernel module | **host** | module-load signature, node-scoped key, uid-0 modprobe | **100460** |
| 4 | container escape → root shell on the host; uid-0 reads | **host** | root shell in no host SBoB (slot 5) | 100511 / 100521 + **100501** (100512/100522 sustained) |
| 5 | C2 callback (loopback stand-in `127.0.0.1:4446`) | worker | `egress[]` = upstream `10.96.100.40:8443`… only declared peer | 100431 (sustained 100432) |

## Honest gaps (committed findings, not superhero claims)

- **The kernel LPE work is invisible to userspace audit.** Only the
  module-load *event* (sctp autoload) is observable — and on hosts where sctp
  is already loaded there is no event at all. Both variants are recorded:
  the lane fires 100460 live iff the autoload happened on the runner;
  otherwise the sctp-already-loaded variant is the expected-silent finding.
- **delta-7 analog:** exe-scoped audit keys cannot tag the containerized
  nginx worker observed node-side, so worker-scope drift rules are proven on
  the recorded corpus and the behaviors live by side effects; the host-scope
  escape rules are proven on the host-escape corpus plus a node-side
  escape-simulation for the live record.

## Safety boundary (TDS §4 applies in full)

- The C2 stand-in binds `127.0.0.1:4446` and logs what it receives; the real
  C2 is never contacted. The declared upstream `10.96.100.40` is aliased onto
  the container's `lo`. Capture-level and lane-level assertions reject any
  other destination. No actual kernel exploit is run — the LPE phase is
  recorded as a finding, and the escape phase is a benign root-shell *shape*
  (`id`, `head -1 /etc/shadow`) on the disposable CI node.
- Everything runs in disposable CI containers / on the recycled runner; audit
  rules exist only for the lifetime of the job.

## How to run

```sh
docker build -f scenarios/nginx2root/workload/Dockerfile -t sbob-nginx2root:local scenarios/nginx2root
sudo auditctl -R dist/nginx/wazuh/audit/sbob/nginx-worker.rules
docker run --cap-add=NET_ADMIN -v /var/log/audit:/host-audit:ro -d --name sbob-nginx sbob-nginx2root:local
docker exec -e AUDIT_LOG=/host-audit/audit.log sbob-nginx bash /opt/harness/run-behaviors.sh
```

Full flow in CI: `.github/workflows/nginx-detection.yml`. Evidence:
`docs/nginx2root/detection-evidence.md`.
