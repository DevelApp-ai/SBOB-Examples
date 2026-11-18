# Scenario B: PHP2Shell — live post-exploit behavior vs SBoB detection

SBOB-EXAMPLES DEMO WATERMARK — scenario B harness (M6, issue #10). Demo
reconstruction, loopback-only stand-ins (TDS §4).

The question (TDS §1): SBoB never saw a release for PHP2Shell — the entry
vector is a CVE (CVE-2026-109618 OOM/longjmp RCE, CVE-2026-109619 stale
global state RCE, both CVSS v4.0 9.2, disclosed 2026-10-21, CISA KEV since
2026-10-26). There is no supply-chain gate to apply. What SBoB offers is the
declared-contract defense: the workload's own behavior is the baseline, so
post-exploit behavior is drift **by definition**, whatever the CVE.

M6 delivers the part the Stage-1 grounding (corpus replay in
Software-Bill-of-Behavior) could not: the four post-exploit behaviors
**executed for real** inside a disposable php-fpm container, captured by the
kernel, and replayed against the transpiled detection stack.

## Layout

| path | role |
|---|---|
| `workload/` | the php-fpm fixture implementing the SBoB php contract (slot 1): Dockerfile, fpm/pool/php.ini, entrypoint, web root (`index.php`, `benign.php`, `behaviors.php`) |
| `harness/run-behaviors.sh` | in-container orchestration: warm-up, benign window, drift window, capture, pre-checks |
| `harness/capture-window.sh` | audit-log window extraction (record shape parity with the recorded corpus; uid-33 attribution for node-scoped signature keys) |
| `harness/check_capture.py` | runner-side capture parity + safety checker (loopback-only sockets, benign purity, live-fireable memfd leg, delta-7 shape accepted where tagged legs cannot fire) |
| `harness/logtest-replay.ts` | file-driven logtest-API replay of the live windows (benign silent, empty window = delta-7 shape; drift fires 100163 live and asserts 100111/100121/100131 correctly absent, delta 7) |
| `telemetry/` | capture contract + per-run artifacts (see its README) |
| `.github/workflows/php-detection.yml` | the M6 CI lane |

## The four post-exploit behaviors (drift window)

| # | behavior (executed for real, in-worker) | contract violation | rule |
|---|---|---|---|
| 1 | `shell_exec('id > /var/tmp/.pwned')` → execve `/bin/sh -c …` from the php-fpm worker | `execs[]` declares only `/usr/local/sbin/php-fpm` | 100111 (sustained 100112) |
| 2 | `file_put_contents('/var/tmp/.php2shell.php', …)` inert webshell | `opens[]`: web root is read, sessions dir is the only declared write | 100121 (sustained 100122) |
| 3 | `fsockopen('127.0.0.1', 4444)` — loopback stand-in for the C2 callback | `egress[]`: only the memcache peer `10.96.100.10:11211` | 100131 (sustained 100132) |
| 4 | `FFI` `memfd_create` staging (fileless variant) | signature: execution-from-memory, node-scoped key, fires by default | 100163 |

## The honest finding this scenario records (delta 7)

The four behaviors execute for real in every run. From the node-side
observer (the production SBoB deployment model on hosted CI), only the
node-scoped signature rule (100163) can tag the containerized workload:
the exe-scoped rules filter on `exe=/usr/local/sbin/php-fpm`, but a
node-side auditd resolves the container binary through the overlay2 path,
so behaviors 1-3 leave real side effects and no tagged records. The lane
fires what can fire (100163, JSON-asserted), proves behaviors 1-3 by their
side effects, asserts their rules stay correctly absent on the live
replay, and proves all four plus the sustained children on the recorded
corpus (leg 1, the proven Stage-1 scripts from the pinned SBoB repo).
That boundary is a real SBoB finding about exe-scoping and containers, not
a harness defect; see `docs/php2shell/detection-evidence.md` delta 7 for
the full statement and its toolchain follow-up.

## Safety boundary (TDS §4 applies in full)

- The C2 stand-in binds `127.0.0.1` only; the real C2 IP is never contacted.
- The declared memcache peer `10.96.100.10` is aliased onto the container's
  `lo` interface, so the benign declared-egress connect also never leaves the
  container. Both capture-level and lane-level assertions reject any other
  destination.
- The dropped webshell is inert watermark content under `/var/tmp`, which is
  not the web root; nothing serves it.
- Everything runs in disposable CI containers on a recycled runner
  (TDS §7); audit rules exist only for the lifetime of the job.

## How to run

```sh
# locally (assumes docker; the observer is node-side — see workload/CONTRACT.md):
docker build -f scenarios/php2shell/workload/Dockerfile -t sbob-php2shell:local scenarios/php2shell
sudo auditctl -R dist/php/wazuh/audit/sbob/php-fpm.rules   # node kernel, node auditd
docker run --cap-add=NET_ADMIN -v /var/log/audit:/host-audit:ro -d --name sbob-php sbob-php2shell:local
docker exec -e AUDIT_LOG=/host-audit/audit.log sbob-php bash /opt/harness/run-behaviors.sh
```

The full flow (transpile → workload capture → containerized wazuh-manager →
recorded-corpus parity → live-telemetry replay gates) runs in CI:
`.github/workflows/php-detection.yml`. Committed evidence:
`docs/php2shell/detection-evidence.md`.
