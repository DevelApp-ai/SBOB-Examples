# Workload fixture: the SBoB php contract (slot 1)

SBOB-EXAMPLES DEMO WATERMARK — scenario B workload image spec. Demo
reconstruction, loopback-only stand-ins (TDS §4).

This fixture implements the workload contract declared in
`DevelApp-ai/Software-Bill-of-Behavior` `sbobs/php-fpm.yaml` (slot 1, rule
band `1001xx`, namespace `web-tier`), pinned by commit SHA in the CI lane.
The contract (see SBoB `docs/php2shell-scenario.md`):

| section | declaration | fixture implementation |
|---|---|---|
| image | digest-pinned `docker.io/library/php` imageID | built from `php:8.3-fpm` (the contract's image family); the digest pin is what `sbobctl enforce` verifies, an M7 concern — the harness records the resolved image digest in the lane log |
| `execs[]` | `/usr/local/sbin/php-fpm` only | official image binary path, unchanged; the worker never shells out in the benign run |
| `opens[]` | `/var/www/html/*` (read), `/var/lib/php/sessions/*` (write), `/etc/resolv.conf` (read) | web root, `session.save_path`, explicit resolver read in `benign.php` |
| `egress[]` | `10.96.100.10:11211` (internal memcache) | the peer is aliased onto the container's `lo` (`ip addr add 10.96.100.10/32 dev lo`) with a socat stand-in listener: the declared-egress connect is real, and it never leaves the container |
| `ingress[]` | `10.244.0.0/16 → :9000` (nginx frontends) | the fastcgi endpoint `127.0.0.1:9000`; the frontend stand-in is `cgi-fcgi` (run as root), whose connect is invisible to the exe-scoped audit rules — ingress enforcement is M7's NetworkPolicy concern |

Process model matches the corpus: php-fpm master (root, like production
masters) with `www-data` workers, **uid 33**, the uid the recorded corpus
carries.

## Privilege note

The container must run `--privileged`: in-container `auditd` needs
`CAP_AUDIT_CONTROL` to load the SBoB-generated audit fragment, and the `lo`
alias needs `NET_ADMIN`. The audit rules are kernel-wide for the lifetime of
the CI job only, on a recycled runner node; the exe-scoped rules cannot fire
for anything outside this container, and node-scoped signature keys are
attributed to the workload by uid in the capture (see
`scenarios/php2shell/telemetry/README.md`).
