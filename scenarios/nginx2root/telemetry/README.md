# Scenario D telemetry contract

SBOB-EXAMPLES DEMO WATERMARK — recorded harness corpus for scenario D
(NGINX2Root, issue #15), in the SBoB repo's `test/corpus/php-*.audit` record
shape (SYSCALL + EXECVE/PATH/SOCKADDR aux records per event, serial-grouped).

| file | scope | content |
|---|---|---|
| `nginx-benign.audit` | worker (slot 4) | one benign request round: `/etc/nginx/nginx.conf` read, `/var/www/html/index.html` read, `/var/log/nginx/access.log` create, `/etc/resolv.conf` read, declared upstream connect `10.96.100.40:8080` (saddr `02001F900A606428`) |
| `nginx-drift.audit` | worker + host signature | the post-RCE chain: `/bin/sh` execve (100411), `/etc/passwd` + `/etc/shadow` opens (100421 + overlay 100401), sctp autoload `init_module` as uid-0 modprobe with node-scoped key `sbob-module-load` (100460), C2 stand-in connect `127.0.0.1:4446` (saddr `0200115E7F000001`, 100431) |
| `host-escape.audit` | host (slot 5) | the post-LPE phase: root `/bin/sh` execve (100511), uid-0 reads of `/etc/passwd` / `/etc/shadow` (100521 + overlay 100501) |

Per-run captured windows land in the `nginx2root-telemetry` CI artifact.
