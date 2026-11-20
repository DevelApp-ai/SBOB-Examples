# SBOB-EXAMPLES DEMO WATERMARK — scenario B: PHP2Shell post-exploit harness.
# This image is a disposable php-fpm workload fixture implementing the SBoB
# php contract (DevelApp-ai/Software-Bill-of-Behavior sbobs/php-fpm.yaml,
# slot 1, pinned by commit SHA in the CI lane). Not real malware. All network
# stand-ins are loopback-local inside this container (TDS §4): the declared
# memcache peer is aliased onto `lo`, and the C2 stand-in binds 127.0.0.1
# only. The real PHP2Shell C2 address is never contacted.
# Grounding: CVE-2026-109618 / CVE-2026-109619 (watchtowr FAQ, disclosed
# 2026-10-21; CISA KEV 2026-10-26); SBoB repo docs/php2shell-scenario.md.

# The SBoB php contract pins the workload image by digest (imageID). This
# harness builds on the matching official image tag; digest-pinning the
# fixture image is an M7 enforcement concern (the contract's declared image
# is what sbobctl enforce verifies), noted in docs/php2shell/detection-evidence.md.
ARG PHP_IMAGE=php:8.3-fpm
FROM ${PHP_IMAGE}

# auditd        : observer for self-hosted nodes where in-container auditd works;
#                 on GitHub-hosted runners the lane runs auditd node-side and
#                 mounts the node audit log read-only (/host-audit) — see
#                 workload/CONTRACT.md (EPERM proven live for the netlink in
#                 containers on those runners, even under --privileged)
# socat         : stand-in listeners (declared memcache peer + loopback C2)
# libfcgi-bin   : cgi-fcgi, the fastcgi client stand-in for the declared nginx ingress
# iproute2      : `ip addr add` for the loopback-local declared-peer alias
# iptables      : the M7 enforce lane applies the uid-scoped egress allowlist
#                 (NET_ADMIN is granted at docker run; same as the M4 lane image)
# libffi-dev    : build dep for the PHP FFI extension (memfd_create behavior)
RUN apt-get update && apt-get install -y --no-install-recommends \
      auditd \
      socat \
      libfcgi-bin \
      iproute2 \
      iptables \
      libffi-dev \
      procps \
    && rm -rf /var/lib/apt/lists/*

# FFI powers behavior 4 (memfd_create staging, the fileless variant).
RUN docker-php-ext-install ffi

# Workload configuration: the SBoB php contract's declared paths.
# session.save_path  -> /var/lib/php/sessions/*   (the only declared write path)
# ffi.enable=true    -> FFI usable in the fpm worker (web SAPI restricts it by default)
# gc_probability=0   -> no garbage collector opendir() on the session dir inside
#                       capture windows (the bare session dir is not a declared
#                       opens[] entry; gc would be benign-window noise)
COPY workload/php.ini /usr/local/etc/php/conf.d/zz-sbob-demo.ini
COPY workload/php-fpm.conf /usr/local/etc/php-fpm.conf
COPY workload/pool-www.conf /usr/local/etc/php-fpm.d/www.conf

# Web root (declared read path). index.php is the app file the benign run
# reads; benign.php and behaviors.php are the two harness entrypoints,
# requested over fastcgi exactly like the real RCE requests were.
# Build context is the scenario root (scenarios/php2shell), so workload/
# and harness/ files are COPYable in one image build.
COPY workload/www/ /var/www/html/
RUN mkdir -p /var/lib/php/sessions \
    && chown -R www-data:www-data /var/lib/php/sessions /var/www/html

# Harness orchestration (run via docker exec once the CI lane has loaded the
# SBoB-generated audit fragment; see scenarios/php2shell/harness/).
# run-enforce.sh is the M7 (issue #11) in-container half of the php-enforce
# lane: it applies the enforce artifacts' semantics and asserts the blocks.
COPY harness/run-behaviors.sh harness/capture-window.sh harness/run-enforce.sh /opt/harness/
RUN chmod +x /opt/harness/*.sh

COPY workload/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 9000
ENTRYPOINT ["/opt/entrypoint.sh"]
