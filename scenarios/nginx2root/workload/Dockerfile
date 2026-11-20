# SBOB-EXAMPLES DEMO WATERMARK — scenario D: NGINX2Root (CVE-2026-123007 et
# al., disclosed 2026-11-18 by Xint) detection-replay workload fixture (M9,
# issue #15). Disposable nginx container implementing the SBoB nginx-worker
# contract (sbobs/workload/nginx-worker.yaml, slot 4, pinned by commit SHA in
# the CI lane). Not real malware. All network stand-ins are loopback-local
# inside this container (TDS §4): the declared upstream is aliased onto `lo`,
# the C2 stand-in binds 127.0.0.1 only. The real C2 is never contacted.
#
# The RCE entry vector is NOT simulated (SBoB makes no claim about the
# exploit); the harness executes the POST-RCE worker activity for real as the
# nginx worker uid (101) via setpriv, inside this container.

ARG NGINX_IMAGE=nginx:1.27
FROM ${NGINX_IMAGE}

# socat     : stand-in listeners (declared upstream + loopback C2 stand-in)
# iproute2  : `ip addr add` for the loopback-local declared-upstream alias
# curl      : HTTP client stand-in for the declared edge frontend
# python3   : SCTP-socket probe (behavior 3: sctp module autoload) + C2 client
# auditd    : in-container observer on self-hosted nodes (EPERM on
#             GitHub-hosted runners — the lane runs auditd node-side)
RUN apt-get update && apt-get install -y --no-install-recommends \
      auditd \
      socat \
      iproute2 \
      procps \
      curl \
      python3 \
    && rm -rf /var/lib/apt/lists/*

# web root at the contract's declared read path
RUN mkdir -p /var/www/html
COPY workload/www/index.html /var/www/html/index.html
COPY workload/nginx.conf /etc/nginx/nginx.conf

# harness orchestration (run via docker exec once the CI lane has loaded the
# SBoB-generated audit fragment; see scenarios/nginx2root/harness/)
COPY harness/run-behaviors.sh harness/capture-window.sh /opt/harness/
RUN chmod +x /opt/harness/*.sh

COPY workload/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/opt/entrypoint.sh"]
