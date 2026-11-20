# SBOB-EXAMPLES DEMO WATERMARK — scenario C: Java2Shell (CVE-2026-114938)
# detection-replay workload fixture (M8, issue #14). This image is a
# disposable Java 17 service implementing the SBoB java-service contract
# (sbobs/workload/java-service.yaml, slot 3, pinned by commit SHA in the CI
# lane). Not real malware. All network stand-ins are loopback-local inside
# this container (TDS §4): the declared config peer is aliased onto `lo`,
# and the C2 stand-in binds 127.0.0.1 only. The real C2 address is never
# contacted.
#
# Grounding: CVE-2026-114938 ("Java2Shell", disclosed 2026-11-17): unauth
# RCE via the JIT-compiled Base64 decode fast path in OpenJDK 17 (x86-64
# AVX-512 VBMI), demonstrated pre-auth on default Keycloak, Jenkins, Jira,
# Confluence, Artifactory, PingFederate (JFrog, Qualys, SecureLayer7).

ARG JDK_IMAGE=eclipse-temurin:17-jdk
FROM ${JDK_IMAGE}

# socat         : stand-in listeners (declared config peer + loopback C2)
# iproute2      : `ip addr add` for the loopback-local declared-peer alias
# curl          : the HTTP client stand-in for the declared nginx ingress
# auditd        : in-container observer on self-hosted nodes (GitHub-hosted
#                 runner containers cannot hold the audit netlink — EPERM
#                 proven live in the scenario-B lane; the CI lane runs auditd
#                 node-side and mounts /var/log/audit read-only)
RUN apt-get update && apt-get install -y --no-install-recommends \
      auditd \
      socat \
      iproute2 \
      procps \
      curl \
    && rm -rf /var/lib/apt/lists/*

# dedicated workload uid 1000 (the temurin base's existing `ubuntu` user —
# useradd -u 1000 fails on the non-unique UID): node-side signature keys are
# attributed to the workload by uid in the capture (scenario-B pattern)
RUN mkdir -p /app /var/lib/app-data /var/www/webapp \
    && chown -R 1000:1000 /app /var/lib/app-data /var/www/webapp

# the service + the in-JVM payload class (b4 reads /app/Payload.class through
# the DECLARED /app read, then defineClass — no OS-level syscall)
# build context is the scenario root (scenarios/java2shell), like scenario B
COPY workload/src/App.java workload/src/Payload.java /build/
RUN javac -d /app /build/App.java /build/Payload.java
COPY workload/www/index.html /app/index.html
RUN chown -R 1000:1000 /app

# harness orchestration (run via docker exec once the CI lane has loaded the
# SBoB-generated audit fragment; see scenarios/java2shell/harness/)
COPY harness/run-behaviors.sh harness/capture-window.sh /opt/harness/
RUN chmod +x /opt/harness/*.sh

COPY workload/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/opt/entrypoint.sh"]
