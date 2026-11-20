# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# M4 enforcement demo container (issue #5, layer-3 enforcement).
#
# Disposable container for enforce_orchestrator.py (TDS §7): a python:3.12
# interpreter at /usr/local/bin/python3.12 (the same interpreter path the
# consumer workload profile declares in execs[]), iptables + setpriv for the
# uid-scoped egress policy, and the dedicated workload uid 1500 that the
# podSelector -> uid translation selects. The repo is mounted READ-ONLY at
# /src; all writable state (fixtures, receipts, verdicts) lives in the
# mounted work dir passed with `docker run -v`.
#
# Run (see .github/workflows/enforce-block.yml):
#   docker build -t sbob-af-enforce:local \
#     -f scenarios/agent-framework/harness/enforce.Dockerfile .
#   work=$(mktemp -d)
#   docker run --rm --cap-add=NET_ADMIN \
#     -v "$PWD:/src:ro" -v "$work:/opt/af-work" \
#     sbob-af-enforce:local python3 \
#     /src/scenarios/agent-framework/harness/enforce_orchestrator.py \
#       --repo /src --work /opt/af-work
# ============================================================================
FROM python:3.12-slim

# iptables: the uid-scoped egress policy (NET_ADMIN is granted at docker run)
# util-linux: setpriv (uid 1500 workload legs; the orchestrator NEVER runs
#             scenario code as root — see enforce_orchestrator.py)
# passwd:    useradd (the dedicated workload uid)
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables util-linux passwd \
 && rm -rf /var/lib/apt/lists/*

# Workload identity (podSelector -> uid translation; owner-match in iptables)
RUN useradd --uid 1500 --no-create-home --shell /usr/sbin/nologin af-workload

WORKDIR /opt/af-work
