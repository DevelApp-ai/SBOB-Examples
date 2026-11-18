# Scenario A incident map: agent-framework PyPI hijack (2026-11-17)

Reference map from the real incident (reconstructed here for verification
purposes) to the SBoB behavior sections the reconstructed activity must
trigger. Grounding: Wiz advisory, OpenSourceMalware write-up, Aikido and
Socket alerts. All indicators are defanged.

## Timeline

| Event | Version | Mechanism |
| --- | --- | --- |
| Clean baseline | 1.26.0 | legitimate wheel, no hook |
| Compromise | 1.26.1 | `agent_framework_meta.pth` imports `agent_framework_meta`, whose `__init__.py` now calls `_telemetry._start()` |
| Follow-up | 1.26.2 | `__init__.py` restored byte-for-byte to the clean 1.26.0 file; stealer moved to top-level `af_runtime_diag.py` fired by `af_runtime_diag.pth` |

Both malicious releases were wheel-only uploads pinning the previous core
(`agent-framework-core[all]==1.26.0`), with no corresponding source
distribution or tag: a provenance break on its own.

## Defanged indicators

| Indicator | Value |
| --- | --- |
| Exfil endpoint | `hxxp://webhook[.]site/<uuid>?t=telemetry` |
| Hook file (1.26.1) | `agent_framework_meta.pth` |
| Stealer module (1.26.1) | `agent_framework_meta/_telemetry.py` |
| Hook file (1.26.2) | `af_runtime_diag.pth` |
| Stealer module (1.26.2) | `af_runtime_diag.py` (top level) |
| User agent (1.26.1) | `af-runtime-diagnostics/1` |
| User agent (1.26.2) | `runtime-diagnostics/1` |
| Run-once guard | env `_AF_TEL=1` |
| Package restored in 1.26.2 | `agent_framework_meta/__init__.py` (byte-identical to 1.26.0) |

## Collector behavior (1.26.1 vs 1.26.2)

| Behavior | 1.26.1 | 1.26.2 |
| --- | --- | --- |
| Env-key matchers | TOKEN, SECRET, PASSWORD, KEY, AZURE, AWS, GITHUB, OPENAI, HF_, FOUNDRY, NPM, PIP, NUGET, SYSTEM, BUILD, AGENT | adds ACTIONS, OIDC, RUNNER, ARM_ |
| Process environ sweep | up to 300 `/proc/*/environ` | same |
| Credential files | up to 60 | cap raised to 80; adds runner paths |
| Metadata endpoints | ADO OIDC, IMDS (12 resources), instance metadata | adds GitHub Actions OIDC theft shape |
| Staging | one JSON doc, zlib-compressed, base64-encoded | same |
| Egress | single HTTPS POST, silent failure, no retry | same |

## Behavior to SBoB section mapping

The reconstruction is the input corpus for the M2 gates and the M3/M4
detection and enforcement replay. Each incident behavior maps to the SBoB
(software bill of behavior) section that must carry it:

| Incident behavior | SBoB section |
| --- | --- |
| `.pth` executes `import agent_framework_meta` at interpreter start | opens/imports |
| `import af_runtime_diag` at interpreter start (1.26.2) | opens/imports |
| `os.fork()` + `os.setsid()` detach, daemon-thread fallback | execs/process |
| read `~/.azure/*`, `.npmrc`, `.docker/config.json`, `.netrc`, `.git-credentials`, HF token, ADO `.credentials`, `.env`, app/workspace configs | opens (capability: credential access) |
| sweep `/proc/*/environ` (up to 300) | opens (capability: credential access) |
| match env names TOKEN/SECRET/PASSWORD/KEY/... | capabilities (credential access) |
| metadata requests: ADO OIDC, IMDS, instance metadata, GHA OIDC | egress (capability: identity abuse) |
| single zlib+base64 JSON POST to hardcoded webhook | egress (capability: exfiltration) |

Expected verdicts for the harness (TDS §6):

- 1.26.0 clean: no opens/execs/egress beyond baseline; zero receipts.
- 1.26.1 / 1.26.2 malicious: credential-access opens, process detach, single
  exfil egress; in this demo all egress is forced to a loopback-only sink.
- Diff vs the 1.26.0 baseline profile must flag every behavior above; the
  supply-chain gate (M2 Gate A) must additionally fail-closed on the
  wheel-only/no-sdist/no-tag provenance break before any profile is trusted.
