# SBOB-Examples

End-to-end, runnable demonstrations of the **Software Bill of Behavior (SBoB)**
toolchain replayed against a real supply-chain compromise: the
**2026-11-17 Microsoft `agent-framework` PyPI hijack** (malicious versions
1.26.1 and 1.26.2, ~41k downloads/week at the time).

The repo answers one question with evidence, not opinion:

> Could SBOB-Forge and Software-Bill-of-Behavior have changed the outcome?

Three defenses, each a milestone with its own CI lane and committed evidence:

| # | Defense | Tooling | Effect on 2026-11-17 |
|---|---------|---------|----------------------|
| 1 | **Supply-chain gate** (pre-install) | `sbobforge generate` + `sbobctl diff --fail-on mandatory` | The dependency-update PR flags 1.26.1/1.26.2 as MANDATORY behavior deltas vs the committed 1.26.0 profile. Reviewed before install; nothing reaches a runner holding credentials. |
| 2 | **Runtime detection** (Monitor / Audit) | `sbobctl transpile` (Wazuh audit rules, CDB allowlists, Sigma) | Drift alerts fire on the first `.pth`-triggered Python start: new startup-hook execution, `/proc/*/environ` reads, unknown external egress. |
| 3 | **Enforcement** (Enforce) | `sbobctl enforce` (NetworkPolicy / AppArmor / seccomp) | The single HTTPS POST to the exfil endpoint fails closed. Clean 1.26.0 workloads are unaffected (no false positive). |

## What happened (summary)

On 2026-11-17, versions 1.26.1 (20:35 UTC) and 1.26.2 (~21:08 UTC) of
Microsoft's official `agent-framework` package were published to PyPI with an
added credential stealer. Both were built outside the normal release process
(wheel-only, no matching git tag) and were gone from PyPI by ~21:30 UTC. The
stealer ran on **every Python start** via a `.pth` startup hook, harvested
Azure, Azure DevOps, GitHub Actions and CI/CD credentials, and exfiltrated
them in a single zlib+base64 HTTPS POST to `webhook[.]site`. Full IOC table
and payload mechanics: [docs/TDS.md](docs/TDS.md), section 2.

## The honest limitations

SBoB is a **damage-prevention and detection** control, not a provenance
control. It would not have stopped the unauthorized PyPI publish (that is
identity/provenance: stolen token, wheel-only upload, missing git tag). What
it changes is everything after publication. The demo documents both sides:
[docs/TDS.md](docs/TDS.md), section 9.

## Repo layout

```
scenario/            reconstruction of the incident (see safety policy, TDS 4)
  package/v1.26.0/   clean baseline + pytest corpus
  package/v1.26.1/   agent_framework_meta.pth + _telemetry.py reconstruction
  package/v1.26.2/   af_runtime_diag.pth + af_runtime_diag.py reconstruction
  sink/              loopback-only exfil sink (stands in for webhook[.]site)
  fixtures/          synthetic credential tree (no real secrets, ever)
sbobs/               committed, drift-gated SBoB profiles per version
docs/                TDS, incident map, per-layer evidence docs
.github/workflows/   supply-chain-gate / runtime-detection / enforce-block lanes
```

## Safety policy (read before touching scenario/)

The reconstruction is behaviorally faithful but **not a weapon**: the exfil
endpoint is a loopback sink, all credentials are synthetic fixtures, and the
CI asserts that no non-loopback socket is opened. Details and hard rules:
[docs/TDS.md](docs/TDS.md), section 4.

## References

- Wiz: [Microsoft agent-framework Compromised: Credential Stealer Targets Azure and CI Pipelines](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi)
- OpenSourceMalware: [Official Microsoft agent-framework PyPI package compromised](https://opensourcemalware.com/blog/agent-framework-pypi-compromised)
- Aikido: [Two malicious agent-framework releases hit PyPI in 33 minutes](https://www.aikido.dev/blog/two-malicious-agent-framework-releases-hit-pypi-in-33-minutes)
- Tooling: [SBOB-Forge](https://github.com/DevelApp-ai/SBOB-Forge) (generate), [Software-Bill-of-Behavior](https://github.com/DevelApp-ai/Software-Bill-of-Behavior) (validate/diff/transpile/enforce), [adoption guide](https://github.com/DevelApp-ai/SBOB-Forge/blob/main/docs/adoption.md)
