# SBOB-Examples

A **verification harness** for the Software Bill of Behavior (SBoB) toolchain:
replay real compromises and measure, with committed evidence, what each SBoB
layer would have changed. The repo answers one question with evidence, not
opinion:

> Is SBoB good enough?

Two scenarios, deliberately different compromise classes:

- **Scenario A — supply-chain release:** the [2026-11-17 Microsoft
  `agent-framework` PyPI hijack](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi)
  (malicious 1.26.1/1.26.2, ~41k downloads/week). The attacker authors the
  artifact and its corpus; the demo tests the supply-chain gates (fail-closed
  refusal, canary identification, scored diff), runtime detection and
  enforcement. Milestones M1-M5.
- **Scenario B — runtime CVE exploit:** the October 2026 PHP RCEs
  (CVE-2026-109618 / CVE-2026-109619, the PHP2Shell campaign), mapped onto
  the proven [php-fpm SBoB contract](https://github.com/DevelApp-ai/Software-Bill-of-Behavior/blob/main/docs/php2shell-scenario.md).
  No release ever shipped, so there is no supply-chain layer to engage; the
  demo tests the declared-contract defense — post-exploit behavior is drift
  by definition — with LIVE harness behaviors against detection and
  enforcement in a disposable container. Milestones M6-M7.

## Scenario A: agent-framework PyPI hijack

Three defenses, each a milestone with its own CI lane and committed evidence:

| # | Defense | Tooling | Effect on 2026-11-17 |
|---|---------|---------|----------------------|
| 1 | **Supply-chain gate** (pre-install) | fail-closed refusal + `sbobctl profile` (canary) + `sbobctl diff --fail-on mandatory` | Three gates: refuse what cannot be profiled (wheel-only, no sdist, no tag, no signed entry); identify the stealer by canary-observed telemetry (the `.pth` hook fires on first Python start, no test reachability needed); score its delta MANDATORY vs the 1.26.0 baseline. |
| 2 | **Runtime detection** (Monitor / Audit) | `sbobctl transpile` (Wazuh audit rules, CDB allowlists, Sigma) | Drift alerts fire on the first `.pth`-triggered Python start: new startup-hook execution, `/proc/*/environ` reads, unknown external egress. |
| 3 | **Enforcement** (Enforce) | `sbobctl enforce` (NetworkPolicy / AppArmor / seccomp) | The single HTTPS POST to the exfil endpoint fails closed. Clean 1.26.0 workloads are unaffected (no false positive). |

Layer 3 is evidenced (issue #5, PR #18): enforced 1.26.1/1.26.2 legs deny the
exfil POST at the kernel level (REJECT counter hit) and the sink receives
nothing; clean 1.26.0 is unaffected —
[docs/agent-framework/enforce-evidence.md](docs/agent-framework/enforce-evidence.md),
lane `enforce-block.yml`, run
[44800715326](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44800715326).
Narrative: [docs/incident-report.md](docs/incident-report.md).

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
identity/provenance: stolen token, wheel-only upload, missing git tag). And
the attacker authors the candidate release's corpus: code outside test reach
is invisible to test-derived profiles, so a pure corpus diff would not have
marked 1.26.1/1.26.2. The supply-chain layer's real catches are **refusal**
(fail-closed when no comparable profile can be generated or verified) and
**observation** (canary profiling sees the `.pth` hook fire on the first
Python start, no attacker cooperation needed). Details:
[docs/TDS.md](docs/TDS.md), sections 6 (M2) and 9.

## Scenario B: PHP2Shell (October 2026 PHP RCEs)

| # | Defense | What the demo proves |
|---|---------|----------------------|
| 1 | **Runtime detection** | A live harness performs the four post-exploit behaviors (shell spawn, webshell drop, C2 connect, memfd staging) inside a disposable php-fpm container; the transpiled bundle fires 100111/100121/100131/100163 + sustained children on the REAL captured telemetry; benign stays silent. |
| 2 | **Enforcement in anger** | AppArmor/seccomp/NetworkPolicy from `sbobctl enforce` block all four behaviors for real; the benign workload is unaffected — live-asserted in the `php-enforce` lane, evidence in [docs/php2shell/enforce-evidence.md](docs/php2shell/enforce-evidence.md) (issue #11). |

The point of the contrast: scenario A engages the gate/detection/enforcement
ladder; scenario B engages only the contract — and that asymmetry is stated,
not papered over ([docs/TDS.md](docs/TDS.md), limitation 9.0).

## Scenario C: Java2Shell (CVE-2026-114938)

| # | Defense | What the demo proves |
|---|---------|----------------------|
| 1 | **Runtime detection** | A Java 17 service fixture runs the four post-RCE behaviors for real inside a disposable container; the transpiled bundle (slot 3) fires the mapped drift rules — 100311 (shell exec), 100321 (webshell write), 100331 (C2 connect) — plus sustained children 100312/100322/100332 on the session replay; benign stays silent. The in-JVM `defineClass` leg is recorded as expected-silent (committed finding). Issue #14, evidence: [docs/java2shell/detection-evidence.md](docs/java2shell/detection-evidence.md) |

## Run the demos

Everything is loopback-only; the CI asserts that no non-loopback socket is
opened (TDS §4 hard rules). No reconstructed payload ever runs on a runner
host outside a disposable container.

Local, scenario A reconstruction (what the stealer does, against the sink):

```bash
python3 scenarios/agent-framework/scripts/validate_scenario_a.py   # stdlib-only integrity checks
cd scenarios/agent-framework && python3 -m pytest tests/ -v          # full M1 suite (needs pytest)
```

The layer lanes run in CI on push/PR (watch them under
[Actions](https://github.com/DevelApp-ai/SBOB-Examples/actions)):

| Lane | Workflow | Proves |
|------|----------|--------|
| Scenario A reconstruction tests | `scenario-a-tests.yml` | sink receives exactly one POST per stealer run; zero non-loopback sockets |
| Layer 1: supply-chain gate | `supply-chain-gate.yml` | Gates A/B/C verdicts, canary scores — [docs/supply-chain-evidence.md](docs/supply-chain-evidence.md) |
| Layer 2: runtime detection | `runtime-detection.yml` | drift rules 100221/100231 (+100222) fire, benign silent — [docs/agent-framework/runtime-evidence.md](docs/agent-framework/runtime-evidence.md) |
| Layer 3: enforcement | `enforce-block.yml` | exfil POST fails closed (0 new sink receipts, REJECT counter hit), clean 1.26.0 unaffected — [docs/agent-framework/enforce-evidence.md](docs/agent-framework/enforce-evidence.md) |
| Scenario B: PHP2Shell detection | `php-detection.yml` | rules 100111/100121/100131/100163 fire on live post-exploit behaviors — [docs/php2shell/detection-evidence.md](docs/php2shell/detection-evidence.md) |
| Scenario B: PHP2Shell enforcement | `php-enforce.yml` | all four post-exploit behaviors blocked live under Enforce, benign unaffected — [docs/php2shell/enforce-evidence.md](docs/php2shell/enforce-evidence.md) |
| Scenario C: Java2Shell detection | `java-detection.yml` | 100311/100321/100331 fire on the harness corpus, sustained children via session replay, benign silent — [docs/java2shell/detection-evidence.md](docs/java2shell/detection-evidence.md) |

The full incident narrative — real 2026-11-17 timeline side-by-side with the
demo, each layer mapped to "what would have happened when", limitations
stated plainly — is [docs/incident-report.md](docs/incident-report.md).

## Repo layout

```
scenarios/agent-framework/   reconstruction of the PyPI hijack (safety policy, TDS 4)
  package/v1.26.0/   clean baseline + pytest corpus
  package/v1.26.1/   agent_framework_meta.pth + _telemetry.py reconstruction
  package/v1.26.2/   af_runtime_diag.pth + af_runtime_diag.py reconstruction
  sink/              loopback-only exfil sink (stands in for webhook[.]site)
  fixtures/          synthetic credential tree (no real secrets, ever)
  php2shell/           post-exploit behavior harness + captured telemetry
  java2shell/          scenario C: Java 17 service fixture + post-RCE harness
upstream/corpus-1.26.0/  the REAL microsoft/agent-framework pytest corpus,
                         vendored at tag python-1.26.0 (MIT) - the baseline
                         profile is generated from upstream's own tests
sbobs/               committed, drift-gated SBoB profiles per version
docs/                TDS, incident map, incident report, per-layer evidence docs
.github/workflows/   supply-chain-gate / runtime-detection / enforce-block /
                     php-detection / php-enforce / java-detection lanes
```

## Safety policy (read before touching scenarios/)

The reconstruction is behaviorally faithful but **not a weapon**: the exfil
endpoint is a loopback sink, all credentials are synthetic fixtures, and the
CI asserts that no non-loopback socket is opened. Details and hard rules:
[docs/TDS.md](docs/TDS.md), section 4.

## References

- Wiz: [Microsoft agent-framework Compromised: Credential Stealer Targets Azure and CI Pipelines](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi)
- OpenSourceMalware: [Official Microsoft agent-framework PyPI package compromised](https://opensourcemalware.com/blog/agent-framework-pypi-compromised)
- Aikido: [Two malicious agent-framework releases hit PyPI in 33 minutes](https://www.aikido.dev/blog/two-malicious-agent-framework-releases-hit-pypi-in-33-minutes)
- Upstream: [microsoft/agent-framework](https://github.com/microsoft/agent-framework) (tests vendored under MIT)
- Tooling: [SBOB-Forge](https://github.com/DevelApp-ai/SBOB-Forge) (generate), [Software-Bill-of-Behavior](https://github.com/DevelApp-ai/Software-Bill-of-Behavior) (validate/diff/transpile/enforce), [adoption guide](https://github.com/DevelApp-ai/SBOB-Forge/blob/main/docs/adoption.md)
