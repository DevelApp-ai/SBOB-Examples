# TDS: SBOB-Examples — the agent-framework compromise, replayed against SBoB

**Status:** v1.1 (2026-11-18; v1.1 adds upstream corpus provenance, Lars's call)
**Repo:** DevelApp-ai/SBOB-Examples (public)
**Spec owner:** Lars. **Delivery:** org decisions #26–#29 (squash merges, agents
merge their own PRs when green with their own tests). Milestones tracked as
issues M1–M5 in this repo.

---

## 1. Purpose

One question, answered with runnable, evidence-gated demonstrations instead of
argument:

> Could the SBoB toolchain (SBOB-Forge + Software-Bill-of-Behavior) have
> changed the outcome of the agent-framework PyPI compromise of 2026-11-17?

Three layers, each with its own milestone, CI lane, and committed evidence:

| # | Defense | Tooling | Effect on 2026-11-17 |
|---|---------|---------|----------------------|
| 1 | Supply-chain gate (pre-install) | `sbobforge generate` (pytest corpus) + `sbobctl diff --fail-on mandatory` | The consumer's dependency-update PR diffs the new version's generated profile against the committed 1.26.0 profile. New opens on credential paths, new exec surface, and a new external egress peer score MANDATORY. Reviewed before install. |
| 2 | Runtime detection (Monitor/Audit) | `sbobctl transpile` (Wazuh audit rules + CDB allowlists; Sigma) | The consumer's workload profile transpiles to detection artifacts. First `.pth`-triggered Python start drifts against it: new startup-hook execution, `/proc/*/environ` reads, unknown external egress. Alert fires in minutes, not on the next CVE scan. |
| 3 | Enforcement (Enforce) | `sbobctl enforce` (NetworkPolicy; AppArmor/seccomp documented) | Egress limited to declared peers. The single HTTPS POST to the exfil endpoint fails closed. Clean 1.26.0 workload behavior is fully inside the profile, so nothing false-positives. |

## 2. Background: the incident (facts used by this demo)

All facts from public advisories (Wiz, OpenSourceMalware, Aikido, Socket).

**Timeline (UTC):**

| Time | Event |
|------|-------|
| 2026-11-12 18:25 | Legit 1.26.0 published (wheel + sdist, alongside agent-framework-core 1.26.0) |
| 2026-11-17 20:35 | Malicious 1.26.1 published (wheel only; still pins agent-framework-core[all]==1.26.0; no matching tag in microsoft/agent-framework) |
| 2026-11-17 ~21:08 | Malicious 1.26.2 published (repacked 1.26.1, same exfil endpoint, new trigger) |
| 2026-11-17 ~21:30 | Both versions removed/quarantined on PyPI |

**Payload mechanics:**

- 1.26.1 drops `agent_framework_meta.pth` (single line:
  `import agent_framework_meta`) into site-packages root. Python runs `.pth`
  files on every interpreter start, so the stealer runs **even if
  agent-framework is never imported**. `agent_framework_meta/__init__.py`
  calls `_telemetry._start()`, disguised as "Lightweight runtime diagnostics
  hook" (user-agent `af-runtime-diagnostics/1`).
- The stealer forks into a detached session (`os.setsid()`), or falls back to
  a daemon thread; sets `_AF_TEL=1` as a run-once guard.
- Collection: env vars matching TOKEN, SECRET, PASSWORD, KEY, AZURE, AWS,
  GITHUB, OPENAI, HF_, FOUNDRY, NPM, PIP, NUGET, SYSTEM, BUILD, AGENT; up to
  300 `/proc/*/environ` files; up to 60 credential files (`~/.azure/`,
  `.npmrc`, `pip.conf`, `.netrc`, `.git-credentials`,
  `.docker/config.json`, HF tokens, ADO agent `.credentials`, `.env` and
  JSON under /app and /workspace); ADO OIDC tokens; Azure managed-identity
  and IMDS tokens for 12 resources; Azure instance metadata.
- Exfiltration: one JSON document, zlib-compressed, base64-encoded, a single
  HTTPS POST to `webhook[.]site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb`
  (`?t=telemetry`). Hardcoded, no fallback channel, failures silently
  ignored and never retried.
- 1.26.2: `__init__.py` restored byte-for-byte to the clean 1.26.0 file (so
  inspecting the package directory misses it); the trigger becomes top-level
  `af_runtime_diag.pth` importing top-level `af_runtime_diag.py`
  (user-agent `runtime-diagnostics/1`). Adds GitHub Actions OIDC token theft
  (workflows with `id-token: write`, for `api://AzureADTokenExchange` and
  `management.azure.com`), env matching adds ACTIONS/OIDC/RUNNER/ARM_,
  runner paths `/home/runner/work/_temp/*` and `/home/runner/.azure/`,
  file cap raised 60 to 80.

**Indicators (defanged):** the exfil URL above; `.pth`/`_telemetry.py` /
`af_runtime_diag.py` filenames; `_AF_TEL=1`; wheel SHA256s published by Wiz.
Full table: `docs/incident-map.md` (M1).

## 3. Non-goals

- Not a malware collection. One incident, reconstructed, watermarked.
- Not a provenance/signing control. The root cause (unauthorized PyPI publish
  access; wheel-only upload with no matching git tag) is an identity/provenance
  failure SBoB does not observe. The demo documents it as the complement to
  the behavior gate, not as something SBoB claims to catch.
- Not a registry-publishing demo. Profiles are committed in-repo and
  drift-gated; no SBOB-Registry PR is opened from these lanes.

## 4. Reconstruction policy (fidelity vs safety)

**Faithful (identical to the original):** file and module names, `.pth`
trigger mechanics, run-once guard, detached-session fork, collection target
lists, staging format (single zlib+base64 JSON), single-POST semantics,
silent-failure no-retry semantics, user-agent strings, version numbering.

**Replaced (safety boundary):**

| Original | Demo |
|----------|------|
| HTTPS POST to `webhook[.]site/<uuid>?t=telemetry` | HTTP POST to a loopback-only sink (`127.0.0.1`), same URL path shape |
| Real credential paths on victim hosts | Synthetic fixture tree under `scenario/fixtures/` (fake tokens only) |
| ADO/GHA OIDC + Azure IMDS endpoints | Sink-simulated endpoints (same request shape, loopback) |

**Hard rules (enforced by tests, M1 acceptance):**

1. The real exfil URL is never contacted. The sink binds 127.0.0.1 only.
2. No real credentials exist anywhere in the repo; fixtures are synthetic.
3. Tests assert no non-loopback socket is opened during any corpus run.
4. Every reconstructed file carries a watermark header stating it is a
   demonstration reconstruction, plus the advisory source.

## 5. Repo layout

```
scenario/
  package/
    v1.26.0/   clean agent_framework_meta baseline + pytest corpus
    v1.26.1/   agent_framework_meta.pth + __init__ hook + _telemetry.py
    v1.26.2/   af_runtime_diag.pth + af_runtime_diag.py (init byte-clean)
  sink/        loopback HTTP sink; asserts payload shape; logs receipt
  fixtures/    synthetic HOME tree: .azure/, .npmrc, .netrc, .docker/, .env ...
upstream/
  corpus-1.26.0/   vendored microsoft/agent-framework pytest corpus at tag
                   python-1.26.0 (MIT; attribution headers preserved)
  ATTRIBUTION.md   upstream source, tag, resolved commit SHA, license,
                   vendoring scope
sbobs/
  versions/    generated, committed profiles: 1.26.0 / 1.26.1 / 1.26.2
  workload/    the consumer workload profile (Python CI runner using the pkg)
docs/
  TDS.md  incident-map.md  supply-chain-evidence.md
  runtime-evidence.md  enforce-evidence.md  incident-report.md
.github/workflows/
  supply-chain-gate.yml  runtime-detection.yml  enforce-block.yml
```

## 6. Milestones

Each milestone lands as PRs (squash) with its own tests; the lane proving the
milestone's claim ships with it. Issues M1–M5 track acceptance.

### M1: scenario reconstruction
- Clean 1.26.0 package, faithful 1.26.1 and 1.26.2 reconstructions, loopback
  sink, synthetic credential fixtures, pytest corpora per version.
- `docs/incident-map.md`: defanged IOC table + a behavior-to-SBoB-section
  mapping (each malicious behavior line mapped to the profile section that
  would flag it: opens, execs, egress, capabilities).
- **Accept:** pytest green in a disposable container; sink receives exactly
  one POST per stealer run; a test asserts zero non-loopback sockets;
  watermark headers present.

### M2: supply-chain diff gate (layer 1)
- **Baseline profile from the real upstream tests** (Lars's call, chat
  2026-11-18): the 1.26.0 baseline profile is generated from
  microsoft/agent-framework's own committed pytest corpus, vendored under
  `upstream/corpus-1.26.0/` from tag `python-1.26.0` (MIT; attribution
  and license preserved). The first lane run resolves and records the tag's
  commit SHA in `upstream/ATTRIBUTION.md`; afterwards the lane pins that
  SHA and byte-verifies the vendored copy against it (the .github
  template-sync pattern). Maximum realism: the clean baseline is derived
  from upstream's own suite, exactly what a consumer-side gate consumes.
- **Candidate profiles** for the reconstructed 1.26.1/1.26.2 package trees
  are generated from the same corpus, **extended, never skipped** (org scope
  rule): watermarked pytest tests exercising the attacker's new top-level
  hook modules (`import agent_framework_meta` / `af_runtime_diag`) so
  the generator attributes the new opens/egress to the candidate package.
- **Fail-closed provenance note** (documented in the evidence doc): a real
  consumer gate would already refuse 1.26.1/1.26.2 at the corpus level:
  wheel-only, no sdist and no matching tag means no comparable corpus can
  be pinned, so no candidate profile can be generated or trusted. The demo
  reconstructs the package source to run the deeper behavior-diff layer
  anyway; both refusals are part of the story.
- Lane `supply-chain-gate.yml`: consumer shape. `sbobctl diff` old=1.26.0
  new=1.26.1, and old=1.26.0 new=1.26.2, each asserting **verdict MANDATORY,
  exit 1**; control diff (clean vs clean) asserting **verdict none, exit 0**.
- Delta reports committed under `docs/` as evidence with a verdict table.
- **Accept:** lane green asserting expected verdicts (no permanently red
  lane); `docs/supply-chain-evidence.md` maps each delta row to the scoring
  ladder classes (capabilities +5, exec outside namespace +4, external DNS +3,
  widened wildcard +2, removed +1); vendored corpus byte-verified against the
  pinned upstream SHA; ATTRIBUTION.md carries tag + SHA + license.

### M3: runtime detection (layer 2)
- Commit the consumer workload profile (a Python CI runner using the
  package) under `sbobs/workload/`; transpile to Wazuh audit rules + CDB
  allowlists (+ Sigma), per the proven lab-validate container pattern
  (wazuh-manager 4.x pinned, logtest corpus replay).
- Synthetic event corpus: auditd lines for the `.pth`-triggered execution,
  `/proc/*/environ` reads, credential-file opens, DNS + connect to the exfil
  endpoint (sink IP standing in).
- **Accept:** drift rules fire on the malicious corpus and stay quiet on the
  clean corpus; `docs/runtime-evidence.md` records rule IDs and replay
  evidence.

### M4: enforcement (layer 3)
- `enforce-block.yml`: run each version in a container whose egress is
  limited to the profile's declared peers (loopback sink **not** in the
  allowlist). Assert: clean version's tests pass; malicious version's POST
  fails closed and the sink receives nothing.
- `sbobctl enforce` artifacts committed; Monitor→Audit→Enforce state file
  shows the transition; AppArmor/seccomp variant documented.
- **Accept:** expected-block assertions green; no false positive on clean.

### M5: narrative + evidence report
- `docs/incident-report.md`: the real timeline side-by-side with the demo
  timeline, all three layers mapped to "what would have happened when",
  including the honest limitations.
- README finalized (the story, how to run each demo, evidence links).
- **Accept:** report cites committed evidence for every claim; README runs
  end-to-end for a third party.

## 7. CI lane design (org lessons applied)

- **Expected-verdict assertions, never permanently red lanes:** gates run
  with `continue-on-error` + exit-code/verdict assertions (the SBOB-Registry
  #27/#30 lesson: evidence lives in docs and asserted tests, not open red
  PRs).
- **SHA-pinned tooling:** SBOB-Forge and Software-Bill-of-Behavior actions
  pinned by commit SHA in every lane.
- **Vendored-corpus integrity:** upstream test files are MIT-licensed,
  attributed, and byte-verified against the pinned upstream SHA on every
  lane run.
- **Disposable containers:** scenario runs only in CI containers; the repo
  never executes reconstructed payloads on runner hosts outside them.
- **Public-repo observability:** step summaries + PR-comment failure
  diagnostics via `github.token`.

## 8. Tooling pins

- SBOB-Forge action (generate): binary mode `binary: true` +
  `binary-version: 1.0.0` (cosign-verified, fail-closed) if the release assets
  are attached; source mode (.NET 8 + `nuget-auth-token`) otherwise.
- Software-Bill-of-Behavior `sbobctl` action (validate/diff/transpile/enforce),
  Node 22, zero npm install.
- Wazuh manager container pinned (4.14.x lane pattern) for M3.
- Upstream corpus: microsoft/agent-framework tag `python-1.26.0`; commit SHA
  resolved and recorded by the first M2 lane run, then pinned.

## 9. Honest limitations (stated in the demo itself)

1. **Provenance gap:** SBoB sees behavior, not identity. The unauthorized
   publish, wheel-only packaging and missing git tag are provenance signals;
   the demo documents them but does not claim SBoB catches them.
2. **Cold-start consumers:** no baseline profile means no drift signal;
   Monitor mode must come before Audit and Enforce for exactly this reason.
3. **DNS-blind egress:** drift rules key on domain resolution; a raw-IP or
   allowlisted-domain beacon is a weaker signal (documented blind spot).
4. **The gate's reach depends on the corpus:** the baseline comes from
   upstream's own committed tests (max realism), but the malicious candidates
   shipped no tests at all; their candidate profiles rest on the extension
   tests we author (extend-not-skip). The `.pth` file write and the module
   import are the load-bearing signals even when collection paths are thinly
   covered.

## 10. References

- Wiz advisory: https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi
- OpenSourceMalware: https://opensourcemalware.com/blog/agent-framework-pypi-compromised
- Aikido: https://www.aikido.dev/blog/two-malicious-agent-framework-releases-hit-pypi-in-33-minutes
- Upstream (tests vendored under MIT): https://github.com/microsoft/agent-framework
- SBOB-Forge: https://github.com/DevelApp-ai/SBOB-Forge
- Software-Bill-of-Behavior: https://github.com/DevelApp-ai/Software-Bill-of-Behavior
- Adoption guide: https://github.com/DevelApp-ai/SBOB-Forge/blob/main/docs/adoption.md
