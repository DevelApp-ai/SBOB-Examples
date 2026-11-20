# Incident report: agent-framework PyPI hijack (2026-11-17), replayed against SBoB

SBOB-EXAMPLES DEMO WATERMARK — narrative + evidence report for milestone M5
(issue #6). Every claim below cites a committed evidence document and a lane
run URL. All three layers have committed evidence on main — layer 3 landed
with issue #5 (PR #18).

Sources for the real incident: Wiz, OpenSourceMalware, Aikido advisories
(links in [TDS.md](TDS.md) §10). Indicators are defanged; the full IOC table
is [agent-framework/incident-map.md](agent-framework/incident-map.md).

## 1. The real timeline vs the demo timeline

| Real event (2026-11-17, UTC) | Demo counterpart |
|---|---|
| 2026-11-12 18:25 — legit 1.26.0 published (wheel + sdist, with agent-framework-core 1.26.0) | Clean baseline reconstruction `scenarios/agent-framework/package/v1.26.0/` (M1, issue #2) |
| 2026-11-17 20:35 — malicious 1.26.1 published (wheel-only, no sdist, no matching git tag; `agent_framework_meta.pth` + `_telemetry.py`) | Reconstruction `package/v1.26.1/` (M1); gated by the supply-chain lane (M2, issue #3) |
| ~21:08 — malicious 1.26.2 published (repacked; `__init__.py` byte-restored to clean, stealer moved to `af_runtime_diag.pth`/`af_runtime_diag.py`) | Reconstruction `package/v1.26.2/` (M1); same gates |
| ~21:30 — both versions removed/quarantined on PyPI (~55 minutes of exposure) | The demo's "what would have happened when" window below |
| Stealer ran on every Python start via `.pth`, harvested env + `/proc/*/environ` (up to 300) + up to 60-80 credential files + cloud metadata, exfiltrated in a single zlib+base64 HTTPS POST to `webhook[.]site`, silent failure, no retry | Loopback-only sink stands in for the exfil endpoint (TDS §4 hard rules); pytest corpus asserts the shape and zero non-loopback sockets (M1 lane `scenario-a-tests.yml`) |

Demo milestones as delivered: M1 reconstruction (issue #2), M2 supply-chain
gate (issue #3), M3 runtime detection (issue #4), M4 enforcement (issue #5,
PR #18) — all merged. M5 is this report (issue #6).
Scenario B (PHP2Shell) runs on its own track: M6 detection replay merged
(issue #10), M7 enforcement in anger open (issue #11).

## 2. What each layer would have happened when

Three layers, three moments — all evidenced below.

### Layer 1 — supply-chain gate, at the dependency-update PR (before install)

The realistic catch is **refusal, not scoring**: 1.26.1/1.26.2 shipped
wheel-only with no sdist, no tag and no tests, so no comparable candidate
profile can be generated or verified — the gate fails closed and flags the
PR for human review, breaking the automated-install path (loose `>=1.26`
pins) that did the damage in the 55-minute window. A consumer pinning signed
registry profiles finds no signed entry (`sbobctl verify` →
`ERR_VERIFY_SIG_MISSING`) and refuses. The **canary** (kernel-observed,
no attacker cooperation needed) identifies the stealer pre-install: the
`.pth` hook fires on the first Python start, and the observed delta scores
ADVISORY (1.26.1: 21, 1.26.2: 23; control Δ=0) — below MANDATORY because the
ladder under-weights credential-read mass, which is itself a recorded
finding, not a hidden one.

Evidence: [supply-chain-evidence.md](supply-chain-evidence.md) (gates A/B/C,
scoring ladder, findings 1-4), lane `.github/workflows/supply-chain-gate.yml`,
run [44657815995](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44657815995).
The Gate B delta scoring clean (0) on both malicious versions is the
demonstrated corpus blind spot: the attacker authors the corpus, so only the
demo-granted watermarked extension produces a diff at all.

### Layer 2 — runtime detection (Monitor/Audit), at the first Python start after install

The consumer's committed workload profile (`sbobs/workload/python-ci-runner.yaml`)
transpiles to Wazuh drift rules. On the first `.pth`-triggered interpreter
start, open-drift rule **100221** fires on the `/proc/*/environ` sweep and
credential-file reads, and connect-drift rule **100231** fires on the single
exfil POST — minutes after install, not on the next CVE scan. Sustained
collection escalates via **100222**. Asserted honest absences: exec drift
100211 stays quiet (the stealer lives inside the declared interpreter) and
the sensitive-file overlay 100201 stays quiet (cloud credential files are
not on the watchlist).

Evidence: [agent-framework/runtime-evidence.md](agent-framework/runtime-evidence.md)
(rule map, corpora, honest absences, findings 1-4), lane
`.github/workflows/runtime-detection.yml`, runs
[44789125134](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44789125134)
and [44789707792](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44789707792).

### Layer 3 — enforcement (Enforce), at the exfil POST

With egress allowlist-enforced to the profile's declared peers (cluster-dns
UDP 53 + pypi mirror TCP 443; the loopback sink deliberately NOT
allowlisted), the hijack's damage step fails closed: on the enforced
1.26.1 / 1.26.2 legs the exfil POST is attempted and denied at the kernel
level (REJECT counter +1) and the sink receives **0 new receipts**, while
the clean 1.26.0 workload is untouched (0 receipts, REJECT delta 0 — no
false positive). The lane proves the NetworkPolicy's deny-all-undeclared
semantics live in a disposable container (uid-scoped iptables allowlist,
workload uid 1500) across 8 pinned legs; the Monitor→Audit→Enforce transition
is committed in `sbobs/enforce-state.yaml` (only egress advances to enforce,
after the M3 clean-window audit record), and the drift-gated enforce bundles
regenerate byte-identical from the pinned toolchain on every lane run.
AppArmor/seccomp variants are committed as documented-with-artifacts, with
their honest limitations recorded (complaint-mode profile, SCMP_ACT_LOG
signature surface) rather than papered over.

Evidence: [agent-framework/enforce-evidence.md](agent-framework/enforce-evidence.md)
(8-leg verdict table, state file, honest limitations 1-4), lane
`.github/workflows/enforce-block.yml`, run
[44800715326](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44800715326)
(all 8 legs PASS).

## 3. Honest limitations (unsugarcoated)

From TDS §9 and the committed layer evidence:

1. **Provenance gap.** SBoB sees behavior, not identity. The unauthorized
   publish, wheel-only upload and missing git tag are provenance signals;
   SBoB does not observe them and the demo does not claim it catches them.
   (TDS §9.1)
2. **Cold-start consumers.** No baseline profile means no drift signal;
   Monitor must come before Audit and Enforce for exactly this reason.
   (TDS §9.2)
3. **DNS-blind egress.** Resolving the exfil domain rides the declared
   resolver and alerts nothing; only the CONNECT to the resolved sink IP
   (100231) fires. A raw-IP or allowlisted-domain beacon is a weaker signal.
   (TDS §9.3; runtime-evidence.md honest absence 3)
4. **Corpus reach.** The baseline is test-derived; code outside test
   reach is invisible to it, and the malicious releases shipped no tests at
   all — Gate B's clean-0 delta is the demonstration. Corpus-derived
   profiles are author-supplied claims; the layer rests on refusal and
   kernel observation instead. (TDS §9.4; supply-chain-evidence.md)
5. **Credential-read mass is under-weighted on the ladder** (+1 per
   read-only path), so a stealer reading dozens of credential files scores
   ADVISORY, not MANDATORY (observed: 21/23). Proposed +5
   credential-path class is the scenario-A ask on the SBoB roadmap.
   (TDS §9.5; supply-chain-evidence.md finding 2)
6. **The `.pth` import itself is invisible at the path layer** — an
   interpreter start importing installed code is declared behavior; drift
   begins one syscall later at the first undeclared open. Profile tightness
   is load-bearing; no toolchain rule catches profile mistakes.
   (runtime-evidence.md findings 2-3)

## 4. Evidence index

| Layer / artifact | Evidence doc | Lane | Run |
|---|---|---|---|
| M1 reconstruction + IOC map | [agent-framework/incident-map.md](agent-framework/incident-map.md) | `scenario-a-tests.yml` | CI green on main |
| M2 supply-chain gate | [supply-chain-evidence.md](supply-chain-evidence.md) | `supply-chain-gate.yml` | [44657815995](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44657815995) |
| M3 runtime detection | [agent-framework/runtime-evidence.md](agent-framework/runtime-evidence.md) | `runtime-detection.yml` | [44789125134](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44789125134), [44789707792](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44789707792) |
| M4 enforcement | [agent-framework/enforce-evidence.md](agent-framework/enforce-evidence.md) | `enforce-block.yml` | [44800715326](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44800715326) |
| M6 PHP2Shell detection | [php2shell/detection-evidence.md](php2shell/detection-evidence.md) | `php-detection.yml` | [44591553822](https://github.com/DevelApp-ai/SBOB-Examples/actions/runs/44591553822) |
