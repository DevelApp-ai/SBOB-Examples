# M2 supply-chain-gate evidence (scenario A, issue #3)

SBOB-EXAMPLES DEMO WATERMARK — evidence document for the layer-1
supply-chain lane (`.github/workflows/supply-chain-gate.yml`). Committed
verdict stamps and reports live under `docs/agent-framework/m2/` once the
lane's first green run is reviewed; this file states the facts the lane
asserts, honestly, including what the SBoB ladder does NOT catch.

## The layer's premise (and why it is two refusals + one identification)

Lars's challenge stands at the center: the attacker authors the candidate
release AND its corpus. A pure corpus diff would not have flagged 1.26.1 /
1.26.2 — they shipped no tests at all. So the layer rests on:

- **Gate A — fail-closed refusals.** The artifact as shipped contains no
  generation manifest and no corpus: profile generation fails closed
  (asserted, job `gate-a` step A1). A consumer pinning signed registry
  profiles finds no signed entry for 1.26.1 (`sbobctl verify` exits 1 with
  `ERR_VERIFY_SIG_MISSING`; asserted, step A2, committed fabricated entry
  `scenarios/agent-framework/mock-registry/agent-framework-1.26.1.entry.yaml`
  kept schema-valid so the refusal is provenance-based, not parse-based).
  A3 (manifest granted, corpus withheld) pins the honest complement,
  observed on the first run: sbobforge does NOT refuse — it emits a
  section-less EMPTY profile and exits 0. An empty profile is itself an
  author-supplied claim of "no behavior"; the corpus blind spot (Findings)
  starts exactly here.
- **Gate B — the scored delta, on demo scaffolding only.** To show WHAT a
  diff would score, the lane extends the (reconstructed) 1.26.0 corpus with
  watermarked tests starting the attacker's hook modules and generates
  candidate profiles for 1.26.1/1.26.2. A real attacker never grants this.
- **Gate C — identification without attacker cooperation.** Each version
  runs as a disposable canary under a dedicated uid with a kernel-level
  auditd observer and seeded synthetic credentials; `sbobctl profile`
  derives the candidate SBoB from what actually happened, and `sbobctl
  diff` scores it against the clean canary's own derived contract. The
  attacker can game a corpus; they cannot game the kernel.

## What the upstream-404 finding means (recorded, not hidden)

microsoft/agent-framework no longer resolves (checked every lane run; the
re-check step records the HTTP status). The planned vendored corpus does
not exist; `upstream/corpus-1.26.0/` is a demo-authored watermarked
RECONSTRUCTION (decision + re-check promise in `upstream/ATTRIBUTION.md`).
This is itself the layer's honest point: **publisher-side corpus
availability cannot be assumed** — a taken-down upstream or an
artifact-only release leaves the profiler nothing to lift, which is
exactly the Gate A failure mode.

## The corpus blind spot, in plain words

The baseline is derived from tests. Tests only prove what their author
wanted proven: code placed outside corpus reach is invisible to
test-derived profiling, and the malicious releases shipped no tests at
all. Gate B's delta therefore exists ONLY because the demo grants the
attacker-corpus extension (watermarked, committed for review under
`upstream/tests-attack/`). The lane labels this scaffolding everywhere it
appears; Gate C exists precisely because Gate B cannot be granted by an
attacker.

## The scoring ladder (what each delta row costs)

| class | weight |
|---|---|
| new Linux capability | +5 (immediate mandatory) |
| new exec path outside the package namespace | +4 |
| new external-DNS egress peer | +3 |
| new egress ip/port · write-flag open · widened wildcard · new ingress | +2 each |
| new read-only open path · removed entry | +1 each |

Verdict: ADVISORY at Δ ≥ 10, MANDATORY at Δ ≥ 25 or on any +5 row
(`sbobctl diff --report` JSON carries `score` + `verdict`; the lane pins
the ACTUAL first-run verdicts per the expected-verdict discipline).

## Gate B — recorded shape (verdicts stamped from the lane's actual runs)

- Baseline: sbobforge profile of the reconstructed clean corpus
  (`upstream/corpus-1.26.0/`), converted to the sbob registry dialect.
  The reconstruction manifest declares the SUT's own memcache notify peer
  (`netPolicies`); the corpus tests carry parametrized entries over the
  SUT's declared config/session locations (the shape the forge fixture
  grammar lifts), while the SUT's identifier-parameterized open shapes
  stay quarantined coverage rows. The attacker extension's dynamic sites
  get no such courtesy, which is the point.
- Candidates: corpus + watermarked attacker-corpus extension
  (`upstream/tests-attack/v1.26.1/`, `v1.26.2/`) per version.
- Delta reports are uploaded per run as lane artifacts and the observed
  verdicts pinned in the lane (env `EXPECT_B1_VERDICT`/`EXPECT_B2_VERDICT`)
  from the first honest run. Known limitation shadowing this gate, stated
  up front: sbobforge's static lift UNDER-scores dynamic destinations —
  `open(os.path.join(home, rel))` and `urlopen(request_obj)` sites quarantine
  unless `pathPolicies`/`netPolicies` declare them; the corpus extension
  alone may keep the delta below advisory. Whatever the actual verdict, the
  finding is recorded here rather than papered over.

<!-- STAMP: first green Gate B verdicts recorded here after review:
| version | verdict | score | run |
|---------|---------|-------|-----|
| 1.26.1  | (record on first green run) | | |
| 1.26.2  | (record on first green run) | | |
-->

## Gate C — canary design and honest scope rules

- **Node-side canary, dedicated uid (deviation from the TDS draft).** The
  TDS draft said "disposable canary container with auditd"; the M6 lane
  proved live that GitHub-hosted runner containers cannot hold the audit
  netlink (in-container auditctl EPERMs on the shared kernel). The canary
  therefore runs on the node under a dedicated disposable uid
  (`af-canary`) and the observer loads uid-scoped keyed rules
  (`canary-observer.sh`). The canary stays disposable: fresh work trees,
  synthetic fixture credentials, loopback-only sink (TDS §4 hard rules).
- **Three starts per canary (cadence, not massage).** `sbobctl profile`
  classifies a behavior seen exactly once in the window as a one-off →
  investigate → NOT declared; a single-start canary derives an empty
  candidate (verified locally against the pinned sbobctl: the review queue
  lists every behavior, the candidate is nothing-declarable). Three starts
  make every observed behavior steady in the 1-day window. Baseline and
  candidates use the same cadence.
- **Observer scope rules (stated, not hidden filtering):**
  opens count only under the canary fixture roots (the demo's declared
  blast radius); connects count only to loopback (the hard rule says no
  socket ever leaves); execs count every canary-uid execve (identical shape
  in every window, so exec rows self-cancel in the delta); the open-flag
  vocabulary is {O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL} — volatile
  bits (O_TRUNC etc.) are dropped on BOTH sides of every diff.
- **Control:** a second independent clean canary must diff Δ0 / exit 0
  against the first clean canary's derived candidate (run-to-run
  determinism of the observer pipeline).
- **Honesty floor:** whatever the ladder class of the malicious deltas,
  the canary diffs MUST score at least ADVISORY; a kernel-observed
  credential-harvesting stealer diffing at zero would mean the pipeline is
  broken, not that the stealer is benign.

<!-- STAMP: first green Gate C verdicts recorded here after review:
| version | verdict | score | run |
|---------|---------|-------|-----|
| 1.26.1 canary | (record on first green run) | | |
| 1.26.2 canary | (record on first green run) | | |
| control      | clean, Δ=0 (asserted)      | | |
-->

## Findings — what scenario A exposes about SBoB (the gap map)

1. **The corpus blind spot is real and structural** (§ above): Gate B's
   scores exist only because the DEMO granted the corpus; consumers must
   treat corpus-derived profiles as author-supplied claims.
2. **The ladder under-weights credential-read mass.** A new read-only
   open costs +1; a stealer that reads dozens of credential paths but
   only opens ONE new network peer scores Δ ≈ (n_paths + 4 + 1), which
   crosses ADVISORY long before MANDATORY. Observed Gate C verdicts
   (stamped above) quantify exactly this. Candidate missing ladder
   class: credential-path reads (proposed +5, like capabilities), keyed
   on destination-path shape (`/proc/*/environ`, dotfile credential
   names) — recorded here as the scenario-A ask on the SBoB
   roadmap.
3. **Static lift quarantines dynamic destinations** (Gate B recorded
   verdicts): `os.path.join`-built opens and `urlopen` sites quarantine
   without declared placeholder policies; publisher-side generated
   profiles therefore UNDER-report exactly the harvesting surface the
   canary observes.
3a. **Cross-tool defect (observed, recorded for the forge/SBoB roadmaps):
   the tier-P identifier lift emits opens with empty flags.** Lifting a
   quarantined open through a `pathPolicies` identifier match produces
   `flags: []` (the quarantine loses the literal mode argument), which the
   sbobctl schema rejects at the first diff (`ERR_SCHEMA_INVALID:
   spec.opens[0].flags: must not be empty (flags is required per spec
   4.6)`). The two honest options at the source are forge-side (carry the
   resolved literal mode's flags into the quarantined candidate) or
   dialect-side (spec stance on empty flags); the M2 corpus avoids the
   shape by lifting declared locations through parametrized literal-mode
   corpus entries, and the defect is recorded here instead of hidden.
4. **Single-window canaries derive NOTHING unless repeated**: a
   minute-scale canary with one start yields one-offs; the observation
   cadence is part of the canary design, not an optional detail.

## Lane

workflow: `.github/workflows/supply-chain-gate.yml` — jobs `gate-a`
(fail-closed + verify-refusal + upstream re-check), `gate-b` (baseline,
candidates, delta reports pinned after first run), `gate-c` (baseline
canary, control, 1.26.1 + 1.26.2 canaries, honesty floor, evidence
upload).

<!-- STAMP: first fully green run: (record on merge, with run URL) -->
