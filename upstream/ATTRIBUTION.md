# SBOB-EXAMPLES DEMO WATERMARK — upstream corpus attribution (issue #3, M2)

## What the M2 lane needed and what exists

The TDS M2 draft planned the Gate B baseline as a profile generated from
`microsoft/agent-framework`'s own committed pytest corpus, vendored under
`upstream/corpus-1.26.0/` from tag `python-1.26.0` with attribution and
license preserved, byte-verified against a pinned upstream SHA.

**That upstream does not exist.** `microsoft/agent-framework` returns 404
from both codeload and the anonymous GitHub API (checked 2026-11-19, and
re-checked by every M2 lane run): the post-hijack takedowns removed it,
and the 2026-11-17 compromise was committed directly to the real
`agent-framework` PyPI distribution by a hijacked maintainer token
(advisories: Aikido, Wiz, Socket). No upstream repository corpus for the
1.26.x series is retrievable at all — sdist, wheel or git tag.

## What this repo ships instead (honest reconstruction)

`upstream/corpus-1.26.0/` is therefore a **demo-authored, watermarked
RECONSTRUCTION**, not a vendored upstream corpus:

- every file carries the `SBOB-EXAMPLES DEMO WATERMARK` banner;
- the corpus SUT (`sut/agent_framework/__init__.py`) is a representative
  clean-version subset (four functions: version report, config load,
  session cache write, declared memcache notify) chosen to exercise the
  SBoB section surface the M2 gates score (execs / opens / egress);
- the corpus tests (`tests/test_agent_framework.py`) are pytest-shaped
  corpus entries for those functions, matching the repo layout the
  sbobforge python-pytest fixture grammar parses;
- licenses: nothing is vendored from the removed upstream; no upstream
  copyright is claimed. The reconstruction draws only on public advisory
  descriptions of behavior.

Recorded as a finding, not hidden: **the layer-1 supply-chain gate cannot
rely on publisher-side corpus availability at all.** A take-down or an
artifact-only release (the actual 1.26.1/1.26.2 shape: wheel-only, no
sdist, no tests) leaves the profiler nothing to lift. That is exactly what
Gate A asserts: profile generation over the artifact-only candidate fails
closed (docs/TDS.md §M2; lane `supply-chain-gate.yml`).

## Re-check promise

The lane re-checks the upstream on every run and records the result in the
Gate A job summary: `microsoft/agent-framework` resolving again would
re-open the vendoring decision (the honest corpus blind spot statement in
docs/supply-chain-evidence.md would then be re-derived, not edited away).
