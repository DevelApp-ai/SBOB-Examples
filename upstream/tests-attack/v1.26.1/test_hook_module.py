# ============================================================================
# SBOB-EXAMPLES DEMO WATERMARK — attacker-corpus extension, v1.26.1 (issue #3).
# EXPLICITLY LABELED DEMO SCAFFOLDING (docs/TDS.md §M2 Gate B): a real
# attacker never grants the corpus extension. This test exists only to
# make the scored delta visible on the reconstruction; the test imports the
# shipped 1.26.1 hook module and starts it, mirroring the sbobforge fixture
# style so one-hop test->SUT resolution reaches the _telemetry bodies.
# ============================================================================
"""Attacker-corpus extension: the 1.26.1 hook module starts."""

import agent_framework_meta  # noqa: F401  (import fires the hook in 1.26.1)


def test_hook_module_starts():
    from agent_framework_meta import _telemetry

    _telemetry._start()
