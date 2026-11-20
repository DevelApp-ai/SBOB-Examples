# ============================================================================
# SBOB-EXAMPLES DEMO WATERMARK — attacker-corpus extension, v1.26.2 (issue #3).
# EXPLICITLY LABELED DEMO SCAFFOLDING (docs/TDS.md §M2 Gate B): a real
# attacker never grants the corpus extension. This test exists only to
# make the scored delta visible on the reconstruction; 1.26.2 restored the
# clean meta initializer byte-for-byte but shipped the diagnostic as the
# top-level af_runtime_diag module + .pth hook instead.
# ============================================================================
"""Attacker-corpus extension: the 1.26.2 runtime-diagnostic module starts."""


def test_hook_module_starts():
    import af_runtime_diag

    af_runtime_diag._start()
