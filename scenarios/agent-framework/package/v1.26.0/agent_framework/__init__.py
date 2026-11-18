# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# Representative subset of the clean agent-framework 1.26.0 meta distribution
# (real wheel published 2026-11-12 18:25 UTC, wheel + sdist, alongside
# agent-framework-core 1.26.0). The full upstream package and its tests are
# vendored separately under upstream/corpus-1.26.0/ (M2); this file carries
# only the version surface the reconstruction needs.
# ============================================================================
"""agent-framework meta distribution (representative reconstruction subset)."""

__version__ = "1.26.0"


def get_version():
    """Return the distribution version."""
    return __version__
