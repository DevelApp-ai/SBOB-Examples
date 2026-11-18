# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# agent_framework initializer as shipped by 1.26.1: version bump only.
# In the real incident the attacker did not modify agent_framework itself
# (the malicious work lived in agent_framework_meta + the .pth hook).
# ============================================================================
"""agent-framework (demo reconstruction of 1.26.1)."""

__version__ = "1.26.1"


def get_version():
    return __version__
