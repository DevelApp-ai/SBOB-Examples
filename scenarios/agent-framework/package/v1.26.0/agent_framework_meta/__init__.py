# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# Clean agent_framework_meta package initializer, 1.26.0 bytes. This is the
# "legitimate package initializer" that the malicious 1.26.1 replaced with
# the runtime-diagnostics hook and that 1.26.2 restored byte-for-byte
# (Aikido/Wiz advisories) — which is why the 1.26.2 test asserts byte
# identity against THIS file.
# ============================================================================
"""agent_framework_meta: package metadata for agent-framework."""

__all__ = ["META"]

META = {
    "distribution": "agent-framework",
    "version": "1.26.0",
    "maintainer": "Microsoft",
}
