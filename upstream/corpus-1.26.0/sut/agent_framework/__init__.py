# ============================================================================
# SBOB-EXAMPLES DEMO WATERMARK — reconstructed corpus SUT (issue #3, M2).
# A demo-authored reconstruction, NOT a vendored upstream corpus: the real
# upstream repo was taken down post-hijack (upstream/ATTRIBUTION.md records
# the 404 and the decision). Representative clean-1.26.0 subset exercising
# the SBoB section surface the M2 gates score.
# ============================================================================
"""agent-framework corpus SUT (representative clean reconstruction subset)."""

import json
import socket

CONFIG_PATH = "/var/lib/agent-framework/config.json"
SESSIONS_DIR = "/var/lib/agent-framework/sessions"
MEMCACHE = ("127.0.0.1", 11211)


def get_version():
    """Report the distribution version."""
    return "1.26.0"


def load_config(path=CONFIG_PATH):
    """Load the agent's on-disk configuration."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def cache_session(session_id, state, path=None):
    """Persist the last session state for resume-after-restart."""
    target = path or (SESSIONS_DIR + "/last.json")
    with open(target, "w", encoding="utf-8") as fh:
        json.dump({"session": session_id, "state": state}, fh)


def notify_memcache(key):
    """Notify the declared local memcache that a session changed."""
    conn = socket.create_connection(MEMCACHE, timeout=1)
    try:
        conn.sendall(("set " + key + " 0 0 2\r\n").encode())
    finally:
        conn.close()
