# ============================================================================
# SBOB-EXAMPLES DEMO WATERMARK — reconstructed corpus tests (issue #3, M2).
# Demo-authored reconstruction (upstream/ATTRIBUTION.md): pytest-shaped
# corpus entries for the corpus SUT, matching the layout the sbobforge
# python-pytest fixture grammar parses.
# ============================================================================
"""Corpus tests for the reconstructed clean-1.26.0 SUT."""

import json

from agent_framework import cache_session, get_version, load_config, notify_memcache


def test_get_version_reports_series():
    assert get_version() == "1.26.0"


def test_load_config_reads_declared_path(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"flags": []}))
    assert load_config(str(path)) == {"flags": []}


def test_cache_session_writes_last(tmp_path):
    target = tmp_path / "last.json"
    cache_session("s-1", {"stage": 1}, path=str(target))
    assert json.loads(target.read_text())["session"] == "s-1"


def test_notify_memcache_connects_declared_peer():
    # corpus entry: the declared local memcache notify reaches the SUT's
    # socket.create_connection site through one-hop test resolution
    notify_memcache("session:s-1")
