# ============================================================================
# SBOB-EXAMPLES DEMO WATERMARK — reconstructed corpus tests (issue #3, M2).
# Demo-authored reconstruction (upstream/ATTRIBUTION.md): pytest-shaped
# corpus entries for the corpus SUT, matching the layout the sbobforge
# python-pytest fixture grammar parses.
#
# Two honest entry families live side by side:
#   1. parametrized entries over the SUT's DECLARED locations (literal paths,
#      literal open modes) — the shape the fixture grammar lifts into the
#      profile, mirroring forge's own python-pytest fixture examples;
#   2. one-hop entries that call the SUT's identifier-parameterized shapes —
#      the corpus exercises the SUT surface honestly; those open sites
#      quarantine into the coverage report (dynamic path, no declared
#      lift), which is the reconstruction finding recorded in
#      docs/supply-chain-evidence.md, not a lane failure.
# ============================================================================
"""Corpus tests for the reconstructed clean-1.26.0 SUT."""

import json

import pytest

from agent_framework import cache_session, get_version, load_config, notify_memcache


def test_get_version_reports_series():
    assert get_version() == "1.26.0"


@pytest.mark.parametrize("config", ["/var/lib/agent-framework/config.json"])
def test_reads_the_declared_config(config):
    # corpus entry: the SUT's declared configuration path, read-only
    with open(config, "r", encoding="utf-8") as fh:
        json.loads(fh.read())


@pytest.mark.parametrize("last", ["/var/lib/agent-framework/sessions/last.json"])
def test_writes_the_declared_session_state(last):
    # corpus entry: the SUT's declared session-state write target
    with open(last, "w") as fh:
        fh.write("text")


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
