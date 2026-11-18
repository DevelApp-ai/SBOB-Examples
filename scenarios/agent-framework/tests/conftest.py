# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# pytest wiring: loopback sink + synthetic fixture tree for the whole session.
# ============================================================================
import os
import sys

import pytest

SCENARIO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUPPORT_DIR = os.path.join(SCENARIO_DIR, "support")
if SUPPORT_DIR not in sys.path:
    sys.path.insert(0, SUPPORT_DIR)

import demo_support as ds  # noqa: E402

PACKAGE_DIR = os.path.join(SCENARIO_DIR, "package")


@pytest.fixture(scope="session")
def sink(tmp_path_factory):
    """Loopback-only sink server (fresh free port) for the whole session."""
    receipts = str(tmp_path_factory.mktemp("sink") / "receipts.jsonl")
    port = ds.free_loopback_port()
    server = ds.start_sink(receipts, port=port)
    try:
        yield {
            "receipts": receipts,
            "server": server,
            "url": "http://127.0.0.1:%d/?t=telemetry" % port,
        }
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except Exception:
            server.kill()


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    """Synthetic credential tree; fake tokens only (TDS §4)."""
    root = str(tmp_path_factory.mktemp("fixtures"))
    return ds.make_fixtures(root)


@pytest.fixture
def baseline(sink):
    """Receipt count before the test, so each test counts only its own POSTs."""
    return len(ds.read_receipts(sink["receipts"]))


@pytest.fixture
def run_version(tmp_path, sink, fixtures, baseline):
    """Exercise one reconstructed version and return receipts/guard info."""
    def _run(version, env_extra=None):
        version_dir = os.path.join(PACKAGE_DIR, version)
        work_dir = str(tmp_path / version.replace(".", "-"))
        out = ds.exercise(
            version_dir, work_dir,
            home=fixtures["home"], proc_root=fixtures["proc"],
            receipts_path=sink["receipts"],
            env_extra=env_extra,
            sink_url=sink["url"],
        )
        out["baseline"] = baseline
        return out

    return _run
