# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# Integrity tests:
#   - 1.26.2 restored agent_framework_meta/__init__.py byte-for-byte to the
#     clean 1.26.0 file (the attacker's camouflage; Wiz advisory)
#   - 1.26.1 replaced it (the hook)
#   - every reconstructed Python file carries the demo watermark header
# ============================================================================
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "support"))
import demo_support as ds  # noqa: E402

SCENARIO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(SCENARIO_DIR, "package")

META_INIT = os.path.join("agent_framework_meta", "__init__.py")


def _read(version, rel):
    with open(os.path.join(PKG, version, rel), "rb") as fh:
        return fh.read()


def test_1262_restored_meta_byte_identical_to_1260():
    """The camouflage claim from the advisory, as a hard byte assertion."""
    assert _read("v1.26.0", META_INIT) == _read("v1.26.2", META_INIT)


def test_1261_replaced_meta_differs_from_clean():
    """1.26.1 shipped the hook, so its meta initializer is not the clean one."""
    assert _read("v1.26.0", META_INIT) != _read("v1.26.1", META_INIT)


def test_1261_hook_calls_telemetry_start():
    body = _read("v1.26.1", META_INIT).decode("utf-8")
    assert "_telemetry._start()" in body


def test_1262_standalone_hook_fires_at_import():
    body = _read("v1.26.2", "af_runtime_diag.py").decode("utf-8")
    assert body.rstrip().endswith("_start()"), \
        "top-level module must run on import (fires via .pth on every start)"


def test_all_reconstructed_python_files_watermarked():
    checked = 0
    for version in sorted(os.listdir(PKG)):
        vdir = os.path.join(PKG, version)
        for root, dirs, files in os.walk(vdir):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                assert ds.check_watermark(path), \
                    "missing watermark header: %s" % os.path.relpath(path, PKG)
                checked += 1
    assert checked >= 8, "expected the full reconstruction to be checked"


def test_pth_files_are_single_import_lines():
    """Faithful to the incident: the .pth hooks are bare import lines."""
    for version, name in (("v1.26.1", "agent_framework_meta.pth"),
                          ("v1.26.2", "af_runtime_diag.pth")):
        with open(os.path.join(PKG, version, name), "r", encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        assert len(lines) == 1
        assert lines[0].startswith("import ")
