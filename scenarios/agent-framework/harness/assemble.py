#!/usr/bin/env python3
# ============================================================================
# SBOB-EXAMPLES DEMO WATERMARK — M2 gate assembler (issue #3).
# Assembles the per-gate working trees sbobforge generates from, so the
# reconstructed artifact trees under scenarios/agent-framework/package/
# stay pristine (Gate A needs the as-shipped artifact-only shape).
#
#   assemble.py gate-a  <version> <workdir>   artifact-only copy (as shipped)
#   assemble.py gate-a3 <version> <workdir>   artifact copy + generation
#                                            manifest but NO test corpus
#   assemble.py gate-b <version> <workdir>    artifact copy + corpus (+ the
#                                            watermarked attacker-corpus
#                                            extension for 1.26.1/1.26.2)
#                                            + manifest with the candidate
#                                            packageVersion
#
# stdlib only (org lesson: no pip in CI lanes; python:3.12-slim container).
# ============================================================================
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCENARIO = REPO / "scenarios" / "agent-framework"
CORPUS = REPO / "upstream" / "corpus-1.26.0"
ATTACK_DIR = REPO / "upstream" / "tests-attack"
MALICIOUS = {"1.26.1", "1.26.2"}


def die(msg: str) -> None:
    print(f"assemble: {msg}", file=sys.stderr)
    raise SystemExit(2)


def copy_tree(src: Path, dst: Path) -> None:
    if not src.is_dir():
        die(f"missing source dir: {src}")
    shutil.copytree(src, dst)


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in {"gate-a", "gate-a3", "gate-b"}:
        die("usage: assemble.py gate-a|gate-a3|gate-b <version> <workdir>")
    gate, version, workdir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    if version not in MALICIOUS | {"1.26.0"}:
        die(f"unknown version {version}")

    if workdir.exists():
        shutil.rmtree(workdir)

    pkg = SCENARIO / "package" / f"v{version}"
    if not pkg.is_dir():
        die(f"artifact tree not found: {pkg}")

    # the artifact as shipped: wheel contents (the attacker's trees)
    copy_tree(pkg, workdir / "package")

    if gate == "gate-a":
        # as-shipped artifact-only candidate: no manifest, no corpus
        print(f"assembled gate-a workdir {workdir} (artifact-only, no manifest)")
        return

    manifest = json.loads((CORPUS / "sbobforge.json").read_text())
    manifest["packageVersion"] = version

    if gate == "gate-a3":
        # generation manifest present but NO test corpus: records what the
        # tool does with an artifact nobody granted tests for
        (workdir / "sbobforge.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"assembled gate-a3 workdir {workdir} (manifest, no corpus)")
        return

    # gate-b: publisher-tree shape — corpus sut+tests, artifact package
    # mounted under package/, plus the watermarked attacker-corpus extension
    # for the malicious versions (docs/TDS.md §M2)
    copy_tree(CORPUS / "sut", workdir / "sut")
    copy_tree(CORPUS / "tests", workdir / "tests")
    if version in MALICIOUS:
        ext = ATTACK_DIR / f"v{version}"
        if not ext.is_dir():
            die(f"attacker-corpus extension missing: {ext}")
        copy_tree(ext, workdir / "tests" / "attack")
        manifest["testGlobs"] = ["tests/**/*.py"]
    manifest["sutGlobs"] = ["sut/**/*.py", "package/**/*.py"]
    (workdir / "sbobforge.json").write_text(json.dumps(manifest, indent=2) + "\n")
    extra = " + attacker-corpus extension" if version in MALICIOUS else ""
    print(f"assembled gate-b workdir {workdir} (corpus{extra}, version {version})")


if __name__ == "__main__":
    main()
