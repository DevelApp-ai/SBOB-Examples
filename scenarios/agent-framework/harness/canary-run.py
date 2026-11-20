#!/usr/bin/env python3
"""SBOB-EXAMPLES DEMO WATERMARK — scenario A harness: the M2 canary driver.

Issue #3 (M2 Gate C). Runs on the CI RUNNER NODE (not in a container; the
deviation is recorded in docs/supply-chain-evidence.md) as a DEDICATED
disposable uid (af-canary) whose uid scopes the auditd observer window
(canary-observer.sh). What it does per version:

  1. stage the synthetic credential fixture tree (demo_support.make_fixtures)
  2. start the loopback sink (demo_support.start_sink, port 8099)
  3. N ordinary guarded Python interpreter starts against an installed copy
     of the version's wheel (demo_support.build_wheel + install_wheel +
     run_python_start — the exact M1 exercise path), asserting each start:
       - exit 0
       - zero guard violations (no non-loopback socket, TDS §4 hard rule)
       - one new sink receipt per start (1.26.1/1.26.2) or none (1.26.0)

WHY N STARTS (N=3 default): sbobctl profile's fidelity ladder classifies a
behavior seen exactly once in the window as a one-off → investigate → NOT
declared in the candidate. A canary with a single start therefore derives
an empty candidate (verified against sbobctl pin 4bf2eb1d in
docs/supply-chain-evidence.md). Repeating the start within the observation
window makes every behavior steady (count ≥ 2, dayRatio 1.0 on a 1-day
window) so the candidate is a complete derived contract. The repetition is
stated in the evidence doc; it is observation cadence, not verdict
massaging: baseline and candidate canaries use the same cadence.

The .pth hook fires on the FIRST interpreter start against the installed
site dir, with no test and no import: no attacker cooperation required,
which is Gate C's whole point.

Usage:
  canary-run.py --version-dir package/v1.26.0 --out-dir work/canary-1.26.0 \
                --starts 3 [--expect-receipts-per-start 0|1] [--sink-port 8099]

stdlib only; reuses scenarios/agent-framework/support/demo_support.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scenarios" / "agent-framework" / "support"))

import demo_support  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--starts", type=int, default=3)
    ap.add_argument("--expect-receipts-per-start", type=int, default=0,
                    help="0: clean version (no exfil); 1: malicious versions")
    ap.add_argument("--sink-port", type=int, default=8099)
    ns = ap.parse_args()

    version_dir = Path(ns.version_dir).resolve()
    out_dir = Path(ns.out_dir).resolve()
    if not version_dir.is_dir():
        print(f"canary: missing version dir {version_dir}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. fixtures BEFORE any start (the staging writes are inside every canary
    #    window equally and self-cancel in the baseline→candidate delta; the
    #    normalizer documents the scope rule)
    fixtures = demo_support.make_fixtures(out_dir / "fixtures")
    home, proc_root = fixtures["home"], fixtures["proc"]
    receipts = out_dir / "sink-receipts.jsonl"
    receipts.touch()

    # 2. loopback sink
    sink = demo_support.start_sink(str(receipts), port=ns.sink_port)
    try:
        # 3. N guarded interpreter starts. The steps are driven directly
        #    (demo_support.exercise() unconditionally waits for a NEW sink
        #    receipt, which the clean version never produces — the canary
        #    must not stall per start on a receipt that legally never comes).
        for i in range(ns.starts):
            work = out_dir / f"start-{i}"
            dist_dir = work / "dist"
            site_dir = work / "site"
            wheel_path = demo_support.build_wheel(str(version_dir), str(dist_dir))
            demo_support.install_wheel(str(wheel_path), str(site_dir))
            guard_log = work / "guard.log"
            before = len(demo_support.read_receipts(str(receipts)))
            env = {
                "AF_HOME": home,
                "AF_PROC_ROOT": proc_root,
                "AF_TEST_NO_FORK": "1",  # deterministic: exfil completes inline
                "AF_SINK_URL": "http://127.0.0.1:%d" % ns.sink_port,
            }
            proc = demo_support.run_python_start(
                str(site_dir), str(receipts), str(guard_log),
                env_extra=env, timeout=60)
            if proc.returncode != 0:
                print(f"canary: start {i} exited {proc.returncode}\n"
                      f"stdout: {proc.stdout[-2000:]}\nstderr: {proc.stderr[-2000:]}",
                      file=sys.stderr)
                return 1
            violations = demo_support.guard_violations(str(guard_log))
            if violations:
                print(f"canary: start {i} guard violations {violations}", file=sys.stderr)
                return 1
            if ns.expect_receipts_per_start > 0:
                got = demo_support.wait_for_receipts(
                    str(receipts), before + ns.expect_receipts_per_start, timeout=20)
                n_new = len(got) - before
            else:
                # clean version: give any (illegitimate) exfil time to appear,
                # then assert the receipts file did NOT grow
                time.sleep(2)
                n_new = len(demo_support.read_receipts(str(receipts))) - before
            if n_new != ns.expect_receipts_per_start:
                print(f"canary: start {i} produced {n_new} receipts, expected "
                      f"{ns.expect_receipts_per_start} (TDS §4: loopback-only "
                      "exfil shape broken)", file=sys.stderr)
                return 1
            print(f"[canary] start {i}: exit 0, receipts {n_new}, "
                  f"guard clean, site {site_dir}")
    finally:
        sink.terminate()
        try:
            sink.wait(timeout=10)
        except Exception:
            sink.kill()

    print(f"[canary] {ns.starts} starts complete for {version_dir.name}; "
          f"fixtures {home} {proc_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
