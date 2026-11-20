#!/usr/bin/env python3
# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# M4 enforcement workload runner (issue #5, layer-3 enforcement).
#
# Runs INSIDE A CONTAINER, always as the dedicated workload uid (af-workload,
# uid 1500) via `setpriv --reuid=1500 ...` — never as root, never with other
# privileges. The root orchestrator (enforce_orchestrator.py) never runs
# scenario code itself: every exercise and every network probe runs with the
# workload identity so the uid-scoped egress policy (the podSelector ->
# uid translation of the NetworkPolicy artifact) applies to it and to
# nothing else. Stdlib only.
# ============================================================================
"""Workload-side legs for the M4 enforcement lane.

Modes (selected by --mode):
  exercise  build + install one version's wheel and run one ordinary
            interpreter start against it (exactly the M1 exercise flow,
            demo_support.exercise), then report the result as one JSON line
  probe     one raw socket probe (udp or tcp connect) to a given host:port

The script ALWAYS exits 0 when its own machinery works and relies on the
root orchestrator to rule on the JSON; a nonzero exit means the harness
itself broke, never a verdict.
"""

import argparse
import json
import os
import socket
import sys

REPO = os.environ.get("AF_REPO", "/src")
SCENARIO = os.path.join(REPO, "scenarios", "agent-framework")
sys.path.insert(0, os.path.join(SCENARIO, "support"))


def mode_exercise(args):
    import demo_support as ds  # noqa: E402  (sys.path set above)

    result = ds.exercise(
        version_dir=os.path.join(SCENARIO, "package", args.version),
        work_dir=args.work_dir,
        home=args.home,
        proc_root=args.proc_root,
        receipts_path=args.receipts,
        env_extra={"AF_TEST_NO_FORK": "1"},  # deterministic: exfil inline
        timeout=args.timeout,
        sink_url=args.sink_url,
    )
    return {
        "leg": "exercise",
        "version": args.version,
        "rc": result["proc"].returncode,
        "receipts_new": len(result["receipts"]),
        "guard_violations": result["guard_violations"],
    }


def mode_probe(args):
    out = {"leg": "probe", "probe_type": args.probe_type,
           "host": args.host, "port": args.port}
    try:
        if args.probe_type == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(args.timeout)
                s.sendto(b"sbob-m4-probe", (args.host, args.port))
                out["sent"] = True
            finally:
                s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(args.timeout)
                s.connect((args.host, args.port))
                out["connected"] = True
            finally:
                s.close()
        out["error"] = None
    except Exception as exc:  # expected for unreachable/rejected peers
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["exercise", "probe"])
    ap.add_argument("--probe-type", choices=["udp", "tcp"])
    ap.add_argument("--version", help="scenario package version dir name")
    ap.add_argument("--work-dir", help="writable per-leg work dir")
    ap.add_argument("--home", help="synthetic fixture home tree (AF_HOME)")
    ap.add_argument("--proc-root", help="synthetic fixture /proc tree")
    ap.add_argument("--receipts", help="shared sink receipts jsonl")
    ap.add_argument("--sink-url", help="AF_SINK_URL for this leg")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--host", help="probe target host")
    ap.add_argument("--port", type=int, help="probe target port")
    args = ap.parse_args()
    if args.mode == "exercise":
        os.makedirs(args.work_dir, exist_ok=True)
        os.environ.setdefault("HOME", args.work_dir)
        out = mode_exercise(args)
    else:
        out = mode_probe(args)
    out["uid"] = os.getuid()
    print(json.dumps(out))


if __name__ == "__main__":
    main()
