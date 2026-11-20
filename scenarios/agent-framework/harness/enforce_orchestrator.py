#!/usr/bin/env python3
# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# M4 enforcement orchestrator (issue #5, layer-3 enforcement).
#
# Proves, inside one disposable container (TDS §7), what layer 3 would have
# changed during the 2026-11-17 hijack for the consumer workload profile
# (sbobs/workload/python-ci-runner.yaml) at rollout state
# sbobs/enforce-state.yaml (Monitor -> Audit -> Enforce; ONLY egress has
# advanced to enforce, after the M3 clean-window attestation):
#
#   egress deny-all-undeclared semantics, via the NetworkPolicy shape's
#   iptables translation (the live lane; k8s NetworkPolicies cannot run in
#   GitHub CI):
#
#     OUTPUT -m owner --uid-owner 1500 -j SBOB-EGRESS-ENFORCE
#     SBOB-EGRESS-ENFORCE: -d 10.96.0.10/32 udp dport 53 ACCEPT
#                          -d 10.96.100.20/32 tcp dport 443 ACCEPT
#                          REJECT --reject-with icmp-port-unreachable
#
#   podSelector -> uid translation: the scenario workload (wheel build,
#   install, interpreter start, exfil POST, probes) ALWAYS runs as the
#   dedicated uid 1500 via setpriv; the sink and this orchestrator run as
#   root and are NOT subject to the policy — exactly like a k8s
#   podSelector scoping a NetworkPolicy to the workload's pods only.
#
# Legs (expected values pinned via env, TDS §7 expected-verdict style:
# first run records actuals, then the pins are committed):
#   contrast-1.26.1 / contrast-1.26.2   rules ABSENT: the malicious releases
#                       exfiltrate to the loopback sink (M1 parity: exactly
#                       one receipt each, inline POST, guard quiet)
#   declared-udp       rules PRESENT, uid 1500: datagram to the declared
#                      DNS peer 10.96.0.10:53 is ACCEPTED (no REJECT hit)
#   declared-tcp       rules PRESENT, uid 1500: connect to the declared
#                      pypi-mirror peer 10.96.100.20:443 is ACCEPTED by the
#                      rules (no REJECT hit; delivery untestable from CI —
#                      the peer does not exist outside the lab cluster)
#   undeclared-udp    rules PRESENT, uid 1500: datagram to undeclared
#                      9.9.9.9:53 hits the REJECT counter (fail closed)
#   enforced-1.26.1 / enforced-1.26.2   rules PRESENT: the SAME malicious
#                      releases build and install, the ordinary interpreter
#                      start succeeds, the exfil POST fails closed — ZERO
#                      new receipts, REJECT counter increments
#   clean-1.26.0      rules PRESENT: the legitimate release runs unchanged
#                      (exit 0, zero receipts, zero REJECT hits — no false
#                      positive under enforcement)
#
# The AppArmor and seccomp artifacts for the same profile/state are committed
# under sbobs/enforce/ (linux bundle) and documented-with-artifacts in
# docs/agent-framework/enforce-evidence.md; the NetworkPolicy semantics is
# the proven/live lane (the artifacts carry honest mode annotations — see
# the generator finding recorded in sbobs/enforce-state.yaml).
#
# Stdlib only. Exit: 0 all legs match the pinned expectations, 1 any
# assertion failed, 2 harness broken.
# ============================================================================

import argparse
import json
import os
import subprocess
import sys
import time

WL_UID = 1500  # af-workload (enforce.Dockerfile)
REPO = os.environ.get("AF_REPO", "/src")
SCENARIO = os.path.join(REPO, "scenarios", "agent-framework")

# declared egress peers (must mirror sbobs/workload/python-ci-runner.yaml
# egress[] exactly: cluster-dns + internal pypi mirror)
DNS_PEER = ("10.96.0.10", 53)
PYPI_PEER = ("10.96.100.20", 443)
UNDECLARED_UDP_PEER = ("9.9.9.9", 53)

ENV_DEFAULTS = {
    "AF_EXPECT_CONTRAST_RECEIPTS": "1",
    "AF_EXPECT_ENFORCED_RECEIPTS": "0",
    "AF_EXPECT_CLEAN_RECEIPTS": "0",
    "AF_EXPECT_ENFORCED_REJECT_GTE": "1",
    "AF_EXPECT_UNDECLARED_REJECT_GTE": "1",
    "AF_EXPECT_DECLARED_REJECT_DELTA": "0",
    "AF_EXPECT_CLEAN_REJECT_DELTA": "0",
    "AF_EXPECT_EXITS_ZERO": "1",
}
for _k, _v in ENV_DEFAULTS.items():
    os.environ.setdefault(_k, _v)


def expect(name):
    return os.environ[name]


def banner(msg):
    print("=" * 78)
    print(msg)
    print("=" * 78)


def notice(title, msg):
    print("::notice title=%s::%s" % (title, msg.replace("\n", " ")))


def fail(msg):
    print("::error title=enforce-block::%s" % msg.replace("\n", " "))
    print("M4-VERDICT overall=FAIL")
    sys.exit(1)


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def ipt(*args):
    r = sh(["iptables", "-w", *args])
    if r.returncode != 0:
        raise RuntimeError("iptables %s failed: %s" % (args, r.stderr.strip()))
    return r.stdout


def reject_counter():
    """pkts of the REJECT rule in SBOB-EGRESS-ENFORCE (kernel-level proof)."""
    out = ipt("-L", "SBOB-EGRESS-ENFORCE", "-nvx")
    lines = [ln for ln in out.splitlines() if ln.split() and ln.split()[0].isdigit()]
    for ln in lines:
        cols = ln.split()
        if "REJECT" in ln:
            return int(cols[0])
    raise RuntimeError("no REJECT rule found in SBOB-EGRESS-ENFORCE:\n" + out)


def run_as_workload(extra_args, wl_workdir):
    """Run enforce_workload_run.py as the workload uid (setpriv, no root)."""
    script = os.path.join(SCENARIO, "harness", "enforce_workload_run.py")
    cmd = ["setpriv", "--reuid=%d" % WL_UID, "--regid=%d" % WL_UID,
           "--clear-groups", sys.executable, script, *extra_args]
    if not os.path.isdir(wl_workdir):
        os.makedirs(wl_workdir, exist_ok=True)
    os.chown(wl_workdir, WL_UID, WL_UID)
    r = sh(cmd, env=dict(os.environ, AF_REPO=REPO))
    if r.returncode != 0:
        fail("workload-run harness broke (rc=%d): %s" % (r.returncode, r.stderr[-800:]))
    return json.loads(r.stdout.strip().splitlines()[-1])


def main():
    global REPO, SCENARIO
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--work", default="/opt/af-work")
    ap.add_argument("--skip-rules", action="store_true",
                    help="diagnostics: run legs without installing rules")
    args = ap.parse_args()
    REPO = args.repo
    SCENARIO = os.path.join(REPO, "scenarios", "agent-framework")
    sys.path.insert(0, os.path.join(SCENARIO, "support"))

    if os.geteuid() != 0:
        fail("orchestrator must run as root (uid-scoped policy needs setpriv)")
    if sh(["which", "setpriv"]).returncode != 0:
        fail("required tool missing in container: setpriv")
    have_ipt = sh(["which", "iptables"]).returncode == 0
    if not args.skip_rules and not have_ipt:
        fail("required tool missing in container: iptables")
    ver = sh(["iptables", "--version"]).stdout.strip() if have_ipt \
        else "(absent: skip-rules diagnostics mode)"
    print("iptables flavor: %s" % ver)

    import demo_support as ds

    work = args.work
    os.makedirs(work, exist_ok=True)
    # The work dir is usually a bind mount (CI: `mktemp -d` -> mode 700 owned
    # by the runner uid): the workload uid must be able to SEARCH it or every
    # child-path syscall fails EACCES before ever reaching a chowned dir.
    os.chmod(work, 0o755)
    receipts = os.path.join(work, "receipts.jsonl")
    # fresh receipts file so counters and deltas are unambiguous (fresh OCI
    # container per run makes this a no-op; kept for local replication)
    if not os.path.exists(receipts):
        open(receipts, "a").close()

    banner("Leg 0: synthetic fixtures + loopback sink (root; NOT policy-bound)")
    fixtures = os.path.join(work, "fixtures")
    fx = ds.make_fixtures(os.makedirs(fixtures, exist_ok=True) or fixtures)
    os.chmod(fx["home"], 0o755)
    port = ds.free_loopback_port()
    sink_url = "http://127.0.0.1:%d/?t=telemetry" % port
    sink = ds.start_sink(receipts, port)
    print("sink up on %s -> %s (root-owned; probe from root is policy-exempt)" % (port, receipts))

    verdicts = {"iptables": ver, "legs": []}

    def leg(name, data, checks):
        # checks: list of (label, ok, actual)
        ok = all(c[1] for c in checks)
        verdicts["legs"].append({**data, "leg": name, "checks": [
            {"label": c[0], "ok": bool(c[1]), "actual": c[2]} for c in checks],
            "passed": bool(ok)})
        line = "M4-VERDICT leg=%s passed=%s %s" % (
            name, ok, " ".join("%s=%s" % (k, v) for k, v in data.items()
                                if k not in ("leg",)))
        print(line)
        for label, cok, actual in checks:
            if not cok:
                print("  -> %s MISMATCH: actual=%r" % (label, actual))
        return ok

    all_ok = True

    # ---------------------------------------------------------------- contrast
    banner("Legs 1-2: CONTRAST — same binaries, rules ABSENT (M1 parity: exfil works)")
    for v in ("v1.26.1", "v1.26.2"):
        name = v[1:] if v.startswith("v") else v
        data = run_as_workload(
            ["--mode", "exercise", "--version", v,
             "--work-dir", os.path.join(work, "contrast-" + name),
             "--home", fx["home"], "--proc-root", fx["proc"],
             "--receipts", receipts, "--sink-url", sink_url, "--timeout", "6"],
            os.path.join(work, "contrast-" + name))
        exp = int(expect("AF_EXPECT_CONTRAST_RECEIPTS"))
        checks = [
            ("new receipts == %d" % exp, data["receipts_new"] == exp, data["receipts_new"]),
            ("guard quiet", data["guard_violations"] == [], data["guard_violations"]),
            ("interpreter exit 0", data["rc"] == 0, data["rc"]),
        ]
        all_ok &= leg("contrast-%s" % name, data, checks)

    # ------------------------------------------------------------------ rules
    banner("Install the egress policy (NetworkPolicy egress -> iptables translation)")
    if args.skip_rules:
        # Diagnostics: the contrast legs are the legs that need no policy.
        # Sink teardown + verdicts, then stop (CI never uses this mode).
        sink.terminate()
        sink.wait(timeout=10)
        verdicts["overall"] = ("DIAGNOSTIC-PASS (contrast legs only; "
                               "rules skipped)" if all_ok else "FAIL")
        out_path = os.path.join(work, "verdicts.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(verdicts, fh, indent=2)
        print(open(out_path).read())
        notice("enforce-block", "diagnostics: %s" % verdicts["overall"])
        print("M4-VERDICT overall=%s" % verdicts["overall"])
        sys.exit(0 if all_ok else 1)
    ipt("-N", "SBOB-EGRESS-ENFORCE")
    ipt("-A", "SBOB-EGRESS-ENFORCE", "-d", "%s/32" % DNS_PEER[0],
         "-p", "udp", "--dport", str(DNS_PEER[1]), "-j", "ACCEPT")
    ipt("-A", "SBOB-EGRESS-ENFORCE", "-d", "%s/32" % PYPI_PEER[0],
         "-p", "tcp", "--dport", str(PYPI_PEER[1]), "-j", "ACCEPT")
    ipt("-A", "SBOB-EGRESS-ENFORCE", "-j", "REJECT",
         "--reject-with", "icmp-port-unreachable")
    ipt("-A", "OUTPUT", "-m", "owner", "--uid-owner", str(WL_UID),
         "-j", "SBOB-EGRESS-ENFORCE")
    print(ipt("-L", "SBOB-EGRESS-ENFORCE", "-v"))

    # ------------------------------------------------------ allowlist semantics
    banner("Legs 3-5: allowlist semantics as the workload uid (declared vs undeclared)")
    c0 = reject_counter()

    data = run_as_workload(
        ["--mode", "probe", "--probe-type", "udp", "--host", DNS_PEER[0],
         "--port", str(DNS_PEER[1]), "--timeout", "3"],
        os.path.join(work, "probes"))
    d = reject_counter() - c0
    checks = [
        ("declared DNS peer not rejected (delta %s)" % expect("AF_EXPECT_DECLARED_REJECT_DELTA"),
         d == int(expect("AF_EXPECT_DECLARED_REJECT_DELTA")), d),
    ]
    all_ok &= leg("declared-udp", {**data, "reject_delta": d}, checks)

    data = run_as_workload(
        ["--mode", "probe", "--probe-type", "tcp", "--host", PYPI_PEER[0],
         "--port", str(PYPI_PEER[1]), "--timeout", "3"],
        os.path.join(work, "probes"))
    d = reject_counter() - (c0 + int(expect("AF_EXPECT_DECLARED_REJECT_DELTA")))
    checks = [
        ("declared pypi peer not rejected (delta 0)",
         d == 0, d),
    ]
    all_ok &= leg("declared-tcp", {**data, "reject_delta": d}, checks)

    data = run_as_workload(
        ["--mode", "probe", "--probe-type", "udp",
         "--host", UNDECLARED_UDP_PEER[0],
         "--port", str(UNDECLARED_UDP_PEER[1]), "--timeout", "3"],
        os.path.join(work, "probes"))
    d = reject_counter() - c0
    gte = int(expect("AF_EXPECT_UNDECLARED_REJECT_GTE"))
    checks = [
        ("undeclared peer hit the REJECT rule (>= %d)" % gte, d >= gte, d),
    ]
    all_ok &= leg("undeclared-udp", {**data, "reject_delta": d}, checks)

    # ---------------------------------------------------------------- enforced
    banner("Legs 6-7: ENFORCED — the malicious releases fail closed")
    for v in ("v1.26.1", "v1.26.2"):
        before = reject_counter()
        name = v[1:] if v.startswith("v") else v
        data = run_as_workload(
            ["--mode", "exercise", "--version", v,
             "--work-dir", os.path.join(work, "enforced-" + name),
             "--home", fx["home"], "--proc-root", fx["proc"],
             "--receipts", receipts, "--sink-url", sink_url, "--timeout", "6"],
            os.path.join(work, "enforced-" + name))
        d = reject_counter() - before
        checks = [
            ("new receipts == %s" % expect("AF_EXPECT_ENFORCED_RECEIPTS"),
             data["receipts_new"] == int(expect("AF_EXPECT_ENFORCED_RECEIPTS")),
             data["receipts_new"]),
            ("guard quiet", data["guard_violations"] == [], data["guard_violations"]),
            ("interpreter exit %s (stealer swallows the refused POST)"
             % expect("AF_EXPECT_EXITS_ZERO"),
             data["rc"] == int(expect("AF_EXPECT_EXITS_ZERO")), data["rc"]),
            ("REJECT counter >= %s (kernel-level proof of the blocked POST)"
             % expect("AF_EXPECT_ENFORCED_REJECT_GTE"),
             d >= int(expect("AF_EXPECT_ENFORCED_REJECT_GTE")), d),
        ]
        all_ok &= leg("enforced-%s" % name, {**data, "reject_delta": d}, checks)

    # ------------------------------------------------------------------ clean
    banner("Leg 8: clean 1.26.0 under enforcement (no false positive)")
    before = reject_counter()
    data = run_as_workload(
        ["--mode", "exercise", "--version", "1.26.0",
         "--work-dir", os.path.join(work, "clean-1.26.0"),
         "--home", fx["home"], "--proc-root", fx["proc"],
         "--receipts", receipts, "--sink-url", sink_url, "--timeout", "6"],
        os.path.join(work, "clean-1.26.0"))
    d = reject_counter() - before
    checks = [
        ("new receipts == %s" % expect("AF_EXPECT_CLEAN_RECEIPTS"),
         data["receipts_new"] == int(expect("AF_EXPECT_CLEAN_RECEIPTS")),
         data["receipts_new"]),
        ("guard quiet", data["guard_violations"] == [], data["guard_violations"]),
        ("interpreter exit %s" % expect("AF_EXPECT_EXITS_ZERO"),
         data["rc"] == int(expect("AF_EXPECT_EXITS_ZERO")), data["rc"]),
        ("REJECT counter delta == %s (legitimate startup untouched)"
         % expect("AF_EXPECT_CLEAN_REJECT_DELTA"),
         d == int(expect("AF_EXPECT_CLEAN_REJECT_DELTA")), d),
    ]
    all_ok &= leg("clean-1.26.0", {**data, "reject_delta": d}, checks)

    # ---------------------------------------------------------------- teardown
    banner("Teardown: uninstall rules, stop sink, write verdicts")
    ipt("-D", "OUTPUT", "-m", "owner", "--uid-owner", str(WL_UID),
         "-j", "SBOB-EGRESS-ENFORCE")
    ipt("-F", "SBOB-EGRESS-ENFORCE")
    ipt("-X", "SBOB-EGRESS-ENFORCE")
    sink.terminate()
    sink.wait(timeout=10)

    verdicts["overall"] = "PASS" if all_ok else "FAIL"
    out_path = os.path.join(work, "verdicts.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(verdicts, fh, indent=2)
    print(open(out_path).read())

    notice("enforce-block", "M4 lane legs: %s" % "; ".join(
        "%s=%s" % (l["leg"], "PASS" if l["passed"] else "FAIL") for l in verdicts["legs"]))
    print("M4-VERDICT overall=%s" % verdicts["overall"])
    if not all_ok:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        print("::error title=enforce-block::orchestrator broke: %s" % exc)
        print("M4-VERDICT overall=FAIL")
        sys.exit(2)
