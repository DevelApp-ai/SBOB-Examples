#!/usr/bin/env python3
# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# Local pre-push validation WITHOUT pytest (the sandbox has no pip; CI runs
# the real pytest lane). Mirrors tests/test_scenario_a.py assertions.
# Usage: python3 scripts/validate_scenario_a.py
# ============================================================================
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(SCENARIO, "support"))
import demo_support as ds  # noqa: E402

FAKE = ds.FAKE_TOKEN
DEMO_ENV = {
    "DEMO_AGENT_TOKEN": FAKE,
    "DEMO_BUILD_SECRET": FAKE,
    "DEMO_AZURE_KEY": FAKE,
    "DEMO_ACTIONS_TOKEN": FAKE,
    "DEMO_OIDC_SECRET": FAKE,
    "DEMO_RUNNER_KEY": FAKE,
    "DEMO_ARM_KEY": FAKE,
}

FAILURES = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print("  [%s] %s%s" % (status, name, (" :: " + detail) if (detail and not condition) else ""))
    if not condition:
        FAILURES.append(name)


def main():
    work = tempfile.mkdtemp(prefix="sbob-validate-")
    server = None
    try:
        receipts = os.path.join(work, "receipts.jsonl")
        port = ds.free_loopback_port()
        sink_url = "http://127.0.0.1:%d/?t=telemetry" % port
        server = ds.start_sink(receipts, port=port)
        fixtures = ds.make_fixtures(os.path.join(work, "fixtures"))

        def run(version, env_extra=None):
            env = dict(DEMO_ENV)
            env.update(env_extra or {})
            return ds.exercise(
                os.path.join(SCENARIO, "package", version),
                os.path.join(work, version.replace(".", "-")),
                home=fixtures["home"], proc_root=fixtures["proc"],
                receipts_path=receipts, env_extra=env, sink_url=sink_url,
            )

        print("v1.26.0 (clean baseline)")
        out = run("v1.26.0")
        check("no egress", out["receipts"] == [])
        check("no guard violations", out["guard_violations"] == [])
        check("start exits 0", out["proc"].returncode == 0)

        print("v1.26.1 (hooked meta stealer)")
        out = run("v1.26.1")
        check("one receipt", len(out["receipts"]) == 1,
              "got %d" % len(out["receipts"]))
        check("no guard violations", out["guard_violations"] == [])
        if out["receipts"]:
            r = out["receipts"][0]
            doc = ds.decode_payload(r)
            check("user-agent af-runtime-diagnostics/1",
                  r["user_agent"] == "af-runtime-diagnostics/1", r["user_agent"])
            check("payload_ok", r["payload_ok"] is True)
            check("env collection", doc["env"].get("DEMO_AGENT_TOKEN") == FAKE)
            check("proc sweep", doc["proc_environ"].get("7", {}).get("DEMO_BUILD_TOKEN") == FAKE)
            creds = doc["credential_files"]
            check("azure token file", ".azure/accessToken.json" in creds, str(sorted(creds)))
            check("ado credentials file", ".azure-devops/agent/.credentials" in creds)
            check("oidc shape recorded",
                  doc["metadata"]["azure_devops_oidc"]["audience"] == "api://AzureADTokenExchange")
        out = run("v1.26.1", {"_AF_TEL": "1"})
        check("_AF_TEL guard blocks hook", out["receipts"] == [])

        print("v1.26.2 (restored meta + top-level stealer)")
        out = run("v1.26.2")
        check("one receipt", len(out["receipts"]) == 1,
              "got %d" % len(out["receipts"]))
        check("no guard violations", out["guard_violations"] == [])
        if out["receipts"]:
            r = out["receipts"][0]
            doc = ds.decode_payload(r)
            check("user-agent runtime-diagnostics/1",
                  r["user_agent"] == "runtime-diagnostics/1", r["user_agent"])
            check("actions env key collected", doc["env"].get("DEMO_ACTIONS_TOKEN") == FAKE)
            check("runner cred path swept",
                  "runner/work/_temp/gha_token" in doc["credential_files"],
                  str(sorted(doc["credential_files"])))
            check("gha oidc shape recorded",
                  doc["metadata"]["github_actions_oidc"]["audience"] == "api://AzureADTokenExchange")
        out = run("v1.26.2", {"_AF_TEL": "1"})
        check("_AF_TEL guard blocks hook", out["receipts"] == [])

        print("integrity")
        pkg = os.path.join(SCENARIO, "package")
        with open(os.path.join(pkg, "v1.26.0", "agent_framework_meta", "__init__.py"), "rb") as fh:
            clean = fh.read()
        with open(os.path.join(pkg, "v1.26.2", "agent_framework_meta", "__init__.py"), "rb") as fh:
            restored = fh.read()
        with open(os.path.join(pkg, "v1.26.1", "agent_framework_meta", "__init__.py"), "rb") as fh:
            hooked = fh.read()
        check("1.26.2 meta byte-identical to 1.26.0", clean == restored)
        check("1.26.1 meta differs from clean", clean != hooked)

        watermarked = 0
        for root, dirs, files in os.walk(pkg):
            for name in files:
                if name.endswith(".py") and ds.check_watermark(os.path.join(root, name)):
                    watermarked += 1
        check("all reconstructed .py watermarked", watermarked >= 8,
              "%d watermarked" % watermarked)

    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except Exception:
                server.kill()
        shutil.rmtree(work, ignore_errors=True)

    print()
    if FAILURES:
        print("VALIDATION FAILED: %d checks failed" % len(FAILURES))
        for name in FAILURES:
            print("  - " + name)
        return 1
    print("VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
