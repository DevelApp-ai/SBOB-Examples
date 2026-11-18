# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# M1 verdict tests: replay each reconstructed version through a guarded
# interpreter start and rule on the expected verdict (docs/TDS.md §6):
#   1.26.0  clean      -> zero receipts, no egress
#   1.26.1  malicious  -> exactly one receipt, full stealer payload, loopback
#   1.26.2  malicious  -> exactly one receipt, evolved stealer, loopback
# Every test also asserts the safety boundary held: zero non-loopback sockets.
# ============================================================================
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "support"))
import demo_support as ds  # noqa: E402

FAKE = ds.FAKE_TOKEN

# Demo secrets injected through the environment the same way CI/machines
# carry real ones; the stealer's env-key matchers must pick them up.
DEMO_ENV = {
    "DEMO_AGENT_TOKEN": FAKE,
    "DEMO_BUILD_SECRET": FAKE,
    "DEMO_AZURE_KEY": FAKE,
    # 1.26.2 additions (GitHub Actions focus):
    "DEMO_ACTIONS_TOKEN": FAKE,
    "DEMO_OIDC_SECRET": FAKE,
    "DEMO_RUNNER_KEY": FAKE,
    "DEMO_ARM_KEY": FAKE,
}


# --------------------------------------------------------------------------
# 1.26.0 — the clean baseline: no .pth hook, no egress on plain Python start
# --------------------------------------------------------------------------

def test_v1260_clean_start_is_silent(run_version):
    out = run_version("v1.26.0", env_extra=DEMO_ENV)
    assert out["receipts"] == [], "clean 1.26.0 must not exfiltrate anything"
    assert out["guard_violations"] == [], "no non-loopback sockets allowed"
    assert out["proc"].returncode == 0


def test_v1260_agent_framework_meta_is_inert(run_version, tmp_path):
    out = run_version("v1.26.0")
    site = out["site_dir"]
    pth_files = [f for f in os.listdir(site) if f.endswith(".pth")]
    assert pth_files == [], "clean wheel ships no .pth hook"
    # The initializer is plain metadata: importing it changes nothing.
    import subprocess, sys as _sys
    code = "import sys; sys.path.insert(0, %r); import agent_framework_meta; print(agent_framework_meta.META['version'])" % site
    res = subprocess.run([_sys.executable, "-c", code], capture_output=True, text=True)
    assert res.stdout.strip() == "1.26.0"


# --------------------------------------------------------------------------
# 1.26.1 — the credential stealer fires on interpreter start, once, loopback
# --------------------------------------------------------------------------

def test_v1261_exfiltrates_once_on_start(run_version):
    out = run_version("v1.26.1", env_extra=DEMO_ENV)
    assert out["guard_violations"] == [], "egress must stay loopback-only"
    assert out["proc"].returncode == 0, "guarded start must succeed normally"
    assert len(out["receipts"]) == 1, "exactly one POST expected"
    receipt = out["receipts"][0]
    assert receipt["user_agent"] == "af-runtime-diagnostics/1"
    assert receipt["payload_ok"] is True
    assert "env" in receipt["payload_keys"]
    assert "credential_files" in receipt["payload_keys"]


def test_v1261_payload_shape(run_version):
    out = run_version("v1.26.1", env_extra=DEMO_ENV)
    doc = ds.decode_payload(out["receipts"][0])
    # env-key matchers picked up the demo secrets
    assert doc["env"]["DEMO_AGENT_TOKEN"] == FAKE
    assert doc["env"]["DEMO_AZURE_KEY"] == FAKE
    # /proc sweep found the synthetic process environ
    assert doc["proc_environ"]["7"]["DEMO_BUILD_TOKEN"] == FAKE
    # credential files: azure, npm, docker, HF, ADO, .env, app/workspace
    creds = doc["credential_files"]
    for expected in (".azure/accessToken.json", ".npmrc", ".docker/config.json",
                     ".cache/huggingface/token",
                     ".azure-devops/agent/.credentials", ".env",
                     "app/config.json", "workspace/config.json"):
        assert expected in creds, "expected credential file missing: %s" % expected
    assert FAKE in creds[".azure/accessToken.json"]
    # metadata endpoints are shape-recorded, never issued
    oidc = doc["metadata"]["azure_devops_oidc"]
    assert oidc["audience"] == "api://AzureADTokenExchange"
    assert doc["metadata"]["imds_managed_identity"]["endpoint_shape"] == \
        "http://169.254.169.254/metadata/oauth2/token"


def test_v1261_run_once_guard_blocks_second_fire(run_version):
    out = run_version("v1.26.1", env_extra=dict(DEMO_ENV, _AF_TEL="1"))
    assert out["receipts"] == [], "_AF_TEL guard must suppress the hook"
    assert out["guard_violations"] == []


# --------------------------------------------------------------------------
# 1.26.2 — the evolved top-level stealer (restored meta + af_runtime_diag)
# --------------------------------------------------------------------------

def test_v1262_exfiltrates_once_on_start(run_version):
    out = run_version("v1.26.2", env_extra=DEMO_ENV)
    assert out["guard_violations"] == [], "egress must stay loopback-only"
    assert out["proc"].returncode == 0
    assert len(out["receipts"]) == 1
    receipt = out["receipts"][0]
    assert receipt["user_agent"] == "runtime-diagnostics/1", \
        "1.26.2 changed the user-agent string"
    assert receipt["payload_ok"] is True


def test_v1262_payload_evolution(run_version):
    out = run_version("v1.26.2", env_extra=DEMO_ENV)
    doc = ds.decode_payload(out["receipts"][0])
    # new GitHub-Actions env-key matchers
    assert doc["env"]["DEMO_ACTIONS_TOKEN"] == FAKE
    assert doc["env"]["DEMO_RUNNER_KEY"] == FAKE
    assert doc["env"]["DEMO_ARM_KEY"] == FAKE
    # runner credential paths added to the file sweep
    creds = doc["credential_files"]
    assert "runner/work/_temp/gha_token" in creds
    assert creds["runner/work/_temp/gha_token"].strip() == FAKE
    # GHA OIDC theft shape recorded (never issued in the demo)
    gha = doc["metadata"]["github_actions_oidc"]
    assert gha["audience"] == "api://AzureADTokenExchange"


def test_v1262_guard_blocks_second_fire(run_version):
    out = run_version("v1.26.2", env_extra=dict(DEMO_ENV, _AF_TEL="1"))
    assert out["receipts"] == [], "_AF_TEL guard must suppress the hook"
    assert out["guard_violations"] == []
