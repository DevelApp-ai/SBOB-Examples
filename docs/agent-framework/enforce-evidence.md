# M4 enforcement evidence (scenario A, issue #5)

Layer 3, Enforce: what the egress deny-all-undeclared policy would have done
during the 2026-11-17 agent-framework hijack, proven live in a disposable
CI container, with the Monitor -> Audit -> Enforce transition recorded as a
committed, toolchain-validated state file.

## The premise

M3 proved detection: the drift bundle fires level-9 alerts on the
credential sweep and the single exfil POST while the corpus is real. This
milestone proves the next rung: when the same consumer contract
(`sbobs/workload/python-ci-runner.yaml`) is ALLOWLIST-ENFORCED at the
network layer, the hijack's damage step (one undeclared HTTPS POST carrying
the stolen credential document) fails closed, and the legitimate workload
(clean 1.26.0) is untouched.

## Monitor -> Audit -> Enforce (the committed transition)

`sbobs/enforce-state.yaml` is the rollout state file, validated by the
pinned sbobctl on every lane run (the drift gate regenerates the enforce
bundles from it, so an invalid ladder — `ERR_ENFORCE_LADDER` — or enforcement
without a clean audit window — `ERR_ENFORCE_NOT_AUDITED` — fails CI):

- Monitor: the profile ships detection only (M1-M2 lanes).
- Audit: the default state of every section; the audit record cites the M3
  runtime-detection lane's benign replay (green runs 44789125134 +
  44789707792) as the incident-free window evidence.
- Enforce: ONLY `egress` advances (the deliberate rung). execs/opens stay
  at audit — the M3 lane already recorded their honest absences (100211
  exec drift: the stealer lives inside the declared interpreter; 100201:
  cloud credentials are not on the sensitive-file watchlist), and
  promoting them is future work, not this rung.

## The artifacts (committed under `sbobs/enforce/`, drift-gated)

Generated deterministically by the pinned toolchain
(DevelApp-ai/Software-Bill-of-Behavior @
4bf2eb1d2413de388c10a0c7de38026e07e46fd7) from the committed profile +
registry + state file, on both targets, and re-diffed on every lane run —
any drift fails CI:

| Artifact | Target | Role in scenario A |
|---|---|---|
| `networkpolicy/python-ci-runner.yaml` | k8s-node | THE live lane: egress allowlist = `ipBlock` cluster-dns UDP 53 + pypi-mirror TCP 443, `policyTypes: [Egress]` (deny-all-undeclared egress) |
| `apparmor/python-ci-runner.profile` | linux | documented-with-artifacts: exec/opens allowlist in complain mode (states execs=opens=audit; profile tightness is load-bearing, M3 finding 3) |
| `systemd/python-ci-runner-seccomp.conf` | linux | documented-with-artifacts: SCMP_ACT_LOG signature surface (kernel-module/memfd/ptrace-class syscalls; scenario A uses none — recorded, not papered over) |
| `seccomp/python-ci-runner.json` | k8s-node | same signature surface, pod-seccomp shape |
| `100200_python-ci-runner_enforce.xml` + AR scripts + agent-conf fragments | both | detection-plane enforcement wiring: process-kill/firewall-drop active responses + `sbob-enforce.log` telemetry (kill-switch per agent group) |
| manifests (`*-enforce.manifest.json`) | both | what was generated, from which state, with the notes |

## The live lane: NetworkPolicy egress semantics, proven in a container

k8s NetworkPolicies cannot run in GitHub CI (no kube firewall). The lane
enforces the SAME semantics inside one disposable `python:3.12-slim`
container (`--cap-add=NET_ADMIN`) as a uid-scoped iptables allowlist, and
every scenario leg runs as the dedicated workload uid 1500 via
`setpriv` (the podSelector -> uid translation: the policy selects the
workload identity; the loopback sink and the orchestrator run as root and
are policy-exempt, exactly like non-workload pods):

```
OUTPUT -m owner --uid-owner 1500 -j SBOB-EGRESS-ENFORCE
SBOB-EGRESS-ENFORCE:
  -d 10.96.0.10/32  -p udp --dport 53  -j ACCEPT   (declared: cluster-dns)
  -d 10.96.100.20/32 -p tcp --dport 443 -j ACCEPT  (declared: pypi mirror)
  -j REJECT --reject-with icmp-port-unreachable     (everything else: fail closed)
```

The REJECT rule's packet counter is the kernel-level proof that the exfil
POST was attempted and denied; the sink's receipt delta is the proof that
nothing arrived.

## Expected verdicts (pinned in the workflow env)

| Leg | Rules | Expected | Meaning |
|---|---|---|---|
| contrast 1.26.1 / 1.26.2 | absent | 1 new receipt each, exit 0, guard quiet | M1 parity: the SAME binaries exfiltrate when nothing enforces (the controls) |
| declared-udp 10.96.0.10:53 | present, uid 1500 | accepted, REJECT delta 0 | the allowlist admits the declared DNS peer |
| declared-tcp 10.96.100.20:443 | present, uid 1500 | accepted by the rules, REJECT delta 0 | the allowlist admits the declared mirror peer |
| undeclared-udp 9.9.9.9:53 | present, uid 1500 | REJECT counter +1 | undeclared egress fails closed |
| enforced 1.26.1 / 1.26.2 | present, uid 1500 | 0 new receipts, REJECT counter +1, exit 0 (.pth exception swallowed, faithful reconstruction) | the hijack's POST is denied; nothing reaches the sink |
| clean 1.26.0 | present, uid 1500 | 0 new receipts, REJECT delta 0, exit 0 | no false positive: a legitimate interpreter start under enforcement is untouched |

<!-- STAMP: recorded from the lane's actual green run(s):
- verdicts recorded on run 44800715326 (public ::notice annotations, 40s
  job): all 8 legs PASS —
  contrast-1.26.1 / contrast-1.26.2 (1 new receipt each: M1 parity, exit 0,
  guard quiet); declared-udp + declared-tcp (declared peers admitted, no
  REJECT hit); undeclared-udp (REJECT +1); enforced-1.26.1 / enforced-1.26.2
  (0 new receipts, REJECT counter hit, interpreter exit 0 — the swallowed
  refusal, recorded as the pinned AF_EXPECT_INTERPRETER_RC); clean-1.26.0
  (0 receipts, REJECT delta 0, exit 0: no false positive).
- drift gate green on the same run: sbobs/enforce/{k8s-node,linux}
  regenerate byte-identical from pin 4bf2eb1d2413de388c10a0c7de38026e07e46fd7
  + sbobs/enforce-state.yaml (ladder + audit-record validation accepted).
- artifacts uploaded: enforce-block-evidence (verdicts.json, receipts.jsonl,
  enforce-demo.log, drift diffs, regenerate logs, manifests).
-->

## Honest limitations

1. **Annotation-level gap (generator finding, recorded not papered over):**
   the NetworkPolicy artifact labels itself `mode: "audit"` + "do NOT apply
   live" while carrying exactly the enforce semantics this lane proves
   (`policyTypes: [Egress]` + allowlist = deny-all-undeclared). The
   generator only flips the label to "enforce" when BOTH egress AND
   ingress sections advance (src/codegen/networkpolicy.ts), so an
   egress-only workload can never ship an artifact labeled enforce. The
   label gap is a candidate SBoB roadmap item; the lane documents it in
   `sbobs/enforce-state.yaml` and enforces the section semantics by
   translation. (Setting `ingress: enforce` in the state file would flip
   the label but emit no ingress rules — the profile declares no inbound
   peers and the generator only emits `policyTypes: [Egress, Ingress]` when
   the profile has ingress entries — so the annotation would claim an
   enforcement the artifact does not deliver. That would be papering
   over; the state file advances only egress.)
2. **Declared-peer delivery is untestable from CI:** 10.96.0.10 and
   10.96.100.20 are lab-cluster IPs that do not exist on a GitHub runner.
   The declared-peer legs prove the ruleset ADMITS those destinations
   (no REJECT hit); actual delivery needs the lab cluster. The REJECT
   counter + the undeclared leg carry the blocking semantics.
3. **AppArmor and seccomp are documented-with-artifacts, not live-applied:**
   the AppArmor profile is complaint-mode by design (execs/opens are still
   at the audit rung) and its opens allowlist does not cover the container
   layout's Python stdlib paths (it covers exactly what the profile
   declares), so a naive live enforce would deny legitimate interpreter
   startup: a caller-visible false positive the M4 state deliberately does
   not request. The seccomp artifact is SCMP_ACT_LOG on the M4 signature
   syscall surface and blocks nothing (scenario A uses none of those
   syscalls). Issue #5 names the NetworkPolicy shape as the proven/live
   lane; promoting execs/opens to enforce (real AppArmor/seccomp) is the
   natural M5+ roadmap item.
4. **Rule placement, not just ruleset:** the container applies the policy
   at boot of the demo; a real consumer needs the policy live BEFORE the
   malicious wheel is ever installed. The lane's ordering (contrast ->
   rules -> enforced) is a controlled experiment, not a deployment timeline.

## Lane shape

Single job: drift gate (regenerate both enforce bundles from the pinned
toolchain + committed state file, diff against the committed trees) ->
`docker build` of the demo container (iptables, setpriv, uid 1500) ->
`docker run --cap-add=NET_ADMIN` orchestrating the eight pinned legs above
(::notice annotations + step summary + verdicts.json/receipts.jsonl
artifacts; the lane never stays red, TDS §7).
