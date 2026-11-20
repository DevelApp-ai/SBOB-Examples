# sbobctl generated AppArmor profile — workload: python-ci-runner (TDS 14.3, M7)
# do not edit by hand; regenerate from the pinned SBoB + state file
# states: execs=audit opens=audit — AUDIT (complain) mode: violations are logged, allowed
abi <abi/3.0>,

#include <tunables/global>

profile sbob-python-ci-runner /usr/local/bin/python3.12 flags=(attach_disconnected, complain) {
  #include <abstractions/base>

  # execs[] — process execution allowlist (args not enforceable, TDS 14.3)
  /usr/local/bin/python3.12 ixr,

  # opens[] — file access allowlist (flags map coarsely, TDS 14.3)
  /usr/local/lib/python3.12/site-packages/** r,
  /home/runner/work/demo/** rwka,
  /etc/resolv.conf r,
}
