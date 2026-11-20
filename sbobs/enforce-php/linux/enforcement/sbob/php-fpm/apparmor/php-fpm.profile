# sbobctl generated AppArmor profile — workload: php-fpm (TDS 14.3, M7)
# do not edit by hand; regenerate from the pinned SBoB + state file
# states: execs=enforce opens=enforce — ENFORCE (blocking) mode
abi <abi/3.0>,

#include <tunables/global>

profile sbob-php-fpm /usr/local/sbin/php-fpm flags=(attach_disconnected) {
  #include <abstractions/base>

  # execs[] — process execution allowlist (args not enforceable, TDS 14.3)
  /usr/local/sbin/php-fpm ixr,

  # opens[] — file access allowlist (flags map coarsely, TDS 14.3)
  /var/www/html/** r,
  /var/lib/php/sessions/** rwk,
  /etc/resolv.conf r,
}
