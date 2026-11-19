<?php
// SBOB-EXAMPLES DEMO WATERMARK — scenario B: the BENIGN workload run.
// Demo reconstruction, loopback-only stand-ins (TDS §4). Every behavior here
// is inside the SBoB php contract (sbobs/php-fpm.yaml slot 1):
//   app-file read   -> opens[] /var/www/html/* (read)
//   session write   -> opens[] /var/lib/php/sessions/* (write)
//   resolver read   -> opens[] /etc/resolv.conf (read)
//   memcache peer   -> egress[] 10.96.100.10:11211 (loopback-local alias)
// Nothing here may fire an sbob drift rule: level-0 base chain only.
header('Content-Type: text/plain');

echo "benign: begin\n";

// 1. app-file read (declared)
$index = file_get_contents('/var/www/html/index.php');
echo "benign: read " . strlen($index) . " bytes of /var/www/html/index.php\n";

// 2. session write (declared — the only declared write path)
session_start();
$_SESSION['sbob_hits'] = ($_SESSION['sbob_hits'] ?? 0) + 1;
echo "benign: session hits " . $_SESSION['sbob_hits'] . "\n";

// 3. resolver read (declared)
$resolv = file_get_contents('/etc/resolv.conf');
echo "benign: resolver line: " . trim(strtok($resolv, "\n")) . "\n";

// 4. declared memcache peer connect (numeric literal: no DNS machinery, so
//    no undeclared nsswitch/hosts opens in the capture window)
$fp = @fsockopen('10.96.100.10', 11211, $errno, $errstr, 3.0);
if ($fp) {
    fwrite($fp, "version\r\n");
    fclose($fp);
    echo "benign: memcache peer 10.96.100.10:11211 connected\n";
} else {
    echo "benign: memcache connect failed: $errstr ($errno)\n";
}

echo "benign: end\n";
