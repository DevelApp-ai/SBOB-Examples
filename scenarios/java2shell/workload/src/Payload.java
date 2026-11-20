// SBOB-EXAMPLES DEMO WATERMARK — scenario C: the in-JVM payload class staged
// via ClassLoader.defineClass from bytes read through the DECLARED /app read.
// Its run() stays inside the JVM (no exec, no undeclared open, no socket) —
// this is the expected-silent leg recorded as a committed finding in
// docs/java2shell/detection-evidence.md. Demo only (TDS §4).
public class Payload {
    public void run() {
        System.out.println("payload staged in-JVM via defineClass (no OS-level syscall)");
    }
}
