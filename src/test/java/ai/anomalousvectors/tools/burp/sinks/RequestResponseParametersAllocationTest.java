package ai.anomalousvectors.tools.burp.sinks;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import burp.api.montoya.http.message.HttpHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

/** Verifies supplemental form retention in an isolated small-heap process. */
class RequestResponseParametersAllocationTest {

    @TempDir
    Path tempDir;

    @Test
    void millionsOfPairs_retainCappedRowsWithinSmallHeap() throws Exception {
        String javaExecutable = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classes = Path.of(RequestResponseParametersAllocationTest.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
        String montoya = Path.of(HttpHeader.class.getProtectionDomain().getCodeSource()
                .getLocation().toURI()).toString();
        String classpath = classes + File.pathSeparator + System.getProperty("burp.exporter.packagedJar")
                + File.pathSeparator + montoya;
        Path output = tempDir.resolve("form-allocation.log");
        Process child = new ProcessBuilder(javaExecutable, "-Xmx96m", "-cp", classpath, Probe.class.getName())
                .redirectErrorStream(true)
                .redirectOutput(output.toFile())
                .start();
        try {
            assertThat(child.waitFor(45, TimeUnit.SECONDS)).as("small-heap parser completed").isTrue();
            String log = java.nio.file.Files.readString(output, StandardCharsets.UTF_8);
            assertThat(child.exitValue()).as(log).isZero();
            assertThat(log).contains("retained=1000, dropped=1999000");
        } finally {
            if (child.isAlive()) {
                child.destroyForcibly();
                assertThat(child.waitFor(10, TimeUnit.SECONDS)).as("parser process terminated").isTrue();
            }
        }
    }

    /** Small-heap entry point without test-framework or mocking initialization. */
    public static final class Probe {
        private Probe() {}

        /**
         * Parses two million fields using the packaged implementation and checks retained counts.
         *
         * @param args unused process arguments
         */
        public static void main(String[] args) {
            byte[] body = "a=&".repeat(2_000_000).getBytes(StandardCharsets.US_ASCII);
            var result = RequestResponseParametersSupport.parseUrlEncodedBodyParameters(body, List.of());
            if (result.entries().size() != 1_000 || result.droppedBodyParams() != 1_999_000) {
                throw new AssertionError("Unexpected form retention counts");
            }
            System.out.println("retained=" + result.entries().size() + ", dropped=" + result.droppedBodyParams());
        }
    }
}
