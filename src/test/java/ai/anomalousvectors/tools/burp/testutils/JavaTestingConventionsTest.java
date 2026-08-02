package ai.anomalousvectors.tools.burp.testutils;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

/** Enforces durable test-source conventions during every test or build run. */
class JavaTestingConventionsTest {

    @Test
    void testSources_followJavaTestingMdcConventions() throws Exception {
        var violations = JavaTestingConventionScanner.scan(Path.of("src/test/java"));
        String details = violations.stream().map(violation -> violation.toString()).collect(Collectors.joining("\n"));
        assertThat(violations)
                .withFailMessage("Test-source convention violations:\n%s", details)
                .isEmpty();
    }
}
