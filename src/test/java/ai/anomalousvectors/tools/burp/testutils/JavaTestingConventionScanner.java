package ai.anomalousvectors.tools.burp.testutils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Checks source-level test patterns that can hide asynchronous logging assertion races.
 *
 * <p>Runs as part of the normal {@code test} task via {@link JavaTestingConventionsTest}.</p>
 */
public final class JavaTestingConventionScanner {

    private static final Pattern TEST_METHOD =
            Pattern.compile("@Test\\s*(?:\\([^)]*\\))?\\s*\\n\\s*(?:public\\s+)?void\\s+(\\w+)\\s*\\([^)]*\\)\\s*(?:throws\\s+[\\w.]+\\s*)?\\{",
                    Pattern.MULTILINE);

    private static final Pattern LOGGER_LISTENER_ASSERT = Pattern.compile(
            "assertThat\\(\\s*(?:infoMessages|warnMessages|debugMessages)\\b");

    private static final List<String> LOGGER_LISTENER_SYNC_MARKERS = List.of(
            "invokeAndWait",
            "flushLogListeners",
            "awaitInfoLine",
            "awaitInfoLineStartingWith",
            "onEdt(");

    private JavaTestingConventionScanner() {}

    /**
     * Scans test sources under {@code testJavaRoot} for convention violations.
     *
     * @param testJavaRoot typically {@code src/test/java}
     * @return violations; empty when all checked conventions pass
     * @throws IOException if sources cannot be read
     */
    public static List<Violation> scan(Path testJavaRoot) throws IOException {
        List<Violation> violations = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(testJavaRoot)) {
            paths.filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> !path.getFileName().toString().startsWith("JavaTestingConvention"))
                    .forEach(path -> {
                        try {
                            scanFile(path, testJavaRoot, violations);
                        } catch (IOException ex) {
                            throw new IllegalStateException("Failed to read " + path, ex);
                        }
                    });
        }
        return List.copyOf(violations);
    }

    private static void scanFile(Path file, Path testJavaRoot, List<Violation> violations) throws IOException {
        String source = Files.readString(file);
        if (!source.contains("Logger.registerListener")) {
            return;
        }
        String relative = testJavaRoot.relativize(file).toString().replace('\\', '/');
        scanLoggerListenerEdtConvention(relative, source, violations);
    }

    /**
     * Requires captured-listener assertions to synchronize with asynchronous Log delivery.
     *
     * <p>Recognizes an EDT flush or an established await/on-EDT helper before accepting a test
     * body that asserts on captured listener lists.</p>
     */
    private static void scanLoggerListenerEdtConvention(
            String relativePath, String source, List<Violation> violations) {
        Matcher matcher = TEST_METHOD.matcher(source);
        while (matcher.find()) {
            String methodName = matcher.group(1);
            int bodyStart = matcher.end();
            int bodyEnd = findMatchingBraceEnd(source, bodyStart - 1);
            if (bodyEnd < 0) {
                continue;
            }
            String body = source.substring(bodyStart, bodyEnd);
            if (!LOGGER_LISTENER_ASSERT.matcher(body).find()) {
                continue;
            }
            if (LOGGER_LISTENER_SYNC_MARKERS.stream().anyMatch(body::contains)) {
                continue;
            }
            violations.add(new Violation(
                    relativePath,
                    methodName,
                    "Logger.registerListener test asserts on infoMessages/warnMessages/debugMessages without "
                            + "invokeAndWait, flushLogListeners, or an await/onEdt helper. "
                            + "See java-testing.mdc EDT / async Log panel row and BodyEnumerationSkippedLogTest."));
        }
    }

    private static int findMatchingBraceEnd(String source, int openBraceIndex) {
        int depth = 0;
        for (int i = openBraceIndex; i < source.length(); i++) {
            char c = source.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * A single convention violation in a test source file.
     *
     * @param relativePath path under {@code src/test/java}
     * @param testMethod JUnit test method name
     * @param message operator-facing explanation
     */
    public record Violation(String relativePath, String testMethod, String message) {

        @Override
        public String toString() {
            return relativePath + " > " + testMethod + ": " + message;
        }
    }
}
