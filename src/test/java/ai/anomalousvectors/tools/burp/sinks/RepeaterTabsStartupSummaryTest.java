package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Locks down the shape of the Repeater Tabs startup completion summary emitted by
 * {@code RepeaterTabsIndexReporter.logStartupExportCompletionSummary(String)}.
 *
 * <p>Uses reflection to invoke the package-private lifecycle hooks and the private summary
 * method so the test can assert prefix + {@link SnapshotSummary} body + metadata suffix
 * composition without spinning up Burp's Montoya API.</p>
 *
 * <p>Static state is reset per-test in the constructor (JUnit 5 creates a new instance per
 * {@code @Test} method by default); the log listener is registered/unregistered around each
 * test body via try/finally so no lifecycle-hook methods are needed.</p>
 */
class RepeaterTabsStartupSummaryTest {

    private final List<String> capturedMessages = new ArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level) && message.startsWith("[StartupExport] Repeater Tabs:")) {
            capturedMessages.add(message);
        }
    };

    public RepeaterTabsStartupSummaryTest() {
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        RepeaterTabsIndexReporter.clearSessionState();
    }

    @Test
    void logStartupExportCompletionSummary_composesPrefixBodyAndMetadataSuffix() throws Exception {
        Logger.registerListener(listener);
        try {
            invokeStatic("openCaptureWindowForCurrentRun");

            ExportStats.recordTrafficToolTypeSuccess("REPEATER_TABS", 2);
            FileExportStats.recordTrafficToolTypeSuccess("REPEATER_TABS", 2);

            invokeStartupExportCompletionSummary();
            drainEventDispatchThread();

            assertThat(capturedMessages).hasSize(1);
            String line = capturedMessages.get(0);
            assertThat(line).startsWith("[StartupExport] Repeater Tabs: export complete startupSession=");
            assertThat(line).contains(" captured 0 tab(s)");
            assertThat(line).contains("file={written=2, failure=0}");
            assertThat(line).contains("openSearch={exported=2, failure=0}");
            assertThat(line).endsWith(".");
        } finally {
            Logger.unregisterListener(listener);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void logStartupExportCompletionSummary_rendersZeroedBodyWhenBaselineAbsent() throws Exception {
        Logger.registerListener(listener);
        try {
            invokeStartupExportCompletionSummary();
            drainEventDispatchThread();

            assertThat(capturedMessages).hasSize(1);
            String line = capturedMessages.get(0);
            assertThat(line).contains(" captured 0 tab(s); ");
            assertThat(line).contains("file={written=0, failure=0}");
            assertThat(line).contains("openSearch={exported=0, failure=0}");
        } finally {
            Logger.unregisterListener(listener);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void logStartupExportCompletionSummary_usesProvidedStartupSession() throws Exception {
        Logger.registerListener(listener);
        try {
            invokeStatic("logStartupExportCompletionSummary", "g1-s1", true);
            drainEventDispatchThread();

            assertThat(capturedMessages).hasSize(1);
            assertThat(capturedMessages.get(0))
                    .startsWith("[StartupExport] Repeater Tabs: export complete startupSession=g1-s1 ");
        } finally {
            Logger.unregisterListener(listener);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void logStartupExportCompletionSummary_labelsIncompleteDeliveryAsPending() throws Exception {
        Logger.registerListener(listener);
        try {
            invokeStatic("logStartupExportCompletionSummary", "g1-s1", false);
            drainEventDispatchThread();

            assertThat(capturedMessages).hasSize(1);
            assertThat(capturedMessages.get(0))
                    .startsWith("[StartupExport] Repeater Tabs: capture complete startupSession=g1-s1 ")
                    .contains("; delivery_pending=0;");
        } finally {
            Logger.unregisterListener(listener);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    private static void invokeStartupExportCompletionSummary() throws Exception {
        Method sessionMethod = RepeaterTabsIndexReporter.class.getDeclaredMethod("currentStartupSessionId");
        sessionMethod.setAccessible(true);
        String sessionId = (String) sessionMethod.invoke(null);
        invokeStatic("logStartupExportCompletionSummary", sessionId, true);
    }

    private static void invokeStatic(String methodName) throws Exception {
        Method method = RepeaterTabsIndexReporter.class.getDeclaredMethod(methodName);
        method.setAccessible(true);
        method.invoke(null);
    }

    private static void invokeStatic(String methodName, String value, boolean flag) throws Exception {
        Method method = RepeaterTabsIndexReporter.class.getDeclaredMethod(
                methodName, String.class, boolean.class);
        method.setAccessible(true);
        method.invoke(null, value, flag);
    }

    private static void drainEventDispatchThread() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }
}
