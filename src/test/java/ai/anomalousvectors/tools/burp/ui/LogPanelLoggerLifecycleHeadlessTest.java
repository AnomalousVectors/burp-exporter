package ai.anomalousvectors.tools.burp.ui;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.Logger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ensures LogPanel receives log messages only when in the display hierarchy and gets
 * replayed messages when re-added (regression test for tab-switch / clean-start Log panel
 * missing messages). Invokes addNotify/removeNotify on the EDT to simulate hierarchy
 * lifecycle without requiring a display (headless-safe).
 */
@Tag("headless")
class LogPanelLoggerLifecycleHeadlessTest {

    @Test
    void panel_receivesLogsWhenInHierarchy_getsReplayWhenReAdded() throws Exception {
        LogPanel panel = LogPanelTestHarness.newPanel();
        LogPanelTestHarness.resetPanelState(panel);

        SwingUtilities.invokeAndWait(() -> invokeAddNotify(panel));
        // Simulates panel added to hierarchy → register with Logger

        SwingUtilities.invokeAndWait(() -> Logger.logInfo("while-visible"));
        assertThat(LogPanelTestHarness.waitFor(
                () -> LogPanelTestHarness.allText(panel).contains("while-visible"), 5000L))
                .isTrue();
        String afterFirst = LogPanelTestHarness.allText(panel);
        assertThat(afterFirst).contains("while-visible");

        SwingUtilities.invokeAndWait(() -> invokeRemoveNotify(panel));
        // Simulates panel removed → unregister

        SwingUtilities.invokeAndWait(() -> Logger.logInfo("while-removed"));
        // Panel is not registered so it did not receive "while-removed" yet

        SwingUtilities.invokeAndWait(() -> invokeAddNotify(panel));
        // Re-added → register and replay
        assertThat(LogPanelTestHarness.waitFor(
                () -> LogPanelTestHarness.allText(panel).contains("while-removed"), 5000L))
                .isTrue();

        String afterReAdd = LogPanelTestHarness.allText(panel);
        assertThat(afterReAdd).contains("while-visible");
        assertThat(afterReAdd).contains("while-removed");
    }

    private static void invokeAddNotify(LogPanel panel) {
        Reflect.call(panel, "addNotify");
    }

    private static void invokeRemoveNotify(LogPanel panel) {
        Reflect.call(panel, "removeNotify");
    }
}
