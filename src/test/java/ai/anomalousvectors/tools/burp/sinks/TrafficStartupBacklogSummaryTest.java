package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/** Unit tests for {@link TrafficStartupBacklogSummary}. */
class TrafficStartupBacklogSummaryTest {

    @AfterEach
    public void tearDown() {
        ExportReporterLifecycle.resetForTests();
    }

    @Test
    void hasExpectedStartupComponents_falseAfterClearRunState() {
        TrafficStartupBacklogSummary.startForCurrentRun();
        TrafficStartupBacklogSummary.clearRunState();
        assertThat(TrafficStartupBacklogSummary.hasExpectedStartupComponents()).isFalse();
    }

    @Test
    void complete_afterClearRunState_isIgnored() {
        TrafficStartupBacklogSummary.startForCurrentRun();
        TrafficStartupBacklogSummary.clearRunState();
        SnapshotSummary.Baseline baseline =
                SnapshotSummary.forRoute(TrafficRouteBucket.proxyHistorySnapshot());

        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_HISTORY, 100, baseline);
    }

    @Test
    void complete_whenExportNotRunning_isIgnored() {
        TrafficStartupBacklogSummary.startForCurrentRun();
        RuntimeConfig.setExportRunning(false);
        SnapshotSummary.Baseline baseline =
                SnapshotSummary.forRoute(TrafficRouteBucket.proxyHistorySnapshot());

        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_HISTORY, 100, baseline);
    }

    @Test
    void formatCompletionLine_sumsTrafficStartupComponents() {
        String line = TrafficStartupBacklogSummary.formatCompletionLineForTests(
                Map.of(
                        TrafficStartupBacklogSummary.Component.REPEATER_TABS,
                        result(15, 15, 0, 15, 0),
                        TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                        result(117, 117, 0, 117, 0),
                        TrafficStartupBacklogSummary.Component.PROXY_HISTORY,
                        result(26_838, 26_838, 0, 26_838, 0)),
                true,
                true);

        assertThat(line).isEqualTo("[StartupExport] Traffic: backlog complete captured=26970; "
                + "file={written=26970, failure=0}; openSearch={exported=26970, failure=0}; "
                + "components={repeater_tabs=15, proxy_websocket=117, proxy_history=26838}.");
    }

    @Test
    void formatCompletionLine_refreshesDeferredRepeaterDeliveryCounters() {
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forRoute(
                new TrafficRouteBucket.Route(
                        TrafficRouteBucket.Kind.TOOL_TYPE, "REPEATER_TABS"));
        TrafficStartupBacklogSummary.ComponentResult deferred =
                TrafficStartupBacklogSummary.ComponentResult.from(18, baseline);

        ExportStats.recordTrafficToolTypeSuccess("REPEATER_TABS", 18);
        FileExportStats.recordTrafficToolTypeSuccess("REPEATER_TABS", 18);

        String line = TrafficStartupBacklogSummary.formatCompletionLineForTests(
                Map.of(TrafficStartupBacklogSummary.Component.REPEATER_TABS, deferred),
                true,
                true);

        assertThat(line).isEqualTo("[StartupExport] Traffic: backlog complete captured=18; "
                + "file={written=18, failure=0}; openSearch={exported=18, failure=0}; "
                + "components={repeater_tabs=18}.");
    }

    @Test
    void complete_ignoresLateComponentFromPreviousRunGeneration() throws Exception {
        ConfigState.State previous = RuntimeConfig.getState();
        List<String> summaries = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("INFO".equals(level)
                    && message.startsWith("[StartupExport] Traffic: backlog complete")) {
                summaries.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(
                            true, "C:\\temp", true, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy_history"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);
            ExportRunToken firstRun = RuntimeConfig.currentExportRunToken();
            TrafficStartupBacklogSummary.startForCurrentRun(firstRun);

            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportRunning(true);
            ExportRunToken secondRun = RuntimeConfig.currentExportRunToken();
            TrafficStartupBacklogSummary.startForCurrentRun(secondRun);

            TrafficStartupBacklogSummary.complete(
                    TrafficStartupBacklogSummary.Component.PROXY_HISTORY,
                    100,
                    SnapshotSummary.forRoute(TrafficRouteBucket.proxyHistorySnapshot()),
                    firstRun);
            TrafficStartupBacklogSummary.complete(
                    TrafficStartupBacklogSummary.Component.PROXY_HISTORY,
                    3,
                    SnapshotSummary.forRoute(TrafficRouteBucket.proxyHistorySnapshot()),
                    secondRun);
            TrafficStartupBacklogSummary.complete(
                    TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                    2,
                    SnapshotSummary.forRoute(TrafficRouteBucket.proxyWebSocket()),
                    secondRun);
            SwingUtilities.invokeAndWait(() -> {});

            assertThat(summaries).singleElement().satisfies(message -> assertThat(message)
                    .contains(
                            "captured=5",
                            "proxy_websocket=2",
                            "proxy_history=3")
                    .doesNotContain("captured=105"));
        } finally {
            Logger.unregisterListener(listener);
            Logger.resetState();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(previous);
        }
    }

    private static TrafficStartupBacklogSummary.ComponentResult result(
            int captured,
            long fileSuccess,
            long fileFailure,
            long openSearchSuccess,
            long openSearchFailure) {
        return new TrafficStartupBacklogSummary.ComponentResult(
                captured,
                new SnapshotSummary.CompletionDeltas(
                        fileSuccess,
                        fileFailure,
                        openSearchSuccess,
                        openSearchFailure));
    }
}
