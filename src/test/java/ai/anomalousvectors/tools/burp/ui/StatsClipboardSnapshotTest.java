package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.search.IndexingRetryCoordinator;

/** Unit tests for {@link StatsClipboardSnapshot}. */
class StatsClipboardSnapshotTest {

    private final List<String> infoMessages = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level)) {
            infoMessages.add(message);
        }
    };

    private ConfigState.State previousState;

    @BeforeEach
    public void setUp() {
        ConfigPanel.shutdownStartupExecutor();
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
        previousState = RuntimeConfig.getState();
        RuntimeConfig.updateState(new ConfigState.State(
                java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                java.util.List.of(),
                new ConfigState.Sinks(true, "/tmp/export", true, false,
                        true, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.setExportStopping(false);
        ExportStats.recordSuccess("traffic", 100);
        FileExportStats.recordSuccess("traffic", 101);
        ExportStats.recordBodyEnumerationMisgateSuspect();
    }

    @AfterEach
    public void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        IndexingRetryCoordinator.getInstance().stopDrainThread();
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        RuntimeConfig.setExportStopping(false);
        ExportStats.resetForTests();
        FileExportStats.resetForTests();
        if (previousState != null) {
            RuntimeConfig.updateState(previousState);
        }
        ConfigPanel.shutdownStartupExecutor();
    }

    @Test
    void buildClipboardText_includesFileOpenSearchTablesAndParameterIntegrity() {
        ExportStats.recordPermanentDropReason(ExportStats.PERMANENT_DROP_REASON_MAX_FIT, 2);
        ExportStats.recordSearchBodyPrefixTruncation("traffic");
        ExportStats.reserveSnapshotBuildAhead(4, 256L * 1024L);
        ExportStats.recordLastActiveSearchCapacity(5L * 1024L * 1024L, 3);
        FileExportStats.recordRetryAttempt("traffic", 2);
        FileExportStats.recordArtifactRegistration("traffic", 1024L);
        FileExportStats.recordExportedBytes("traffic", 2048L);
        FileExportStats.recordArtifactCompletion(
                "traffic",
                1024L,
                3072L,
                3072L,
                FileExportStats.ArtifactIntegrity.OK,
                null);
        String text = StatsClipboardSnapshot.buildClipboardText();

        assertThat(text).contains("File Counts");
        assertThat(text).contains(
                "Index\tWritten\tFailures\tRetry Attempts\tBaseline\tAppended\tFinal Size\tIntegrity"
                        + "\tLast Append (ms)\tLast Error");
        assertThat(text).contains("Database Counts");
        assertThat(text).contains(
                "Index\tExported\tFailures\tQueued\tRecovered Failures\tRetry Drops\tPermanent Drops\tLast Bulk (ms)\tLast Error");
        assertThat(text).contains("Misc Stats");
        assertThat(text).contains("Traffic\t101");
        assertThat(text).contains("Traffic\t101\t0\t2");
        assertThat(text).contains("1.0 KiB\t2.0 KiB\t3.0 KiB\tOK");
        assertThat(text).contains("Traffic\t100");
        assertThat(text).contains("Mis-gate Suspects: 1");
        assertThat(text).contains("Export Running: No");
        assertThat(text).contains("Soft Outage: No");
        assertThat(text).contains("Authorization Failures: No");
        assertThat(text).contains("Database Exported Size:");
        assertThat(text).contains("Files Exported Size:");
        assertThat(text).contains("Traffic Spill Status:");
        assertThat(text.substring(text.indexOf("\nOverview\n"), text.indexOf("\nProcess\n")))
                .doesNotContain("Streaming Recovery", "tracking=");
        assertThat(text).contains("\nStreaming Recovery\n  Status: "
                + ai.anomalousvectors.tools.burp.sinks.StreamingProxyRecovery.status());
        assertThat(text).doesNotContain("Proxy Correlation", "History Lookups", "Pending Durable");
        assertThat(text).contains("Permanent Drop Reasons: max_fit_exceeded=2");
        assertThat(text).contains("Body Truncations by Index: traffic: 1");
        assertThat(text).contains("Snapshot Build-Ahead: 256.0 KiB / 64.0 MiB (4 / 1,024 permits)");
        assertThat(text).contains("Peak Snapshot Build-Ahead: 256.0 KiB (4 permits)");
        assertThat(text).contains("Bulk Byte Budget: 5.0 MiB");
        assertThat(text).contains("Snapshot Flush Cap: 3");
        assertThat(text).contains("Count Basis: Session counters; no Stop readback");
        assertThat(text).doesNotContain("Authorization Recovery:");
        // Legacy standalone labels (substring "Exported Size:" appears inside the new names).
        assertThat(text).doesNotContain("\n  Exported Size:");
        assertThat(text).doesNotContain("File Total Size Exported:");
        assertThat(text).contains("Capacity Events: 0");
        assertThat(text).contains("Peak Cooldown Wait (ms):");
        assertThat(text).contains("Peak Flush Slot Wait (ms):");
    }

    @Test
    void liveCaptureResourcesAppearInClipboardAndStopSummary() throws Exception {
        ExportAdmissionController.setMemBudgetOverrideForTests(8L * 1024L * 1024L);
        long reserved = 2048L;
        assertThat(ExportAdmissionController.tryReserveLiveBytes(reserved)).isTrue();
        try {
            String text = StatsClipboardSnapshot.buildClipboardText();
            assertThat(text).contains("Live Bytes / Limit (est.): 2.0 KiB / 8.0 MiB");
            assertThat(text).contains("Preparation Queued / Active: "
                    + ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler.preparationStatus());
            StatsClipboardSnapshot.logSessionStopSummary();
            SwingUtilities.invokeAndWait(() -> {});
            var payload = JsonMapper.builderWithJackson2Defaults().build().readTree(
                    infoMessages.get(1).substring("[Stats] Session stop ".length()));
            var capture = payload.path("sections").path("Live HTTP Capture");
            assertThat(capture.path("Live Bytes / Limit (est.)").asString())
                    .isEqualTo("2.0 KiB / 8.0 MiB");
            assertThat(capture.path("Preparation Queued / Active").asString())
                    .isEqualTo(ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler.preparationStatus());
        } finally {
            ExportAdmissionController.releaseLiveBytes(reserved);
            ExportAdmissionController.setMemBudgetOverrideForTests(null);
        }
    }

    @Test
    void logSessionStopSummary_emitsFileAndMiscJson_withoutDatabaseReadbackCounts() throws Exception {
        ExportStats.recordLastActiveSearchCapacity(5L * 1024L * 1024L, 3);
        StatsClipboardSnapshot.logSessionStopSummary();
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(infoMessages).hasSize(2);
        assertThat(infoMessages.get(0)).startsWith("[Stats] Session stop {\"kind\":\"file_counts\"");
        assertThat(infoMessages.get(1)).startsWith("[Stats] Session stop {\"kind\":\"misc_stats\"");
        for (String line : infoMessages) {
            assertThat(line).doesNotContain("\n").doesNotContain("\r");
            assertThat(line).contains("\"kind\":");
        }
        assertThat(infoMessages.get(1))
                .contains("Mis-gate Suspects")
                .contains("\"Bulk Byte Budget\":\"5.0 MiB\"")
                .contains("\"Snapshot Flush Cap\":\"3\"");
        var payload = JsonMapper.builderWithJackson2Defaults().build().readTree(
                infoMessages.get(1).substring("[Stats] Session stop ".length()));
        assertThat(payload.path("sections").path("Overview").has("Streaming Recovery")).isFalse();
        assertThat(payload.path("sections").path("Overview").has("Request Receipts / Limit")).isFalse();
        assertThat(payload.path("sections").path("Live HTTP Capture").has("Request Receipts / Limit")).isTrue();
        assertThat(payload.path("sections").path("Live HTTP Capture").has("Reclaimed Request Receipts")).isTrue();
        assertThat(payload.path("sections").path("Live HTTP Capture").has("Request Receipt Rejections")).isTrue();
        assertThat(payload.path("sections").path("Streaming Recovery").path("Status").asString())
                .isEqualTo(ai.anomalousvectors.tools.burp.sinks.StreamingProxyRecovery.status());
        assertThat(infoMessages).noneMatch(message -> message.contains("\"kind\":\"search_counts\""));
    }

    @Test
    void stopDiscardDropsRemainVisibleWithoutDatabaseCountLog() throws Exception {
        ExportStats.recordFailure("traffic", 2);
        ExportStats.recordPermanentDrop("traffic", 2);
        ExportStats.recordPermanentDropReason(ExportStats.PERMANENT_DROP_REASON_STOP, 2);
        StatsClipboardSnapshot.logSessionStopSummary();
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(ExportStats.getPermanentDrops("traffic")).isEqualTo(2);
        assertThat(infoMessages).noneMatch(message -> message.contains("\"kind\":\"search_counts\""));
        String miscStats = infoMessages.stream()
                .filter(message -> message.contains("\"kind\":\"misc_stats\""))
                .findFirst()
                .orElseThrow();
        assertThat(miscStats).contains("Permanent Drop Reasons").contains("stop_discard=2");
    }

    @Test
    void stopSummaryPreservesAllThrottledCaptureAndSpillFailureTotals() throws Exception {
        ExportStats.recordTrafficDropReason("capture_capacity", 7);
        ExportStats.recordTrafficDropReason("preparation_failed", 11);
        ExportStats.recordTrafficDropReason("spill_failure_reject_new", 13);
        var detached = ExportStats.getTrafficDropReasonCounts();
        ExportStats.recordTrafficDropReason("capture_capacity", 2);
        assertThat(detached.get("capture_capacity")).isEqualTo(7L);
        StatsClipboardSnapshot.logSessionStopSummary();
        SwingUtilities.invokeAndWait(() -> {});
        String misc = infoMessages.stream().filter(message -> message.contains("\"kind\":\"misc_stats\""))
                .findFirst().orElseThrow();
        var payload = JsonMapper.builderWithJackson2Defaults().build()
                .readTree(misc.substring("[Stats] Session stop ".length()));
        var reasons = payload.path("traffic_drop_reasons");
        assertThat(reasons.path("capture_capacity").asLong()).isEqualTo(9L);
        assertThat(reasons.path("preparation_failed").asLong()).isEqualTo(11L);
        assertThat(reasons.path("spill_failure_reject_new").asLong()).isEqualTo(13L);
    }

}
