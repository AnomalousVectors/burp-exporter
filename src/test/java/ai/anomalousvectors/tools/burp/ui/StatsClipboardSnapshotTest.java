package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

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
        assertThat(text).contains("Proxy Correlation");
        assertThat(text).contains("Proxy / HTTP Request Callbacks: 0 / 0");
        assertThat(text).contains("HTTP Marked / Responses: 0 / 0");
        assertThat(text).contains("Unmarked Tracked / Pre-Run: 0 / 0");
        assertThat(text).contains("History Lookups / Matched Rows: 0 / 0");
        assertThat(text).contains("Pending Memory: 0 / 0 B");
        assertThat(text).contains("Pending Durable: 0 / 0 B");
        assertThat(text).contains("Bound / Eligible: 0 / 0");
        assertThat(text).contains("Durable Spool Total: 0");
        assertThat(text).contains("Lookup / Cleanup Failures: 0 / 0");
        assertThat(text).contains("Spool / Explicit Failures: 0 / 0");
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

}
