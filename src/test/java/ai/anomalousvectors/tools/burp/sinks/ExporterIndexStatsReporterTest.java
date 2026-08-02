package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class ExporterIndexStatsReporterTest {

    private final ConfigState.State previousState = RuntimeConfig.getState();

    private void tearDown() {
        ExporterIndexStatsReporter.stop();
        RuntimeConfig.updateState(previousState);
        RuntimeConfig.setExportRunning(false);
        ExportStats.resetForTests();
        FileExportService.resetForTests();
    }

    @Test
    void unloadFinalSnapshotIsAttemptedOnlyForAnActiveRun() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "build/tmp/unload-final", true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            ExportStats.recordSuccess("exporter", 1);

            RuntimeConfig.setExportRunning(false);
            assertThat(ExporterIndexStatsReporter.shouldAttemptFinalPushOnUnload()).isFalse();

            RuntimeConfig.setExportRunning(true);
            assertThat(ExporterIndexStatsReporter.shouldAttemptFinalPushOnUnload()).isTrue();
        } finally {
            tearDown();
        }
    }

    @Test
    void pushFinalSnapshotNow_writesExporterStats_whenExportStopped() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-stats-final-stop");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(false);
            ExportStats.recordBodyEnumerationMisgateSuspect();
            ExportStats.recordPermanentDropReason(
                    ExportStats.PERMANENT_DROP_REASON_MAX_FIT, 1);

            ExporterStatsPushOutcome outcome = ExporterIndexStatsReporter.pushFinalSnapshotNow();

            assertThat(outcome.succeeded()).isTrue();
            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl");
            assertThat(jsonlPath).exists();
            String jsonl = Files.readString(jsonlPath);
            assertThat(jsonl).contains("stats_snapshot");
            assertThat(jsonl).contains("\"running\":false");
            assertThat(jsonl).contains("docs_body_enumeration_misgate_suspect_total");
            assertThat(jsonl)
                    .contains("\"permanent_drop_reason_counts\":{\"max_fit_exceeded\":1}");
        } finally {
            tearDown();
        }
    }

    @Test
    void pushFinalSnapshotNow_succeedsWithFileSinkOnlyWhenOpenSearchDisabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-stats-file-only-final");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(false);

            assertThat(RuntimeConfig.isOpenSearchActive()).isFalse();

            ExporterStatsPushOutcome outcome = ExporterIndexStatsReporter.pushFinalSnapshotNow();

            assertThat(outcome.succeeded()).isTrue();
            assertThat(root.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl")).exists();
        } finally {
            tearDown();
        }
    }

    @Test
    void pushFinalSnapshotNow_returnsSkippedDisabled_whenStatsSubOptionOff() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "", true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    List.of(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_CONFIG),
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(false);

            ExporterStatsPushOutcome outcome = ExporterIndexStatsReporter.pushFinalSnapshotNow();

            assertThat(outcome.kind()).isEqualTo(ExporterStatsPushOutcome.Kind.SKIPPED_DISABLED);
        } finally {
            tearDown();
        }
    }

    @Test
    void finalSnapshotDoc_countsPendingExporterStatsDocumentWhenOpenSearchActive() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, "build/tmp/stats-reporter", true, false,
                            true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            ExportStats.recordSuccess("exporter", 7);
            ExportStats.recordSuccess("traffic", 3);
            ExportStats.recordSearchBodyPrefixTruncation("traffic");
            ExportStats.reserveSnapshotBuildAhead(4, 256L * 1024L);
            FileExportStats.recordSuccess("traffic", 3);
            FileExportStats.recordFailure("traffic", 1);
            FileExportStats.recordRetryAttempt("traffic", 2);

            Map<?, ?> doc = asMap(callStatic(ExporterIndexStatsReporter.class, "buildSnapshotDoc", true));
            Map<?, ?> event = asMap(doc.get("event"));
            Map<?, ?> data = asMap(event.get("data"));
            Map<?, ?> indexes = asMap(data.get("indexes"));
            Map<?, ?> exporter = asMap(indexes.get("exporter"));
            Map<?, ?> traffic = asMap(indexes.get("traffic"));
            Map<?, ?> stats = asMap(data.get("stats"));
            Map<?, ?> buildAhead = asMap(stats.get("snapshot_build_ahead"));

            assertThat(exporter.get("exported")).isEqualTo(8L);
            assertThat(exporter.get("count")).isEqualTo(8L);
            assertThat(traffic.get("exported")).isEqualTo(3L);
            assertThat(traffic.get("body_truncations")).isEqualTo(1L);
            assertThat(traffic.get("file_written")).isEqualTo(3L);
            assertThat(traffic.get("file_failures")).isEqualTo(1L);
            assertThat(traffic.get("file_retry_attempts")).isEqualTo(2L);
            assertThat(buildAhead.get("current_reserved_bytes")).isEqualTo(256L * 1024L);
            assertThat(buildAhead.get("current_reserved_permits")).isEqualTo(4);
            assertThat(buildAhead.get("peak_reserved_bytes")).isEqualTo(256L * 1024L);
            assertThat(buildAhead.get("capacity_bytes")).isEqualTo(64L * 1024L * 1024L);
            assertThat(buildAhead.get("capacity_permits")).isEqualTo(1_024);
            assertThat(ExportStats.getExportedCount("exporter")).isEqualTo(7L);
        } finally {
            tearDown();
        }
    }

    @Test
    void periodicFailureCoalescing_logsFirstAndChangedReasonsOnly() {
        try {
            assertThat(callStatic(ExporterIndexStatsReporter.class,
                    "shouldLogPeriodicFailure", true, "cluster down")).isEqualTo(true);
            assertThat(callStatic(ExporterIndexStatsReporter.class,
                    "shouldLogPeriodicFailure", true, "cluster down")).isEqualTo(false);
            assertThat(callStatic(ExporterIndexStatsReporter.class,
                    "shouldLogPeriodicFailure", true, "auth failed")).isEqualTo(true);
            assertThat(callStatic(ExporterIndexStatsReporter.class,
                    "shouldLogPeriodicFailure", false, "auth failed")).isEqualTo(false);
        } finally {
            tearDown();
        }
    }

    @Test
    void pushSnapshotNow_writesExporterStats_whenExporterStatsEnabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-stats-file-only");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);
            ExportStats.recordRepeaterMetadataSource("request_identity");

            ExporterIndexStatsReporter.pushSnapshotNow();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl");
            assertThat(jsonlPath).exists();
            String jsonl = Files.readString(jsonlPath);
            assertThat(jsonl).contains("stats_snapshot");
            assertThat(jsonl)
                    .contains("\"jvm\"")
                    .contains("\"indexes\"")
                    .contains("\"exporter\"")
                    .contains("\"traffic\"")
                    .contains("\"spill\"")
                    .contains("\"queue_bytes_estimate\"")
                    .contains("\"active_drain_batches\"")
                    .contains("\"stats\"")
                    .contains("\"snapshot_flush_executor\"")
                    .contains("\"dual_sink\"")
                    .contains("\"repeater_live_metadata_sources\"")
                    .contains("request_identity");
            assertThat(jsonl)
                    .doesNotContain("repeater_live_metadata_source_summary")
                    .doesNotContain("traffic_indexed_count")
                    .doesNotContain("total_indexed_bytes")
                    .doesNotContain("traffic_opensearch_tool_type_success");
        } finally {
            tearDown();
        }
    }

    @Test
    void pushSnapshotNow_skipsWrite_whenExporterStatsDisabled() throws Exception {
        try {
            Path root = TestPathSupport.createDirectory("exporter-stats-disabled");
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(true, root.toString(), true, false,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    List.of(ConfigKeys.SRC_EXPORTER_INFO, ConfigKeys.SRC_EXPORTER_CONFIG),
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            ExporterIndexStatsReporter.pushSnapshotNow();

            Path jsonlPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".jsonl");
            assertThat(jsonlPath).doesNotExist();
        } finally {
            tearDown();
        }
    }

    @Test
    void refreshScheduleForCurrentState_recreatesScheduler_whenIntervalChanges() {
        try {
            RuntimeConfig.updateState(stateWithInterval(30));
            RuntimeConfig.setExportRunning(true);

            ExporterIndexStatsReporter.refreshScheduleForCurrentState();

            LazyScheduler holder = LazyScheduler.class.cast(getStatic(ExporterIndexStatsReporter.class, "SCHEDULER"));
            ScheduledExecutorService firstScheduler = holder.peek();
            assertThat(firstScheduler).isNotNull();
            assertThat(Integer.class.cast(getStatic(ExporterIndexStatsReporter.class, "scheduledIntervalSeconds"))).isEqualTo(30);

            RuntimeConfig.updateState(stateWithInterval(45));
            ExporterIndexStatsReporter.refreshScheduleForCurrentState();

            ScheduledExecutorService secondScheduler = holder.peek();
            assertThat(secondScheduler).isNotNull();
            assertThat(secondScheduler).isNotSameAs(firstScheduler);
            assertThat(Integer.class.cast(getStatic(ExporterIndexStatsReporter.class, "scheduledIntervalSeconds"))).isEqualTo(45);
        } finally {
            tearDown();
        }
    }

    private static ConfigState.State stateWithInterval(int intervalSeconds) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_EXPORTER),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, false,
                        false, "https://opensearch.url:9200", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                intervalSeconds,
                null);
    }

    private static Map<?, ?> asMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }
}
