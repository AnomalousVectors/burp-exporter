package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class ExporterIndexLogForwarderTest {

    @Test
    void onLog_noops_beforeStart_and_doesNotQueueWork() {
        ExporterIndexLogForwarder forwarder = new ExporterIndexLogForwarder();
        try {
            RuntimeConfig.setExportRunning(false);

            forwarder.onLog("INFO", "pre-start log");
        } finally {
            forwarder.stop();
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void onLog_noops_duringStartupBootstrap_and_doesNotQueueWork() {
        ExporterIndexLogForwarder forwarder = new ExporterIndexLogForwarder();
        try {
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(true);

            forwarder.onLog("INFO", "startup log");
        } finally {
            forwarder.stop();
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void onLog_writesExporterLog_whenOnlyFileExportIsEnabled_andSavedOpenSearchUrlExists() throws Exception {
        ExporterIndexLogForwarder forwarder = null;
        try {
            Path root = TestPathSupport.createDirectory("exporter-log-file-only");
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(true, root.toString(), false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);
            long openSearchExporterSuccessBefore = ExportStats.getSuccessCount("exporter");
            forwarder = new ExporterIndexLogForwarder();

            forwarder.onLog("INFO", "file-only log");

            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".ndjson");
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(250L);
            assertThat(ndjsonPath).exists();
            assertThat(Files.readString(ndjsonPath)).contains("file-only log");
            assertThat(ExportStats.getSuccessCount("exporter")).isEqualTo(openSearchExporterSuccessBefore);
        } finally {
            if (forwarder != null) {
                forwarder.stop();
            }
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void onLog_skipsFileWrite_whenExporterSourceDisabled() throws Exception {
        ExporterIndexLogForwarder forwarder = null;
        try {
            Path root = TestPathSupport.createDirectory("exporter-log-disabled");
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(true, root.toString(), false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);
            forwarder = new ExporterIndexLogForwarder();

            forwarder.onLog("INFO", "should not be exported");
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(250L);

            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".ndjson");
            assertThat(ndjsonPath).doesNotExist();
        } finally {
            if (forwarder != null) {
                forwarder.stop();
            }
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void stop_terminatesWorkerExecutor_onUnload() throws Exception {
        ExporterIndexLogForwarder forwarder = new ExporterIndexLogForwarder();
        ExecutorService worker = workerOf(forwarder);
        try {
            assertThat(worker.isShutdown()).isFalse();

            forwarder.stop();

            assertThat(worker.isShutdown()).isTrue();
            assertThat(worker.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
        } finally {
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void onLog_skipsExporterStatsAndBulkLifecycleNoise() throws Exception {
        ExporterIndexLogForwarder forwarder = null;
        try {
            Path root = TestPathSupport.createDirectory("exporter-log-noise-filter");
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_EXPORTER),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(true, root.toString(), false, true,
                            false, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null
            ));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);
            forwarder = new ExporterIndexLogForwarder();

            forwarder.onLog("INFO", "[PeriodicExport] Exporter stats: push failed index=tool-burp-exporter reason=busy.");
            forwarder.onLog("INFO", "[Amazon OpenSearch] Bulk HTTP slow response: requestId=1 index=tool-burp-exporter.");
            forwarder.onLog("INFO", "keep this operator line");
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(250L);

            Path ndjsonPath = root.resolve(IndexNaming.indexNameForShortName("exporter") + ".ndjson");
            assertThat(ndjsonPath).exists();
            String body = Files.readString(ndjsonPath);
            assertThat(body).contains("keep this operator line");
            assertThat(body).doesNotContain("Exporter stats: push failed");
            assertThat(body).doesNotContain("Bulk HTTP slow response");
        } finally {
            if (forwarder != null) {
                forwarder.stop();
            }
            RuntimeConfig.setExportRunning(false);
            BurpRuntimeMetadata.clear();
            MontoyaApiProvider.set(null);
        }
    }

    private static ExecutorService workerOf(ExporterIndexLogForwarder forwarder) throws Exception {
        Field field = ExporterIndexLogForwarder.class.getDeclaredField("worker");
        field.setAccessible(true);
        return (ExecutorService) field.get(forwarder);
    }
}
