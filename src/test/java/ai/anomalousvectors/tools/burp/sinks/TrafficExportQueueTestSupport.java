package ai.anomalousvectors.tools.burp.sinks;

import java.util.List;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Helpers for tests that assert {@link TrafficExportQueue} depth without racing the drain worker.
 */
final class TrafficExportQueueTestSupport {

    private static final String TEST_SEARCH_URL = "https://opensearch.url:9200";

    private TrafficExportQueueTestSupport() {}

    /**
     * Runs {@code action} with the drain worker and inherited destination pressure suppressed.
     *
     * <p>This guarantees accepted documents remain in memory unless the action itself changes an
     * admission budget or pressure state.</p>
     */
    static void withDrainWorkerDisabled(ThrowingRunnable action) throws Exception {
        TrafficExportQueue.setDrainDisabledForTests(true);
        try {
            TrafficExportQueue.stopWorker();
            TrafficExportQueue.clearPendingWork();
            resetAdmissionState();
            action.run();
        } finally {
            TrafficExportQueue.setDrainDisabledForTests(false);
            TrafficExportQueue.stopWorker();
            TrafficExportQueue.clearPendingWork();
            resetAdmissionState();
        }
    }

    static void configureRunningTraffic(List<String> toolTypes) {
        RuntimeConfig.setExportRunning(false);
        updateTrafficTools(toolTypes);
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
    }

    static void updateTrafficTools(List<String> toolTypes) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                enabledTestSearchSink(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                toolTypes,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
    }

    private static ConfigState.Sinks enabledTestSearchSink() {
        return new ConfigState.Sinks(
                false,
                "",
                false,
                false,
                true,
                ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                true,
                ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                true,
                TEST_SEARCH_URL,
                "",
                "",
                ConfigState.OPEN_SEARCH_TLS_VERIFY,
                ConfigState.defaultOpenSearchOptions(),
                ConfigState.DEFAULT_SEARCH_DESTINATION,
                "",
                ConfigState.defaultOpenSearchAmazonOptions(),
                "",
                ConfigState.defaultElasticsearchOptions());
    }

    private static void resetAdmissionState() {
        IndexingRetryCoordinator.getInstance().clearPendingWork();
        ExportAdmissionController.resetForTests();
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }
}
