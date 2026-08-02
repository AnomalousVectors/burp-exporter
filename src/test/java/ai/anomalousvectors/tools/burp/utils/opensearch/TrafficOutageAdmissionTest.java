package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class TrafficOutageAdmissionTest {

    @Test
    void softOutage_acceptsLiveTrafficIntoSpill_andRefillCanResumeAfterCooldown() {
        ConfigState.State previous = RuntimeConfig.getState();
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        RuntimeConfig.setExportRunning(false);
        TrafficExportQueue.stopWorker(0L);
        TrafficExportQueue.clearPendingWork();
        BulkRateLimitBackoff.clear();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(
                            true, "C:\\temp", true, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.setExportStarting(false);
            coordinator.setSoftCapacityOutageForTests(true);
            BulkRateLimitBackoff.noteRateLimited(
                    429, null, "tool-burp-traffic", "Prepared bulk");

            boolean accepted = TrafficExportQueue.offerAccepted(
                    Map.of("burp", Map.of("reporting_tool", "Proxy")));

            assertThat(accepted).isTrue();
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isEqualTo(1);
            assertThat(ExportAdmissionController.shouldRefillFromSpill()).isFalse();

            BulkRateLimitBackoff.clearCooldownDeadline();

            assertThat(ExportAdmissionController.shouldRefillFromSpill()).isTrue();
        } finally {
            coordinator.setSoftCapacityOutageForTests(false);
            RuntimeConfig.setExportRunning(false);
            TrafficExportQueue.stopWorker(0L);
            TrafficExportQueue.clearPendingWork();
            BulkRateLimitBackoff.clear();
            RuntimeConfig.updateState(previous);
        }
    }
}
