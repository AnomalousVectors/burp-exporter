package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.SearchRecoveryBootstrap;
import ai.anomalousvectors.tools.burp.utils.ControlStatusBridge;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;

/** Tests the multi-stage authorization-recovery transition. */
class IndexingRetryCoordinatorAuthorizationRecoveryTest {

    @Test
    void successfulProbe_revalidatesThenReplaysBeforeResuming() {
        ConfigState.State previous = RuntimeConfig.getState();
        IndexingRetryCoordinator coordinator = new IndexingRetryCoordinator();
        List<String> order = new CopyOnWriteArrayList<>();
        AtomicBoolean identityChanged = new AtomicBoolean();
        AtomicReference<String> status = new AtomicReference<>();
        try {
            configureRunningOpenSearch();
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            coordinator.recordHealthyClusterIdentity("old-cluster");
            coordinator.setAuthorizationRecoveryHooksForTests(
                    ignored -> successfulStatus("new-cluster"),
                    (baseUrl, changed, runToken) -> {
                        order.add("revalidate");
                        identityChanged.set(changed);
                        assertThat(runToken).isEqualTo(token);
                        return new SearchRecoveryBootstrap.RecoveryPreparation(
                                true, true, "ready");
                    },
                    runToken -> {
                        order.add("replay");
                        assertThat(runToken).isEqualTo(token);
                        return true;
                    });
            ControlStatusBridge.register(status::set);
            coordinator.enterAuthorizationRecoveryPauseForTests(failedStatus());

            coordinator.probeAuthorizationRecoveryForTests(token);

            assertThat(order).containsExactly("revalidate", "replay");
            assertThat(identityChanged).isTrue();
            assertThat(coordinator.isAuthorizationRecoveryPaused()).isFalse();
            assertThat(status.get()).isEqualTo("OpenSearch: Running");
        } finally {
            coordinator.setAuthorizationRecoveryHooksForTests(null, null, null);
            coordinator.clearPendingWork();
            ControlStatusBridge.clear();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void probeWithUnreadyRevalidation_remainsPausedAndDoesNotReplay() {
        ConfigState.State previous = RuntimeConfig.getState();
        IndexingRetryCoordinator coordinator = new IndexingRetryCoordinator();
        AtomicInteger replays = new AtomicInteger();
        try {
            configureRunningOpenSearch();
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            coordinator.setAuthorizationRecoveryHooksForTests(
                    ignored -> successfulStatus("cluster"),
                    (baseUrl, changed, runToken) ->
                            new SearchRecoveryBootstrap.RecoveryPreparation(
                                    false, false, "mapping unavailable"),
                    runToken -> {
                        replays.incrementAndGet();
                        return true;
                    });
            coordinator.enterAuthorizationRecoveryPauseForTests(failedStatus());

            coordinator.probeAuthorizationRecoveryForTests(token);

            assertThat(coordinator.isAuthorizationRecoveryPaused()).isTrue();
            assertThat(replays).hasValue(0);
        } finally {
            coordinator.setAuthorizationRecoveryHooksForTests(null, null, null);
            coordinator.clearPendingWork();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(previous);
        }
    }

    private static void configureRunningOpenSearch() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        false,
                        "",
                        true,
                        "https://opensearch.url:9200",
                        "",
                        "",
                        false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }

    private static SearchConnectionStatus successfulStatus(String clusterUuid) {
        return new SearchConnectionStatus(
                "OpenSearch",
                true,
                "opensearch",
                "3",
                clusterUuid,
                "Connected",
                "Connected",
                "Authenticated",
                "Trusted");
    }

    private static SearchConnectionStatus failedStatus() {
        return new SearchConnectionStatus(
                "OpenSearch",
                false,
                "",
                "",
                "",
                "HTTP 403 Forbidden",
                "Connected",
                "Failed",
                "Trusted");
    }
}
