package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/** Tests authorization-recovery replay lifetime independently of the production watchdog period. */
class SearchRecoveryBootstrapTest {

    private final CountDownLatch releaseReplay = new CountDownLatch(1);

    @AfterEach
    void resetRuntime() {
        releaseReplay.countDown();
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.setExportRunning(false);
        StartupSnapshotCoordinator.cancelRun(token);
        StartupSnapshotCoordinator.awaitIdle(token, 2_000L);
        StartupSnapshotCoordinator.resetForTests();
        RuntimeConfig.resetExportRunForTests();
    }

    @Test
    void replayFlagRemainsSetBeyondWatchdogUntilCoordinatorCompletes() throws Exception {
        RuntimeConfig.setExportRunning(true);
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        CountDownLatch replayStarted = new CountDownLatch(1);

        CompletableFuture<Boolean> replay = CompletableFuture.supplyAsync(() ->
                SearchRecoveryBootstrap.runReplayWithWatchdog(
                        token,
                        20L,
                        () -> StartupSnapshotCoordinator.submit(
                                StartupSnapshotCoordinator.Lane.FINDINGS,
                                token,
                                "test-replay",
                                () -> {
                                    replayStarted.countDown();
                                    awaitRelease();
                                }),
                        () -> true));

        assertThat(replayStarted.await(2, TimeUnit.SECONDS)).isTrue();
        TimeUnit.MILLISECONDS.sleep(80L);
        assertThat(replay).isNotDone();
        assertThat(RuntimeConfig.isSearchRecoveryReplay()).isTrue();

        releaseReplay.countDown();

        assertThat(replay.get(2, TimeUnit.SECONDS)).isTrue();
        assertThat(RuntimeConfig.isSearchRecoveryReplay()).isFalse();
    }

    private void awaitRelease() {
        try {
            releaseReplay.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
