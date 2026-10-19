package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/** Tests authorization-recovery replay lifetime independently of the production watchdog period. */
class SearchRecoveryBootstrapTest {

    private final CountDownLatch releaseReplay = new CountDownLatch(1);
    private final CountDownLatch watchdogElapsed = new CountDownLatch(1);
    private final ExecutorService replayExecutor = Executors.newSingleThreadExecutor();
    private final Logger.LogListener watchdogListener = (level, message) -> {
        if ("WARN".equals(level) && message.contains("phase=snapshot_replay waitedMs=20 ")) {
            watchdogElapsed.countDown();
        }
    };

    @AfterEach
    void resetRuntime() throws InterruptedException {
        releaseReplay.countDown();
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.setExportRunning(false);
        StartupSnapshotCoordinator.cancelRun(token);
        replayExecutor.shutdownNow();
        try {
            // The outer replay finally block must finish before resetting run-global flags.
            assertThat(replayExecutor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
            assertThat(StartupSnapshotCoordinator.awaitIdle(token, 2_000L)).isTrue();
        } finally {
            Logger.unregisterListener(watchdogListener);
            StartupSnapshotCoordinator.resetForTests();
            RuntimeConfig.resetExportRunForTests();
        }
    }

    @Test
    void replayFlagRemainsSetBeyondWatchdogUntilCoordinatorCompletes() throws Exception {
        RuntimeConfig.setExportRunning(true);
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        CountDownLatch replayStarted = new CountDownLatch(1);
        Logger.registerListener(watchdogListener);

        Future<Boolean> replay = replayExecutor.submit(() ->
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
        assertThat(watchdogElapsed.await(2, TimeUnit.SECONDS))
                .as("The watchdog must actually fire while replay is held").isTrue();
        assertThat(replay.isDone()).isFalse();
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
