package ai.anomalousvectors.tools.burp.utils.concurrent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/** Deterministic fairness and generation-isolation tests for startup snapshot scheduling. */
class StartupSnapshotCoordinatorTest {

    @AfterEach
    void resetCoordinator() {
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.setExportRunning(false);
        StartupSnapshotCoordinator.cancelRun(token);
        StartupSnapshotCoordinator.awaitIdle(token, 2_000L);
        StartupSnapshotCoordinator.resetForTests();
        RuntimeConfig.resetExportRunForTests();
    }

    @Test
    void firstAndSecondRotationsFollowConfigStartLaneOrder() throws Exception {
        RuntimeConfig.setExportRunning(true);
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        StartupSnapshotCoordinator.beginRun(token);
        List<StartupSnapshotCoordinator.Lane> observed =
                Collections.synchronizedList(new ArrayList<>());
        CountDownLatch completed = new CountDownLatch(8);

        for (StartupSnapshotCoordinator.Lane lane : StartupSnapshotCoordinator.Lane.values()) {
            submitTwoTurns(lane, token, observed, completed, new AtomicInteger());
        }
        StartupSnapshotCoordinator.activateRun(token);

        assertThat(completed.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(observed).containsExactly(
                StartupSnapshotCoordinator.Lane.FINDINGS,
                StartupSnapshotCoordinator.Lane.SITEMAP,
                StartupSnapshotCoordinator.Lane.PROXY_HISTORY,
                StartupSnapshotCoordinator.Lane.PROXY_WEBSOCKET,
                StartupSnapshotCoordinator.Lane.FINDINGS,
                StartupSnapshotCoordinator.Lane.SITEMAP,
                StartupSnapshotCoordinator.Lane.PROXY_HISTORY,
                StartupSnapshotCoordinator.Lane.PROXY_WEBSOCKET);
        assertThat(StartupSnapshotCoordinator.awaitIdle(token, 2_000L)).isTrue();
    }

    @Test
    void staleQueuedStepsAreDroppedAndNextStartIsIsolated() throws Exception {
        RuntimeConfig.setExportRunning(true);
        ExportRunToken oldToken = RuntimeConfig.currentExportRunToken();
        StartupSnapshotCoordinator.beginRun(oldToken);
        AtomicInteger oldMutations = new AtomicInteger();
        StartupSnapshotCoordinator.submit(
                StartupSnapshotCoordinator.Lane.FINDINGS,
                oldToken,
                "old",
                oldMutations::incrementAndGet);

        RuntimeConfig.setExportRunning(false);
        StartupSnapshotCoordinator.cancelRun(oldToken);
        StartupSnapshotCoordinator.activateRun(oldToken);
        assertThat(StartupSnapshotCoordinator.awaitIdle(oldToken, 2_000L)).isTrue();

        RuntimeConfig.setExportRunning(true);
        ExportRunToken newToken = RuntimeConfig.currentExportRunToken();
        CountDownLatch nextRan = new CountDownLatch(1);
        StartupSnapshotCoordinator.beginRun(newToken);
        StartupSnapshotCoordinator.submit(
                StartupSnapshotCoordinator.Lane.SITEMAP,
                newToken,
                "new",
                nextRan::countDown);
        StartupSnapshotCoordinator.activateRun(newToken);

        assertThat(nextRan.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(oldMutations).hasValue(0);
        assertThat(newToken.generation()).isGreaterThan(oldToken.generation());
    }

    @Test
    void cancelRunMakesActiveStepObserveStopAndAwaitIdleCompletes() throws Exception {
        RuntimeConfig.setExportRunning(true);
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch exited = new CountDownLatch(1);
        StartupSnapshotCoordinator.submit(
                StartupSnapshotCoordinator.Lane.PROXY_HISTORY,
                token,
                "blocking",
                () -> {
                    started.countDown();
                    while (RuntimeConfig.isExportRunActive(token)) {
                        Thread.onSpinWait();
                    }
                    exited.countDown();
                });

        assertThat(started.await(2, TimeUnit.SECONDS)).isTrue();
        RuntimeConfig.setExportRunning(false);
        StartupSnapshotCoordinator.cancelRun(token);

        assertThat(exited.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(StartupSnapshotCoordinator.awaitIdle(token, 2_000L)).isTrue();
    }

    @Test
    void adaptiveSliceTargetsStartBalancedAndChangeByBoundedSteps() {
        StartupSnapshotCoordinator.Lane lane = StartupSnapshotCoordinator.Lane.FINDINGS;

        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane))
                .isEqualTo(StartupSnapshotCoordinator.INITIAL_SLICE_ITEMS);

        StartupSnapshotCoordinator.recordSliceOutcome(
                lane, "Findings", 0, 50, 1_000_000L, 60_000L, true);
        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane)).isEqualTo(13);

        StartupSnapshotCoordinator.recordSliceOutcome(
                lane, "Findings", 50, 25, 500_000L, 1_000L, true);
        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane)).isEqualTo(19);

        StartupSnapshotCoordinator.recordSliceOutcome(
                lane, "Findings", 75, 37, 700_000L, 15_000L, true);
        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane)).isEqualTo(19);
    }

    @Test
    void recordSliceOutcome_emitsDetailedSchedulingSummaryAtDebugOnly() throws Exception {
        List<String> matchingLevels = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if (message.startsWith("[StartupExport] Findings: slice lane=")) {
                matchingLevels.add(level + ":" + message);
            }
        };
        Logger.registerListener(listener);
        try {
            StartupSnapshotCoordinator.recordSliceOutcome(
                    StartupSnapshotCoordinator.Lane.FINDINGS,
                    "Findings",
                    10,
                    50,
                    1_000_000L,
                    60_000L,
                    true);
            SwingUtilities.invokeAndWait(() -> {});

            assertThat(matchingLevels).singleElement().satisfies(line -> assertThat(line)
                    .startsWith("DEBUG:")
                    .contains(
                            "lane=FINDINGS",
                            "range=10-59",
                            "count=50",
                            "bytes=1000000",
                            "elapsedMs=60000",
                            "nextTarget=13",
                            "reason=shrink_fast"));
        } finally {
            Logger.unregisterListener(listener);
            Logger.resetState();
        }
    }

    @Test
    void adaptiveSliceTargetsResetOnBeginRunAndDoNotChangeAfterFinalSlice() {
        StartupSnapshotCoordinator.Lane lane = StartupSnapshotCoordinator.Lane.SITEMAP;
        StartupSnapshotCoordinator.recordSliceOutcome(
                lane, "Sitemap", 0, 50, 1_000_000L, 60_000L, true);
        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane)).isEqualTo(13);

        StartupSnapshotCoordinator.recordSliceOutcome(
                lane, "Sitemap", 50, 10, 100_000L, 60_000L, false);
        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane)).isEqualTo(13);

        RuntimeConfig.setExportRunning(true);
        StartupSnapshotCoordinator.beginRun(RuntimeConfig.currentExportRunToken());
        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane))
                .isEqualTo(StartupSnapshotCoordinator.INITIAL_SLICE_ITEMS);
    }

    @Test
    void severeMeasuredOverrunShrinksImmediatelyAndKeepsOtherLanesIndependent() {
        StartupSnapshotCoordinator.recordSliceOutcome(
                StartupSnapshotCoordinator.Lane.PROXY_HISTORY,
                "Proxy History",
                0,
                50,
                20_000_000L,
                981_000L,
                true);

        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(
                StartupSnapshotCoordinator.Lane.PROXY_HISTORY)).isEqualTo(1);
        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(
                StartupSnapshotCoordinator.Lane.SITEMAP))
                .isEqualTo(StartupSnapshotCoordinator.INITIAL_SLICE_ITEMS);
    }

    @Test
    void fastSliceWithoutPreparedBytesDoesNotGrowTarget() {
        StartupSnapshotCoordinator.Lane lane = StartupSnapshotCoordinator.Lane.PROXY_WEBSOCKET;

        StartupSnapshotCoordinator.recordSliceOutcome(
                lane, "Proxy WebSocket", 0, 50, 0L, 500L, true);

        assertThat(StartupSnapshotCoordinator.nextSliceItemCount(lane))
                .isEqualTo(StartupSnapshotCoordinator.INITIAL_SLICE_ITEMS);
    }

    private static void submitTwoTurns(
            StartupSnapshotCoordinator.Lane lane,
            ExportRunToken token,
            List<StartupSnapshotCoordinator.Lane> observed,
            CountDownLatch completed,
            AtomicInteger turns) {
        StartupSnapshotCoordinator.submit(
                lane,
                token,
                lane.name(),
                () -> {
                    observed.add(lane);
                    completed.countDown();
                    if (turns.incrementAndGet() == 1) {
                        submitTwoTurns(lane, token, observed, completed, turns);
                    }
                });
    }
}
