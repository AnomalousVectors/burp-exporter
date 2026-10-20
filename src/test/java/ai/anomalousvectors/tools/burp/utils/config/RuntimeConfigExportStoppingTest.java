package ai.anomalousvectors.tools.burp.utils.config;

import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RuntimeConfigExportStoppingTest {

    /** Resets run globals before each scenario and after its test-owned workers have retired. */
    @BeforeEach
    @AfterEach
    public void reset() {
        RuntimeConfig.resetExportRunForTests();
        RuntimeConfig.setExportStopping(false);
    }

    @Test
    void setExportStopping_tracksStoppingState() {
        assertThat(RuntimeConfig.isExportStopping()).isFalse();

        RuntimeConfig.setExportStopping(true);

        assertThat(RuntimeConfig.isExportStopping()).isTrue();
    }

    @Test
    void setExportRunning_false_preservesActiveStopLifecycle() {
        RuntimeConfig.setExportStopping(true);

        RuntimeConfig.setExportRunning(false);

        assertThat(RuntimeConfig.isExportStopping()).isTrue();
        assertThat(RuntimeConfig.isExportRunning()).isFalse();
    }

    @Test
    void beginExportStop_startsBudgetBeforeWorkerRegistration() {
        RuntimeConfig.beginExportStop();

        assertThat(RuntimeConfig.remainingExportStopBudgetMs())
                .isPositive()
                .isLessThanOrEqualTo(RuntimeConfig.EXPORT_STOP_UX_WALL_CLOCK_MS);
    }

    @Test
    void beginExportStopWorker_preservesPreWorkerForceRequest_andInterruptsImmediately() {
        RuntimeConfig.beginExportStop();
        assertThat(RuntimeConfig.requestExportStopForceAbort()).isTrue();
        Thread worker = new Thread(() -> { }, "test-pre-forced-stop-worker");

        RuntimeConfig.beginExportStopWorker(worker);

        assertThat(RuntimeConfig.isExportStopForceAbortRequested()).isTrue();
        assertThat(worker.isInterrupted()).isTrue();
    }

    @Test
    void runTokenInvalidatesImmediatelyAndNextStartUsesNewGeneration() {
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.ExportRunToken first = RuntimeConfig.currentExportRunToken();
        assertThat(RuntimeConfig.isExportRunActive(first)).isTrue();

        RuntimeConfig.setExportRunning(false);
        assertThat(RuntimeConfig.isExportRunActive(first)).isFalse();
        assertThat(RuntimeConfig.lastInvalidatedExportRunToken()).isEqualTo(first);

        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.ExportRunToken second = RuntimeConfig.currentExportRunToken();
        assertThat(second.generation()).isGreaterThan(first.generation());
        assertThat(RuntimeConfig.isExportRunActive(first)).isFalse();
        assertThat(RuntimeConfig.isExportRunActive(second)).isTrue();
    }

    @Test
    void ordinaryFalseTransition_clearsResolvedNamesOutsideStopLifecycle() {
        RuntimeConfig.setExportRunning(true);
        assertThat(RuntimeConfig.prepareIndexNamesForCurrentRun().valid()).isTrue();
        assertThat(RuntimeConfig.resolvedIndexNamesAt()).isNotEqualTo(Instant.EPOCH);

        RuntimeConfig.setExportRunning(false);

        assertThat(RuntimeConfig.resolvedIndexNamesAt()).isEqualTo(Instant.EPOCH);
    }

    @Test
    void requestExportStopForceAbort_interruptsRegisteredStopWorker() throws Exception {
        Thread worker = new Thread(() -> {
            try {
                Thread.sleep(30_000L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "test-export-stop-worker");
        try {
            worker.start();
            RuntimeConfig.beginExportStop();
            RuntimeConfig.beginExportStopWorker(worker);
            assertThat(RuntimeConfig.requestExportStopForceAbort()).isTrue();
            assertThat(RuntimeConfig.isExportStopForceAbortRequested()).isTrue();
            assertThat(RuntimeConfig.requestExportStopForceAbort()).isFalse();
            worker.join(2_000L);
            assertThat(worker.isAlive()).isFalse();
        } finally {
            worker.interrupt();
            try {
                worker.join(1_000L);
                assertThat(worker.isAlive()).as("The registered fixture worker must retire").isFalse();
            } finally {
                RuntimeConfig.endExportStopWorker(worker);
                RuntimeConfig.clearExportStopForceAbort();
            }
        }
    }

    @Test
    void awaitExportStopWorker_timesOutForNonCooperativeOwner_withoutClearingRegistration()
            throws Exception {
        AtomicBoolean release = new AtomicBoolean();
        AtomicBoolean releaseReplacement = new AtomicBoolean();
        Thread worker = new Thread(() -> {
            while (!release.get()) {
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5L));
                Thread.interrupted();
            }
        }, "test-stubborn-export-stop-worker");
        Thread replacement = new Thread(() -> {
            while (!releaseReplacement.get()) {
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5L));
                Thread.interrupted();
            }
        }, "test-replacement-export-stop-worker");
        try {
            worker.start();
            RuntimeConfig.beginExportStop();
            RuntimeConfig.beginExportStopWorker(worker);
            RuntimeConfig.requestExportStopForceAbort();

            assertThat(RuntimeConfig.awaitExportStopWorker(25L)).isFalse();

            replacement.start();
            RuntimeConfig.beginExportStopWorker(replacement);
            RuntimeConfig.endExportStopWorker(worker);
            assertThat(RuntimeConfig.awaitExportStopWorker(0L)).isFalse();
            releaseReplacement.set(true);
            LockSupport.unpark(replacement);
            replacement.join(1_000L);
            assertThat(replacement.isAlive()).isFalse();
            RuntimeConfig.endExportStopWorker(replacement);
        } finally {
            // Retain both exact owners: a failed stale-owner assertion must not strand replacement.
            release.set(true);
            releaseReplacement.set(true);
            LockSupport.unpark(worker);
            LockSupport.unpark(replacement);
            worker.interrupt();
            replacement.interrupt();
            try {
                worker.join(1_000L);
                replacement.join(1_000L);
                assertThat(worker.isAlive()).isFalse();
                assertThat(replacement.isAlive()).isFalse();
            } finally {
                RuntimeConfig.endExportStopWorker(worker);
                RuntimeConfig.endExportStopWorker(replacement);
                RuntimeConfig.clearExportStopForceAbort();
            }
        }
    }
}
