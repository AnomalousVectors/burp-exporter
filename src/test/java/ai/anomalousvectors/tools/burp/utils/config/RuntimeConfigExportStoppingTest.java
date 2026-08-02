package ai.anomalousvectors.tools.burp.utils.config;

import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RuntimeConfigExportStoppingTest {

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
        worker.start();
        try {
            RuntimeConfig.beginExportStop();
            RuntimeConfig.beginExportStopWorker(worker);
            assertThat(RuntimeConfig.requestExportStopForceAbort()).isTrue();
            assertThat(RuntimeConfig.isExportStopForceAbortRequested()).isTrue();
            assertThat(RuntimeConfig.requestExportStopForceAbort()).isFalse();
            worker.join(2_000L);
            assertThat(worker.isAlive()).isFalse();
        } finally {
            RuntimeConfig.endExportStopWorker();
            RuntimeConfig.clearExportStopForceAbort();
            if (worker.isAlive()) {
                worker.interrupt();
                worker.join(1_000L);
            }
        }
    }
}
