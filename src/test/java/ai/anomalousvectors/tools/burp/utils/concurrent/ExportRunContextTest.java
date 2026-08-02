package ai.anomalousvectors.tools.burp.utils.concurrent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;

/** Verifies stale snapshot contexts cannot update adaptive controllers or emit their logs. */
class ExportRunContextTest {

    @AfterEach
    void resetRuntime() {
        RuntimeConfig.resetExportRunForTests();
        BulkByteBudget.resetForStart();
    }

    @Test
    void staleContextSuppressesLateAdaptiveAndLogMutationAfterNextStart() {
        RuntimeConfig.setExportRunning(true);
        ExportRunToken oldToken = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportRunning(true);

        BatchSizeController batchController = new BatchSizeController();
        int batchBefore = batchController.getCurrentBatchSize();
        BulkByteBudget.resetForStart();
        long bytesBefore = BulkByteBudget.currentMaxBytes();
        AtomicInteger logCalls = new AtomicInteger();
        Logger.LogListener listener = (level, message) -> logCalls.incrementAndGet();
        Logger.registerListener(listener);
        try {
            ExportRunContext.call(oldToken, () -> {
                batchController.recordFailure(batchBefore);
                BulkByteBudget.recordFailure();
                return null;
            });
        } finally {
            Logger.unregisterListener(listener);
        }

        assertThat(batchController.getCurrentBatchSize()).isEqualTo(batchBefore);
        assertThat(BulkByteBudget.currentMaxBytes()).isEqualTo(bytesBefore);
        assertThat(logCalls).hasValue(0);
    }

    @Test
    void call_restoresNestedAndExceptionalThreadContext() {
        RuntimeConfig.setExportRunning(true);
        ExportRunToken outer = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportRunning(true);
        ExportRunToken inner = RuntimeConfig.currentExportRunToken();

        ExportRunContext.call(outer, () -> {
            assertThat(ExportRunContext.currentToken()).isEqualTo(outer);
            ExportRunContext.call(inner, () -> {
                assertThat(ExportRunContext.currentToken()).isEqualTo(inner);
                return null;
            });
            assertThat(ExportRunContext.currentToken()).isEqualTo(outer);
            return null;
        });
        assertThat(ExportRunContext.currentToken()).isNull();
        assertThat(ExportRunContext.allowsRunMutation()).isTrue();

        assertThatThrownBy(() -> ExportRunContext.call(inner, () -> {
            throw new IllegalStateException("expected");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(ExportRunContext.currentToken()).isNull();
        assertThat(ExportRunContext.allowsRunMutation()).isTrue();
    }
}
