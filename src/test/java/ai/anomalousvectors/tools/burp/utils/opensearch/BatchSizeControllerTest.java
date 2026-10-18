package ai.anomalousvectors.tools.burp.utils.opensearch;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link BatchSizeController}: initial state, decay on failure,
 * growth on success (with smoothing), listener, bounds, and recordPartialSuccess.
 */
class BatchSizeControllerTest {

    private BatchSizeController controller;

    @BeforeEach
    public void setUp() {
        controller = BatchSizeController.isolatedController();
        BatchSizeController.setInstance(controller);
    }

    @AfterEach
    public void tearDown() {
        BatchSizeController.setInstance(null);
    }

    @Test
    void initialBatchSize_is100() {
        assertThat(controller.getCurrentBatchSize()).isEqualTo(100);
    }

    @Test
    void recordFailure_halvesSize_andFloorsAt50() {
        assertThat(controller.getCurrentBatchSize()).isEqualTo(100);
        controller.recordFailure(100);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(50);
        controller.recordFailure(50);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(50);
    }

    @Test
    void recordFailure_from200_goesTo100() {
        for (int i = 0; i < 5; i++) {
            controller.recordSuccess(100);
        }
        assertThat(controller.getCurrentBatchSize()).isEqualTo(120);
        controller.recordSuccess(120);
        controller.recordSuccess(120);
        controller.recordSuccess(120);
        controller.recordSuccess(120);
        controller.recordSuccess(120);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(144);
        controller.recordFailure(144);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(72);
    }

    @Test
    void recordSuccess_afterFiveSuccessesAtOrAboveThreshold_growsSize() {
        assertThat(controller.getCurrentBatchSize()).isEqualTo(100);
        controller.recordSuccess(100);
        controller.recordSuccess(100);
        controller.recordSuccess(100);
        controller.recordSuccess(100);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(100);
        controller.recordSuccess(100);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(120);
    }

    @Test
    void recordSuccess_smoothing_avgBelowThreshold_doesNotGrow() {
        controller.recordSuccess(80);
        controller.recordSuccess(80);
        controller.recordSuccess(80);
        controller.recordSuccess(80);
        controller.recordSuccess(80);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(100);
    }

    @Test
    void recordPartialSuccess_reducesLikeFailure() {
        assertThat(controller.getCurrentBatchSize()).isEqualTo(100);
        controller.recordPartialSuccess(50, 100);
        assertThat(controller.getCurrentBatchSize()).isEqualTo(50);
    }

    @Test
    void onChangeListener_invokedWhenSizeChanges() {
        AtomicInteger lastValue = new AtomicInteger(-1);
        controller.setOnChangeListener(size -> lastValue.set(size == null ? -1 : size));
        controller.recordFailure(100);
        assertThat(lastValue.get()).isEqualTo(50);
        lastValue.set(-1);
        for (int i = 0; i < 5; i++) {
            controller.recordSuccess(50);
        }
        assertThat(lastValue.get()).isEqualTo(60);
    }

    @Test
    void manySuccesses_cappedAtMax1000() {
        int size = controller.getCurrentBatchSize();
        for (int round = 0; round < 30; round++) {
            for (int i = 0; i < 5; i++) {
                controller.recordSuccess(size);
            }
            size = controller.getCurrentBatchSize();
            if (size >= 1000) break;
        }
        assertThat(controller.getCurrentBatchSize()).isLessThanOrEqualTo(1000);
    }
}
