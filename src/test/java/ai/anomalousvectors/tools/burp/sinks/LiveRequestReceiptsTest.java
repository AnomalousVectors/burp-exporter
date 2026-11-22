package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import burp.api.montoya.core.ToolType;

/** Exact membership, bounded auxiliary state and pressure-only reclamation regressions. */
class LiveRequestReceiptsTest {
    private static final ExportRunToken RUN = new ExportRunToken(1);
    private final AtomicLong clock = new AtomicLong();

    @Test
    void productionCapacity_boundsSustainedNoResponseTrafficAndBothIndexes() {
        var cache = new LiveRequestReceipts(LiveRequestReceipts.CAPACITY, 120_000, clock::get);
        cache.beginRun(RUN);
        int capacity = LiveRequestReceipts.CAPACITY;
        long started = System.nanoTime();
        for (int id = 0; id < capacity; id++) cache.releasePayload(admit(cache, id));
        assertThat(admit(cache, capacity)).isNull();
        clock.set(TimeUnit.MINUTES.toNanos(3));
        for (int id = capacity; id < capacity * 3; id++) {
            // Advance across each generation so old finished receipts, not young ones, make room.
            clock.addAndGet(TimeUnit.MILLISECONDS.toNanos(2));
            var receipt = admit(cache, id);
            assertThat(receipt).isNotNull();
            cache.releasePayload(receipt);
        }
        assertThat(cache.snapshot()).isEqualTo(new LiveRequestReceipts.Snapshot(
                capacity, capacity, capacity, capacity * 2L, 1));
        assertThat(cache.reclaimableSize()).isEqualTo(capacity);
        System.out.println("Receipt pressure exercise: admissions=" + capacity * 3L
                + ", retained=" + cache.snapshot().retained()
                + ", indexed=" + cache.reclaimableSize()
                + ", elapsedMs=" + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
        cache.clear();
        assertThat(cache.snapshot().retained()).isZero();
        assertThat(cache.reclaimableSize()).isZero();
    }

    @Test
    void oldReceiptsDoNotExpireWithoutPressure_andResponsesConsumeExactlyOnce() {
        var cache = cache(2);
        var first = admit(cache, 1);
        cache.releasePayload(first);
        clock.set(TimeUnit.DAYS.toNanos(1));
        assertThat(cache.get(key(1))).isSameAs(first);
        assertThat(cache.remove(key(1))).isSameAs(first);
        assertThat(cache.remove(key(1))).isNull();
        assertThat(cache.snapshot().reclaimed()).isZero();
        assertThat(cache.reclaimableSize()).isZero();
    }

    @Test
    void activePreparationAndOrphanFlushAreProtectedEvenAfterTheTimeout() {
        var cache = cache(1);
        var first = admit(cache, 1);
        clock.set(TimeUnit.HOURS.toNanos(1));
        assertThat(admit(cache, 2)).isNull();
        assertThat(cache.get(key(1))).isSameAs(first);
        cache.releasePayload(first);
        assertThat(admit(cache, 2)).isNotNull();
        assertThat(cache.get(key(1))).isNull();
    }

    @Test
    void oldestEligibleReceiptWinsRegardlessOfPayloadReleaseOrder() {
        var cache = cache(3);
        var first = admit(cache, 1);
        var second = admit(cache, 2);
        var third = admit(cache, 3);
        cache.releasePayload(third);
        cache.releasePayload(second);
        clock.set(TimeUnit.MINUTES.toNanos(2));
        assertThat(admit(cache, 4)).isNotNull();
        assertThat(cache.get(key(1))).isSameAs(first);
        assertThat(cache.get(key(2))).isNull();
        assertThat(cache.get(key(3))).isSameAs(third);
    }

    @Test
    void duplicateRequestsAndEqualNativeGeneralIdsHaveDistinctAccounting() {
        var cache = cache(2);
        var general = admit(cache, 1);
        var nativeKey = new TrafficHttpHandlerSupport.MessageKey(true, 1);
        var nativeReceipt = cache.admit(nativeKey, 3, ToolType.PROXY, RUN, 8081);
        assertThat(admit(cache, 1)).isNull();
        assertThat(cache.snapshot().rejected()).isZero();
        assertThat(cache.remove(nativeKey)).isSameAs(nativeReceipt);
        assertThat(cache.get(key(1))).isSameAs(general);
    }

    @Test
    void newRunResetsTotalsAndStaleCompletionCannotReindexAReplacement() {
        var cache = cache(1);
        var old = admit(cache, 1);
        assertThat(admit(cache, 2)).isNull();
        cache.clear();
        assertThat(cache.snapshot().peak()).isEqualTo(1);
        assertThat(cache.snapshot().rejected()).isEqualTo(1);
        var nextRun = new ExportRunToken(2);
        assertThat(cache.snapshot(nextRun).peak()).isZero();
        cache.beginRun(nextRun);
        var replacement = cache.admit(key(1), 4, ToolType.SCANNER, nextRun, null);
        cache.releasePayload(old);
        assertThat(cache.reclaimableSize()).isZero();
        assertThat(cache.get(key(1))).isSameAs(replacement);
        assertThat(cache.snapshot().rejected()).isZero();
        assertThat(cache.beginRun(nextRun)).isFalse();
    }

    @Test
    void highRateRejectionsProduceOnlyThrottledAggregateSummariesAndAStopRemainder() {
        var cache = cache(1);
        admit(cache, 1);
        assertThat(admit(cache, 2)).isNull();
        assertThat(cache.takePressureSummary(false).rejected()).isEqualTo(1);
        for (int id = 3; id < 10_003; id++) {
            assertThat(admit(cache, id)).isNull();
            assertThat(cache.takePressureSummary(false)).isNull();
        }
        clock.set(TimeUnit.SECONDS.toNanos(30));
        assertThat(cache.takePressureSummary(false).rejected()).isEqualTo(10_001);
        assertThat(admit(cache, 10_003)).isNull();
        assertThat(cache.takePressureSummary(false)).isNull();
        assertThat(cache.takePressureSummary(true).rejected()).isEqualTo(10_002);
        assertThat(cache.takePressureSummary(true)).isNull();
    }

    @Test
    void invalidCapacityAndAgeAreRejected() {
        assertThatThrownBy(() -> new LiveRequestReceipts(0, 0, clock::get))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LiveRequestReceipts(1, -1, clock::get))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void concurrentResponseAndPressure_haveExactlyOneOutcomeForTheOldReceipt() throws Exception {
        try (var workers = Executors.newFixedThreadPool(2)) {
            for (int attempt = 0; attempt < 100; attempt++) {
                var cache = cache(1);
                cache.releasePayload(admit(cache, 1));
                clock.addAndGet(TimeUnit.MINUTES.toNanos(3));
                Object lifecycleLock = new Object();
                CountDownLatch start = new CountDownLatch(1);
                var response = workers.submit(() -> {
                    if (!start.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Start timeout.");
                    synchronized (lifecycleLock) { return cache.remove(key(1)); }
                });
                var pressure = workers.submit(() -> {
                    if (!start.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Start timeout.");
                    synchronized (lifecycleLock) { return admit(cache, 2); }
                });
                start.countDown();
                var consumed = response.get(10, TimeUnit.SECONDS);
                assertThat(pressure.get(10, TimeUnit.SECONDS)).isNotNull();
                assertThat(cache.snapshot().reclaimed()).isEqualTo(consumed == null ? 1 : 0);
                assertThat(cache.snapshot().retained()).isEqualTo(1);
                assertThat(cache.reclaimableSize()).isZero();
            }
        }
    }

    private LiveRequestReceipts cache(int capacity) {
        var cache = new LiveRequestReceipts(capacity, 120_000, clock::get);
        cache.beginRun(RUN);
        return cache;
    }

    private static LiveRequestReceipts.Receipt admit(LiveRequestReceipts cache, int id) {
        return cache.admit(key(id), 2, ToolType.SCANNER, RUN, null);
    }

    private static TrafficHttpHandlerSupport.MessageKey key(int id) {
        return new TrafficHttpHandlerSupport.MessageKey(false, id);
    }
}
