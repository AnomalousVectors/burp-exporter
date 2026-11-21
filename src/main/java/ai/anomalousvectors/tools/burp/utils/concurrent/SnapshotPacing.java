package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/**
 * Pacing primitives for snapshot reporters that walk large per-item collections
 * (proxy history, sitemap, websocket history) and risk dominating JVM allocation
 * throughput.
 *
 * <p>Two complementary mechanisms work together at the same boundary points and
 * are independent of live traffic queue depth because snapshot preparation and
 * snapshot flushes have their own scheduling and capacity limits:</p>
 * <ul>
 *   <li><b>Periodic per-item yield.</b> Every {@link #YIELD_EVERY_N_ITEMS} items,
 *       a brief {@link LockSupport#parkNanos(long)} sleeps for
 *       {@link #PERIODIC_YIELD_NS}, giving the EDT, GC concurrent threads, and other
 *       background workers scheduling opportunities during allocation-heavy loops.</li>
 *   <li><b>GC duty-cycle gate.</b> At the same boundary, the JMX
 *       {@link GarbageCollectorMXBean#getCollectionTime()} totals are sampled
 *       and the fraction of recent wall-clock time spent in GC is computed.
 *       When that fraction exceeds {@link #GC_DUTY_BACKPRESSURE_THRESHOLD}, the
 *       snapshot thread sleeps for an additional
 *       {@link #GC_DUTY_BACKPRESSURE_PAUSE_MS} to reduce allocation pressure before the
 *       next chunk is built. The cached observation is
 *       exposed via {@link #gcSaturated()} so chunk-level backpressure code can
 *       additionally shrink chunk targets and reduce the resident allocation
 *       footprint of the in-flight chunk list.</li>
 * </ul>
 *
 * <p>Sampling is bounded to the periodic boundary (a few JMX bean reads every
 * {@link #YIELD_EVERY_N_ITEMS} items); other calls avoid those bean reads while
 * updating the run's pacing counters.</p>
 */
public final class SnapshotPacing {

    /** Per-item pacing fires when the loop counter is a positive multiple of this value. */
    public static final int YIELD_EVERY_N_ITEMS = 64;

    /** Brief per-item yield duration. */
    public static final long PERIODIC_YIELD_NS = 500_000L;

    /** GC duty cycle (fraction in {@code [0, 1]}) above which the snapshot is throttled. */
    public static final double GC_DUTY_BACKPRESSURE_THRESHOLD = 0.30d;

    /** Additional sleep applied when the GC duty cycle gate trips. */
    public static final long GC_DUTY_BACKPRESSURE_PAUSE_MS = 100L;

    /** Threshold expressed as integer per-mille so atomic comparisons stay branch-free. */
    private static final long GC_DUTY_THRESHOLD_PER_MILLE =
            Math.round(GC_DUTY_BACKPRESSURE_THRESHOLD * 1000.0d);

    private static final List<GarbageCollectorMXBean> GC_BEANS =
            ManagementFactory.getGarbageCollectorMXBeans();

    private static final AtomicLong lastTimestampMs = new AtomicLong(0L);
    private static final AtomicLong lastGcTimeMs = new AtomicLong(0L);
    private static final AtomicLong cachedDutyPerMille = new AtomicLong(0L);

    // Run-scoped observability so callers can see whether the gate engaged at all and how
    // much wall-clock time was actually spent in the cooperative pause. Reset by callers via
    // resetCountersForSnapshot() at the start of each snapshot loop.
    private static final AtomicLong paceCallCount = new AtomicLong(0L);
    private static final AtomicLong paceBoundaryCount = new AtomicLong(0L);
    private static final AtomicLong gateTripCount = new AtomicLong(0L);
    private static final AtomicLong cumulativeGateSleepMs = new AtomicLong(0L);
    private static final AtomicLong cumulativeYieldNanos = new AtomicLong(0L);

    private SnapshotPacing() {}

    /**
     * Per-item pacing hook for snapshot loops.
     *
     * <p>Call once per item processed. Each call updates pacing counters; positive multiples of
     * {@link #YIELD_EVERY_N_ITEMS} also yield briefly and apply the bounded GC-pressure pause
     * when the sampled duty cycle is high.</p>
     *
     * @param itemIndex 0-based or 1-based loop counter; pacing fires only when the
     *                  counter is a positive multiple of {@link #YIELD_EVERY_N_ITEMS}.
     */
    public static void paceItem(int itemIndex) {
        paceCallCount.incrementAndGet();
        if (itemIndex <= 0 || (itemIndex % YIELD_EVERY_N_ITEMS) != 0) {
            return;
        }
        paceBoundaryCount.incrementAndGet();
        long yieldStartNs = System.nanoTime();
        LockSupport.parkNanos(PERIODIC_YIELD_NS);
        cumulativeYieldNanos.addAndGet(System.nanoTime() - yieldStartNs);
        sampleAndCacheDutyCycle();
        if (cachedDutyPerMille.get() >= GC_DUTY_THRESHOLD_PER_MILLE) {
            gateTripCount.incrementAndGet();
            long gateStartMs = System.currentTimeMillis();
            try {
                Thread.sleep(GC_DUTY_BACKPRESSURE_PAUSE_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            cumulativeGateSleepMs.addAndGet(System.currentTimeMillis() - gateStartMs);
        }
    }

    /**
     * Returns {@code true} when the most recently sampled GC duty cycle exceeds the
     * configured threshold.
     *
     * <p>Does not re-sample the JMX beans; sampling happens inside
     * {@link #paceItem(int)} so callers like chunk-level backpressure observe the
     * same value the per-item gate just acted on.</p>
     */
    public static boolean gcSaturated() {
        return cachedDutyPerMille.get() >= GC_DUTY_THRESHOLD_PER_MILLE;
    }

    /**
     * Reads JMX GC bean totals and updates the cached recent duty cycle.
     *
     * <p>The duty cycle is stored as integer per-mille so concurrent observers can
     * compare via a single {@link AtomicLong#get()} without floating-point hazards.</p>
     */
    private static void sampleAndCacheDutyCycle() {
        long now = System.currentTimeMillis();
        long curGc = totalGcTimeMs();
        long prevTs = lastTimestampMs.getAndSet(now);
        long prevGc = lastGcTimeMs.getAndSet(curGc);
        if (prevTs <= 0L) {
            return;
        }
        long perMille = computeDutyPerMille(now - prevTs, curGc - prevGc);
        cachedDutyPerMille.set(perMille);
    }

    /**
     * Pure helper that converts a wall-clock / GC-time delta pair to per-mille duty
     * cycle, clamped to {@code [0, 1000]}. Negative GC deltas (clock skew or bean
     * reset) are treated as zero.
     */
    static long computeDutyPerMille(long wallDeltaMs, long gcDeltaMs) {
        if (wallDeltaMs <= 0L) {
            return 0L;
        }
        long clampedGc = Math.max(0L, gcDeltaMs);
        long perMille = (clampedGc * 1000L) / wallDeltaMs;
        if (perMille < 0L) {
            return 0L;
        }
        return Math.min(1000L, perMille);
    }

    private static long totalGcTimeMs() {
        long sum = 0L;
        try {
            for (GarbageCollectorMXBean gc : GC_BEANS) {
                long t = gc.getCollectionTime();
                if (t > 0L) {
                    sum += t;
                }
            }
        } catch (RuntimeException ignored) {
            // JMX may be restricted; treat as no observation.
        }
        return sum;
    }

    /** Returns the most recently sampled GC duty cycle as integer per-mille in {@code [0, 1000]}. */
    public static long lastDutyPerMille() {
        return cachedDutyPerMille.get();
    }

    /** Total number of {@link #paceItem(int)} invocations since the last counter reset. */
    public static long paceCallCount() {
        return paceCallCount.get();
    }

    /** Number of {@link #paceItem(int)} invocations that landed on a pacing boundary. */
    public static long paceBoundaryCount() {
        return paceBoundaryCount.get();
    }

    /** Number of pacing boundaries where the GC duty-cycle gate engaged and slept. */
    public static long gateTripCount() {
        return gateTripCount.get();
    }

    /** Cumulative wall-clock time spent inside the GC duty-cycle gate since the last reset. */
    public static long cumulativeGateSleepMs() {
        return cumulativeGateSleepMs.get();
    }

    /** Cumulative wall-clock time spent inside the periodic per-item yield since the last reset. */
    public static long cumulativeYieldMs() {
        return cumulativeYieldNanos.get() / 1_000_000L;
    }

    /**
     * Returns a single {@code key=value} summary string of the run-scoped counters for use
     * in diagnostic log lines. Pure read; does not reset state.
     *
     * @param tag short identifier of the calling snapshot (e.g. {@code "ProxyHistory"}).
     */
    public static String summaryLine(String tag) {
        return "[SnapshotPacing] tag=" + tag
                + " pace_calls=" + paceCallCount.get()
                + " boundaries=" + paceBoundaryCount.get()
                + " gate_trips=" + gateTripCount.get()
                + " yield_ms=" + (cumulativeYieldNanos.get() / 1_000_000L)
                + " gate_sleep_ms=" + cumulativeGateSleepMs.get()
                + " last_duty_per_mille=" + cachedDutyPerMille.get();
    }

    /**
     * Resets only the run-scoped counters (call counts, gate trips, sleep totals).
     *
     * <p>Leaves the rolling GC-duty sampler state intact so the first
     * {@link #paceItem(int)} call after reset still produces a meaningful duty-cycle
     * reading from the prior wall-clock observation.</p>
     */
    public static void resetCountersForSnapshot() {
        paceCallCount.set(0L);
        paceBoundaryCount.set(0L);
        gateTripCount.set(0L);
        cumulativeGateSleepMs.set(0L);
        cumulativeYieldNanos.set(0L);
    }

    /**
     * Test seam: simulate a duty-cycle observation without touching JMX beans.
     *
     * <p>Sets the cached duty so {@link #gcSaturated()} reflects the supplied value
     * on the next call. Public to match the {@code *ForTests} convention used
     * elsewhere in the codebase; production code never invokes it.</p>
     *
     * @param perMille observation in {@code [0, 1000]}; clamped if out of range
     */
    public static void setCachedDutyPerMilleForTests(long perMille) {
        cachedDutyPerMille.set(Math.max(0L, Math.min(1000L, perMille)));
    }

    /**
     * Test seam: reset all sampler state so tests start from a clean slate.
     *
     * <p>Public to match the {@code *ForTests} convention used elsewhere in the
     * codebase; production code never invokes it.</p>
     */
    public static void resetForTests() {
        lastTimestampMs.set(0L);
        lastGcTimeMs.set(0L);
        cachedDutyPerMille.set(0L);
        resetCountersForSnapshot();
    }
}
