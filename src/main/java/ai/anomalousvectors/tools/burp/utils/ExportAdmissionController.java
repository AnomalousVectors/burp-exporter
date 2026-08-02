package ai.anomalousvectors.tools.burp.utils;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkRateLimitBackoff;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Closed-loop admission and capacity budgets for live traffic, retry, and spill.
 *
 * <p>Sizes in-memory and retry buffers from JVM heap headroom (not fixed document counts) and sizes
 * spill from free-disk headroom with a modest absolute ceiling. Soft Outage and cooldown force new
 * live traffic to spill, while spill Full is the actual admission limit. Snapshot/retry work stays
 * paced and spill refill resumes after cooldown to provide payload recovery canaries.</p>
 *
 * <p>Thread-safe. Safe to call from HTTP handlers, drain workers, and the EDT.</p>
 */
public final class ExportAdmissionController {

    /** Spill / Overview traffic overflow status. */
    public enum SpillStatus {
        /** No spilled docs (or negligible). */
        READY,
        /** Spill holds backlog but still accepts writes. */
        IN_USE,
        /** Spill cannot accept more; new live traffic is rejected. */
        FULL
    }

    /** Floor for the live in-memory traffic byte budget. */
    public static final long MEM_FLOOR_BYTES = 8L * 1024L * 1024L;
    /** Ceiling so large Burp heaps do not greedily reserve multi-GiB. */
    public static final long MEM_CEILING_BYTES = 256L * 1024L * 1024L;
    /** Fraction of heap headroom used for the live mem budget. */
    public static final double MEM_HEADROOM_FRACTION = 0.08d;
    /** Soft watermark: prefer spill once held bytes exceed this fraction of budget. */
    public static final double MEM_SOFT_WATERMARK = 0.70d;
    /** Hard watermark: reject new live traffic when held bytes exceed this fraction. */
    public static final double MEM_HARD_WATERMARK = 0.95d;
    /** Document-count safety rail for the live mem queue (bytes remain primary). */
    public static final int MEM_DOC_SAFETY_RAIL = 100_000;

    /** Floor for total RetryQueue byte budget across indexes. */
    public static final long RETRY_FLOOR_BYTES = 8L * 1024L * 1024L;
    /** Ceiling for total RetryQueue bytes. */
    public static final long RETRY_CEILING_BYTES = 256L * 1024L * 1024L;
    /** Fraction of heap headroom used for retry retention. */
    public static final double RETRY_HEADROOM_FRACTION = 0.06d;
    /** Per-index doc safety rail (bytes remain primary). */
    public static final int RETRY_DOC_SAFETY_RAIL = 50_000;

    /** Absolute spill byte ceiling (also {@link DiskSpaceGuard#MAX_MANAGED_BYTES}). */
    public static final long SPILL_ABSOLUTE_CEILING_BYTES = DiskSpaceGuard.MAX_MANAGED_BYTES;
    /** Fraction of usable free space (above reserve) allowed for spill. */
    public static final double SPILL_FREE_FRACTION = 0.25d;
    /** Material-use threshold retained for spill pressure classification and diagnostics. */
    public static final double SPILL_IN_USE_FRACTION = 0.05d;

    private static final AtomicReference<Long> MEM_BUDGET_OVERRIDE = new AtomicReference<>();
    private static final AtomicReference<Long> RETRY_BUDGET_OVERRIDE = new AtomicReference<>();
    private static final AtomicReference<Long> SPILL_BUDGET_OVERRIDE = new AtomicReference<>();
    private static final AtomicLong LAST_SPILL_FULL_LOG_MS = new AtomicLong(0L);
    private static final long SPILL_FULL_LOG_THROTTLE_MS = 15_000L;

    private ExportAdmissionController() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns the current live in-memory traffic byte budget from heap headroom.
     *
     * <p>Under Soft Outage or hard cooldown the budget is halved (still floored) so refill and
     * enqueue stay conservative while the destination is sick.</p>
     *
     * @return positive byte budget
     */
    public static long memBudgetBytes() {
        Long override = MEM_BUDGET_OVERRIDE.get();
        if (override != null) {
            // Test overrides may be below the production floor for constrained-heap scenarios.
            return Math.max(1L, override);
        }
        long budget = budgetFromHeadroom(MEM_HEADROOM_FRACTION, MEM_FLOOR_BYTES, MEM_CEILING_BYTES);
        if (destinationUnderPressure()) {
            budget = Math.max(MEM_FLOOR_BYTES, budget / 2L);
        }
        return budget;
    }

    /**
     * Returns whether the live mem queue should accept {@code docBytes} given current held bytes.
     *
     * @param heldBytes current estimated queue bytes; negative values are treated as zero
     * @param docBytes estimated new document bytes; negative values are treated as zero
     * @return {@code true} when the resulting size does not exceed the hard watermark
     */
    public static boolean memAccepts(long heldBytes, long docBytes) {
        long budget = memBudgetBytes();
        long next = Math.max(0L, heldBytes) + Math.max(0L, docBytes);
        return next <= (long) (budget * MEM_HARD_WATERMARK);
    }

    /**
     * Returns whether new live traffic should prefer spill over memory (soft watermark).
     *
     * @param heldBytes current estimated queue bytes; negative values are treated as zero
     * @param docBytes estimated new document bytes; negative values are treated as zero
     * @return {@code true} when the resulting size exceeds the soft watermark
     */
    public static boolean shouldPreferSpill(long heldBytes, long docBytes) {
        long budget = memBudgetBytes();
        long next = Math.max(0L, heldBytes) + Math.max(0L, docBytes);
        return next > (long) (budget * MEM_SOFT_WATERMARK);
    }

    /**
     * Returns the total RetryQueue byte budget from heap headroom.
     *
     * @return positive total retry byte budget
     */
    public static long retryBudgetBytes() {
        Long override = RETRY_BUDGET_OVERRIDE.get();
        if (override != null) {
            // Test overrides may be below the production floor for constrained-heap scenarios.
            return Math.max(1L, override);
        }
        long budget = budgetFromHeadroom(RETRY_HEADROOM_FRACTION, RETRY_FLOOR_BYTES, RETRY_CEILING_BYTES);
        if (destinationUnderPressure()) {
            budget = Math.max(RETRY_FLOOR_BYTES, budget / 2L);
        }
        return budget;
    }

    /**
     * Returns a soft per-index retry byte cap derived from the total retry budget.
     *
     * @return positive per-index retry byte cap
     */
    public static long retryBudgetBytesPerIndex() {
        long total = retryBudgetBytes();
        if (RETRY_BUDGET_OVERRIDE.get() != null) {
            return Math.max(1L, total);
        }
        return Math.max(RETRY_FLOOR_BYTES, total / 2L);
    }

    /**
     * Returns the spill byte budget for {@code spillDirectory} from free-disk headroom.
     *
     * <p>Uses a fraction of usable space above {@link DiskSpaceGuard#MIN_FREE_BYTES}, capped by
     * {@link #SPILL_ABSOLUTE_CEILING_BYTES}. Unknown usable space and space at or below the reserve
     * return the absolute ceiling so {@link DiskSpaceGuard} remains responsible for a distinct
     * low-disk refusal.</p>
     *
     * @param spillDirectory spill path or directory; {@code null} uses the managed root
     * @return positive spill byte budget
     */
    public static long spillBudgetBytes(Path spillDirectory) {
        Long override = SPILL_BUDGET_OVERRIDE.get();
        if (override != null) {
            return Math.max(1L, override);
        }
        long usable = DiskSpaceGuard.usableSpacePublic(spillDirectory);
        if (usable < 0L) {
            return SPILL_ABSOLUTE_CEILING_BYTES;
        }
        long aboveReserve = usable - DiskSpaceGuard.MIN_FREE_BYTES;
        if (aboveReserve <= 0L) {
            // Below the disk reserve: do not invent a 1-byte LIMIT. Let DiskSpaceGuard refuse the
            // write as low-disk so Stats/logs keep a distinct Full/low-disk signal.
            return SPILL_ABSOLUTE_CEILING_BYTES;
        }
        long fromFree = (long) (aboveReserve * SPILL_FREE_FRACTION);
        return Math.max(1L, Math.min(SPILL_ABSOLUTE_CEILING_BYTES, fromFree));
    }

    /**
     * Returns whether live traffic may be prepared/enqueued right now.
     *
     * <p>Destination pressure does not reject live traffic while spill still has capacity. The
     * queue forces those accepted documents to spill instead of growing its in-memory backlog.</p>
     *
     * @return {@code true} when spill or memory can accept another live document
     */
    public static boolean shouldAdmitLiveTraffic() {
        SpillStatus spill = currentSpillStatus();
        if (spill == SpillStatus.FULL) {
            return false;
        }
        if (shouldForceLiveTrafficToSpill()) {
            return true;
        }
        long held = TrafficExportQueue.getCurrentBytesEstimate();
        return memAccepts(held, 1L);
    }

    /**
     * Returns whether accepted new live traffic must bypass memory and enter spill.
     *
     * @return {@code true} during Soft Outage or any active bulk cooldown
     */
    public static boolean shouldForceLiveTrafficToSpill() {
        return IndexingRetryCoordinator.getInstance().isSoftCapacityOutage()
                || BulkRateLimitBackoff.remainingCooldownMs() > 0L;
    }

    /**
     * Returns whether spill refill into memory should proceed.
     *
     * <p>Paused while a cooldown is active or when memory is already above the soft watermark.
     * After cooldown, one bounded refill may become the payload canary that proves recovery even
     * when spill is the only remaining source.</p>
     *
     * @return {@code true} when refill may proceed
     */
    public static boolean shouldRefillFromSpill() {
        if (BulkRateLimitBackoff.remainingCooldownMs() > 0L) {
            return false;
        }
        long held = TrafficExportQueue.getCurrentBytesEstimate();
        long budget = memBudgetBytes();
        return held < (long) (budget * MEM_SOFT_WATERMARK);
    }

    /**
     * Returns whether snapshot reporters should apply live backpressure.
     *
     * @return {@code true} during destination pressure, material spill use, or memory pressure
     */
    public static boolean shouldBackpressureSnapshots() {
        if (IndexingRetryCoordinator.getInstance().isSoftCapacityOutage()) {
            return true;
        }
        SpillStatus spill = currentSpillStatus();
        if (spill == SpillStatus.IN_USE || spill == SpillStatus.FULL) {
            return true;
        }
        long held = TrafficExportQueue.getCurrentBytesEstimate();
        long budget = memBudgetBytes();
        return held >= (long) (budget * MEM_SOFT_WATERMARK);
    }

    /**
     * Returns whether non-final exporter log/stats pushes should pause.
     *
     * <p>Final/Stop snapshots remain allowed so operators still get an end-of-run document.</p>
     *
     * @return {@code true} when a non-final exporter push should pause
     */
    public static boolean shouldPauseExporterNonFinal() {
        return IndexingRetryCoordinator.getInstance().isSoftCapacityOutage()
                || BulkRateLimitBackoff.isCoolingDown();
    }

    /**
     * Returns the current Traffic Spill status for Overview / Stats.
     *
     * @return current spill status
     */
    public static SpillStatus currentSpillStatus() {
        int spillDocs = TrafficExportQueue.getCurrentSpillSize();
        long spillBytes = TrafficExportQueue.getCurrentSpillBytes();
        long budget = TrafficExportQueue.currentSpillBudgetBytes();
        return classifySpill(spillDocs, spillBytes, budget, TrafficExportQueue.isSpillAccepting());
    }

    /**
     * Classifies spill status from depth, bytes, budget, and whether spill still accepts writes.
     *
     * <p>A non-accepting spill is {@link SpillStatus#FULL}. Any positive document depth is
     * {@link SpillStatus#IN_USE}; an empty accepting spill is {@link SpillStatus#READY}. Negative
     * byte values do not independently change the result, and non-positive budgets normalize to
     * one byte for ratio calculations.</p>
     *
     * @param spillDocs current spill document depth
     * @param spillBytes current estimated spill bytes
     * @param spillBudgetBytes configured spill byte budget
     * @param spillAccepting whether spill can accept another write
     * @return classified spill status
     */
    public static SpillStatus classifySpill(
            int spillDocs,
            long spillBytes,
            long spillBudgetBytes,
            boolean spillAccepting) {
        if (!spillAccepting) {
            return SpillStatus.FULL;
        }
        long budget = Math.max(1L, spillBudgetBytes);
        boolean materiallyUsed = spillDocs > 0
                && (spillBytes >= (long) (budget * SPILL_IN_USE_FRACTION) || spillDocs >= 8);
        if (materiallyUsed) {
            return SpillStatus.IN_USE;
        }
        if (spillDocs > 0) {
            return SpillStatus.IN_USE;
        }
        return SpillStatus.READY;
    }

    /**
     * Logs a throttled WARN when spill is Full and new live traffic is rejected.
     *
     * <p>Safe to call concurrently; at most one caller wins each throttle interval.</p>
     */
    public static void noteSpillFullReject() {
        long now = System.currentTimeMillis();
        long prev = LAST_SPILL_FULL_LOG_MS.get();
        if (now - prev < SPILL_FULL_LOG_THROTTLE_MS) {
            return;
        }
        if (!LAST_SPILL_FULL_LOG_MS.compareAndSet(prev, now)) {
            return;
        }
        Logger.logWarnPanelOnly(
                "[TrafficExportQueue] Traffic Spill Full: rejecting new live traffic "
                        + "(preserving earliest backlog). "
                        + "spill_depth=" + TrafficExportQueue.getCurrentSpillSize()
                        + ", spill_bytes=" + TrafficExportQueue.getCurrentSpillBytes()
                        + ", spill_budget=" + TrafficExportQueue.currentSpillBudgetBytes());
    }

    /**
     * Test-only override for the live mem byte budget; {@code null} clears.
     *
     * @param bytes override bytes; non-positive non-null values are read back as one
     */
    public static void setMemBudgetOverrideForTests(Long bytes) {
        MEM_BUDGET_OVERRIDE.set(bytes);
    }

    /**
     * Test-only override for the retry byte budget; {@code null} clears.
     *
     * @param bytes override bytes; non-positive non-null values are read back as one
     */
    public static void setRetryBudgetOverrideForTests(Long bytes) {
        RETRY_BUDGET_OVERRIDE.set(bytes);
    }

    /**
     * Test-only override for the spill byte budget; {@code null} clears.
     *
     * @param bytes override bytes; non-positive non-null values are read back as one
     */
    public static void setSpillBudgetOverrideForTests(Long bytes) {
        SPILL_BUDGET_OVERRIDE.set(bytes);
    }

    /** Clears all test overrides. */
    public static void resetForTests() {
        MEM_BUDGET_OVERRIDE.set(null);
        RETRY_BUDGET_OVERRIDE.set(null);
        SPILL_BUDGET_OVERRIDE.set(null);
        LAST_SPILL_FULL_LOG_MS.set(0L);
    }

    private static boolean destinationUnderPressure() {
        return IndexingRetryCoordinator.getInstance().isSoftCapacityOutage()
                || BulkRateLimitBackoff.isCoolingDown();
    }

    private static long budgetFromHeadroom(double fraction, long floor, long ceiling) {
        SystemMetrics.Snapshot snap = SystemMetrics.snapshot();
        long used = Math.max(0L, snap.heapUsedBytes());
        long committed = Math.max(used, snap.heapCommittedBytes());
        long max = snap.heapMaxBytes();
        long headroomCommitted = Math.max(0L, committed - used);
        long headroomMax = max > 0L ? Math.max(0L, max - used) : headroomCommitted;
        // Prefer the tighter headroom so we stay a good neighbor inside Burp's shared JVM.
        long headroom = Math.min(headroomCommitted, headroomMax);
        if (headroom <= 0L && max > 0L) {
            headroom = Math.max(0L, max - used);
        }
        long raw = (long) (headroom * fraction);
        return Math.max(floor, Math.min(ceiling, raw));
    }
}
