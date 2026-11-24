package ai.anomalousvectors.tools.burp.sinks;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import burp.api.montoya.core.ToolType;

/**
 * Bounds exact live-request membership without expiring late responses during normal operation.
 *
 * <p>Contains no HTTP views or payloads. Only receipts whose request-only preparation/flush has
 * finished enter the reclamation index. At capacity, the oldest indexed receipt can be reclaimed
 * after the request-only timeout; otherwise admission fails without waiting for space. Both
 * indexes are bounded by the same capacity. Callers serialize every access with their lifecycle
 * lock; this class is not independently thread-safe.</p>
 */
final class LiveRequestReceipts {
    // A count limit is appropriate for these fixed-shape, payload-free entries, not HTTP bodies.
    static final int CAPACITY = 100_000;
    private static final long SUMMARY_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(30);

    record Receipt(TrafficHttpHandlerSupport.MessageKey key, long order, long admittedNanos,
            long timestamp, ToolType toolType, ExportRunToken runToken, Integer listenerPort) { }

    record Snapshot(int retained, int capacity, int peak, long reclaimed, long rejected) { }

    private final int capacity;
    private final long minimumAgeNanos;
    private final LongSupplier clock;
    private final Map<TrafficHttpHandlerSupport.MessageKey, Receipt> receipts = new HashMap<>();
    private final TreeSet<Receipt> reclaimable = new TreeSet<>(
            (left, right) -> Long.compare(left.order(), right.order()));
    private ExportRunToken runToken;
    private long sequence;
    private int peak;
    private long reclaimed;
    private long rejected;
    private long reportedReclaimed;
    private long reportedRejected;
    private long lastSummaryNanos;
    private boolean summaryEmitted;

    LiveRequestReceipts(long minimumAgeMs) {
        this(CAPACITY, minimumAgeMs, System::nanoTime);
    }

    LiveRequestReceipts(int capacity, long minimumAgeMs, LongSupplier clock) {
        if (capacity < 1 || minimumAgeMs < 0) {
            throw new IllegalArgumentException("Receipt capacity and age must be non-negative, with positive capacity.");
        }
        this.capacity = capacity;
        this.minimumAgeNanos = TimeUnit.MILLISECONDS.toNanos(minimumAgeMs);
        this.clock = java.util.Objects.requireNonNull(clock);
    }

    /** Starts accounting when the token changes, clearing preceding membership and pressure totals. */
    boolean beginRun(ExportRunToken token) {
        if (token.equals(runToken)) return false;
        clear();
        runToken = token;
        sequence = 0;
        peak = 0;
        reclaimed = 0;
        rejected = 0;
        reportedReclaimed = 0;
        reportedRejected = 0;
        summaryEmitted = false;
        return true;
    }

    /** Returns null for duplicate callbacks or capacity rejection; rejected counts only the latter. */
    Receipt admit(TrafficHttpHandlerSupport.MessageKey key, long timestamp,
            ToolType toolType, ExportRunToken token, Integer listenerPort) {
        if (receipts.containsKey(key)) return null;
        long now = clock.getAsLong();
        if (receipts.size() == capacity) {
            Receipt oldest = reclaimable.isEmpty() ? null : reclaimable.first();
            if (oldest == null || now - oldest.admittedNanos() < minimumAgeNanos) {
                rejected++;
                return null;
            }
            remove(oldest.key());
            reclaimed++;
        }
        Receipt receipt = new Receipt(key, sequence++, now, timestamp, toolType, token, listenerPort);
        receipts.put(key, receipt);
        peak = Math.max(peak, receipts.size());
        return receipt;
    }

    Receipt get(TrafficHttpHandlerSupport.MessageKey key) {
        return receipts.get(key);
    }

    Receipt remove(TrafficHttpHandlerSupport.MessageKey key) {
        Receipt receipt = receipts.remove(key);
        if (receipt != null) reclaimable.remove(receipt);
        return receipt;
    }

    /** Identity checks prevent a stale preparation/flush from changing replacement membership. */
    void releasePayload(Receipt receipt) {
        if (receipt != null && receipts.get(receipt.key()) == receipt) reclaimable.add(receipt);
    }

    /** Discards membership on Stop but preserves the run's peak/pressure totals for final Stats. */
    void clear() {
        receipts.clear();
        reclaimable.clear();
    }

    Snapshot snapshot() {
        return new Snapshot(receipts.size(), capacity, peak, reclaimed, rejected);
    }

    Snapshot snapshot(ExportRunToken activeToken) {
        return activeToken.isValid() && !activeToken.equals(runToken)
                ? new Snapshot(0, capacity, 0, 0, 0) : snapshot();
    }

    /** Builds a summary only after pressure changes and at most once per interval, except Stop. */
    Snapshot takePressureSummary(boolean force) {
        if (reclaimed == reportedReclaimed && rejected == reportedRejected) return null;
        long now = clock.getAsLong();
        if (!force && summaryEmitted && now - lastSummaryNanos < SUMMARY_INTERVAL_NANOS) return null;
        reportedReclaimed = reclaimed;
        reportedRejected = rejected;
        lastSummaryNanos = now;
        summaryEmitted = true;
        return snapshot();
    }

    int reclaimableSize() {
        return reclaimable.size();
    }
}
