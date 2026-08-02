package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Backoff for search-database bulk HTTP rate limiting and capacity pressure.
 *
 * <p>Hard pressure (HTTP {@code 429}/{@code 502}/{@code 503}/{@code 504}, transport timeouts, failed
 * capacity probes) uses one <em>cluster-wide</em> deadline so gateway outages park every path.
 * Mild per-item capacity pressure (HTTP {@code 200} circuit-break / throttle) uses a
 * <em>per-index</em> deadline so a hot traffic index does not freeze findings/sitemap/settings
 * recovery.</p>
 *
 * <p>The shared {@link OfferedLoadGovernor} consumes active deadlines before normal request starts.
 * Stop retry drain uses {@link #awaitIfNeeded(String, long)} explicitly to preserve its existing
 * bounded cooldown slice while governor waiting itself is bypassed during Stop.</p>
 *
 * <p>Thread-safe. Deadlines use the process monotonic clock and are shared across sender threads;
 * wall-clock changes do not shorten or extend an active cooldown.</p>
 */
public final class BulkRateLimitBackoff {

    /** Default shared cooldown when {@code Retry-After} is absent. */
    public static final long DEFAULT_BACKOFF_MS = 5_000L;

    /** Upper bound for shared hard capacity cooldowns. */
    public static final long MAX_BACKOFF_MS = 60_000L;

    /** Escalation ladder for hard capacity pressure (gateway / transport) without {@code Retry-After}. */
    static final long[] ESCALATION_MS = {5_000L, 15_000L, 30_000L, 60_000L};

    /**
     * Milder ladder for per-item capacity pressure (HTTP 200 item throttle / circuit break).
     * Caps well below the hard gateway ladder so one item failure does not park all paths for 60s.
     */
    static final long[] MILD_ESCALATION_MS = {5_000L, 5_000L, 15_000L, 15_000L};

    /** Upper bound for mild item-capacity cooldowns. */
    public static final long MAX_MILD_BACKOFF_MS = 15_000L;

    /**
     * Maximum cooldown wait during Stop drain so a 60s shared deadline cannot consume the entire
     * shutdown budget before any recovery push runs.
     */
    public static final long STOP_DRAIN_MAX_COOLDOWN_WAIT_MS = 2_000L;

    private static final AtomicLong HARD_NOT_BEFORE_NANOS = new AtomicLong(0L);
    private static final AtomicLong PRESSURE_STREAK = new AtomicLong(0L);
    private static final AtomicLong MILD_PRESSURE_STREAK = new AtomicLong(0L);
    private static final ConcurrentHashMap<String, AtomicLong> MILD_NOT_BEFORE_BY_INDEX =
            new ConcurrentHashMap<>();

    private BulkRateLimitBackoff() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns whether the HTTP status indicates rate limiting, temporary unavailability, or a
     * gateway timeout that should cool down before the next bulk.
     */
    static boolean isRateLimited(int status) {
        return status == 429 || status == 502 || status == 503 || status == 504;
    }

    /**
     * Returns whether a cluster-wide hard cooldown is still active.
     *
     * <p>Does not include per-index mild cooldowns — those must not block flush-concurrency restore
     * for unrelated indexes.</p>
     */
    public static boolean isCoolingDown() {
        return remainingHardCooldownMs() > 0L;
    }

    /**
     * Returns whether the named index must wait (hard cluster cooldown or that index's mild
     * cooldown).
     *
     * @param indexName target index; blank uses hard cooldown only
     * @return {@code true} when an applicable cooldown is active
     */
    public static boolean isCoolingDown(String indexName) {
        return remainingCooldownMs(indexName) > 0L;
    }

    /**
     * Returns milliseconds remaining on the cluster-wide hard capacity cooldown.
     *
     * @return {@code 0} when no hard cooldown is active
     */
    public static long remainingHardCooldownMs() {
        return remainingMs(HARD_NOT_BEFORE_NANOS.get());
    }

    /**
     * Returns milliseconds remaining before the next bulk for {@code indexName}.
     *
     * <p>Uses the later of the hard cluster deadline and that index's mild deadline. Blank index
     * names report hard cooldown only. Misc Stats {@code Cooldown Remaining} uses the blank-index
     * form plus the largest mild remaining across indexes (via {@link #remainingCooldownMs()}).</p>
     *
     * @param indexName target index; may be blank
     * @return {@code 0} when no applicable cooldown is active
     */
    public static long remainingCooldownMs(String indexName) {
        long hard = remainingHardCooldownMs();
        long mild = remainingMildCooldownMs(indexName);
        return Math.max(hard, mild);
    }

    /**
     * Returns milliseconds remaining for Stats display: max of hard cooldown and any mild
     * per-index cooldown.
     *
     * @return {@code 0} when no cooldown is active
     */
    public static long remainingCooldownMs() {
        long max = remainingHardCooldownMs();
        for (Map.Entry<String, AtomicLong> entry : MILD_NOT_BEFORE_BY_INDEX.entrySet()) {
            max = Math.max(max, remainingMs(entry.getValue().get()));
        }
        return max;
    }

    /**
     * Resolves how long to wait before the next bulk attempt.
     *
     * @param response HTTP response that may carry {@code Retry-After}; {@code null} uses default
     * @return backoff milliseconds in {@code (0, MAX_BACKOFF_MS]}
     */
    static long resolveBackoffMs(HttpResponse response) {
        Long retryAfterMs = parseRetryAfterMs(response);
        if (retryAfterMs == null) {
            return DEFAULT_BACKOFF_MS;
        }
        if (retryAfterMs <= 0L) {
            return DEFAULT_BACKOFF_MS;
        }
        return Math.min(MAX_BACKOFF_MS, retryAfterMs);
    }

    /**
     * Returns the next escalated hard cooldown for a capacity event.
     *
     * @param response HTTP response that may carry {@code Retry-After}; may be {@code null}
     * @return backoff milliseconds in {@code (0, MAX_BACKOFF_MS]}
     */
    static long nextEscalatedBackoffMs(HttpResponse response) {
        long streak = PRESSURE_STREAK.incrementAndGet();
        int idx = (int) Math.min(ESCALATION_MS.length - 1L, Math.max(0L, streak - 1L));
        long escalated = ESCALATION_MS[idx];
        Long retryAfterMs = parseRetryAfterMs(response);
        if (retryAfterMs != null && retryAfterMs > 0L) {
            return Math.min(MAX_BACKOFF_MS, Math.max(escalated, retryAfterMs));
        }
        return escalated;
    }

    /**
     * Clears pressure only after the offered-load governor observes stable payload recovery.
     *
     * <p>A health probe, exporter single, partial bulk, or one full success must never call this
     * method. Those observations cannot erase an active pressure epoch. The synchronized
     * transition resets hard/mild streaks and deadlines, clears governor pressure, and restores
     * the byte-budget recovery state exactly once relative to new pressure events.</p>
     */
    static synchronized void noteStablePayloadRecovery() {
        PRESSURE_STREAK.set(0L);
        MILD_PRESSURE_STREAK.set(0L);
        clearCooldownDeadline();
        OfferedLoadGovernor.noteStableRecoveryComplete();
        BulkByteBudget.restoreAfterRecovery("payload_success_hysteresis");
    }

    /**
     * Returns the current hard capacity-pressure streak.
     *
     * @return non-negative number of consecutive hard-pressure observations
     */
    public static long pressureStreak() {
        return PRESSURE_STREAK.get();
    }

    /**
     * Clears hard and mild cooldown deadlines while retaining pressure streaks.
     *
     * <p>Concurrent pressure observations may install a later deadline immediately after return.</p>
     */
    public static void clearCooldownDeadline() {
        HARD_NOT_BEFORE_NANOS.set(0L);
        for (AtomicLong deadline : MILD_NOT_BEFORE_BY_INDEX.values()) {
            deadline.set(0L);
        }
    }

    /**
     * Records a hard rate-limit cooldown from an HTTP response without parking the caller.
     *
     * @param status HTTP status code
     * @param response response used for {@code Retry-After}; may be {@code null}
     * @param indexName target index for the log line
     * @param pathLabel short path label such as {@code Prepared bulk} or {@code Chunked bulk}
     */
    static synchronized void noteRateLimited(
            int status, HttpResponse response, String indexName, String pathLabel) {
        if (!isRateLimited(status)) {
            return;
        }
        long delayMs = nextEscalatedBackoffMs(response);
        OfferedLoadGovernor.noteHardPressure();
        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delayMs);
        if (!extendHardDeadline(deadlineNanos)) {
            return;
        }
        String index = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        String path = pathLabel == null || pathLabel.isBlank() ? "Bulk" : pathLabel;
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk capacity pressure:"
                + " index=" + index
                + " path=" + path
                + " status=" + status
                + " cooldownMs=" + delayMs
                + " pressureStreak=" + PRESSURE_STREAK.get()
                + " scope=cluster.");
        BulkByteBudget.applyRateLimitPressure(status, indexName, pathLabel, delayMs);
        AmazonOpenSearchPressureLog.maybeNoteHttpPressure(status, indexName, pathLabel);
    }

    /**
     * Records a hard shared cooldown after a bulk transport failure without an HTTP status.
     *
     * @param detail exception message or short cause; may be blank
     * @param indexName target index for the log line
     * @param pathLabel short path label such as {@code Prepared bulk} or {@code Chunked bulk}
     */
    static synchronized void noteTransportPressure(
            String detail, String indexName, String pathLabel) {
        if (!isTransientTransportDetail(detail)) {
            return;
        }
        long delayMs = nextEscalatedBackoffMs(null);
        OfferedLoadGovernor.noteHardPressure();
        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delayMs);
        if (!extendHardDeadline(deadlineNanos)) {
            return;
        }
        String index = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        String path = pathLabel == null || pathLabel.isBlank() ? "Bulk" : pathLabel;
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk transport pressure:"
                + " index=" + index
                + " path=" + path
                + " cooldownMs=" + delayMs
                + " pressureStreak=" + PRESSURE_STREAK.get()
                + " scope=cluster.");
        BulkByteBudget.applyRateLimitPressure(504, indexName, pathLabel, delayMs);
    }

    /**
     * Records a milder per-index cooldown after per-item bulk capacity pressure (HTTP 200 item
     * errors).
     *
     * @param indexName target index for the cooldown scope and log line
     * @param pathLabel short path label such as {@code Retry drain} or {@code Prepared bulk}
     * @param detail first failing item type/reason; may be blank
     */
    static synchronized void noteItemCapacityPressure(
            String indexName, String pathLabel, String detail) {
        long delayMs = nextMildEscalatedBackoffMs();
        OfferedLoadGovernor.noteMildPressure();
        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delayMs);
        String indexKey = normalizeIndexKey(indexName);
        if (!extendMildDeadline(indexKey, deadlineNanos)) {
            return;
        }
        String index = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        String path = pathLabel == null || pathLabel.isBlank() ? "Bulk" : pathLabel;
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk item capacity pressure:"
                + " index=" + index
                + " path=" + path
                + " cooldownMs=" + delayMs
                + " mildPressureStreak=" + MILD_PRESSURE_STREAK.get()
                + " scope=index"
                + " detail=" + truncateDetail(detail) + ".");
        BulkByteBudget.applyMildItemPressure(indexName, pathLabel, delayMs);
    }

    /** Returns the next mild item-capacity cooldown (capped at {@link #MAX_MILD_BACKOFF_MS}). */
    static long nextMildEscalatedBackoffMs() {
        long streak = MILD_PRESSURE_STREAK.incrementAndGet();
        int idx = (int) Math.min(MILD_ESCALATION_MS.length - 1L, Math.max(0L, streak - 1L));
        return Math.min(MAX_MILD_BACKOFF_MS, MILD_ESCALATION_MS[idx]);
    }

    /**
     * Returns whether a bulk item error looks like capacity/throttle pressure.
     *
     * @param type OpenSearch error type; may be null
     * @param reason error reason; may be null
     * @return {@code true} for circuit-breaker / rejected-execution / throttled item failures
     */
    static boolean isItemCapacityPressure(String type, String reason) {
        String typeLower = type == null ? "" : type.toLowerCase(java.util.Locale.ROOT);
        String reasonLower = reason == null ? "" : reason.toLowerCase(java.util.Locale.ROOT);
        return typeLower.contains("circuit_breaking")
                || typeLower.contains("es_rejected_execution")
                || reasonLower.contains("throttled")
                || reasonLower.contains("rejected execution");
    }

    /**
     * Records hard capacity cooldown after a failed health probe without an HTTP response object.
     *
     * @param detail probe message; may be blank
     */
    static synchronized void noteCapacityProbeFailure(String detail) {
        long delayMs = nextEscalatedBackoffMs(null);
        OfferedLoadGovernor.noteHardPressure();
        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delayMs);
        if (!extendHardDeadline(deadlineNanos)) {
            Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Capacity probe failed:"
                    + " cooldownActive=true"
                    + " detail=" + truncateDetail(detail) + ".");
            return;
        }
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Capacity probe failed:"
                + " cooldownMs=" + delayMs
                + " pressureStreak=" + PRESSURE_STREAK.get()
                + " detail=" + truncateDetail(detail) + ".");
        BulkByteBudget.applyRateLimitPressure(504, "probe", "Health probe", delayMs);
    }

    /** Returns whether {@code detail} matches transient transport/capacity symptoms. */
    static boolean isTransientTransportDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return false;
        }
        String lower = detail.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("failed to respond")
                || lower.contains("timeout")
                || lower.contains("timed out")
                || lower.contains("connection reset")
                || lower.contains("connection refused")
                || lower.contains("broken pipe")
                || lower.contains("nohttpresponse");
    }

    /**
     * Parks until applicable cooldowns expire or {@code maxWaitMs} elapses.
     *
     * <p>Returns early when interrupted and preserves the thread interrupt flag. This method does
     * not clear deadlines or pressure streaks.</p>
     *
     * @param indexName target index; blank waits on hard cooldown only
     * @param maxWaitMs maximum milliseconds to park; {@code <= 0} returns immediately
     */
    static void awaitIfNeeded(String indexName, long maxWaitMs) {
        if (maxWaitMs <= 0L) {
            return;
        }
        long waitBudgetNanos = maxWaitMs == Long.MAX_VALUE
                ? Long.MAX_VALUE
                : TimeUnit.MILLISECONDS.toNanos(maxWaitMs);
        long waitStarted = System.nanoTime();
        long firstRemainingMs = remainingCooldownMs(indexName);
        if (firstRemainingMs > 0L) {
            long cappedMs = maxWaitMs == Long.MAX_VALUE
                    ? firstRemainingMs
                    : Math.min(firstRemainingMs, maxWaitMs);
            String waitMessage = RuntimeConfig.searchDestinationLogPrefix()
                    + " Bulk cooldown wait:"
                    + " index=" + (indexName == null || indexName.isBlank() ? "*" : indexName)
                    + " waitMs=" + cappedMs
                    + (cappedMs < firstRemainingMs ? " (capped from " + firstRemainingMs + ")" : "")
                    + " byteBudget=" + BulkByteBudget.currentMaxBytes()
                    + " inFlightFlushes=" + BulkByteBudget.maxInFlightFlushes() + ".";
            if (cappedMs >= 1_000L) {
                Logger.logInfoPanelOnly(waitMessage);
            } else {
                Logger.logDebug(waitMessage);
            }
            ExportStats.recordCooldownWaitMs(cappedMs);
        }
        while (true) {
            long elapsed = System.nanoTime() - waitStarted;
            if (elapsed >= waitBudgetNanos) {
                return;
            }
            long remainingMs = remainingCooldownMs(indexName);
            if (remainingMs <= 0L) {
                return;
            }
            long park = TimeUnit.MILLISECONDS.toNanos(remainingMs);
            if (waitBudgetNanos != Long.MAX_VALUE) {
                park = Math.min(park, waitBudgetNanos - elapsed);
            }
            if (park <= 0L) {
                return;
            }
            LockSupport.parkNanos(park);
            if (Thread.currentThread().isInterrupted()) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /**
     * Resets shared cooldown, pressure streaks, mild per-index deadlines, and adaptive byte budget
     * for a new export Start.
     *
     * <p>Safe to call from the Config Start path on the EDT before reporters begin.</p>
     *
     * <p>Call before sender threads start; concurrent pressure observations may otherwise race the
     * reset and become part of the new epoch.</p>
     */
    public static void resetForStart() {
        HARD_NOT_BEFORE_NANOS.set(0L);
        PRESSURE_STREAK.set(0L);
        MILD_PRESSURE_STREAK.set(0L);
        MILD_NOT_BEFORE_BY_INDEX.clear();
        BulkByteBudget.resetForStart();
        OfferedLoadGovernor.resetForStart();
        AmazonOpenSearchPressureLog.clear();
    }

    /** Clears the shared cooldown (export stop/clear and focused unit tests). */
    static void clear() {
        ExportStats.recordLastActiveSearchCapacity(
                BulkByteBudget.currentMaxBytes(),
                BulkByteBudget.maxInFlightFlushes());
        resetForStart();
    }

    private static long remainingMildCooldownMs(String indexName) {
        if (indexName == null || indexName.isBlank()) {
            return 0L;
        }
        AtomicLong deadline = MILD_NOT_BEFORE_BY_INDEX.get(normalizeIndexKey(indexName));
        if (deadline == null) {
            return 0L;
        }
        return remainingMs(deadline.get());
    }

    private static long remainingMs(long deadlineNanos) {
        long remainingNanos = deadlineNanos - System.nanoTime();
        if (remainingNanos <= 0L) {
            return 0L;
        }
        return TimeUnit.NANOSECONDS.toMillis(remainingNanos);
    }

    private static String normalizeIndexKey(String indexName) {
        if (indexName == null || indexName.isBlank()) {
            return "";
        }
        return indexName.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static String truncateDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return "none";
        }
        String oneLine = detail.replace('\n', ' ').replace('\r', ' ').strip();
        if (oneLine.length() <= 160) {
            return oneLine;
        }
        return oneLine.substring(0, 157) + "...";
    }

    private static boolean extendHardDeadline(long deadlineNanos) {
        while (true) {
            long current = HARD_NOT_BEFORE_NANOS.get();
            if (deadlineNanos <= current) {
                return false;
            }
            if (HARD_NOT_BEFORE_NANOS.compareAndSet(current, deadlineNanos)) {
                ExportStats.recordCapacityPressureEvent();
                return true;
            }
        }
    }

    private static boolean extendMildDeadline(String indexKey, long deadlineNanos) {
        if (indexKey == null || indexKey.isBlank()) {
            // No index scope — fall back to hard deadline so pressure is not dropped.
            return extendHardDeadline(deadlineNanos);
        }
        AtomicLong holder = MILD_NOT_BEFORE_BY_INDEX.computeIfAbsent(indexKey, key -> new AtomicLong(0L));
        while (true) {
            long current = holder.get();
            if (deadlineNanos <= current) {
                return false;
            }
            if (holder.compareAndSet(current, deadlineNanos)) {
                ExportStats.recordCapacityPressureEvent();
                return true;
            }
        }
    }

    private static Long parseRetryAfterMs(HttpResponse response) {
        if (response == null) {
            return null;
        }
        Header header = response.getFirstHeader("Retry-After");
        if (header == null) {
            return null;
        }
        String raw = header.getValue();
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim();
        try {
            long seconds = Long.parseLong(value);
            if (seconds < 0) {
                return null;
            }
            return TimeUnit.SECONDS.toMillis(seconds);
        } catch (NumberFormatException ignored) {
            // Fall through to HTTP-date parsing.
        }
        try {
            ZonedDateTime when = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME);
            long delay = when.toInstant().toEpochMilli() - System.currentTimeMillis();
            return delay > 0 ? delay : 0L;
        } catch (RuntimeException ignored) {
            return null;
        }
    }
}
