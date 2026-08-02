package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;

/**
 * Adaptive bulk payload byte budget and snapshot flush concurrency for search destinations.
 *
 * <p>All search-database destinations (Amazon OpenSearch Hosted/Serverless, upstream OpenSearch,
 * Elasticsearch) share the same AIMD-style controller: start well under observed cloud limits, grow
 * on sustained success, shrink on capacity pressure, and briefly serialize snapshot flushes under
 * hard pressure. Adaptive destinations begin at {@code 1 MiB} with a single in-flight flush, then
 * climb toward the {@code 5 MiB} ceiling and higher concurrency only after a healthy success
 * streak.</p>
 *
 * <p>Hard capacity signals ({@code 429}/{@code 502}/{@code 503}/{@code 504} and equivalent
 * transport failures) floor the budget immediately so small Hosted instances are not re-slammed
 * with half-sized retries. Soft Outage clear keeps the floored budget and serialized flushes;
 * growth must be re-earned by successes while healthy. One document's NDJSON is indivisible on the
 * wire, so a derived search copy must be fitted to the live budget before posting (see
 * {@link #exceedsLiveBudget(long)}).</p>
 *
 * <p>Thread-safe. Call {@link #resetForStart()} before an export run begins; until that lifecycle
 * initialization occurs, static defaults are not a promise of the documented one-flush cold-start
 * state. Adaptation is process-wide and observations from concurrent senders may be coalesced.</p>
 */
public final class BulkByteBudget {

    /** Historical / non-adaptive ceiling label (also the shared adaptive max). */
    public static final long FIXED_MAX_BYTES = 5L * 1024 * 1024;

    /** Shared adaptive starting bulk byte budget (well under small-hosted pressure). */
    public static final long AMAZON_INITIAL_BYTES = 1L * 1024 * 1024;

    /** Shared floor after repeated shrinks. */
    public static final long AMAZON_MIN_BYTES = 512L * 1024;

    /** Shared ceiling (AWS 3–5 MiB guidance band upper end). */
    public static final long AMAZON_MAX_BYTES = 5L * 1024 * 1024;

    /** Alias for the shared adaptive floor. */
    public static final long ADAPTIVE_MIN_BYTES = AMAZON_MIN_BYTES;

    /** Alias for the shared adaptive ceiling. */
    public static final long ADAPTIVE_MAX_BYTES = AMAZON_MAX_BYTES;

    private static final long GROW_STEP_BYTES = 512L * 1024;
    /** Start serialized so cold Start cannot pile concurrent bulks onto a cold cloud endpoint. */
    private static final int INITIAL_IN_FLIGHT_FLUSHES = 1;
    /** Proven default concurrency after a healthy warm-up streak. */
    private static final int DEFAULT_IN_FLIGHT_FLUSHES = 2;
    /** Proven-headroom snapshot concurrency when metrics show unused capacity. */
    private static final int HEADROOM_IN_FLIGHT_FLUSHES = 3;
    private static final int RATE_LIMITED_IN_FLIGHT_FLUSHES = 1;
    private static final AtomicLong budgetBytes = new AtomicLong(AMAZON_INITIAL_BYTES);
    private static final AtomicLong lastKnownGoodBytes = new AtomicLong(AMAZON_INITIAL_BYTES);
    private static final AtomicInteger maxInFlightFlushes = new AtomicInteger(DEFAULT_IN_FLIGHT_FLUSHES);
    private static final AtomicBoolean rateLimitByteShrinkPending = new AtomicBoolean(false);
    private static final AtomicInteger successStreak = new AtomicInteger(0);
    private static final AtomicLong appliedGrowthGeneration = new AtomicLong(0L);
    private static final AtomicLong lastFloorLogNanos = new AtomicLong(0L);
    private static final long FLOOR_LOG_INTERVAL_NANOS = 30_000_000_000L;
    /** EMA of successful bulk latency (ms); {@code 0} means uninitialized. */
    private static final AtomicLong latencyEmaMs = new AtomicLong(0L);
    /** Healthy baseline EMA captured while not under pressure. */
    private static final AtomicLong latencyBaselineMs = new AtomicLong(0L);
    private static final double LATENCY_EMA_ALPHA = 0.20d;
    /** Shrink when live latency exceeds this multiple of the healthy baseline. */
    private static final double LATENCY_PRESSURE_RATIO = 2.5d;
    private static final long LATENCY_MIN_SAMPLES_MS = 250L;

    private BulkByteBudget() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns whether the active search destination is Amazon OpenSearch.
     *
     * @return {@code true} for the Amazon OpenSearch destination
     */
    public static boolean isAmazonDestination() {
        return RuntimeConfig.searchDestinationKind() == ConfigState.SearchDestination.OPEN_SEARCH_AMAZON;
    }

    /**
     * Returns whether the active destination uses the adaptive bulk controller.
     *
     * <p>All configured search destinations share adaptation so cloud OpenSearch, Amazon, and
     * Elasticsearch receive equal limit handling.</p>
     *
     * @return {@code true} when the active destination participates in adaptation
     */
    public static boolean isAdaptiveDestination() {
        ConfigState.SearchDestination kind = RuntimeConfig.searchDestinationKind();
        return kind == ConfigState.SearchDestination.OPEN_SEARCH
                || kind == ConfigState.SearchDestination.OPEN_SEARCH_AMAZON
                || kind == ConfigState.SearchDestination.ELASTICSEARCH;
    }

    /**
     * Returns the starting byte budget for the active destination kind.
     *
     * @return initial NDJSON byte ceiling
     */
    public static long initialBytesForDestination() {
        return isAdaptiveDestination() ? AMAZON_INITIAL_BYTES : FIXED_MAX_BYTES;
    }

    /**
     * Returns the bulk payload byte ceiling for the next send.
     *
     * @return positive live NDJSON byte ceiling
     */
    public static long currentMaxBytes() {
        if (!isAdaptiveDestination()) {
            return FIXED_MAX_BYTES;
        }
        return budgetBytes.get();
    }

    /**
     * Returns whether a single prepared document exceeds the live HTTP bulk ceiling.
     *
     * <p>Oversized documents cannot be split across requests. Callers must
     * {@linkplain ai.anomalousvectors.tools.burp.utils.export.SearchBodyPrefixFitter fit} them to
     * {@link #currentMaxBytes()} by prefix-truncating large values (never size Permanent Drop).</p>
     *
     * @param docBytes prepared NDJSON byte length; {@code <= 0} is treated as fitting
     * @return {@code true} when {@code docBytes} is larger than the live budget
     */
    public static boolean exceedsLiveBudget(long docBytes) {
        return docBytes > currentMaxBytes();
    }

    /**
     * Returns how many snapshot bulk flushes may be in flight.
     *
     * @return positive live snapshot-flush concurrency ceiling
     */
    public static int maxInFlightFlushes() {
        if (!isAdaptiveDestination()) {
            return DEFAULT_IN_FLIGHT_FLUSHES;
        }
        return maxInFlightFlushes.get();
    }

    /**
     * Grows the byte budget after a successful bulk and restores flush concurrency.
     *
     * <p>Growth consumes elapsed stable-window generations from {@link OfferedLoadGovernor}; many
     * fast successes in one window therefore cannot inflate payload size or concurrency. Growth is
     * suppressed while Soft Outage or a hard cooldown is active.</p>
     *
     * @param bulkBytes successful bulk payload size hint; {@code <= 0} still counts toward the streak
     */
    public static void recordSuccess(long bulkBytes) {
        recordFullPayloadSuccess(bulkBytes, false);
    }

    /**
     * Records a full payload bulk success and applies at most one elapsed stable growth window.
     *
     * <p>When {@code recoveryEligible} is true, spaced successes contribute to Soft Outage
     * hysteresis. Growth remains disabled until outage and pressure state have actually cleared.</p>
     *
     * @param bulkBytes successful bulk payload size hint
     * @param recoveryEligible whether this was a payload bulk that may prove destination recovery
     * @return {@code true} when the configured full-payload recovery streak is complete
     */
    public static boolean recordFullPayloadSuccess(long bulkBytes, boolean recoveryEligible) {
        if (!ExportRunContext.allowsRunMutation()) {
            return false;
        }
        boolean outageActive = IndexingRetryCoordinator.getInstance().isSoftCapacityOutage();
        OfferedLoadGovernor.SuccessObservation observation =
                OfferedLoadGovernor.noteFullPayloadSuccess(recoveryEligible, outageActive);
        if (observation.recoveryQualified()) {
            BulkRateLimitBackoff.noteStablePayloadRecovery();
        }
        if (!isAdaptiveDestination()) {
            return observation.recoveryQualified();
        }
        rateLimitByteShrinkPending.set(false);
        boolean underPressure = BulkRateLimitBackoff.isCoolingDown()
                || BulkRateLimitBackoff.pressureStreak() > 0L
                || OfferedLoadGovernor.isPressureActive()
                || outageActive;
        if (underPressure) {
            // Full payload evidence may advance hysteresis, but must not grow during the epoch.
            successStreak.set(0);
            return observation.recoveryQualified();
        }
        long generation = observation.growthGeneration();
        long applied = appliedGrowthGeneration.get();
        if (generation <= applied || !appliedGrowthGeneration.compareAndSet(applied, generation)) {
            return observation.recoveryQualified();
        }
        int stableWindows = successStreak.incrementAndGet();
        maxInFlightFlushes.set(stableWindows >= 2
                ? HEADROOM_IN_FLIGHT_FLUSHES
                : DEFAULT_IN_FLIGHT_FLUSHES);
        long prev = budgetBytes.get();
        if (bulkBytes > 0L) {
            lastKnownGoodBytes.updateAndGet(known -> Math.max(known, Math.min(ADAPTIVE_MAX_BYTES, bulkBytes)));
        } else {
            lastKnownGoodBytes.updateAndGet(known -> Math.max(known, prev));
        }
        if (latencyElevated()) {
            // Latency pressure: do not grow; optionally step down once.
            if (prev > ADAPTIVE_MIN_BYTES) {
                long next = Math.max(ADAPTIVE_MIN_BYTES, prev - GROW_STEP_BYTES);
                if (budgetBytes.compareAndSet(prev, next) && next != prev) {
                    logBudgetChange("shrunk:latency", prev, next, bulkBytes);
                }
            }
            return observation.recoveryQualified();
        }
        if (prev >= ADAPTIVE_MAX_BYTES) {
            return observation.recoveryQualified();
        }
        long known = lastKnownGoodBytes.get();
        long step = Math.min(GROW_STEP_BYTES, Math.max(1L, prev / 10L));
        long next = Math.min(ADAPTIVE_MAX_BYTES, Math.max(prev + step, Math.min(known, prev + GROW_STEP_BYTES)));
        if (budgetBytes.compareAndSet(prev, next) && next != prev) {
            logBudgetChange("grew", prev, next, bulkBytes);
        }
        return observation.recoveryQualified();
    }

    /**
     * Shrinks the byte budget after a failed or partial bulk.
     *
     * <p>Skips a second shrink when {@link #applyRateLimitPressure} already halved the budget for
     * the same capacity event.</p>
     *
     * <p>Stale export-run observations are ignored.</p>
     */
    public static void recordFailure() {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        OfferedLoadGovernor.notePartialOrFailedPayload();
        if (!isAdaptiveDestination()) {
            return;
        }
        successStreak.set(0);
        if (rateLimitByteShrinkPending.compareAndSet(true, false)) {
            return;
        }
        shrinkBudget("failure");
    }

    /**
     * Applies hard capacity controls after gateway/transport pressure
     * ({@code 429}/{@code 502}/{@code 503}/{@code 504} or equivalent).
     *
     * <p>Floors the byte budget (once per event), serializes snapshot flushes, and emits a WARN
     * diagnostic.</p>
     *
     * @param status HTTP status
     * @param indexName target index
     * @param pathLabel prepared/chunked path label
     * @param cooldownMs shared cooldown about to apply
     */
    public static void applyRateLimitPressure(
            int status,
            String indexName,
            String pathLabel,
            long cooldownMs) {
        applyRateLimitPressure(status, indexName, pathLabel, cooldownMs, true);
    }

    /**
     * Compatibility alias for {@link #applyRateLimitPressure(int, String, String, long)}.
     *
     * @param status HTTP status
     * @param indexName target index
     * @param pathLabel prepared/chunked path label
     * @param cooldownMs shared cooldown about to apply
     */
    public static void applyAmazonRateLimitPressure(
            int status,
            String indexName,
            String pathLabel,
            long cooldownMs) {
        applyRateLimitPressure(status, indexName, pathLabel, cooldownMs);
    }

    /**
     * Applies milder pressure for per-item capacity errors (HTTP 200 item throttle / circuit break).
     *
     * <p>Shrinks the budget but keeps a slightly higher floor step and does not force flush
     * serialization unless concurrency is already reduced — avoids treating one item failure like a
     * gateway outage.</p>
     *
     * @param indexName target index
     * @param pathLabel prepared/chunked path label
     * @param cooldownMs per-index cooldown about to apply
     */
    public static void applyMildItemPressure(String indexName, String pathLabel, long cooldownMs) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        OfferedLoadGovernor.notePartialOrFailedPayload();
        if (!isAdaptiveDestination()) {
            return;
        }
        successStreak.set(0);
        long prevBytes = budgetBytes.get();
        // Mild: step down by 25% instead of half, still respect floor.
        long next = Math.max(ADAPTIVE_MIN_BYTES, prevBytes - Math.max(GROW_STEP_BYTES, prevBytes / 4L));
        if (budgetBytes.compareAndSet(prevBytes, next) && next != prevBytes) {
            lastKnownGoodBytes.updateAndGet(known -> Math.min(known, next));
            logBudgetChange("shrunk:item", prevBytes, next, -1L);
        }
        rateLimitByteShrinkPending.set(true);
        String index = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        String path = pathLabel == null || pathLabel.isBlank() ? "Bulk" : pathLabel;
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk mild item pressure applied:"
                + " path=" + path
                + " index=" + index
                + " cooldownMs=" + cooldownMs
                + " docBatch=" + BatchSizeController.getInstance().getCurrentBatchSize()
                + " byteBudget=" + formatMib(budgetBytes.get())
                + " (was " + formatMib(prevBytes) + ")"
                + " inFlightFlushes=" + maxInFlightFlushes.get() + ".");
    }

    private static void applyRateLimitPressure(
            int status,
            String indexName,
            String pathLabel,
            long cooldownMs,
            boolean serializeFlushes) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        if (!isAdaptiveDestination()) {
            return;
        }
        successStreak.set(0);
        long prevBytes = budgetBytes.get();
        shrinkBudget("rate_limit");
        rateLimitByteShrinkPending.set(true);
        int prevInFlight = maxInFlightFlushes.get();
        if (serializeFlushes) {
            maxInFlightFlushes.set(RATE_LIMITED_IN_FLIGHT_FLUSHES);
        }
        int docBatch = BatchSizeController.getInstance().getCurrentBatchSize();
        long nextBytes = budgetBytes.get();
        String index = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        String path = pathLabel == null || pathLabel.isBlank() ? "Bulk" : pathLabel;
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk pressure applied: HTTP " + status
                + " path=" + path
                + " index=" + index
                + " cooldownMs=" + cooldownMs
                + " docBatch=" + docBatch
                + " byteBudget=" + formatMib(nextBytes)
                + " (was " + formatMib(prevBytes) + ")"
                + " inFlightFlushes=" + maxInFlightFlushes.get()
                + " (was " + prevInFlight + ")");
    }

    /**
     * Holds the floored budget after payload-success hysteresis clears Soft Outage.
     *
     * <p>Keeps snapshot flushes serialized ({@code 1} in-flight) and resets the success streak so
     * concurrency and larger budgets must be re-earned from successes. Does not bump the byte budget
     * on clear — larger payloads must be re-earned through elapsed stable windows.</p>
     *
     * @param reason short diagnostic reason; blank becomes {@code recovered}
     */
    public static void restoreAfterRecovery(String reason) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        if (!isAdaptiveDestination()) {
            return;
        }
        rateLimitByteShrinkPending.set(false);
        successStreak.set(0);
        // Stay serialized after Soft Outage; require a fresh success streak for concurrency.
        maxInFlightFlushes.set(RATE_LIMITED_IN_FLIGHT_FLUSHES);
        long prev = budgetBytes.get();
        String label = reason == null || reason.isBlank() ? "recovered" : ("recovered:" + reason);
        Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk byte budget " + label + ": hold " + formatMib(prev)
                + " inFlightFlushes=" + maxInFlightFlushes.get());
    }

    /**
     * Resets adaptive budget and flush concurrency to the cold-start state.
     *
     * <p>Intended for lifecycle ownership paths after active senders have quiesced.</p>
     */
    public static void clear() {
        resetForStart();
    }

    /**
     * Seeds adaptive state for the active destination at export Start.
     *
     * <p>Lifecycle code should invoke this before reporters or traffic workers begin recording
     * observations.</p>
     */
    public static void resetForStart() {
        long initial = initialBytesForDestination();
        budgetBytes.set(initial);
        lastKnownGoodBytes.set(initial);
        maxInFlightFlushes.set(INITIAL_IN_FLIGHT_FLUSHES);
        rateLimitByteShrinkPending.set(false);
        successStreak.set(0);
        lastFloorLogNanos.set(0L);
        latencyEmaMs.set(0L);
        latencyBaselineMs.set(0L);
        appliedGrowthGeneration.set(0L);
    }

    /**
     * Updates the bulk latency EMA from a completed send and may tighten growth under delay.
     *
     * @param durationMs observed bulk duration; values {@code <= 0} are ignored
     */
    public static void recordBulkLatency(long durationMs) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        if (!isAdaptiveDestination() || durationMs <= 0L) {
            return;
        }
        long prevEma = latencyEmaMs.get();
        long nextEma;
        if (prevEma <= 0L) {
            nextEma = durationMs;
        } else {
            nextEma = Math.round((LATENCY_EMA_ALPHA * durationMs)
                    + ((1.0d - LATENCY_EMA_ALPHA) * prevEma));
        }
        latencyEmaMs.set(nextEma);
        boolean healthy = !BulkRateLimitBackoff.isCoolingDown()
                && BulkRateLimitBackoff.pressureStreak() == 0L
                && !IndexingRetryCoordinator.getInstance().isSoftCapacityOutage();
        if (healthy && durationMs >= LATENCY_MIN_SAMPLES_MS) {
            long baseline = latencyBaselineMs.get();
            // Do not let elevated samples inflate the healthy baseline.
            if (baseline > 0L && durationMs >= (long) (baseline * LATENCY_PRESSURE_RATIO)) {
                return;
            }
            if (baseline <= 0L) {
                latencyBaselineMs.set(nextEma);
            } else {
                long nextBaseline = Math.round((0.10d * nextEma) + (0.90d * baseline));
                latencyBaselineMs.set(nextBaseline);
            }
        }
    }

    /**
     * Returns whether the latency EMA is elevated versus the healthy baseline.
     *
     * @return {@code true} when initialized latency exceeds the pressure ratio
     */
    public static boolean latencyElevated() {
        long ema = latencyEmaMs.get();
        long baseline = latencyBaselineMs.get();
        if (ema <= 0L || baseline < LATENCY_MIN_SAMPLES_MS) {
            return false;
        }
        return ema >= (long) (baseline * LATENCY_PRESSURE_RATIO);
    }

    private static void shrinkBudget(String reason) {
        long prev = budgetBytes.get();
        // Hard gateway/transport pressure: floor immediately so the next send matches a small
        // Hosted instance instead of yo-yoing through half-sized multi-MiB retries.
        long next = "rate_limit".equals(reason)
                ? ADAPTIVE_MIN_BYTES
                : Math.max(ADAPTIVE_MIN_BYTES, prev / 2L);
        if (budgetBytes.compareAndSet(prev, next) && next != prev) {
            // Drop stale high-water marks so Soft Outage clear cannot jump back to pre-collapse size.
            lastKnownGoodBytes.updateAndGet(known -> Math.min(known, next));
            logBudgetChange("shrunk:" + reason, prev, next, -1L);
        } else if (next == prev) {
            long now = System.nanoTime();
            long previousLog = lastFloorLogNanos.get();
            if (now - previousLog >= FLOOR_LOG_INTERVAL_NANOS
                    && lastFloorLogNanos.compareAndSet(previousLog, now)) {
                Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                        + " Bulk byte budget already at floor " + formatMib(prev)
                        + " (" + reason + ")");
            }
        }
    }

    private static void logBudgetChange(String action, long prev, long next, long bulkBytes) {
        String bulkHint = bulkBytes > 0L ? (" lastBulk=" + formatMib(bulkBytes)) : "";
        String message = RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk byte budget " + action + ": "
                + formatMib(prev) + " -> " + formatMib(next)
                + bulkHint
                + " docBatch=" + BatchSizeController.getInstance().getCurrentBatchSize()
                + " inFlightFlushes=" + maxInFlightFlushes.get();
        if (action != null && (action.startsWith("grew") || action.startsWith("recovered"))) {
            Logger.logDebug(message);
        } else {
            Logger.logInfoPanelOnly(message);
        }
    }

    private static String formatMib(long bytes) {
        double mib = bytes / (1024.0 * 1024.0);
        return String.format(java.util.Locale.ROOT, "%.2fMiB", mib);
    }
}
