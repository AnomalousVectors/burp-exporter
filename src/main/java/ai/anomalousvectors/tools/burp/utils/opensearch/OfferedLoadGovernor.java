package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;

/**
 * Governs aggregate request starts and offered bytes for every remote search bulk path.
 *
 * <p>The single process-wide governor starts at one MiB per second and one in-flight request.
 * Reservations use monotonic time, so wall-clock changes cannot create bursts. Hard destination
 * pressure halves the offered rate down to a bounded floor and immediately serializes requests.
 * Recovery is deliberately slower: full payload successes must be spaced, and capacity grows only
 * after elapsed stable windows rather than once per successful request.</p>
 *
 * <p>Thread-safe. Waiting is cooperative: interruption, force-stop, or export Stop bypasses any
 * remaining governor delay so the existing Stop drain wall-clock cap remains authoritative.</p>
 */
public final class OfferedLoadGovernor {

    /** Conservative initial offered rate for small hosted search nodes. */
    public static final long INITIAL_BYTES_PER_SECOND = 1024L * 1024L;
    /** Lowest offered rate retained after repeated hard pressure. */
    public static final long MIN_BYTES_PER_SECOND = 256L * 1024L;
    /** Upper bound reached only after sustained stable operation. */
    public static final long MAX_BYTES_PER_SECOND = 8L * 1024L * 1024L;
    /** Full payload successes required to recover from pressure or Soft Outage. */
    public static final int RECOVERY_SUCCESS_STREAK = 8;

    static final long MIN_SUCCESS_SPACING_NANOS = TimeUnit.MILLISECONDS.toNanos(250L);
    static final long STABLE_GROWTH_WINDOW_NANOS = TimeUnit.SECONDS.toNanos(30L);
    static final long MIN_REQUEST_SPACING_NANOS = TimeUnit.MILLISECONDS.toNanos(25L);
    private static final long MAX_PARK_SLICE_NANOS = TimeUnit.MILLISECONDS.toNanos(50L);

    @FunctionalInterface
    interface WaitStrategy {
        /**
         * Waits for up to the requested monotonic duration.
         *
         * @param nanos positive nanoseconds requested by the governor
         */
        void park(long nanos);
    }

    /**
     * One in-flight request reservation.
     *
     * <p>Close exactly once after the request attempt finishes. Closing is idempotent and may occur
     * on any thread.</p>
     */
    static final class Permit implements AutoCloseable {
        private final OfferedLoadGovernor owner;
        private final boolean counted;
        private final long epoch;
        private boolean closed;

        private Permit(OfferedLoadGovernor owner, boolean counted, long epoch) {
            this.owner = owner;
            this.counted = counted;
            this.epoch = epoch;
        }

        /**
         * Releases the reservation when it belongs to the current governor epoch.
         */
        @Override
        public void close() {
            if (!closed) {
                closed = true;
                owner.release(counted, epoch);
            }
        }
    }

    /**
     * Result of observing one full-payload success.
     *
     * @param recoveryQualified whether pressure-recovery hysteresis is complete
     * @param growthGeneration stable-window generation visible to byte-budget growth
     */
    record SuccessObservation(boolean recoveryQualified, long growthGeneration) {
    }

    private static final OfferedLoadGovernor PRODUCTION = new OfferedLoadGovernor(
            System::nanoTime,
            LockSupport::parkNanos,
            () -> RuntimeConfig.isExportStopping()
                    || RuntimeConfig.isExportStopForceAbortRequested()
                    || Thread.currentThread().isInterrupted(),
            () -> TimeUnit.MILLISECONDS.toNanos(BulkRateLimitBackoff.remainingCooldownMs()));

    private static volatile OfferedLoadGovernor shared = PRODUCTION;

    private final Object monitor = new Object();
    private final LongSupplier nanoTime;
    private final WaitStrategy waitStrategy;
    private final BooleanSupplier stopRequested;
    private final LongSupplier externalDelayNanos;

    private long bytesPerSecond;
    private int maxInFlight;
    private int inFlight;
    private long nextStartNanos;
    private int recoveryStreak;
    private long lastRecoverySuccessNanos;
    private long stableSinceNanos;
    private long lastGrowthNanos;
    private long growthGeneration;
    private boolean pressureActive;
    private long epoch;

    private OfferedLoadGovernor(
            LongSupplier nanoTime,
            WaitStrategy waitStrategy,
            BooleanSupplier stopRequested,
            LongSupplier externalDelayNanos) {
        this.nanoTime = nanoTime;
        this.waitStrategy = waitStrategy;
        this.stopRequested = stopRequested;
        this.externalDelayNanos = externalDelayNanos;
        resetState(nanoTime.getAsLong());
    }

    /**
     * Creates an isolated governor with injectable timing and cancellation collaborators.
     *
     * <p>Suppliers and the wait strategy may be invoked repeatedly from concurrent callers. The
     * clock must be monotonic nanoseconds; external delays use nanoseconds and must be non-negative.
     * Collaborators should not block indefinitely.</p>
     *
     * @param nanoTime monotonic nanosecond clock
     * @param waitStrategy cooperative parking strategy
     * @param stopRequested cancellation/interruption signal
     * @param externalDelayNanos active external cooldown duration supplier
     * @return isolated governor initialized at the supplied current time
     */
    static OfferedLoadGovernor createForTests(
            LongSupplier nanoTime,
            WaitStrategy waitStrategy,
            BooleanSupplier stopRequested,
            LongSupplier externalDelayNanos) {
        return new OfferedLoadGovernor(nanoTime, waitStrategy, stopRequested, externalDelayNanos);
    }

    static Permit acquire(long bytes) {
        if (!ExportRunContext.allowsRunMutation()) {
            return new Permit(shared, false, shared.epochValue());
        }
        return shared.acquirePermit(bytes);
    }

    static SuccessObservation noteFullPayloadSuccess(boolean recoveryEligible, boolean outageActive) {
        if (!ExportRunContext.allowsRunMutation()) {
            return new SuccessObservation(false, shared.growthGenerationForTests());
        }
        return shared.observeFullPayloadSuccess(recoveryEligible, outageActive);
    }

    static void notePartialOrFailedPayload() {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        shared.observePartialOrFailure();
    }

    static void noteHardPressure() {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        shared.observeHardPressure();
    }

    static void noteMildPressure() {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        shared.observeMildPressure();
    }

    static boolean isPressureActive() {
        return shared.pressureActiveValue();
    }

    /**
     * Returns the current aggregate offered byte rate for Stats and diagnostics.
     *
     * @return positive bytes-per-second ceiling
     */
    public static long currentBytesPerSecond() {
        return shared.bytesPerSecondValue();
    }

    /**
     * Returns the current global in-flight request ceiling for Stats and diagnostics.
     *
     * @return positive request-concurrency ceiling
     */
    public static int currentMaxInFlight() {
        return shared.maxInFlightValue();
    }

    /**
     * Returns the current spaced full-payload recovery streak.
     *
     * @return non-negative recovery success count
     */
    public static int currentRecoveryStreak() {
        return shared.recoveryStreakValue();
    }

    /**
     * Resets the shared governor to its conservative Start state.
     *
     * <p>Existing permits from the previous epoch become inert when closed. Lifecycle code should
     * invoke this before new sender work begins.</p>
     */
    public static void resetForStart() {
        shared.resetState(shared.nanoTime.getAsLong());
    }

    /**
     * Replaces the process-wide governor for isolated tests.
     *
     * @param governor replacement governor; {@code null} restores production
     */
    static void setSharedForTests(OfferedLoadGovernor governor) {
        shared = governor == null ? PRODUCTION : governor;
    }

    /** Restores and resets the production governor after an isolated test. */
    static void restoreProductionForTests() {
        shared = PRODUCTION;
        PRODUCTION.resetState(PRODUCTION.nanoTime.getAsLong());
    }

    Permit acquirePermit(long bytes) {
        long normalizedBytes = Math.max(1L, bytes);
        while (true) {
            if (stopRequested.getAsBoolean() || Thread.currentThread().isInterrupted()) {
                return new Permit(this, false, epochValue());
            }
            long waitNanos;
            synchronized (monitor) {
                long now = nanoTime.getAsLong();
                long pacingDelay = Math.max(0L, nextStartNanos - now);
                long cooldownDelay = Math.max(0L, externalDelayNanos.getAsLong());
                if (inFlight < maxInFlight && pacingDelay == 0L && cooldownDelay == 0L) {
                    inFlight++;
                    long byteSpacing = saturatedMultiplyDivide(
                            normalizedBytes, TimeUnit.SECONDS.toNanos(1L), bytesPerSecond);
                    long spacing = Math.max(MIN_REQUEST_SPACING_NANOS, byteSpacing);
                    nextStartNanos = saturatedAdd(now, spacing);
                    return new Permit(this, true, epoch);
                }
                if (inFlight >= maxInFlight) {
                    waitNanos = MAX_PARK_SLICE_NANOS;
                } else {
                    waitNanos = Math.max(pacingDelay, cooldownDelay);
                    waitNanos = Math.min(MAX_PARK_SLICE_NANOS, Math.max(1L, waitNanos));
                }
            }
            waitStrategy.park(waitNanos);
        }
    }

    SuccessObservation observeFullPayloadSuccess(
            boolean recoveryEligible,
            boolean outageActive) {
        synchronized (monitor) {
            long now = nanoTime.getAsLong();
            boolean pressureEpoch =
                    outageActive || pressureActive || externalDelayNanos.getAsLong() > 0L;
            if (recoveryEligible
                    && pressureEpoch
                    && (lastRecoverySuccessNanos < 0L
                            || now - lastRecoverySuccessNanos >= MIN_SUCCESS_SPACING_NANOS)) {
                recoveryStreak++;
                lastRecoverySuccessNanos = now;
            }
            boolean recoveryQualified =
                    recoveryEligible && pressureEpoch && recoveryStreak >= RECOVERY_SUCCESS_STREAK;
            if (pressureEpoch) {
                stableSinceNanos = -1L;
                lastGrowthNanos = -1L;
                return new SuccessObservation(recoveryQualified, growthGeneration);
            }
            if (stableSinceNanos < 0L) {
                stableSinceNanos = now;
                lastGrowthNanos = now;
                return new SuccessObservation(recoveryQualified, growthGeneration);
            }
            if (now - lastGrowthNanos >= STABLE_GROWTH_WINDOW_NANOS) {
                long previous = bytesPerSecond;
                long increase = Math.max(1L, previous / 10L);
                bytesPerSecond = Math.min(MAX_BYTES_PER_SECOND, previous + increase);
                if (bytesPerSecond != previous) {
                    growthGeneration++;
                    if (maxInFlight < 2) {
                        maxInFlight = 2;
                    }
                }
                lastGrowthNanos = now;
            }
            return new SuccessObservation(recoveryQualified, growthGeneration);
        }
    }

    void observePartialOrFailure() {
        synchronized (monitor) {
            recoveryStreak = 0;
            lastRecoverySuccessNanos = -1L;
            stableSinceNanos = -1L;
            lastGrowthNanos = -1L;
        }
    }

    void observeHardPressure() {
        synchronized (monitor) {
            bytesPerSecond = Math.max(MIN_BYTES_PER_SECOND, bytesPerSecond / 2L);
            maxInFlight = 1;
            pressureActive = true;
            recoveryStreak = 0;
            lastRecoverySuccessNanos = -1L;
            stableSinceNanos = -1L;
            lastGrowthNanos = -1L;
        }
    }

    void observeMildPressure() {
        synchronized (monitor) {
            pressureActive = true;
            recoveryStreak = 0;
            lastRecoverySuccessNanos = -1L;
            stableSinceNanos = -1L;
            lastGrowthNanos = -1L;
        }
    }

    static void noteStableRecoveryComplete() {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        shared.completeStableRecovery();
    }

    void completeStableRecovery() {
        synchronized (monitor) {
            pressureActive = false;
            recoveryStreak = 0;
            lastRecoverySuccessNanos = -1L;
            stableSinceNanos = nanoTime.getAsLong();
            lastGrowthNanos = stableSinceNanos;
        }
    }

    private void release(boolean counted, long permitEpoch) {
        if (!counted) {
            return;
        }
        synchronized (monitor) {
            if (permitEpoch != epoch) {
                return;
            }
            if (inFlight > 0) {
                inFlight--;
            }
            monitor.notifyAll();
        }
    }

    long bytesPerSecondValue() {
        synchronized (monitor) {
            return bytesPerSecond;
        }
    }

    int maxInFlightValue() {
        synchronized (monitor) {
            return maxInFlight;
        }
    }

    int recoveryStreakValue() {
        synchronized (monitor) {
            return recoveryStreak;
        }
    }

    /**
     * Returns this instance's in-flight count for isolated concurrency tests.
     *
     * @return non-negative current reservation count
     */
    int inFlightValueForTests() {
        synchronized (monitor) {
            return inFlight;
        }
    }

    private boolean pressureActiveValue() {
        synchronized (monitor) {
            return pressureActive;
        }
    }

    /**
     * Returns this instance's stable growth generation for isolated timing tests.
     *
     * @return non-negative generation counter
     */
    long growthGenerationForTests() {
        synchronized (monitor) {
            return growthGeneration;
        }
    }

    private long epochValue() {
        synchronized (monitor) {
            return epoch;
        }
    }

    void resetState(long now) {
        synchronized (monitor) {
            epoch++;
            bytesPerSecond = INITIAL_BYTES_PER_SECOND;
            maxInFlight = 1;
            inFlight = 0;
            nextStartNanos = now;
            recoveryStreak = 0;
            lastRecoverySuccessNanos = -1L;
            stableSinceNanos = -1L;
            lastGrowthNanos = -1L;
            growthGeneration = 0L;
            pressureActive = false;
            monitor.notifyAll();
        }
    }

    private static long saturatedMultiplyDivide(long value, long multiplier, long divisor) {
        if (value <= 0L || multiplier <= 0L) {
            return 0L;
        }
        if (value > Long.MAX_VALUE / multiplier) {
            return Long.MAX_VALUE;
        }
        return (value * multiplier) / Math.max(1L, divisor);
    }

    private static long saturatedAdd(long left, long right) {
        if (right > 0L && left > Long.MAX_VALUE - right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }
}
