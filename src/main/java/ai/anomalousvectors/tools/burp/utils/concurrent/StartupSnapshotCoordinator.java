package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.ArrayDeque;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Runs startup snapshot slices fairly across source lanes.
 *
 * <p>One daemon owns all lane queues and dispatches at most one slice at a time. Each lane receives
 * one turn per rotation in Config Start order: Findings, Sitemap, Proxy History, then historic
 * WebSocket. Per-lane byte and wall-time observations predict the next item allowance around a
 * 15-second target. A continuation returns to its lane tail, so no source can hold
 * {@link SnapshotExportEngine}'s heavy-work gate for an entire backlog.</p>
 *
 * <p>All public methods are safe to call from any thread. Submitted work runs serially on the
 * coordinator's daemon thread and must not block the EDT while waiting for completion.</p>
 */
public final class StartupSnapshotCoordinator {

    /** Fair startup lanes in Config Start order. */
    public enum Lane {
        /** Burp Scanner findings backlog. */
        FINDINGS,
        /** Burp site map backlog. */
        SITEMAP,
        /** Proxy HTTP history backlog. */
        PROXY_HISTORY,
        /** Proxy WebSocket history backlog. */
        PROXY_WEBSOCKET
    }

    private record QueuedStep(ExportRunToken token, String name, Runnable work) {
    }

    private static final Object LOCK = new Object();
    private static final Map<Lane, ArrayDeque<QueuedStep>> QUEUES = new EnumMap<>(Lane.class);
    private static final Map<Lane, Integer> SLICE_TARGETS = new EnumMap<>(Lane.class);
    private static final Map<Lane, SliceProfile> SLICE_PROFILES = new EnumMap<>(Lane.class);
    static final int INITIAL_SLICE_ITEMS = 50;
    static final int MIN_SLICE_ITEMS = 1;
    static final int MAX_SLICE_ITEMS = 250;
    static final long TARGET_SLICE_MS = 15_000L;
    private static final long TARGET_DEADBAND_MS = 2_250L;
    private static final long SEVERE_OVERRUN_MS = TARGET_SLICE_MS * 3L;
    private static final double PROFILE_WEIGHT = 0.25d;
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "burp-exporter-startup-snapshot");
        thread.setDaemon(true);
        return thread;
    });
    private static int nextLane;
    private static boolean workerScheduled;
    private static QueuedStep runningStep;
    private static ExportRunToken heldRun;

    static {
        for (Lane lane : Lane.values()) {
            QUEUES.put(lane, new ArrayDeque<>());
            SLICE_TARGETS.put(lane, INITIAL_SLICE_ITEMS);
            SLICE_PROFILES.put(lane, SliceProfile.empty());
        }
    }

    private StartupSnapshotCoordinator() {}

    /**
     * Holds dispatch for a new run while Config submits the first lane rotation.
     *
     * <p>Invalid tokens are ignored. A valid token replaces any previous dispatch hold and resets
     * adaptive lane profiles for the new run.</p>
     *
     * @param token committed Start token
     */
    public static void beginRun(ExportRunToken token) {
        if (token == null || !token.isValid()) {
            return;
        }
        synchronized (LOCK) {
            heldRun = token;
            nextLane = 0;
            resetSliceTargetsLocked();
            removeStaleLocked();
        }
    }

    /**
     * Releases a held first rotation after Config has submitted all enabled startup lanes.
     *
     * <p>A null or nonmatching token leaves the active hold unchanged but still schedules any
     * work that is eligible to run.</p>
     *
     * @param token committed Start token
     */
    public static void activateRun(ExportRunToken token) {
        synchronized (LOCK) {
            if (token != null && token.equals(heldRun)) {
                heldRun = null;
            }
            scheduleWorkerLocked();
        }
    }

    /**
     * Queues one source slice in its fair lane.
     *
     * <p>The coordinator invokes {@code step} on its daemon thread. Runtime exceptions are logged
     * and do not stop later lanes. Null lanes or steps and inactive tokens are ignored.</p>
     *
     * @param lane source lane
     * @param token token captured by the reporter
     * @param stepName short label for failure logs
     * @param step bounded work slice
     */
    public static void submit(
            Lane lane,
            ExportRunToken token,
            String stepName,
            Runnable step) {
        if (lane == null || step == null || !RuntimeConfig.isExportRunActive(token)) {
            return;
        }
        String name = stepName == null || stepName.isBlank() ? lane.name() : stepName.trim();
        synchronized (LOCK) {
            QUEUES.get(lane).addLast(new QueuedStep(token, name, step));
            if (!token.equals(heldRun)) {
                scheduleWorkerLocked();
            }
        }
    }

    /**
     * Returns the current adaptive startup item allowance for a lane.
     *
     * <p>A null lane returns the initial allowance.</p>
     *
     * @param lane startup source lane
     * @return item allowance between {@value #MIN_SLICE_ITEMS} and
     *         {@value #MAX_SLICE_ITEMS}
     */
    public static int nextSliceItemCount(Lane lane) {
        if (lane == null) {
            return INITIAL_SLICE_ITEMS;
        }
        synchronized (LOCK) {
            return SLICE_TARGETS.getOrDefault(lane, INITIAL_SLICE_ITEMS);
        }
    }

    /**
     * Records one completed startup slice, adapts its lane, and emits one scheduling summary.
     *
     * <p>The target is advisory for the next slice only. Prepared-byte and throughput history is
     * isolated per lane and reset at each Start. A measured severe overrun may shrink directly to
     * the predicted target; ordinary changes remain step-bounded. This method never interrupts or
     * cancels the completed slice's transport work. Null lanes and nonpositive item counts are
     * ignored; nonpositive byte or elapsed values do not update the throughput profile.</p>
     *
     * @param lane startup source lane
     * @param source operator-facing source label
     * @param startInclusive first source-list index in the completed slice
     * @param itemCount source items consumed by the slice
     * @param bytes prepared NDJSON bytes observed by the snapshot engine
     * @param elapsedMs slice wall time
     * @param hasMore whether the lane has a continuation
     */
    public static void recordSliceOutcome(
            Lane lane,
            String source,
            int startInclusive,
            int itemCount,
            long bytes,
            long elapsedMs,
            boolean hasMore) {
        if (lane == null || itemCount <= 0) {
            return;
        }
        int nextTarget;
        String reason;
        synchronized (LOCK) {
            int current = SLICE_TARGETS.getOrDefault(lane, INITIAL_SLICE_ITEMS);
            SliceProfile profile = updateSliceProfile(
                    SLICE_PROFILES.getOrDefault(lane, SliceProfile.empty()),
                    itemCount,
                    bytes,
                    elapsedMs);
            SLICE_PROFILES.put(lane, profile);
            SliceAdjustment adjustment =
                    adaptSliceTarget(current, itemCount, bytes, elapsedMs, hasMore, profile);
            nextTarget = adjustment.nextTarget();
            reason = adjustment.reason();
            SLICE_TARGETS.put(lane, nextTarget);
        }
        String label = source == null || source.isBlank() ? lane.name() : source.trim();
        int endInclusive = startInclusive + itemCount - 1;
        Logger.logDebug("[StartupExport] " + label
                + ": slice lane=" + lane
                + " range=" + startInclusive + "-" + endInclusive
                + " count=" + itemCount
                + " bytes=" + Math.max(0L, bytes)
                + " elapsedMs=" + Math.max(0L, elapsedMs)
                + " nextTarget=" + nextTarget
                + " reason=" + reason + ".");
    }

    /**
     * Removes queued startup work and requests cancellation of active engine work for {@code token}.
     *
     * <p>An arbitrary lane {@link Runnable} already executing is not forcibly interrupted.
     * Callers may use {@link #awaitIdle(ExportRunToken, long)} to wait for that step to return.
     * Null or invalid tokens are ignored.</p>
     *
     * @param token run being stopped or aborted
     */
    public static void cancelRun(ExportRunToken token) {
        if (token == null || !token.isValid()) {
            return;
        }
        synchronized (LOCK) {
            for (ArrayDeque<QueuedStep> queue : QUEUES.values()) {
                queue.removeIf(step -> token.equals(step.token()));
            }
            if (token.equals(heldRun)) {
                heldRun = null;
            }
            LOCK.notifyAll();
        }
        SnapshotExportEngine.cancelRun(token);
    }

    /**
     * Waits until no queued or running coordinator slice belongs to {@code token}.
     *
     * <p>This method blocks the calling thread. Null or invalid tokens are already idle. A
     * nonpositive timeout performs an immediate check. If interrupted, the method restores the
     * interrupt flag and returns {@code false}.</p>
     *
     * @param token run to observe
     * @param timeoutMs maximum wait in milliseconds
     * @return {@code true} when the run became idle before the deadline
     */
    public static boolean awaitIdle(ExportRunToken token, long timeoutMs) {
        if (token == null || !token.isValid()) {
            return true;
        }
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0L, timeoutMs));
        synchronized (LOCK) {
            while (hasWorkLocked(token)) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0L) {
                    return false;
                }
                try {
                    TimeUnit.NANOSECONDS.timedWait(LOCK, remaining);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * Clears queued work, dispatch holds, and adaptive profiles for deterministic tests.
     *
     * <p>This test seam does not interrupt a step that is already running or clear its
     * {@code runningStep} marker; callers must first ensure active work has completed.</p>
     */
    public static void resetForTests() {
        synchronized (LOCK) {
            for (ArrayDeque<QueuedStep> queue : QUEUES.values()) {
                queue.clear();
            }
            heldRun = null;
            nextLane = 0;
            resetSliceTargetsLocked();
            LOCK.notifyAll();
        }
    }

    private static void scheduleWorkerLocked() {
        if (workerScheduled || heldRun != null || !hasAnyQueuedLocked()) {
            return;
        }
        workerScheduled = true;
        EXECUTOR.execute(StartupSnapshotCoordinator::drain);
    }

    private static void drain() {
        while (true) {
            QueuedStep step;
            synchronized (LOCK) {
                removeStaleLocked();
                if (heldRun != null) {
                    workerScheduled = false;
                    LOCK.notifyAll();
                    return;
                }
                step = pollFairLocked();
                if (step == null) {
                    workerScheduled = false;
                    LOCK.notifyAll();
                    return;
                }
                runningStep = step;
            }
            awaitAuthorizationRecovery(step.token());
            if (RuntimeConfig.isExportRunActive(step.token())) {
                try {
                    step.work().run();
                } catch (RuntimeException e) {
                    if (RuntimeConfig.isExportRunActive(step.token())) {
                        String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                        Logger.logWarnPanelOnly("[StartupExport] " + step.name() + " failed: " + msg);
                    }
                }
            }
            synchronized (LOCK) {
                runningStep = null;
                LOCK.notifyAll();
            }
        }
    }

    private static void awaitAuthorizationRecovery(ExportRunToken token) {
        while (RuntimeConfig.isExportRunActive(token)
                && IndexingRetryCoordinator.getInstance().isAuthorizationRecoveryPaused()
                && !RuntimeConfig.isSearchRecoveryReplay()) {
            try {
                TimeUnit.MILLISECONDS.sleep(250L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static QueuedStep pollFairLocked() {
        Lane[] lanes = Lane.values();
        for (int checked = 0; checked < lanes.length; checked++) {
            int index = (nextLane + checked) % lanes.length;
            ArrayDeque<QueuedStep> queue = QUEUES.get(lanes[index]);
            QueuedStep step = queue.pollFirst();
            if (step != null) {
                nextLane = (index + 1) % lanes.length;
                return step;
            }
        }
        return null;
    }

    private static void removeStaleLocked() {
        for (ArrayDeque<QueuedStep> queue : QUEUES.values()) {
            Iterator<QueuedStep> iterator = queue.iterator();
            while (iterator.hasNext()) {
                if (!RuntimeConfig.isExportRunActive(iterator.next().token())) {
                    iterator.remove();
                }
            }
        }
    }

    private static boolean hasAnyQueuedLocked() {
        for (ArrayDeque<QueuedStep> queue : QUEUES.values()) {
            if (!queue.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasWorkLocked(ExportRunToken token) {
        if (runningStep != null && token.equals(runningStep.token())) {
            return true;
        }
        for (ArrayDeque<QueuedStep> queue : QUEUES.values()) {
            for (QueuedStep step : queue) {
                if (token.equals(step.token())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static SliceAdjustment adaptSliceTarget(
            int current,
            int itemCount,
            long bytes,
            long elapsedMs,
            boolean hasMore,
            SliceProfile profile) {
        if (!hasMore) {
            return new SliceAdjustment(current, "complete");
        }
        long elapsed = Math.max(1L, elapsedMs);
        if (Math.abs(elapsed - TARGET_SLICE_MS) <= TARGET_DEADBAND_MS) {
            return new SliceAdjustment(current, "hold");
        }
        if (bytes <= 0L && elapsed < TARGET_SLICE_MS) {
            return new SliceAdjustment(current, "hold_no_bytes");
        }
        long idealLong = Math.round(itemCount * (double) TARGET_SLICE_MS / elapsed);
        if (profile.hasObservations()) {
            long predictedByteCap = Math.max(
                    1L,
                    Math.round(profile.bytesPerMs() * TARGET_SLICE_MS));
            long byteIdeal = Math.max(
                    MIN_SLICE_ITEMS,
                    Math.round(predictedByteCap / profile.bytesPerItem()));
            idealLong = Math.min(idealLong, byteIdeal);
        }
        int ideal = (int) Math.max(MIN_SLICE_ITEMS, Math.min(MAX_SLICE_ITEMS, idealLong));
        boolean severeMeasuredOverrun = bytes > 0L && elapsed >= SEVERE_OVERRUN_MS;
        int next;
        if (severeMeasuredOverrun && ideal < current) {
            next = ideal;
        } else {
            int step = Math.max(1, current / 2);
            int lower = Math.max(MIN_SLICE_ITEMS, current - step);
            int upper = Math.min(MAX_SLICE_ITEMS, current + step);
            next = Math.max(lower, Math.min(upper, ideal));
        }
        next = Math.max(MIN_SLICE_ITEMS, Math.min(MAX_SLICE_ITEMS, next));
        String reason;
        if (next > current) {
            reason = next == MAX_SLICE_ITEMS ? "clamp_max" : "grow";
        } else if (next < current) {
            if (next == MIN_SLICE_ITEMS) {
                reason = "clamp_min";
            } else {
                reason = severeMeasuredOverrun ? "shrink_fast" : "shrink";
            }
        } else {
            reason = "hold";
        }
        return new SliceAdjustment(next, reason);
    }

    private static SliceProfile updateSliceProfile(
            SliceProfile current, int itemCount, long bytes, long elapsedMs) {
        if (itemCount <= 0 || bytes <= 0L || elapsedMs <= 0L) {
            return current;
        }
        double observedBytesPerItem = bytes / (double) itemCount;
        double observedBytesPerMs = bytes / (double) elapsedMs;
        if (!current.hasObservations()) {
            return new SliceProfile(observedBytesPerItem, observedBytesPerMs);
        }
        return new SliceProfile(
                weighted(current.bytesPerItem(), observedBytesPerItem),
                weighted(current.bytesPerMs(), observedBytesPerMs));
    }

    private static double weighted(double previous, double observed) {
        return previous * (1.0d - PROFILE_WEIGHT) + observed * PROFILE_WEIGHT;
    }

    private static void resetSliceTargetsLocked() {
        for (Lane lane : Lane.values()) {
            SLICE_TARGETS.put(lane, INITIAL_SLICE_ITEMS);
            SLICE_PROFILES.put(lane, SliceProfile.empty());
        }
    }

    private record SliceAdjustment(int nextTarget, String reason) {
    }

    private record SliceProfile(double bytesPerItem, double bytesPerMs) {
        private static SliceProfile empty() {
            return new SliceProfile(0.0d, 0.0d);
        }

        private boolean hasObservations() {
            return bytesPerItem > 0.0d && bytesPerMs > 0.0d;
        }
    }
}
