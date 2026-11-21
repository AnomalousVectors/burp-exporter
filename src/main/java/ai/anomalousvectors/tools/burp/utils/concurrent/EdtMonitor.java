package ai.anomalousvectors.tools.burp.utils.concurrent;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Monitors Event Dispatch Thread (EDT) responsiveness during long-running snapshots so we can
 * tell whether observed UI freezes are caused by JVM-wide stop-the-world pauses, EDT-only
 * starvation (snapshot thread busy, EDT idle but not scheduled), or a specific blocking call
 * holding the EDT.
 *
 * <p>The monitor runs on a dedicated daemon thread and uses a self-pinging probe pattern:</p>
 * <ol>
 *   <li>Every {@link #PROBE_INTERVAL_MS} a tick on the monitor thread records a posted
 *       timestamp and submits {@link SwingUtilities#invokeLater(Runnable)} that records its
 *       run timestamp once the EDT actually executes it.</li>
 *   <li>If the most recently posted probe has not yet been processed and the gap exceeds
 *       {@link #LAG_DUMP_THRESHOLD_MS}, the monitor captures the EDT stack via
 *       {@link Thread#getAllStackTraces()} and emits a {@code [EdtMonitor]} log line. Repeat
 *       captures during the same stuck window are throttled to once per
 *       {@link #LAG_DUMP_THRESHOLD_MS} so a 30 s freeze produces a handful of stack samples
 *       rather than a flood.</li>
 *   <li>A new probe is only posted when the previous one has run, so probes never queue up
 *       behind a frozen EDT and inflate apparent recovery time.</li>
 * </ol>
 *
 * <p>The class is intentionally a small, dependency-free static singleton: snapshot reporters
 * call {@link #start()} when their loop begins and {@link #stop()} when it ends. Multiple
 * concurrent snapshots are reference-counted so the monitor survives across overlapping
 * {@code start}/{@code stop} pairs.</p>
 */
public final class EdtMonitor {

    /** Cadence at which the monitor pings the EDT. */
    static final long PROBE_INTERVAL_MS = 500L;

    /** Lag floor for emitting an {@code [EdtMonitor]} log line and capturing the EDT stack. */
    static final long LAG_DUMP_THRESHOLD_MS = 2_000L;

    /** Maximum number of stack frames included in a single capture line. */
    static final int MAX_STACK_FRAMES = 20;

    private static final Object LOCK = new Object();

    private static volatile ScheduledExecutorService scheduler;
    private static int activeRefs;

    private static final AtomicLong lastPostedMs = new AtomicLong(0L);
    private static final AtomicLong lastRanMs = new AtomicLong(0L);
    private static final AtomicLong lastDumpMs = new AtomicLong(0L);

    /**
     * Top frame from the most recent capture. While unchanged across consecutive captures
     * the monitor emits a one-line "still-stuck" marker rather than the full stack so a long
     * freeze does not flood the panel logger (which itself rides the EDT we are diagnosing).
     */
    private static final AtomicReference<String> lastTopFrame = new AtomicReference<>(null);

    private EdtMonitor() {}

    /**
     * Starts the monitor (or increments its reference count if already started).
     *
     * <p>Safe to call from any thread. Reference-counted so overlapping snapshot lifecycles
     * do not race; the underlying scheduler only stops once {@link #stop()} has been called
     * the same number of times.</p>
     */
    public static void start() {
        synchronized (LOCK) {
            activeRefs++;
            if (scheduler != null) {
                return;
            }
            ScheduledExecutorService s = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "af-edt-monitor");
                t.setDaemon(true);
                return t;
            });
            scheduler = s;
            lastPostedMs.set(0L);
            lastRanMs.set(0L);
            lastDumpMs.set(0L);
            lastTopFrame.set(null);
            s.scheduleWithFixedDelay(
                    EdtMonitor::tick, PROBE_INTERVAL_MS, PROBE_INTERVAL_MS, TimeUnit.MILLISECONDS);
        }
    }

    /**
     * Decrements the reference count and stops the monitor when no callers remain.
     *
     * <p>Safe to call from any thread; mismatched stops (more stops than starts) are tolerated
     * and treated as no-ops so accidental double-stops cannot leak a scheduler.</p>
     */
    public static void stop() {
        ScheduledExecutorService toShutdown = null;
        synchronized (LOCK) {
            if (activeRefs > 0) {
                activeRefs--;
            }
            if (activeRefs == 0 && scheduler != null) {
                toShutdown = scheduler;
                scheduler = null;
            }
        }
        if (toShutdown != null) {
            toShutdown.shutdownNow();
        }
    }

    /**
     * Single tick of the monitor. Captures the EDT stack when a posted probe has not been
     * processed within the configured threshold; otherwise (and additionally) posts a fresh
     * probe so we can observe the next interval.
     */
    static void tick() {
        long now = System.currentTimeMillis();
        long posted = lastPostedMs.get();
        long ran = lastRanMs.get();
        boolean probeOutstanding = posted > ran;
        long lag = probeOutstanding ? (now - posted) : 0L;

        if (probeOutstanding && lag >= LAG_DUMP_THRESHOLD_MS) {
            long lastDump = lastDumpMs.get();
            if (lastDump <= 0L || (now - lastDump) >= LAG_DUMP_THRESHOLD_MS) {
                captureAndLogEdtStack(lag, now);
                lastDumpMs.set(now);
            }
        }

        if (!probeOutstanding) {
            // EDT recovered (or no prior probe). Reset the dedup state so the next freeze
            // emits a full stack capture rather than another "still-stuck" marker against
            // the previous frame.
            lastTopFrame.set(null);
            lastPostedMs.set(now);
            SwingUtilities.invokeLater(() -> lastRanMs.set(System.currentTimeMillis()));
        }
    }

    /**
     * Captures the EDT thread's current stack and emits a single-line log entry tagged with
     * the worker timestamp. Errors during capture are intentionally swallowed so a failure to
     * sample never breaks the monitor.
     */
    private static void captureAndLogEdtStack(long lagMs, long workerTimestampMs) {
        Thread edt = findEdtThread();
        StackTraceElement[] frames = (edt == null) ? new StackTraceElement[0] : safeGetStackTrace(edt);
        String topFrame = (frames.length > 0) ? frames[0].toString() : "";

        String prevTopFrame = lastTopFrame.get();
        if (Objects.equals(topFrame, prevTopFrame) && !topFrame.isEmpty()) {
            // Same blocking frame as last capture; emit a compact marker instead of the full
            // stack to avoid flooding the panel logger during long freezes.
            Logger.logInfoPanelOnly(formatStillStuck(topFrame, lagMs, workerTimestampMs));
            return;
        }

        Logger.logInfoPanelOnly(formatFullStack(edt, frames, lagMs, workerTimestampMs));
        lastTopFrame.set(topFrame);
    }

    static String formatFullStack(Thread edt, StackTraceElement[] frames, long lagMs, long workerTimestampMs) {
        StringBuilder sb = new StringBuilder();
        sb.append("[EdtMonitor] wt=").append(WallClock.format(workerTimestampMs))
                .append(" lag_ms=").append(lagMs)
                .append(" edt=").append(edt == null ? "<not-found>" : edt.getName())
                .append(" state=").append(edt == null ? "?" : edt.getState());
        int n = Math.min(MAX_STACK_FRAMES, frames.length);
        for (int i = 0; i < n; i++) {
            sb.append(" | ").append(frames[i]);
        }
        return sb.toString();
    }

    static String formatStillStuck(String topFrame, long lagMs, long workerTimestampMs) {
        return "[EdtMonitor] wt=" + WallClock.format(workerTimestampMs)
                + " still-stuck top=" + topFrame
                + " lag_ms=" + lagMs;
    }

    private static StackTraceElement[] safeGetStackTrace(Thread t) {
        try {
            Map<Thread, StackTraceElement[]> all = Thread.getAllStackTraces();
            StackTraceElement[] frames = all.get(t);
            return frames == null ? new StackTraceElement[0] : frames;
        } catch (RuntimeException ex) {
            return new StackTraceElement[0];
        }
    }

    private static Thread findEdtThread() {
        try {
            for (Map.Entry<Thread, StackTraceElement[]> entry : Thread.getAllStackTraces().entrySet()) {
                Thread t = entry.getKey();
                String name = t.getName();
                if (name != null && (name.startsWith("AWT-EventQueue") || name.startsWith("AWT-Shutdown"))) {
                    return t;
                }
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return null;
    }

    /** Test seam: returns whether the monitor is currently active. */
    public static boolean isRunningForTests() {
        synchronized (LOCK) {
            return scheduler != null;
        }
    }

    /** Test seam: returns the current reference count. */
    public static int activeRefsForTests() {
        synchronized (LOCK) {
            return activeRefs;
        }
    }

    /** Test seam: forces all state back to clean for unit tests. */
    public static void resetForTests() {
        synchronized (LOCK) {
            ScheduledExecutorService s = scheduler;
            scheduler = null;
            activeRefs = 0;
            if (s != null) {
                s.shutdownNow();
            }
            lastPostedMs.set(0L);
            lastRanMs.set(0L);
            lastDumpMs.set(0L);
            lastTopFrame.set(null);
            // Drain any in-flight probes by waiting briefly; tolerated if EDT is unavailable.
            try {
                if (s != null) {
                    s.awaitTermination(50, TimeUnit.MILLISECONDS);
                }
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Test seam: forwards a synthetic {@code now} into the tick logic without scheduling. */
    static void tickForTests() {
        tick();
    }

    /** Test seam: backs the lag/posted state to a known synthetic value. */
    static void seedStateForTests(long postedMs, long ranMs, long lastDumpMillis) {
        lastPostedMs.set(postedMs);
        lastRanMs.set(ranMs);
        lastDumpMs.set(lastDumpMillis);
    }

    /** Test seam: returns the cached "last dump" timestamp. */
    static long lastDumpMsForTests() {
        return lastDumpMs.get();
    }

    /** Test seam: returns the cached top frame (or {@code null} if none). */
    static String lastTopFrameForTests() {
        return lastTopFrame.get();
    }

    /** Test seam: forces the dedup top-frame state. */
    static void seedLastTopFrameForTests(String topFrame) {
        lastTopFrame.set(topFrame);
    }

    /** Formats epoch timestamps for local-time snapshot diagnostics. */
    public static final class WallClock {
        private static final java.time.format.DateTimeFormatter FORMATTER =
                java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

        private WallClock() {}

        /**
         * Formats one epoch-millisecond timestamp in the system default time zone.
         *
         * @param epochMs epoch milliseconds to format
         * @return local time in {@code HH:mm:ss.SSS} form
         */
        public static String format(long epochMs) {
            return java.time.LocalDateTime.ofInstant(
                            java.time.Instant.ofEpochMilli(epochMs),
                            java.time.ZoneId.systemDefault())
                    .format(FORMATTER);
        }
    }
}
