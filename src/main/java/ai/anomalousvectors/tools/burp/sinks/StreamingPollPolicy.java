package ai.anomalousvectors.tools.burp.sinks;

/** Monotonic deadlines and shared work pacing for live streaming observations. */
final class StreamingPollPolicy {
    static final long WINDOW_MS = 300_000L;
    static final int MAX_TRACKED = 256;
    private long allowedAt;

    static long intervalMs(long ageMs) {
        if (ageMs < 30_000L) return 5_000L;
        if (ageMs < 120_000L) return 10_000L;
        if (ageMs < 180_000L) return 20_000L;
        return 30_000L;
    }

    long allowedAt() {
        return allowedAt;
    }

    // Charge the entire public API/read/build call, not just hashing. One call is not preemptible.
    void charge(long startedMs, long finishedMs) {
        long cost = Math.max(0L, finishedMs - startedMs);
        allowedAt = Math.max(finishedMs, startedMs + cost * 10L);
    }
}
