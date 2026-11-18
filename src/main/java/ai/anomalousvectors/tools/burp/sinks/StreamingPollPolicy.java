package ai.anomalousvectors.tools.burp.sinks;

/** Monotonic deadlines and shared work pacing for live streaming observations. */
final class StreamingPollPolicy {
    static final long WINDOW_MS = 300_000L;
    static final int MAX_TRACKED = 256;
    // Charge repeated wire acquisition separately from API wall time. This is pacing, not a
    // claim that a public response accessor cannot allocate a larger object in one call.
    static final long WIRE_BYTES_PER_SECOND = 256L * 1024L;
    private long allowedAt;

    static long intervalMs(long ageMs) {
        if (ageMs < 30_000L) return 5_000L;
        if (ageMs < 120_000L) return 10_000L;
        if (ageMs < 180_000L) return 20_000L;
        return 30_000L;
    }

    static long intervalMs(long ageMs, long wireBytes) {
        long byteDelay = Math.min(WINDOW_MS, Math.max(0L, wireBytes) * 1_000L / WIRE_BYTES_PER_SECOND);
        return Math.max(intervalMs(ageMs), byteDelay);
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
