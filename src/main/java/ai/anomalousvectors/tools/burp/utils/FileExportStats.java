package ai.anomalousvectors.tools.burp.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe session stats for file-based exports.
 *
 * <p>These counters mirror the high-level database export metrics used by {@code StatsPanel},
 * but track only documents and bytes that were actually written to file sinks.</p>
 */
public final class FileExportStats {

    /** Run-level integrity state aggregated across selected file formats for one index. */
    public enum ArtifactIntegrity {
        /** No file format was selected for the index. */
        NOT_SELECTED,
        /** At least one selected artifact awaits final size and integrity validation. */
        PENDING,
        /** All selected artifacts reached their expected final sizes. */
        OK,
        /** At least one selected artifact failed writing or final validation. */
        FAILED
    }

    private static final List<String> INDEX_KEYS = Collections.unmodifiableList(
            Arrays.asList("traffic", "exporter", "settings", "sitemap", "findings"));
    private static final List<String> TRAFFIC_SOURCE_KEYS = Collections.unmodifiableList(
            Arrays.asList("proxy_live_http", "proxy_history_snapshot", "proxy_websocket"));
    private static final List<String> TRAFFIC_TOOL_TYPE_KEYS = Collections.unmodifiableList(
            Arrays.asList(
                    "BURP_AI",
                    "EXTENSIONS",
                    "INTRUDER",
                    "PROXY",
                    "PROXY_HISTORY",
                    "REPEATER",
                    "REPEATER_TABS",
                    "SCANNER",
                    "SEQUENCER",
                    "UNKNOWN"));
    private static final int LAST_ERROR_MAX_LEN = 200;

    private static final Map<String, PerIndexStats> STATS = new ConcurrentHashMap<>();
    private static final Map<String, TrafficSourceStats> TRAFFIC_SOURCE_STATS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_FAILURE_COUNTS = new ConcurrentHashMap<>();

    static {
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String key : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(key, new TrafficSourceStats());
        }
        for (String key : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(key, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(key, new AtomicLong(0));
        }
    }

    private FileExportStats() { }

    /** Returns the tracked short index keys used by file-export stats. */
    public static List<String> getIndexKeys() {
        return INDEX_KEYS;
    }

    /** Returns the tracked traffic tool-type keys used by file-export source stats. */
    public static List<String> getTrafficToolTypeKeys() {
        return TRAFFIC_TOOL_TYPE_KEYS;
    }

    /** Records one or more successful file-export document writes for an index key. */
    public static void recordSuccess(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).writtenCount.addAndGet(count);
    }

    /** Records one or more documents not written after file-export retries for an index key. */
    public static void recordFailure(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).failureCount.addAndGet(count);
    }

    /**
     * Records additional file-write attempts after an initial I/O failure.
     *
     * @param indexKey short index key; unknown keys create a new counter bucket
     * @param count additional attempt count; values {@code <= 0} are ignored
     */
    public static void recordRetryAttempt(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).retryAttemptCount.addAndGet(count);
    }

    /** Records successfully written file-export bytes for an index key. */
    public static void recordExportedBytes(String indexKey, long bytes) {
        if (bytes <= 0) {
            return;
        }
        forIndex(indexKey).successBytes.addAndGet(bytes);
    }

    /**
     * Registers one selected output artifact before this run appends data.
     *
     * <p>Negative baseline sizes are recorded as zero. Registration increments the artifact count
     * and moves aggregate integrity to {@link ArtifactIntegrity#PENDING}.</p>
     *
     * @param indexKey short index key; unknown keys create a new counter bucket
     * @param baselineBytes bytes present before this run
     */
    public static void recordArtifactRegistration(String indexKey, long baselineBytes) {
        PerIndexStats stats = forIndex(indexKey);
        stats.artifactCount.incrementAndGet();
        stats.artifactBaselineBytes.addAndGet(Math.max(0L, baselineBytes));
        stats.artifactIntegrity.set(ArtifactIntegrity.PENDING);
    }

    /**
     * Records final aggregate artifact sizes and integrity for one index.
     *
     * <p>Negative sizes are clamped to zero. A {@code null} integrity value is recorded as
     * {@link ArtifactIntegrity#FAILED}. A non-blank error updates the index's last-error value;
     * null or blank leaves the existing value unchanged.</p>
     *
     * @param indexKey short index key
     * @param baselineBytes total bytes present before this run
     * @param expectedFinalBytes expected size after successful appends
     * @param finalBytes observed final size
     * @param integrity aggregate completion state; {@code null} records failure
     * @param error integrity failure detail; null or blank leaves the current error unchanged
     */
    public static void recordArtifactCompletion(
            String indexKey,
            long baselineBytes,
            long expectedFinalBytes,
            long finalBytes,
            ArtifactIntegrity integrity,
            String error) {
        PerIndexStats stats = forIndex(indexKey);
        stats.artifactBaselineBytes.set(Math.max(0L, baselineBytes));
        stats.artifactExpectedFinalBytes.set(Math.max(0L, expectedFinalBytes));
        stats.artifactFinalBytes.set(Math.max(0L, finalBytes));
        stats.artifactIntegrity.set(integrity == null ? ArtifactIntegrity.FAILED : integrity);
        if (error != null && !error.isBlank()) {
            recordLastError(indexKey, error);
        }
    }

    /**
     * Marks selected output artifacts as failed before final validation.
     *
     * <p>A null or blank error clears the stored last-error value.</p>
     *
     * @param indexKey short index key; unknown keys create a new counter bucket
     * @param error failure detail; null or blank clears the current error
     */
    public static void recordArtifactIntegrityFailure(String indexKey, String error) {
        forIndex(indexKey).artifactIntegrity.set(ArtifactIntegrity.FAILED);
        recordLastError(indexKey, error);
    }

    /** Records the wall-clock duration of the latest successful file write for an index key. */
    public static void recordLastWriteDurationMs(String indexKey, long durationMs) {
        forIndex(indexKey).lastWriteDurationMs.set(durationMs);
    }

    /** Stores the latest file-export error for an index key, truncating overly long messages. */
    public static void recordLastError(String indexKey, String message) {
        if (message == null || message.isBlank()) {
            forIndex(indexKey).lastError.set(null);
            return;
        }
        String truncated = message.length() <= LAST_ERROR_MAX_LEN
                ? message
                : message.substring(0, LAST_ERROR_MAX_LEN) + "...";
        forIndex(indexKey).lastError.set(truncated);
    }

    /** Returns documents written to file for an index key this run. */
    public static long getSuccessCount(String indexKey) {
        return getWrittenCount(indexKey);
    }

    /**
     * Returns documents written to file for an index key this run.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative written document count
     */
    public static long getWrittenCount(String indexKey) {
        return forIndex(indexKey).writtenCount.get();
    }

    /** Returns the failed file-export document count for an index key. */
    public static long getFailureCount(String indexKey) {
        return forIndex(indexKey).failureCount.get();
    }

    /**
     * Returns additional file-write attempts after initial I/O failures for an index key.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative additional attempt count
     */
    public static long getRetryAttemptCount(String indexKey) {
        return forIndex(indexKey).retryAttemptCount.get();
    }

    /** Returns the successful file-export bytes recorded for an index key. */
    public static long getExportedBytes(String indexKey) {
        return forIndex(indexKey).successBytes.get();
    }

    /**
     * Returns the number of selected output artifacts tracked for an index.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative artifact count
     */
    public static long getArtifactCount(String indexKey) {
        return forIndex(indexKey).artifactCount.get();
    }

    /**
     * Returns bytes already present across selected artifacts before this run.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative baseline byte count
     */
    public static long getArtifactBaselineBytes(String indexKey) {
        return forIndex(indexKey).artifactBaselineBytes.get();
    }

    /**
     * Returns expected final bytes across selected artifacts.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative expected byte count
     */
    public static long getArtifactExpectedFinalBytes(String indexKey) {
        return forIndex(indexKey).artifactExpectedFinalBytes.get();
    }

    /**
     * Returns observed final bytes across selected artifacts.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative observed byte count
     */
    public static long getArtifactFinalBytes(String indexKey) {
        return forIndex(indexKey).artifactFinalBytes.get();
    }

    /**
     * Returns aggregate artifact integrity for an index.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-null aggregate integrity state
     */
    public static ArtifactIntegrity getArtifactIntegrity(String indexKey) {
        return forIndex(indexKey).artifactIntegrity.get();
    }

    /** Returns the latest successful file-write duration for an index key, or {@code -1}. */
    public static long getLastWriteDurationMs(String indexKey) {
        return forIndex(indexKey).lastWriteDurationMs.get();
    }

    /** Returns the latest file-export error for an index key, or {@code null}. */
    public static String getLastError(String indexKey) {
        return forIndex(indexKey).lastError.get();
    }

    /** Returns the total successful file-export document count across all tracked indexes. */
    public static long getTotalSuccessCount() {
        long sum = 0L;
        for (String key : INDEX_KEYS) {
            sum += getSuccessCount(key);
        }
        return sum;
    }

    /** Returns the total failed file-export document count across all tracked indexes. */
    public static long getTotalFailureCount() {
        long sum = 0L;
        for (String key : INDEX_KEYS) {
            sum += getFailureCount(key);
        }
        return sum;
    }

    /**
     * Returns additional file-write attempts across all tracked indexes.
     *
     * @return non-negative additional attempt count
     */
    public static long getTotalRetryAttemptCount() {
        long sum = 0L;
        for (String key : INDEX_KEYS) {
            sum += getRetryAttemptCount(key);
        }
        return sum;
    }

    /** Returns the total successful file-export bytes across all tracked indexes. */
    public static long getTotalExportedBytes() {
        long sum = 0L;
        for (String key : INDEX_KEYS) {
            sum += getExportedBytes(key);
        }
        return sum;
    }

    /** Records one or more successful traffic document writes for a file-export source key. */
    public static void recordTrafficSourceSuccess(String sourceKey, long count) {
        if (count <= 0) {
            return;
        }
        forTrafficSource(sourceKey).successCount.addAndGet(count);
    }

    /** Records one or more failed traffic document writes for a file-export source key. */
    public static void recordTrafficSourceFailure(String sourceKey, long count) {
        if (count <= 0) {
            return;
        }
        forTrafficSource(sourceKey).failureCount.addAndGet(count);
    }

    /** Returns the successful file-export count for a traffic source key. */
    public static long getTrafficSourceSuccessCount(String sourceKey) {
        return forTrafficSource(sourceKey).successCount.get();
    }

    /** Returns the failed file-export count for a traffic source key. */
    public static long getTrafficSourceFailureCount(String sourceKey) {
        return forTrafficSource(sourceKey).failureCount.get();
    }

    /** Records successful file-export traffic writes for a tool type. */
    public static void recordTrafficToolTypeSuccess(String toolTypeKey, long count) {
        if (count <= 0 || toolTypeKey == null || toolTypeKey.isBlank()) {
            return;
        }
        TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.computeIfAbsent(toolTypeKey, ignored -> new AtomicLong(0)).addAndGet(count);
    }

    /** Records failed file-export traffic writes for a tool type. */
    public static void recordTrafficToolTypeFailure(String toolTypeKey, long count) {
        if (count <= 0 || toolTypeKey == null || toolTypeKey.isBlank()) {
            return;
        }
        TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.computeIfAbsent(toolTypeKey, ignored -> new AtomicLong(0)).addAndGet(count);
    }

    /** Returns the successful file-export traffic count for one tool type. */
    public static long getTrafficToolTypeSuccessCount(String toolTypeKey) {
        AtomicLong count = TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.get(toolTypeKey);
        return count == null ? 0L : count.get();
    }

    /** Returns the failed file-export traffic count for one tool type. */
    public static long getTrafficToolTypeFailureCount(String toolTypeKey) {
        AtomicLong count = TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.get(toolTypeKey);
        return count == null ? 0L : count.get();
    }

    /**
     * Clears per-run file-export counters.
     *
     * <p>Individual operations are thread-safe, but reset is not an atomic snapshot transition.
     * Callers must quiesce file-export producers before invoking it.</p>
     */
    public static void resetForRun() {
        for (String key : INDEX_KEYS) {
            PerIndexStats stats = forIndex(key);
            stats.writtenCount.set(0);
            stats.failureCount.set(0);
            stats.retryAttemptCount.set(0);
            stats.successBytes.set(0);
            stats.artifactCount.set(0);
            stats.artifactBaselineBytes.set(0);
            stats.artifactExpectedFinalBytes.set(0);
            stats.artifactFinalBytes.set(0);
            stats.artifactIntegrity.set(ArtifactIntegrity.NOT_SELECTED);
            stats.lastWriteDurationMs.set(-1);
            stats.lastError.set(null);
        }
        for (String key : TRAFFIC_SOURCE_KEYS) {
            TrafficSourceStats source = forTrafficSource(key);
            source.successCount.set(0);
            source.failureCount.set(0);
        }
        for (String key : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(key, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(key, new AtomicLong(0));
        }
    }

    /**
     * Resets all file-export stats for tests or process-local lifecycle cleanup.
     *
     * <p>Callers must ensure no producers are recording concurrently.</p>
     */
    public static void resetForTests() {
        STATS.clear();
        TRAFFIC_SOURCE_STATS.clear();
        TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.clear();
        TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.clear();
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String key : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(key, new TrafficSourceStats());
        }
        for (String key : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(key, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(key, new AtomicLong(0));
        }
    }

    private static PerIndexStats forIndex(String indexKey) {
        PerIndexStats stats = STATS.get(indexKey);
        return stats != null ? stats : STATS.computeIfAbsent(indexKey, ignored -> new PerIndexStats());
    }

    private static TrafficSourceStats forTrafficSource(String sourceKey) {
        TrafficSourceStats stats = TRAFFIC_SOURCE_STATS.get(sourceKey);
        return stats != null ? stats : TRAFFIC_SOURCE_STATS.computeIfAbsent(sourceKey, ignored -> new TrafficSourceStats());
    }

    private static final class PerIndexStats {
        final AtomicLong writtenCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong retryAttemptCount = new AtomicLong(0);
        final AtomicLong successBytes = new AtomicLong(0);
        final AtomicLong artifactCount = new AtomicLong(0);
        final AtomicLong artifactBaselineBytes = new AtomicLong(0);
        final AtomicLong artifactExpectedFinalBytes = new AtomicLong(0);
        final AtomicLong artifactFinalBytes = new AtomicLong(0);
        final AtomicReference<ArtifactIntegrity> artifactIntegrity =
                new AtomicReference<>(ArtifactIntegrity.NOT_SELECTED);
        final AtomicLong lastWriteDurationMs = new AtomicLong(-1);
        final AtomicReference<String> lastError = new AtomicReference<>(null);
    }

    private static final class TrafficSourceStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
    }
}
