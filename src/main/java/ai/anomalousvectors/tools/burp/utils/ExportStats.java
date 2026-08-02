package ai.anomalousvectors.tools.burp.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Thread-safe per-index export stats for OpenSearch pushes.
 *
 * <p>Session-scoped: counts and last error/duration are not persisted. Used by
 * StatsPanel and by the Exporter-index stats snapshot. Index keys align with
 * short names: traffic, exporter, settings, sitemap, findings.</p>
 */
public final class ExportStats {

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
    private static final List<String> REPEATER_METADATA_SOURCE_KEYS = Collections.unmodifiableList(
            Arrays.asList(
                    "request_identity",
                    "request_hash",
                    "exchange_hash",
                    "ui_fallback",
                    "request_stage_reuse",
                    "ambiguous_null",
                    "none"));
    private static final int LAST_ERROR_MAX_LEN = 200;
    private static final long THROUGHPUT_WINDOW_MS = 60_000L;
    private static final long THROUGHPUT_WINDOW_SHORT_MS = 10_000L;
    private static final int THROUGHPUT_CAP = 10_000;

    /** Pairs of { timeMs, count } for successes in the last 60s. Old entries pruned on read. */
    private static final List<long[]> recentSuccesses = Collections.synchronizedList(new ArrayList<>());

    private static final Map<String, PerIndexStats> STATS = new ConcurrentHashMap<>();
    private static final Map<String, TrafficSourceStats> TRAFFIC_SOURCE_STATS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_FAILURE_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_RECOVERY_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_RETRY_QUEUE_DROP_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> TRAFFIC_TOOL_TYPE_PERMANENT_DROP_COUNTS = new ConcurrentHashMap<>();
    private static final Map<String, AtomicLong> REPEATER_METADATA_SOURCE_COUNTS = new ConcurrentHashMap<>();
    private static final Set<String> COUNTED_SEARCH_TRUNCATION_OPERATION_IDS =
            ConcurrentHashMap.newKeySet();
    private static final AtomicLong exportStartRequestedAtMs = new AtomicLong(-1);
    private static final AtomicLong firstTrafficSuccessAtMs = new AtomicLong(-1);
    public static final String SNAPSHOT_PROXY_HISTORY = "proxy_history";
    public static final String SNAPSHOT_SITEMAP = "sitemap";
    public static final String SNAPSHOT_FINDINGS = "findings";
    public static final String SNAPSHOT_PROXY_WEBSOCKET = "proxy_websocket";
    /** Permanent search drop because fitting could not meet the absolute request ceiling. */
    public static final String PERMANENT_DROP_REASON_MAX_FIT = "max_fit_exceeded";
    /** Permanent search drop caused by a non-retryable mapping, parse, or validation rejection. */
    public static final String PERMANENT_DROP_REASON_MAPPING = "mapping_or_validation_rejected";
    /** Permanent drop when bounded Stop handling discards work that could not finish. */
    public static final String PERMANENT_DROP_REASON_STOP = "stop_discard";
    /** Permanent drop because the configured search destination was unavailable or disabled. */
    public static final String PERMANENT_DROP_REASON_DESTINATION = "destination_unavailable";
    /** Permanent drop that does not match another stable category. */
    public static final String PERMANENT_DROP_REASON_OTHER = "other";

    private static final List<String> SNAPSHOT_REPORTER_KEYS = List.of(
            SNAPSHOT_PROXY_HISTORY,
            SNAPSHOT_SITEMAP,
            SNAPSHOT_FINDINGS,
            SNAPSHOT_PROXY_WEBSOCKET);

    private static final Map<String, AtomicReference<SnapshotLastRunStats>> lastSnapshotRuns =
            new ConcurrentHashMap<>();
    private static final AtomicInteger currentProxyHistoryChunkTarget = new AtomicInteger(-1);
    private static final AtomicInteger lastBulkTargetBatch = new AtomicInteger(-1);
    private static final AtomicInteger lastBulkAttemptedDocs = new AtomicInteger(-1);
    private static final AtomicInteger peakTrafficQueueDocs = new AtomicInteger();
    private static final AtomicLong peakTrafficQueueBytes = new AtomicLong();
    private static final AtomicInteger peakSpillDocs = new AtomicInteger();
    private static final AtomicLong peakSpillBytes = new AtomicLong();
    private static final AtomicInteger peakRetryQueueDocs = new AtomicInteger();
    private static final AtomicLong peakRetryQueueBytes = new AtomicLong();
    private static final AtomicInteger peakSnapshotChunkTarget = new AtomicInteger();
    private static final AtomicLong peakSnapshotFlushMs = new AtomicLong();
    private static final AtomicLong lastActiveBulkByteBudget = new AtomicLong();
    private static final AtomicInteger lastActiveSnapshotFlushCap = new AtomicInteger();
    private static final AtomicInteger snapshotBuildAheadReservedPermits = new AtomicInteger();
    private static final AtomicLong snapshotBuildAheadReservedBytes = new AtomicLong();
    private static final AtomicInteger peakSnapshotBuildAheadReservedPermits = new AtomicInteger();
    private static final AtomicLong peakSnapshotBuildAheadReservedBytes = new AtomicLong();

    static {
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String sourceKey : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(sourceKey, new TrafficSourceStats());
        }
        for (String toolType : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_RECOVERY_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_RETRY_QUEUE_DROP_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_PERMANENT_DROP_COUNTS.put(toolType, new AtomicLong(0));
        }
        for (String metadataSource : REPEATER_METADATA_SOURCE_KEYS) {
            REPEATER_METADATA_SOURCE_COUNTS.put(metadataSource, new AtomicLong(0));
        }
        for (String reporterKey : SNAPSHOT_REPORTER_KEYS) {
            lastSnapshotRuns.put(reporterKey, new AtomicReference<>(null));
        }
    }

    private ExportStats() {}

    private static PerIndexStats forIndex(String indexKey) {
        PerIndexStats s = STATS.get(indexKey);
        return s != null ? s : STATS.computeIfAbsent(indexKey, k -> new PerIndexStats());
    }

    /** Returns the list of index keys (traffic, exporter, settings, sitemap, findings). */
    public static List<String> getIndexKeys() {
        return INDEX_KEYS;
    }

    /** Returns known traffic source keys used for source-level traffic stats. */
    public static List<String> getTrafficSourceKeys() {
        return TRAFFIC_SOURCE_KEYS;
    }

    /** Returns known traffic tool type keys shown in Config > Traffic. */
    public static List<String> getTrafficToolTypeKeys() {
        return TRAFFIC_TOOL_TYPE_KEYS;
    }

    /** Returns known live-Repeater metadata source keys used in trace and stats summaries. */
    public static List<String> getRepeaterMetadataSourceKeys() {
        return REPEATER_METADATA_SOURCE_KEYS;
    }

    private static TrafficSourceStats forTrafficSource(String sourceKey) {
        TrafficSourceStats s = TRAFFIC_SOURCE_STATS.get(sourceKey);
        return s != null ? s : TRAFFIC_SOURCE_STATS.computeIfAbsent(sourceKey, k -> new TrafficSourceStats());
    }

    /**
     * Records successful document push(es) for the given index.
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param count number of documents; ignored if &lt;= 0
     */
    public static void recordSuccess(String indexKey, long count) {
        recordExported(indexKey, count);
    }

    /** Records documents successfully indexed to OpenSearch for an index key this run. */
    public static void recordExported(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).exportedCount.addAndGet(count);
        noteTrafficSuccess(indexKey, count);
    }

    /** Records successful OpenSearch {@code noop} bulk results for an index key. */
    public static void recordNoop(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).noopCount.addAndGet(count);
    }

    /** Applies a classified bulk outcome to per-index counters. */
    public static void recordBulkBreakdown(String indexKey, BulkOutcomeBreakdown breakdown) {
        if (breakdown == null) {
            return;
        }
        recordExported(indexKey, breakdown.exportedCount());
        recordNoop(indexKey, breakdown.noop());
        if (breakdown.failed() > 0) {
            recordFailure(indexKey, breakdown.failed());
        }
    }

    /**
     * Applies successful bulk outcomes from the retry drain without re-counting failures.
     *
     * <p>Documents already incremented {@linkplain #recordFailure(String, long) Failures} when they
     * first failed and were queued. Drain pushes that partially succeed must not call
     * {@link #recordBulkBreakdown(String, BulkOutcomeBreakdown)} (that would inflate Failures again
     * for items still being retried). Recoveries are tracked separately via
     * {@link #recordRetryRecovery(String, long)}.</p>
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param breakdown classified bulk outcome; {@code null} ignored
     */
    public static void recordRetryDrainBulkSuccess(String indexKey, BulkOutcomeBreakdown breakdown) {
        if (breakdown == null) {
            return;
        }
        recordExported(indexKey, breakdown.exportedCount());
        recordNoop(indexKey, breakdown.noop());
    }

    private static void noteTrafficSuccess(String indexKey, long count) {
        long now = System.currentTimeMillis();
        if ("traffic".equals(indexKey)) {
            long startMs = exportStartRequestedAtMs.get();
            if (startMs > 0) {
                firstTrafficSuccessAtMs.compareAndSet(-1, now);
            }
        }
        synchronized (recentSuccesses) {
            recentSuccesses.add(new long[] { now, count });
            if (recentSuccesses.size() > THROUGHPUT_CAP) {
                pruneRecentSuccessesOlderThan(now - THROUGHPUT_WINDOW_MS);
            }
        }
    }

    private static void pruneRecentSuccessesOlderThan(long cutoffMs) {
        Iterator<long[]> it = recentSuccesses.iterator();
        while (it.hasNext()) {
            if (it.next()[0] < cutoffMs) {
                it.remove();
            }
        }
    }

    /**
     * Records failed document push(es) for the given index.
     *
     * <p>Counts failed attempts only. Successful retries do not decrement this counter; call
     * {@link #recordRetryRecovery(String, long)} when previously failed documents later succeed.</p>
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param count number of failures; ignored if &lt;= 0
     */
    public static void recordFailure(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).failureCount.addAndGet(count);
    }

    /**
     * Records that previously failed documents later succeeded via the retry drain.
     *
     * @param indexKey index key (e.g. {@code "sitemap"})
     * @param count number of recovered documents; ignored if &lt;= 0
     */
    public static void recordRetryRecovery(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).recoveredFailureCount.addAndGet(count);
    }

    /**
     * Clears the last-error string for an index after retry recovery drains that index.
     *
     * @param indexKey index key
     */
    public static void clearLastError(String indexKey) {
        forIndex(indexKey).lastError.set(null);
    }

    /**
     * Records successful traffic pushes for a specific traffic source.
     *
     * @param sourceKey source key (for example {@code "proxy_live_http"})
     * @param count number of successful documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSourceSuccess(String sourceKey, long count) {
        if (count <= 0) return;
        forTrafficSource(sourceKey).successCount.addAndGet(count);
    }

    /**
     * Records failed traffic pushes for a specific traffic source.
     *
     * @param sourceKey source key (for example {@code "proxy_live_http"})
     * @param count number of failed documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSourceFailure(String sourceKey, long count) {
        if (count <= 0) return;
        forTrafficSource(sourceKey).failureCount.addAndGet(count);
    }

    /**
     * Records recovered OpenSearch traffic pushes for a specific traffic source.
     *
     * @param sourceKey traffic source key; unknown keys create a new counter bucket
     * @param count recovered document count; values {@code <= 0} are ignored
     */
    public static void recordTrafficSourceRecovery(String sourceKey, long count) {
        if (count <= 0) return;
        forTrafficSource(sourceKey).recoveryCount.addAndGet(count);
    }

    /**
     * Records retry-queue capacity drops for a specific traffic source bucket.
     *
     * @param sourceKey source key (for example {@code "proxy_history_snapshot"})
     * @param count number of documents dropped; ignored if {@code <= 0}
     */
    public static void recordTrafficSourceRetryQueueDrop(String sourceKey, long count) {
        if (count <= 0) {
            return;
        }
        forTrafficSource(sourceKey).retryQueueDrops.addAndGet(count);
    }

    /**
     * Records permanent drops for a specific traffic source bucket.
     *
     * @param sourceKey source key (for example {@code "proxy_websocket"})
     * @param count number of documents dropped; ignored if {@code <= 0}
     */
    public static void recordTrafficSourcePermanentDrop(String sourceKey, long count) {
        if (count <= 0) {
            return;
        }
        forTrafficSource(sourceKey).permanentDrops.addAndGet(count);
    }

    /**
     * Records the duration in ms of the most recent live-drain HTTP bulk for the given index.
     *
     * <p>Proxy-history snapshot wall time belongs in {@link #recordProxyHistorySnapshot}, not here.</p>
     *
     * @param indexKey index key (today only {@code traffic} uses this)
     * @param durationMs duration in milliseconds, or -1 if unknown
     */
    public static void recordLastLiveBulkDurationMs(String indexKey, long durationMs) {
        forIndex(indexKey).lastLiveBulkDurationMs.set(durationMs);
    }

    /**
     * Records the last error for the given index.
     *
     * @param indexKey index key
     * @param message error message; {@code null} or empty clears the stored error
     */
    public static void recordLastError(String indexKey, String message) {
        if (message == null || message.isEmpty()) {
            forIndex(indexKey).lastError.set(null);
            return;
        }
        String truncated = message.length() <= LAST_ERROR_MAX_LEN
                ? message
                : message.substring(0, LAST_ERROR_MAX_LEN) + "...";
        forIndex(indexKey).lastError.set(truncated);
    }

    /** Returns documents exported to OpenSearch for the index key this run. */
    public static long getSuccessCount(String indexKey) {
        return getExportedCount(indexKey);
    }

    /** Returns documents exported to OpenSearch for the index key this run. */
    public static long getExportedCount(String indexKey) {
        return forIndex(indexKey).exportedCount.get();
    }

    /**
     * Returns successful OpenSearch {@code noop} bulk results for an index key this run.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative no-op result count
     */
    public static long getNoopCount(String indexKey) {
        return forIndex(indexKey).noopCount.get();
    }

    /** Returns the session total of failed push attempts for the given index. */
    public static long getFailureCount(String indexKey) {
        return forIndex(indexKey).failureCount.get();
    }

    /** Returns estimated successful payload bytes pushed for the given index this session. */
    public static long getExportedBytes(String indexKey) {
        return forIndex(indexKey).successBytes.get();
    }

    /**
     * Records estimated successful payload bytes for the given index.
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param bytes estimated successful payload bytes; ignored if {@code <= 0}
     */
    public static void recordExportedBytes(String indexKey, long bytes) {
        if (bytes <= 0) return;
        forIndex(indexKey).successBytes.addAndGet(bytes);
    }

    /** Returns successful traffic pushes for a specific traffic source. */
    public static long getTrafficSourceSuccessCount(String sourceKey) {
        return forTrafficSource(sourceKey).successCount.get();
    }

    /** Returns failed traffic pushes for a specific traffic source. */
    public static long getTrafficSourceFailureCount(String sourceKey) {
        return forTrafficSource(sourceKey).failureCount.get();
    }

    /**
     * Returns recovered traffic pushes for a specific traffic source.
     *
     * @param sourceKey traffic source key; unknown keys create an empty counter bucket
     * @return non-negative recovered document count
     */
    public static long getTrafficSourceRecoveryCount(String sourceKey) {
        return forTrafficSource(sourceKey).recoveryCount.get();
    }

    /**
     * Returns retry-queue capacity drops for a specific traffic source.
     *
     * @param sourceKey traffic source key; unknown keys create an empty counter bucket
     * @return non-negative dropped document count
     */
    public static long getTrafficSourceRetryQueueDrops(String sourceKey) {
        return forTrafficSource(sourceKey).retryQueueDrops.get();
    }

    /**
     * Returns permanent drops for a specific traffic source.
     *
     * @param sourceKey traffic source key; unknown keys create an empty counter bucket
     * @return non-negative permanently dropped document count
     */
    public static long getTrafficSourcePermanentDrops(String sourceKey) {
        return forTrafficSource(sourceKey).permanentDrops.get();
    }

    /**
     * Records successful OpenSearch traffic pushes for a specific tool type.
     */
    public static void recordTrafficToolTypeSuccess(String toolTypeKey, long count) {
        if (count <= 0) return;
        AtomicLong c = TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.computeIfAbsent(
                normalizeTrafficToolType(toolTypeKey),
                k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /** Records failed OpenSearch traffic pushes for a specific tool type. */
    public static void recordTrafficToolTypeFailure(String toolTypeKey, long count) {
        if (count <= 0) return;
        AtomicLong c = TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.computeIfAbsent(
                normalizeTrafficToolType(toolTypeKey),
                k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /**
     * Records recovered OpenSearch traffic pushes for a specific tool type.
     *
     * @param toolTypeKey tool type label; null or blank normalizes to {@code UNKNOWN}
     * @param count recovered document count; values {@code <= 0} are ignored
     */
    public static void recordTrafficToolTypeRecovery(String toolTypeKey, long count) {
        if (count <= 0) return;
        AtomicLong c = TRAFFIC_TOOL_TYPE_RECOVERY_COUNTS.computeIfAbsent(
                normalizeTrafficToolType(toolTypeKey),
                k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /**
     * Records retry-queue capacity drops for a specific traffic tool type.
     *
     * @param toolTypeKey tool type label; null or blank normalizes to {@code UNKNOWN}
     * @param count dropped document count; values {@code <= 0} are ignored
     */
    public static void recordTrafficToolTypeRetryQueueDrop(String toolTypeKey, long count) {
        if (count <= 0) {
            return;
        }
        AtomicLong c = TRAFFIC_TOOL_TYPE_RETRY_QUEUE_DROP_COUNTS.computeIfAbsent(
                normalizeTrafficToolType(toolTypeKey),
                k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /**
     * Records permanent drops for a specific traffic tool type.
     *
     * @param toolTypeKey tool type label; null or blank normalizes to {@code UNKNOWN}
     * @param count permanently dropped document count; values {@code <= 0} are ignored
     */
    public static void recordTrafficToolTypePermanentDrop(String toolTypeKey, long count) {
        if (count <= 0) {
            return;
        }
        AtomicLong c = TRAFFIC_TOOL_TYPE_PERMANENT_DROP_COUNTS.computeIfAbsent(
                normalizeTrafficToolType(toolTypeKey),
                k -> new AtomicLong(0));
        c.addAndGet(count);
    }

    /** Returns successful OpenSearch traffic push count for a specific tool type. */
    public static long getTrafficToolTypeSuccessCount(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.get(normalizeTrafficToolType(toolTypeKey));
        return c == null ? 0 : c.get();
    }

    /** Returns failed OpenSearch traffic push count for a specific tool type. */
    public static long getTrafficToolTypeFailureCount(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.get(normalizeTrafficToolType(toolTypeKey));
        return c == null ? 0 : c.get();
    }

    /**
     * Returns recovered OpenSearch traffic push count for a specific tool type.
     *
     * @param toolTypeKey tool type label; null or blank normalizes to {@code UNKNOWN}
     * @return non-negative recovered document count
     */
    public static long getTrafficToolTypeRecoveryCount(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_RECOVERY_COUNTS.get(normalizeTrafficToolType(toolTypeKey));
        return c == null ? 0 : c.get();
    }

    /**
     * Returns retry-queue capacity drops for a specific traffic tool type.
     *
     * @param toolTypeKey tool type label; null or blank normalizes to {@code UNKNOWN}
     * @return non-negative dropped document count
     */
    public static long getTrafficToolTypeRetryQueueDrops(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_RETRY_QUEUE_DROP_COUNTS.get(normalizeTrafficToolType(toolTypeKey));
        return c == null ? 0 : c.get();
    }

    /**
     * Returns permanent drops for a specific traffic tool type.
     *
     * @param toolTypeKey tool type label; null or blank normalizes to {@code UNKNOWN}
     * @return non-negative permanently dropped document count
     */
    public static long getTrafficToolTypePermanentDrops(String toolTypeKey) {
        AtomicLong c = TRAFFIC_TOOL_TYPE_PERMANENT_DROP_COUNTS.get(normalizeTrafficToolType(toolTypeKey));
        return c == null ? 0 : c.get();
    }

    /**
     * Returns how many traffic retry-queue documents currently attribute to a Stats display source
     * row (for example {@code PROXY_HISTORY} or {@code REPEATER}).
     *
     * <p>Live snapshot from the traffic index retry queue; not a session counter. Uses the same
     * Proxy History folding as other traffic source display helpers.</p>
     *
     * @param displaySourceKey Stats traffic sub-row key from {@link #getTrafficToolTypeKeys()}
     * @return non-negative queued document count for that display row
     */
    public static int getTrafficDisplaySourceQueueSize(String displaySourceKey) {
        String indexName = RuntimeConfig.indexNameForKey("traffic");
        return TrafficRouteBucket.countQueuedForDisplaySource(
                displaySourceKey,
                IndexingRetryCoordinator.getInstance().snapshotQueuedDocuments(indexName));
    }

    /**
     * Records one live-Repeater metadata source decision.
     *
     * <p>These counters mirror the trace-level {@code metadataSource} vocabulary so the Stats panel
     * and exporter stats snapshots can summarize which correlation paths are doing the work during a
     * run.</p>
     */
    public static void recordRepeaterMetadataSource(String metadataSource) {
        String normalizedSource = normalizeRepeaterMetadataSource(metadataSource);
        REPEATER_METADATA_SOURCE_COUNTS
                .computeIfAbsent(normalizedSource, ignored -> new AtomicLong(0))
                .incrementAndGet();
    }

    /** Returns the session total for one live-Repeater metadata source label. */
    public static long getRepeaterMetadataSourceCount(String metadataSource) {
        AtomicLong count = REPEATER_METADATA_SOURCE_COUNTS.get(normalizeRepeaterMetadataSource(metadataSource));
        return count == null ? 0 : count.get();
    }

    /** Formats live-Repeater metadata source counters for compact UI and stats summaries. */
    public static String describeRepeaterMetadataSourceCounts() {
        return "id=" + getRepeaterMetadataSourceCount("request_identity")
                + " reqHash=" + getRepeaterMetadataSourceCount("request_hash")
                + " exchHash=" + getRepeaterMetadataSourceCount("exchange_hash")
                + " ui=" + getRepeaterMetadataSourceCount("ui_fallback")
                + " reuse=" + getRepeaterMetadataSourceCount("request_stage_reuse")
                + " ambig=" + getRepeaterMetadataSourceCount("ambiguous_null");
    }

    /** Returns last live-drain bulk duration in ms for the index, or -1 if not set. */
    public static long getLastLiveBulkDurationMs(String indexKey) {
        return forIndex(indexKey).lastLiveBulkDurationMs.get();
    }

    /** Updates the in-flight proxy-history chunk doc-count target for Misc Stats (observability only). */
    public static void setCurrentProxyHistoryChunkTarget(int chunkTarget) {
        currentProxyHistoryChunkTarget.set(chunkTarget);
    }

    /** Clears the in-flight proxy-history chunk target after snapshot completion. */
    public static void clearCurrentProxyHistoryChunkTarget() {
        currentProxyHistoryChunkTarget.set(-1);
    }

    /**
     * Returns the current proxy-history chunk doc-count target while a snapshot runs,
     * or {@code -1} when idle.
     */
    public static int getCurrentProxyHistoryChunkTarget() {
        return currentProxyHistoryChunkTarget.get();
    }

    /** Records the most recent live-drain bulk shape for {@code stats_snapshot} export section. */
    public static void recordLastLiveBulkShape(int targetBatch, int attemptedDocs) {
        lastBulkTargetBatch.set(targetBatch);
        lastBulkAttemptedDocs.set(attemptedDocs);
    }

    /** Returns the shared batch target from the most recent live-drain bulk, or {@code -1}. */
    public static int getLastBulkTargetBatch() {
        return lastBulkTargetBatch.get();
    }

    /** Returns attempted docs from the most recent live-drain bulk, or {@code -1}. */
    public static int getLastBulkAttemptedDocs() {
        return lastBulkAttemptedDocs.get();
    }

    /**
     * Records high-water marks for live traffic queue depth during the current export run.
     */
    public static void noteTrafficQueuePeak(int queueDocs, long queueBytes) {
        if (queueDocs > 0) {
            peakTrafficQueueDocs.updateAndGet(prev -> Math.max(prev, queueDocs));
        }
        if (queueBytes > 0) {
            peakTrafficQueueBytes.updateAndGet(prev -> Math.max(prev, queueBytes));
        }
    }

    /**
     * Records high-water marks for traffic spill depth during the current export run.
     */
    public static void noteSpillPeak(int spillDocs, long spillBytes) {
        if (spillDocs > 0) {
            peakSpillDocs.updateAndGet(prev -> Math.max(prev, spillDocs));
        }
        if (spillBytes > 0) {
            peakSpillBytes.updateAndGet(prev -> Math.max(prev, spillBytes));
        }
    }

    /**
     * Records high-water marks for OpenSearch retry queue depth during the current export run.
     */
    public static void noteRetryQueuePeak(int retryDocs, long retryBytes) {
        if (retryDocs > 0) {
            peakRetryQueueDocs.updateAndGet(prev -> Math.max(prev, retryDocs));
        }
        if (retryBytes > 0) {
            peakRetryQueueBytes.updateAndGet(prev -> Math.max(prev, retryBytes));
        }
    }

    /**
     * Samples current queue/spill/retry pressure for run-high-water stats.
     *
     * <p>Called from {@code StatsPanel} refresh so peaks are captured even when depth spikes
     * between individual queue mutations.</p>
     */
    public static void observeExportPressureSamples(
            int trafficQueueDocs,
            long trafficQueueBytes,
            int spillDocs,
            long spillBytes,
            int retryDocs,
            long retryBytes) {
        noteTrafficQueuePeak(trafficQueueDocs, trafficQueueBytes);
        noteSpillPeak(spillDocs, spillBytes);
        noteRetryQueuePeak(retryDocs, retryBytes);
    }

    /** Peak live traffic queue docs observed this export run. */
    public static int getPeakTrafficQueueDocs() {
        return peakTrafficQueueDocs.get();
    }

    /** Peak live traffic queue bytes observed this export run. */
    public static long getPeakTrafficQueueBytes() {
        return peakTrafficQueueBytes.get();
    }

    /** Peak traffic spill docs observed this export run. */
    public static int getPeakSpillDocs() {
        return peakSpillDocs.get();
    }

    /** Peak traffic spill bytes observed this export run. */
    public static long getPeakSpillBytes() {
        return peakSpillBytes.get();
    }

    /** Peak total retry-queue docs observed this export run. */
    public static int getPeakRetryQueueDocs() {
        return peakRetryQueueDocs.get();
    }

    /** Peak total retry-queue bytes observed this export run. */
    public static long getPeakRetryQueueBytes() {
        return peakRetryQueueBytes.get();
    }

    /** Peak snapshot chunk doc-count target observed this export run. */
    public static int getPeakSnapshotChunkTarget() {
        return peakSnapshotChunkTarget.get();
    }

    /** Longest single snapshot chunk flush wall time (ms) observed this export run. */
    public static long getPeakSnapshotFlushMs() {
        return peakSnapshotFlushMs.get();
    }

    /**
     * Captures the final adaptive search-capacity state before Stop resets the controllers.
     *
     * <p>Only the first capture in a run wins because Stop cleanup can clear retry state more than
     * once. Start resets both values before the next run.</p>
     *
     * @param bulkByteBudget final positive bulk payload ceiling
     * @param snapshotFlushCap final positive snapshot flush concurrency
     */
    public static void recordLastActiveSearchCapacity(long bulkByteBudget, int snapshotFlushCap) {
        if (bulkByteBudget > 0L) {
            lastActiveBulkByteBudget.compareAndSet(0L, bulkByteBudget);
        }
        if (snapshotFlushCap > 0) {
            lastActiveSnapshotFlushCap.compareAndSet(0, snapshotFlushCap);
        }
    }

    /**
     * Returns the final active bulk byte budget captured during Stop.
     *
     * @return positive byte budget, or zero before capture
     */
    public static long getLastActiveBulkByteBudget() {
        return lastActiveBulkByteBudget.get();
    }

    /**
     * Returns the final active snapshot flush cap captured during Stop.
     *
     * @return positive concurrency cap, or zero before capture
     */
    public static int getLastActiveSnapshotFlushCap() {
        return lastActiveSnapshotFlushCap.get();
    }

    /**
     * Returns current snapshot build-ahead permits reserved by prepared documents.
     *
     * @return non-negative live permit count
     */
    public static int getSnapshotBuildAheadReservedPermits() {
        return snapshotBuildAheadReservedPermits.get();
    }

    /**
     * Returns current quantized bytes reserved by snapshot build-ahead documents.
     *
     * @return non-negative live byte count
     */
    public static long getSnapshotBuildAheadReservedBytes() {
        return snapshotBuildAheadReservedBytes.get();
    }

    /**
     * Returns peak snapshot build-ahead permits reserved during this export run.
     *
     * @return non-negative peak permit count
     */
    public static int getPeakSnapshotBuildAheadReservedPermits() {
        return peakSnapshotBuildAheadReservedPermits.get();
    }

    /**
     * Returns peak quantized bytes reserved by snapshot build-ahead documents this run.
     *
     * @return non-negative peak byte count
     */
    public static long getPeakSnapshotBuildAheadReservedBytes() {
        return peakSnapshotBuildAheadReservedBytes.get();
    }

    /**
     * Records a successful snapshot build-ahead reservation.
     *
     * @param permits positive semaphore permits reserved
     * @param bytes positive quantized bytes represented by the reservation
     */
    public static void reserveSnapshotBuildAhead(int permits, long bytes) {
        if (permits <= 0 || bytes <= 0L) {
            return;
        }
        int currentPermits = snapshotBuildAheadReservedPermits.addAndGet(permits);
        long currentBytes = snapshotBuildAheadReservedBytes.addAndGet(bytes);
        peakSnapshotBuildAheadReservedPermits.updateAndGet(previous -> Math.max(previous, currentPermits));
        peakSnapshotBuildAheadReservedBytes.updateAndGet(previous -> Math.max(previous, currentBytes));
    }

    /**
     * Releases a snapshot build-ahead reservation after dequeue or cancellation.
     *
     * <p>Non-positive inputs are ignored. Releasing more than the currently reserved amount clamps
     * the corresponding live counter to zero.</p>
     *
     * @param permits positive semaphore permits released
     * @param bytes positive quantized bytes represented by the reservation
     */
    public static void releaseSnapshotBuildAhead(int permits, long bytes) {
        if (permits <= 0 || bytes <= 0L) {
            return;
        }
        snapshotBuildAheadReservedPermits.updateAndGet(current -> Math.max(0, current - permits));
        snapshotBuildAheadReservedBytes.updateAndGet(current -> Math.max(0L, current - bytes));
    }

    /** Clears live snapshot build-ahead reservations after the exclusive engine run ends. */
    public static void clearSnapshotBuildAheadReservations() {
        snapshotBuildAheadReservedPermits.set(0);
        snapshotBuildAheadReservedBytes.set(0L);
    }

    private static void resetRunPeaks() {
        peakTrafficQueueDocs.set(0);
        peakTrafficQueueBytes.set(0);
        peakSpillDocs.set(0);
        peakSpillBytes.set(0);
        peakRetryQueueDocs.set(0);
        peakRetryQueueBytes.set(0);
        peakSnapshotChunkTarget.set(0);
        peakSnapshotFlushMs.set(0);
        lastActiveBulkByteBudget.set(0L);
        lastActiveSnapshotFlushCap.set(0);
        peakSnapshotBuildAheadReservedPermits.set(0);
        peakSnapshotBuildAheadReservedBytes.set(0L);
        clearSnapshotBuildAheadReservations();
    }

    private static void noteSnapshotChunkTargetPeak(int chunkTarget) {
        if (chunkTarget > 0) {
            peakSnapshotChunkTarget.updateAndGet(prev -> Math.max(prev, chunkTarget));
        }
    }

    /**
     * Records one completed snapshot chunk's flush wall time for the run peak.
     *
     * @param flushMs wall time for one chunk; non-positive values are ignored
     */
    public static void recordSnapshotChunkFlushMs(long flushMs) {
        if (flushMs > 0L) {
            peakSnapshotFlushMs.updateAndGet(previous -> Math.max(previous, flushMs));
        }
    }

    /** Returns the last recorded error message for the given index, or {@code null} if none. */
    public static String getLastError(String indexKey) {
        return forIndex(indexKey).lastError.get();
    }

    /**
     * Returns the number of documents currently queued for retry for the given index
     * (0 when no retry coordinator or queue empty).
     */
    public static int getQueueSize(String indexKey) {
        String indexName = RuntimeConfig.indexNameForKey(indexKey);
        return IndexingRetryCoordinator.getInstance().getQueueSize(indexName);
    }

    /** Traffic export queue backpressure: count of documents dropped when the queue is full (oldest dropped). */
    private static final AtomicLong trafficQueueDrops = new AtomicLong(0);
    /** Count of traffic documents persisted to spill storage when memory queue is full. */
    private static final AtomicLong trafficSpillEnqueued = new AtomicLong(0);
    /** Count of traffic documents read back from spill storage into memory queue. */
    private static final AtomicLong trafficSpillDequeued = new AtomicLong(0);
    /** Count of traffic documents dropped because spill storage rejected them. */
    private static final AtomicLong trafficSpillDrops = new AtomicLong(0);
    /** Count of spill documents discovered on startup and available for replay. */
    private static final AtomicLong trafficSpillRecovered = new AtomicLong(0);
    /** Count of spill files pruned by retention policy before replay. */
    private static final AtomicLong trafficSpillExpiredPruned = new AtomicLong(0);
    /** Reason-coded drop counters for extreme traffic handling diagnostics. */
    private static final ReasonCounterSet trafficDropReasons = new ReasonCounterSet();
    /** Count of response-path exports that required request-side tool-type fallback. */
    private static final AtomicLong trafficToolSourceFallbacks = new AtomicLong(0);
    /** Running total of synthesized BODY parameters dropped on binary request bodies. */
    private static final AtomicLong synthesizedBodyParamsDropped = new AtomicLong(0);
    /** Running count of documents whose retained or dropped-synthesized parameter count crossed the WARN threshold. */
    private static final AtomicLong docsBodyParamsTruncated = new AtomicLong(0);
    /** Running total of BODY parameter entries dropped by the BODY cap across all documents. */
    private static final AtomicLong bodyParamsDroppedTotal = new AtomicLong(0);
    /** Running count of documents flagged as mis-gate suspects (declared form, inferred binary, BODY skipped). */
    private static final AtomicLong docsBodyEnumerationMisgateSuspect = new AtomicLong(0);
    /** Running count of documents whose URL parameter list was truncated at {@link ai.anomalousvectors.tools.burp.sinks.RequestResponseParametersSupport#URL_PARAMETERS_CAP}. */
    private static final AtomicLong docsUrlParamsTruncated = new AtomicLong(0);
    /** Running total of URL parameter entries dropped by the URL cap across all documents. */
    private static final AtomicLong urlParamsDroppedTotal = new AtomicLong(0);
    /**
     * Running count of documents that took the heap-safety typed-accessor fast path, where Burp's
     * unfiltered {@code parameters()} call was skipped to avoid materializing synthetic BODY
     * entries from Content-Type-spoofed binary bodies. Tracks how often the E3 protection fired.
     */
    private static final AtomicLong docsWithSkippedBodyEnumeration = new AtomicLong(0);
    /** Documents where Burp wire BODY rows were replaced by supplemental logical parse. */
    private static final AtomicLong docsWireBodyParamsReplaced = new AtomicLong(0);
    /** Burp BODY row entries dropped after wire transform when supplemental parse was empty. */
    private static final AtomicLong wireBodyParamsDroppedTotal = new AtomicLong(0);
    /** Documents that exported supplemental BODY parameters from logical bytes. */
    private static final AtomicLong docsSupplementalBodyParamsUsed = new AtomicLong(0);
    /** Documents where skip-path BODY enumeration was overridden by supplemental parse. */
    private static final AtomicLong docsSkipPathBodyRescued = new AtomicLong(0);
    /** Documents where supplemental parse rejected a non-form logical body. */
    private static final AtomicLong docsSupplementalRejectedNonForm = new AtomicLong(0);
    /** Session counts by body_params_source label. */
    private static final ReasonCounterSet bodyParamsSourceCounts = new ReasonCounterSet();
    /** Session counts by body_params_skip_reason label. */
    private static final ReasonCounterSet bodyParamsSkipReasonCounts = new ReasonCounterSet();
    /** Per-document counts by Content-Encoding token applied during BODY supplemental parse. */
    private static final ReasonCounterSet bodyParamsEncodingCounts = new ReasonCounterSet();
    /** OpenSearch connection-health: epoch ms of the most recent successful push, or -1 when none yet. */
    private static final AtomicLong openSearchLastSuccessAtMs = new AtomicLong(-1L);
    /** OpenSearch connection-health: consecutive push failures since the last success. */
    private static final AtomicLong openSearchConsecutiveFailures = new AtomicLong(0L);
    /** Reason-coded count of documents silently skipped by scope / tool-source / self-export filters. */
    private static final ReasonCounterSet skipReasonCounts = new ReasonCounterSet();
    /** Stable reason-coded totals for documents counted as permanent search drops. */
    private static final ReasonCounterSet permanentDropReasons = new ReasonCounterSet();
    /**
     * Live count of bulk requests currently being serialized or awaiting a response.
     *
     * <p>Incremented by every bulk entry point ({@code ChunkedBulkSender}, {@code PreparedBulkSender},
     * and the Java-client {@code doPushBulkWithDetails} fallback) and decremented in the matching
     * {@code finally}, so the panel always reads a non-negative live value even when a call
     * throws. Surfaced in the Misc Stats {@code Bulk Requests In-Flight} row.</p>
     */
    private static final AtomicInteger bulkInFlight = new AtomicInteger(0);
    /**
     * Session count of soft capacity outage entries (false → true transitions).
     *
     * <p>Surfaced in Misc Stats {@code Soft Outage Entries}. Resets on Start.</p>
     */
    private static final AtomicLong softOutageEntries = new AtomicLong(0L);
    private static final AtomicLong peakCooldownWaitMs = new AtomicLong(0L);
    private static final AtomicLong peakFlushSlotWaitMs = new AtomicLong(0L);
    /**
     * Session count of shared capacity-cooldown extensions (HTTP 429/502/503/504, transport
     * pressure, and capacity probes that lengthen the deadline).
     *
     * <p>Surfaced in Misc Stats {@code Capacity Events}. Resets on Start.</p>
     */
    private static final AtomicLong capacityPressureEvents = new AtomicLong(0L);
    /**
     * Session count of search documents whose HTTP/WebSocket payloads were prefix-truncated to fit
     * the live bulk budget ({@code body.truncated=true} / payload {@code truncated=true}).
     *
     * <p>Surfaced in Misc Stats {@code Body Truncations}. Resets on Start. Files sink is unchanged.</p>
     */
    private static final AtomicLong searchBodyPrefixTruncations = new AtomicLong(0L);

    /** Skip reason: document was dropped by the user's Burp scope filter. */
    public static final String SKIP_REASON_SCOPE = "scope";
    /** Skip reason: document originated from a Burp tool source the user did not enable for export. */
    public static final String SKIP_REASON_TOOL_DISABLED = "tool_disabled";
    /** Skip reason: request targets the configured OpenSearch destination (self-export guard). */
    public static final String SKIP_REASON_SELF_OPENSEARCH = "self_opensearch";

    /**
     * Records that one or more documents were dropped from the traffic queue (queue full, drop oldest).
     *
     * @param count number of documents dropped; ignored if &lt;= 0
     */
    public static void recordTrafficQueueDrop(long count) {
        if (count > 0) trafficQueueDrops.addAndGet(count);
    }

    /**
     * Returns the session total of documents dropped from the traffic queue because it was full.
     *
     * @return total drop count (0 or positive)
     */
    public static long getTrafficQueueDrops() {
        return trafficQueueDrops.get();
    }

    /**
     * Records one or more traffic documents persisted to spill storage.
     *
     * @param count number of spilled documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillEnqueued(long count) {
        if (count > 0) {
            trafficSpillEnqueued.addAndGet(count);
        }
    }

    /** Returns total spilled traffic documents persisted this session. */
    public static long getTrafficSpillEnqueued() {
        return trafficSpillEnqueued.get();
    }

    /**
     * Records one or more traffic documents drained from spill storage.
     *
     * @param count number of drained spilled documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillDequeued(long count) {
        if (count > 0) {
            trafficSpillDequeued.addAndGet(count);
        }
    }

    /** Returns total spilled traffic documents drained back into memory this session. */
    public static long getTrafficSpillDequeued() {
        return trafficSpillDequeued.get();
    }

    /**
     * Records one or more traffic documents dropped because spill storage was unavailable/full.
     *
     * @param count number of dropped spill documents; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillDrop(long count) {
        if (count > 0) {
            trafficSpillDrops.addAndGet(count);
        }
    }

    /** Returns total traffic documents dropped due to spill rejection this session. */
    public static long getTrafficSpillDrops() {
        return trafficSpillDrops.get();
    }

    /**
     * Records one or more spill documents recovered on startup.
     *
     * @param count recovered spill document count; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillRecovered(long count) {
        if (count > 0) {
            trafficSpillRecovered.addAndGet(count);
        }
    }

    /** Returns total spill documents recovered on startup this session. */
    public static long getTrafficSpillRecovered() {
        return trafficSpillRecovered.get();
    }

    /**
     * Records one or more spill files removed by retention cleanup.
     *
     * @param count pruned spill file count; ignored if {@code <= 0}
     */
    public static void recordTrafficSpillExpiredPruned(long count) {
        if (count > 0) {
            trafficSpillExpiredPruned.addAndGet(count);
        }
    }

    /** Returns total spill files pruned by retention this session. */
    public static long getTrafficSpillExpiredPruned() {
        return trafficSpillExpiredPruned.get();
    }

    /**
     * Records a reason-coded traffic drop event.
     *
     * @param reason non-blank reason key
     * @param count number of dropped documents for that reason
     */
    public static void recordTrafficDropReason(String reason, long count) {
        trafficDropReasons.record(reason, count);
    }

    /** Returns the total for one reason-coded traffic drop key (0 when absent). */
    public static long getTrafficDropReasonCount(String reason) {
        return trafficDropReasons.get(reason);
    }

    /**
     * Records a response-path export decision that used request-side tool-type fallback.
     *
     * <p>This is used for observability when response tool source is absent but request-side
     * correlation by message id still allows correct traffic export gating.</p>
     */
    public static void recordTrafficToolSourceFallback() {
        trafficToolSourceFallbacks.incrementAndGet();
    }

    /** Returns total response-path tool-source fallbacks recorded this session. */
    public static long getTrafficToolSourceFallbacks() {
        return trafficToolSourceFallbacks.get();
    }

    /**
     * Records synthesized BODY-typed parameters that were filtered out on binary request bodies.
     *
     * <p>Feeds the {@code Synthesized Body Params Dropped} stats counter; ignored when
     * {@code count <= 0}.</p>
     */
    public static void recordSynthesizedBodyParamsDropped(long count) {
        if (count > 0) {
            synthesizedBodyParamsDropped.addAndGet(count);
        }
    }

    /** Returns the session total of synthesized BODY parameters dropped across all exports. */
    public static long getSynthesizedBodyParamsDropped() {
        return synthesizedBodyParamsDropped.get();
    }

    /**
     * Records one document whose BODY parameters were truncated to
     * {@link ai.anomalousvectors.tools.burp.sinks.RequestResponseParametersSupport#BODY_PARAMETERS_CAP}.
     *
     * @param droppedBodyParamEntries number of BODY parameter entries dropped on that document
     */
    public static void recordBodyParamsTruncated(int droppedBodyParamEntries) {
        if (droppedBodyParamEntries > 0) {
            docsBodyParamsTruncated.incrementAndGet();
            bodyParamsDroppedTotal.addAndGet(droppedBodyParamEntries);
        }
    }

    /** Returns the session total of documents whose BODY parameters were truncated. */
    public static long getDocsBodyParamsTruncated() {
        return docsBodyParamsTruncated.get();
    }

    /** Returns the session total of BODY parameter entries dropped by the BODY cap. */
    public static long getBodyParamsDroppedTotal() {
        return bodyParamsDroppedTotal.get();
    }

    /** Records one document flagged as a mis-gate suspect during BODY enumeration skip. */
    public static void recordBodyEnumerationMisgateSuspect() {
        docsBodyEnumerationMisgateSuspect.incrementAndGet();
    }

    /** Returns the session total of mis-gate suspect documents. */
    public static long getDocsBodyEnumerationMisgateSuspect() {
        return docsBodyEnumerationMisgateSuspect.get();
    }

    /**
     * Records one document whose URL parameters were truncated to
     * {@link ai.anomalousvectors.tools.burp.sinks.RequestResponseParametersSupport#URL_PARAMETERS_CAP}.
     *
     * @param droppedUrlParamEntries number of URL parameter entries dropped on that document
     */
    public static void recordUrlParamsTruncated(int droppedUrlParamEntries) {
        if (droppedUrlParamEntries > 0) {
            docsUrlParamsTruncated.incrementAndGet();
            urlParamsDroppedTotal.addAndGet(droppedUrlParamEntries);
        }
    }

    /** Returns the session total of documents whose URL parameters were truncated. */
    public static long getDocsUrlParamsTruncated() {
        return docsUrlParamsTruncated.get();
    }

    /** Returns the session total of URL parameter entries dropped by the URL cap. */
    public static long getUrlParamsDroppedTotal() {
        return urlParamsDroppedTotal.get();
    }

    /**
     * Records one document where the typed-accessor fast path was taken to avoid Burp's synthetic
     * BODY enumeration. Bumped exactly once per qualifying document in
     * {@link ai.anomalousvectors.tools.burp.sinks.RequestResponseDocBuilder#collectParameters}.
     */
    public static void recordSkippedBodyParameterEnumeration() {
        docsWithSkippedBodyEnumeration.incrementAndGet();
    }

    /** Returns the session total of documents that took the typed-accessor parameter fast path. */
    public static long getDocsWithSkippedBodyEnumeration() {
        return docsWithSkippedBodyEnumeration.get();
    }

    /** Records one document where compressed-wire Burp BODY rows were replaced by supplemental parse. */
    public static void recordWireBodyParamsReplaced() {
        docsWireBodyParamsReplaced.incrementAndGet();
    }

    /** Returns documents with wire BODY rows replaced this session. */
    public static long getDocsWireBodyParamsReplaced() {
        return docsWireBodyParamsReplaced.get();
    }

    /**
     * Records Burp BODY parameter entries dropped after wire transform when supplemental was empty.
     *
     * @param droppedBodyParamEntries number of BODY entries dropped on that document
     */
    public static void recordWireBodyParamsDropped(int droppedBodyParamEntries) {
        if (droppedBodyParamEntries > 0) {
            wireBodyParamsDroppedTotal.addAndGet(droppedBodyParamEntries);
        }
    }

    /** Returns total Burp BODY entries dropped on compressed-wire transform paths. */
    public static long getWireBodyParamsDroppedTotal() {
        return wireBodyParamsDroppedTotal.get();
    }

    /** Records one document that exported supplemental BODY parameters. */
    public static void recordSupplementalBodyParamsUsed() {
        docsSupplementalBodyParamsUsed.incrementAndGet();
    }

    /** Returns documents that used supplemental BODY parameters this session. */
    public static long getDocsSupplementalBodyParamsUsed() {
        return docsSupplementalBodyParamsUsed.get();
    }

    /** Records one document where skip-path enumeration was rescued by supplemental parse. */
    public static void recordSkipPathBodyRescued() {
        docsSkipPathBodyRescued.incrementAndGet();
    }

    /** Returns skip-path BODY rescues this session. */
    public static long getDocsSkipPathBodyRescued() {
        return docsSkipPathBodyRescued.get();
    }

    /** Records one document's body_params_source for session Stats. */
    public static void recordBodyParamsSource(String source) {
        bodyParamsSourceCounts.record(source, 1);
    }

    /** Returns per-source document counts for session Stats. */
    public static Map<String, Long> getBodyParamsSourceCounts() {
        return bodyParamsSourceCounts.snapshot();
    }

    /** Records one document's body_params_skip_reason for session Stats. */
    public static void recordBodyParamsSkipReason(String reason) {
        bodyParamsSkipReasonCounts.record(reason, 1);
    }

    /** Returns per-reason document counts for session Stats. */
    public static Map<String, Long> getBodyParamsSkipReasonCounts() {
        return bodyParamsSkipReasonCounts.snapshot();
    }

    /** Records one document where supplemental urlencoded parse rejected a non-form logical body. */
    public static void recordSupplementalRejectedNonForm() {
        docsSupplementalRejectedNonForm.incrementAndGet();
    }

    /** Returns supplemental non-form rejections this session. */
    public static long getDocsSupplementalRejectedNonForm() {
        return docsSupplementalRejectedNonForm.get();
    }

    /** Records a Content-Encoding token applied on a supplemental BODY parse path. */
    public static void recordBodyParamsEncoding(String encoding) {
        bodyParamsEncodingCounts.record(encoding, 1);
    }

    /** Returns per-encoding document counts for supplemental BODY paths. */
    public static Map<String, Long> getBodyParamsEncodingCounts() {
        return bodyParamsEncodingCounts.snapshot();
    }

    /**
     * Records a successful OpenSearch push. Updates the connection-health timestamp and resets
     * the consecutive-failure counter so the panel can surface live destination health.
     */
    public static void recordOpenSearchSuccess() {
        openSearchLastSuccessAtMs.set(System.currentTimeMillis());
        openSearchConsecutiveFailures.set(0L);
    }

    /**
     * Records a failed OpenSearch push. Increments the consecutive-failure counter without
     * disturbing the last-success timestamp so the panel shows both values side by side.
     */
    public static void recordOpenSearchFailure() {
        openSearchConsecutiveFailures.incrementAndGet();
    }

    /** Returns the epoch-ms timestamp of the most recent successful OpenSearch push, or -1. */
    public static long getOpenSearchLastSuccessAtMs() {
        return openSearchLastSuccessAtMs.get();
    }

    /** Returns the count of consecutive OpenSearch push failures since the last success. */
    public static long getOpenSearchConsecutiveFailures() {
        return openSearchConsecutiveFailures.get();
    }

    /**
     * Records a silent skip of a document at an exporter filter (scope, tool-source, self-export, etc.).
     *
     * <p>Surfaces in the Misc Stats {@code Skips by Reason} row so the UI can show where
     * coverage gaps come from. Ignores {@code null}, blank, or non-positive counts.</p>
     */
    public static void recordSkipReason(String reason, long count) {
        skipReasonCounts.record(reason, count);
    }

    /** Returns the session total for one skip-reason key (0 when absent). */
    public static long getSkipReasonCount(String reason) {
        return skipReasonCounts.get(reason);
    }

    /**
     * Returns a live copy of the skip-reason counters.
     *
     * <p>Keys are the reason labels ({@code "scope"}, {@code "tool_disabled"},
     * {@code "self_opensearch"}, etc.); values are the counts. The returned map is a snapshot
     * and safe to iterate without synchronization.</p>
     */
    public static Map<String, Long> getSkipReasonCounts() {
        return skipReasonCounts.snapshot();
    }

    /** Returns the session total across all skip reasons. */
    public static long getTotalSkipCount() {
        return skipReasonCounts.total();
    }

    /**
     * Marks the start of a bulk request. Pair with {@link #recordBulkEnd()} in a finally block.
     * Increments the live {@code Bulk Requests In-Flight} counter surfaced on the Misc Stats card.
     *
     * <p>Prefer {@link #openBulk()} in new code so the increment / decrement cannot drift
     * apart on early-return or exceptional paths.</p>
     */
    public static void recordBulkStart() {
        bulkInFlight.incrementAndGet();
    }

    /**
     * Marks the end of a bulk request. Never drops below zero even if callers decrement
     * more than they increment, so misuse cannot produce misleading negative readings.
     */
    public static void recordBulkEnd() {
        bulkInFlight.updateAndGet(v -> v > 0 ? v - 1 : 0);
    }

    /**
     * Opens a {@link BulkInFlightTicket} that increments the in-flight counter immediately and
     * decrements it on {@link AutoCloseable#close()}. Use with try-with-resources:
     *
     * <pre>{@code
     * try (ExportStats.BulkInFlightTicket ignored = ExportStats.openBulk()) {
     *     return executeRequest(...);
     * }
     * }</pre>
     *
     * <p>Equivalent to {@link #recordBulkStart()} + {@link #recordBulkEnd()} in a finally block,
     * but enforces pairing at the type level so an early return or unhandled exception cannot
     * leave the counter elevated.</p>
     *
     * @return new single-thread-owned in-flight ticket
     */
    public static BulkInFlightTicket openBulk() {
        return new BulkInFlightTicket();
    }

    /** Returns the current count of bulk requests in flight. */
    public static int getBulkInFlight() {
        return bulkInFlight.get();
    }

    /**
     * Records one soft capacity outage entry (false → true transition).
     *
     * <p>Called from {@link ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator}
     * when soft outage mode activates. Surfaced in Misc Stats {@code Soft Outage Entries}.</p>
     */
    public static void recordSoftOutageEntry() {
        softOutageEntries.incrementAndGet();
    }

    /**
     * Returns soft capacity outage entries this export run.
     *
     * @return non-negative outage transition count
     */
    public static long getSoftOutageEntries() {
        return softOutageEntries.get();
    }

    /**
     * Records one shared capacity-cooldown extension.
     *
     * <p>Called when {@link ai.anomalousvectors.tools.burp.utils.opensearch.BulkRateLimitBackoff}
     * lengthens the shared deadline. Surfaced in Misc Stats {@code Capacity Events}.</p>
     */
    public static void recordCapacityPressureEvent() {
        capacityPressureEvents.incrementAndGet();
    }

    /**
     * Returns capacity-cooldown extensions this export run.
     *
     * @return non-negative capacity-event count
     */
    public static long getCapacityPressureEvents() {
        return capacityPressureEvents.get();
    }

    /**
     * Records a shared cooldown wait duration (peak retained for Misc Stats).
     *
     * @param waitMs milliseconds parked for cooldown; values {@code <= 0} are ignored
     */
    public static void recordCooldownWaitMs(long waitMs) {
        if (waitMs <= 0L) {
            return;
        }
        peakCooldownWaitMs.updateAndGet(prev -> Math.max(prev, waitMs));
    }

    /**
     * Returns the peak shared cooldown wait observed this export run.
     *
     * @return non-negative peak wait in milliseconds
     */
    public static long getPeakCooldownWaitMs() {
        return peakCooldownWaitMs.get();
    }

    /**
     * Records a snapshot flush-slot wait duration (peak retained for Misc Stats).
     *
     * @param waitMs milliseconds blocked waiting for an in-flight flush slot; values
     *               {@code <= 0} are ignored
     */
    public static void recordFlushSlotWaitMs(long waitMs) {
        if (waitMs <= 0L) {
            return;
        }
        peakFlushSlotWaitMs.updateAndGet(prev -> Math.max(prev, waitMs));
    }

    /**
     * Returns the peak snapshot flush-slot wait observed this export run.
     *
     * @return non-negative peak wait in milliseconds
     */
    public static long getPeakFlushSlotWaitMs() {
        return peakFlushSlotWaitMs.get();
    }

    /**
     * AutoCloseable handle for the {@code Bulk Requests In-Flight} counter. The constructor
     * increments the counter and {@link #close()} decrements it exactly once, even if called
     * more than once on the same ticket from its owning thread.
     *
     * <p>The ticket is not thread-safe. The thread that acquires it must retain sole close
     * ownership; concurrent calls to {@link #close()} are unsupported.</p>
     */
    public static final class BulkInFlightTicket implements AutoCloseable {
        private boolean closed;

        private BulkInFlightTicket() {
            recordBulkStart();
        }

        /**
         * Closes this ticket once from its owning thread.
         *
         * <p>Repeated calls on that thread are no-ops. Concurrent calls are unsupported.</p>
         */
        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            recordBulkEnd();
        }
    }

    /**
     * Returns the age (ms) of the oldest document currently queued for the given index, or -1
     * when the queue is empty. Surfaces in the Misc Stats {@code Oldest Queued Age} row.
     */
    public static long getOldestQueuedAgeMs(String indexKey) {
        String indexName = RuntimeConfig.indexNameForKey(indexKey);
        long enqueuedAt = IndexingRetryCoordinator.getInstance().getOldestQueuedEnqueuedAtMs(indexName);
        if (enqueuedAt <= 0) {
            return -1;
        }
        long age = System.currentTimeMillis() - enqueuedAt;
        return age < 0 ? 0 : age;
    }

    /** Run total: sum of documents exported to OpenSearch across all indexes. */
    public static long getTotalSuccessCount() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += getExportedCount(key);
        }
        return sum;
    }

    /** Session total: sum of failures across all indexes. */
    public static long getTotalFailureCount() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).failureCount.get();
        }
        return sum;
    }

    /**
     * Returns recovered-via-retry document count for the given index.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative recovered document count
     */
    public static long getRecoveredFailureCount(String indexKey) {
        return forIndex(indexKey).recoveredFailureCount.get();
    }

    /**
     * Returns the session total of documents recovered after an earlier failed attempt.
     *
     * @return non-negative recovered document count
     */
    public static long getTotalRecoveredFailureCount() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).recoveredFailureCount.get();
        }
        return sum;
    }

    /**
     * Returns failed attempts not yet matched by recovery or a recorded drop for the index.
     *
     * <p>Outstanding = failure attempts − recovered − permanent drops − retry-queue drops.
     * Permanent drops include mapping/validation poison pills and documents discarded from the
     * retry queue on Stop. Does not go below zero.</p>
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative outstanding failure count
     */
    public static long getOutstandingFailureCount(String indexKey) {
        return Math.max(
                0L,
                getFailureCount(indexKey)
                        - getRecoveredFailureCount(indexKey)
                        - getPermanentDrops(indexKey)
                        - getRetryQueueDrops(indexKey));
    }

    /**
     * Returns the session total of outstanding failed attempts.
     *
     * @return non-negative outstanding failure count
     */
    public static long getTotalOutstandingFailureCount() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += getOutstandingFailureCount(key);
        }
        return sum;
    }

    /** Session total: sum of estimated successful payload bytes across all indexes. */
    public static long getTotalExportedBytes() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).successBytes.get();
        }
        return sum;
    }

    /** Per-index retry queue: count of documents dropped when the retry queue was full. */
    public static void recordRetryQueueDrop(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).retryQueueDrops.addAndGet(count);
    }

    /** Returns the session total of documents dropped from the retry queue for the given index. */
    public static long getRetryQueueDrops(String indexKey) {
        return forIndex(indexKey).retryQueueDrops.get();
    }

    /** Returns the session total of documents dropped from retry queues across all indexes. */
    public static long getTotalRetryQueueDrops() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).retryQueueDrops.get();
        }
        return sum;
    }

    /**
     * Records that previously failed documents were pushed again by the retry drain.
     *
     * <p>Counts documents in each drain push batch (not unique docs, and not primary Failures).
     * Successful recoveries are tracked separately via {@link #recordRetryRecovery(String, long)}.</p>
     *
     * @param indexKey index key (e.g. {@code "traffic"})
     * @param count documents in this retry push; ignored if {@code <= 0}
     */
    public static void recordRetryAttempt(String indexKey, long count) {
        if (count <= 0) {
            return;
        }
        forIndex(indexKey).retryAttempts.addAndGet(count);
    }

    /**
     * Returns retry-drain push documents for the given index this session.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative retry-attempt document count
     */
    public static long getRetryAttempts(String indexKey) {
        return forIndex(indexKey).retryAttempts.get();
    }

    /**
     * Returns retry-drain push documents across all indexes this session.
     *
     * @return non-negative retry-attempt document count
     */
    public static long getTotalRetryAttempts() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).retryAttempts.get();
        }
        return sum;
    }

    /**
     * Per-index permanent-failure drops: documents that will not be retried again this session.
     *
     * <p>Includes mapping/parse/validation poison pills from
     * {@link ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator} and queued
     * retry documents discarded on Stop. Distinct from
     * {@link #recordRetryQueueDrop(String, long)} which counts capacity-driven drops while export
     * is still running.</p>
     *
     * @param indexKey short index key; unknown keys create a new counter bucket
     * @param count permanently dropped document count; values {@code <= 0} are ignored
     */
    public static void recordPermanentDrop(String indexKey, long count) {
        if (count <= 0) return;
        forIndex(indexKey).permanentDrops.addAndGet(count);
    }

    /**
     * Records a stable reason-coded permanent-drop total.
     *
     * @param reason stable reason key; blank values are ignored
     * @param count number of permanently dropped documents
     */
    public static void recordPermanentDropReason(String reason, long count) {
        permanentDropReasons.record(reason, count);
    }

    /**
     * Returns permanent-drop reason totals in deterministic key order.
     *
     * @return detached reason-to-count snapshot
     */
    public static Map<String, Long> getPermanentDropReasonCounts() {
        return permanentDropReasons.snapshot();
    }

    /**
     * Returns the session total for one permanent-drop reason key.
     *
     * @param reason stable reason key; null or blank returns zero
     * @return non-negative permanently dropped document count
     */
    public static long getPermanentDropReasonCount(String reason) {
        return permanentDropReasons.get(reason);
    }

    /**
     * Records one search document whose body/payload fields were prefix-truncated to fit the live
     * {@link ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget}.
     *
     * @param indexKey short index key (for example {@code traffic}); blank uses {@code unknown}
     */
    public static void recordSearchBodyPrefixTruncation(String indexKey) {
        searchBodyPrefixTruncations.incrementAndGet();
        String key = indexKey == null || indexKey.isBlank() ? "unknown" : indexKey;
        forIndex(key).bodyTruncations.incrementAndGet();
    }

    /**
     * Records search truncation once for one prepared operation across all retry/refit attempts.
     *
     * <p>Non-blank identifiers are retained until {@link #resetForRun()} so retry attempts in the
     * same run do not inflate the counter. Callers should therefore pass stable, run-scoped
     * operation identifiers.</p>
     *
     * @param operationId stable prepared operation identifier; null or blank records every call
     * @param indexKey short index key; null or blank uses {@code unknown}
     * @return {@code true} when this call recorded the operation, {@code false} when already counted
     */
    public static boolean recordSearchBodyPrefixTruncationOnce(
            String operationId, String indexKey) {
        if (operationId == null || operationId.isBlank()) {
            recordSearchBodyPrefixTruncation(indexKey);
            return true;
        }
        if (!COUNTED_SEARCH_TRUNCATION_OPERATION_IDS.add(operationId)) {
            return false;
        }
        recordSearchBodyPrefixTruncation(indexKey);
        return true;
    }

    /**
     * Returns the session total of search body/payload prefix truncations.
     *
     * @return non-negative truncation count
     */
    public static long getSearchBodyPrefixTruncations() {
        return searchBodyPrefixTruncations.get();
    }

    /**
     * Returns search body/payload prefix truncations for the given index.
     *
     * @param indexKey short index key; unknown keys create an empty counter bucket
     * @return non-negative truncation count
     */
    public static long getSearchBodyPrefixTruncations(String indexKey) {
        return forIndex(indexKey).bodyTruncations.get();
    }

    /** Returns the session total of permanently dropped documents for the given index. */
    public static long getPermanentDrops(String indexKey) {
        return forIndex(indexKey).permanentDrops.get();
    }

    /** Returns the session total of permanently dropped documents across all indexes. */
    public static long getTotalPermanentDrops() {
        long sum = 0;
        for (String key : INDEX_KEYS) {
            sum += forIndex(key).permanentDrops.get();
        }
        return sum;
    }

    /**
     * Returns documents per second over the last 60 seconds (rolling throughput).
     * Prunes entries older than the window. Thread-safe.
     *
     * @return docs/sec (0.0 or positive)
     */
    public static double getThroughputDocsPerSecLast60s() {
        return getThroughputDocsPerSec(THROUGHPUT_WINDOW_MS);
    }

    /**
     * Returns documents per second over the last 10 seconds (rolling throughput).
     * Prunes entries older than the window. Thread-safe.
     *
     * @return docs/sec (0.0 or positive)
     */
    public static double getThroughputDocsPerSecLast10s() {
        return getThroughputDocsPerSec(THROUGHPUT_WINDOW_SHORT_MS);
    }

    private static double getThroughputDocsPerSec(long windowMs) {
        long now = System.currentTimeMillis();
        long cutoff = now - windowMs;
        long sum;
        synchronized (recentSuccesses) {
            pruneRecentSuccessesOlderThan(cutoff);
            sum = 0;
            for (long[] pair : recentSuccesses) {
                if (pair[0] >= cutoff) {
                    sum += pair[1];
                }
            }
        }
        return sum / (windowMs / 1000.0);
    }

    /**
     * Records that a new export start was requested.
     *
     * <p>Resets startup latency tracking so the next successful traffic push can produce
     * an updated start-to-first-traffic metric.</p>
     */
    public static void recordExportStartRequested() {
        resetForRun();
        resetRunPeaks();
        exportStartRequestedAtMs.set(System.currentTimeMillis());
        firstTrafficSuccessAtMs.set(-1);
    }

    /**
     * Clears per-run export counters while preserving snapshot-last-run stats.
     *
     * <p>Individual counter operations are thread-safe, but reset is not an atomic snapshot
     * transition. Callers must quiesce export producers before invoking it.</p>
     */
    public static void resetForRun() {
        FileExportStats.resetForRun();
        for (String key : INDEX_KEYS) {
            PerIndexStats stats = forIndex(key);
            stats.exportedCount.set(0);
            stats.noopCount.set(0);
            stats.failureCount.set(0);
            stats.recoveredFailureCount.set(0);
            stats.successBytes.set(0);
            stats.lastLiveBulkDurationMs.set(-1);
            stats.lastError.set(null);
            stats.retryQueueDrops.set(0);
            stats.permanentDrops.set(0);
            stats.retryAttempts.set(0);
            stats.bodyTruncations.set(0);
        }
        for (String sourceKey : TRAFFIC_SOURCE_KEYS) {
            TrafficSourceStats source = forTrafficSource(sourceKey);
            source.successCount.set(0);
            source.failureCount.set(0);
            source.recoveryCount.set(0);
            source.retryQueueDrops.set(0);
            source.permanentDrops.set(0);
        }
        for (String toolType : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_RECOVERY_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_RETRY_QUEUE_DROP_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_PERMANENT_DROP_COUNTS.put(toolType, new AtomicLong(0));
        }
        synchronized (recentSuccesses) {
            recentSuccesses.clear();
        }
        firstTrafficSuccessAtMs.set(-1);
        softOutageEntries.set(0L);
        capacityPressureEvents.set(0L);
        searchBodyPrefixTruncations.set(0L);
        COUNTED_SEARCH_TRUNCATION_OPERATION_IDS.clear();
        permanentDropReasons.clear();
        peakCooldownWaitMs.set(0L);
        peakFlushSlotWaitMs.set(0L);
        clearSnapshotBuildAheadReservations();
    }

    /**
     * Returns milliseconds from the latest export Start request to the first successful
     * traffic push, or {@code -1} when not available yet.
     */
    public static long getStartToFirstTrafficMs() {
        long start = exportStartRequestedAtMs.get();
        long first = firstTrafficSuccessAtMs.get();
        if (start <= 0 || first <= 0 || first < start) {
            return -1;
        }
        return first - start;
    }

    /** Returns timestamp (epoch ms) for latest export Start request, or {@code -1}. */
    public static long getExportStartRequestedAtMs() {
        return exportStartRequestedAtMs.get();
    }

    /**
     * Resets process-local export stats for test teardown.
     *
     * <p>Callers must ensure no producers are recording concurrently.</p>
     */
    public static void resetForTests() {
        STATS.clear();
        TRAFFIC_SOURCE_STATS.clear();
        TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.clear();
        TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.clear();
        TRAFFIC_TOOL_TYPE_RECOVERY_COUNTS.clear();
        TRAFFIC_TOOL_TYPE_RETRY_QUEUE_DROP_COUNTS.clear();
        TRAFFIC_TOOL_TYPE_PERMANENT_DROP_COUNTS.clear();
        REPEATER_METADATA_SOURCE_COUNTS.clear();
        for (String key : INDEX_KEYS) {
            STATS.put(key, new PerIndexStats());
        }
        for (String sourceKey : TRAFFIC_SOURCE_KEYS) {
            TRAFFIC_SOURCE_STATS.put(sourceKey, new TrafficSourceStats());
        }
        for (String toolType : TRAFFIC_TOOL_TYPE_KEYS) {
            TRAFFIC_TOOL_TYPE_SUCCESS_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_FAILURE_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_RECOVERY_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_RETRY_QUEUE_DROP_COUNTS.put(toolType, new AtomicLong(0));
            TRAFFIC_TOOL_TYPE_PERMANENT_DROP_COUNTS.put(toolType, new AtomicLong(0));
        }
        for (String metadataSource : REPEATER_METADATA_SOURCE_KEYS) {
            REPEATER_METADATA_SOURCE_COUNTS.put(metadataSource, new AtomicLong(0));
        }
        exportStartRequestedAtMs.set(-1);
        firstTrafficSuccessAtMs.set(-1);
        for (AtomicReference<SnapshotLastRunStats> snapshotRef : lastSnapshotRuns.values()) {
            snapshotRef.set(null);
        }
        currentProxyHistoryChunkTarget.set(-1);
        lastBulkTargetBatch.set(-1);
        lastBulkAttemptedDocs.set(-1);
        resetRunPeaks();
        synchronized (recentSuccesses) {
            recentSuccesses.clear();
        }
        trafficQueueDrops.set(0);
        trafficSpillEnqueued.set(0);
        trafficSpillDequeued.set(0);
        trafficSpillDrops.set(0);
        trafficSpillRecovered.set(0);
        trafficSpillExpiredPruned.set(0);
        trafficDropReasons.clear();
        trafficToolSourceFallbacks.set(0);
        synthesizedBodyParamsDropped.set(0);
        docsBodyParamsTruncated.set(0);
        bodyParamsDroppedTotal.set(0);
        docsBodyEnumerationMisgateSuspect.set(0);
        docsUrlParamsTruncated.set(0);
        urlParamsDroppedTotal.set(0);
        docsWithSkippedBodyEnumeration.set(0);
        docsWireBodyParamsReplaced.set(0);
        wireBodyParamsDroppedTotal.set(0);
        docsSupplementalBodyParamsUsed.set(0);
        docsSkipPathBodyRescued.set(0);
        docsSupplementalRejectedNonForm.set(0);
        bodyParamsSourceCounts.clear();
        bodyParamsSkipReasonCounts.clear();
        bodyParamsEncodingCounts.clear();
        openSearchLastSuccessAtMs.set(-1L);
        openSearchConsecutiveFailures.set(0L);
        skipReasonCounts.clear();
        permanentDropReasons.clear();
        bulkInFlight.set(0);
        softOutageEntries.set(0L);
        capacityPressureEvents.set(0L);
        searchBodyPrefixTruncations.set(0L);
        COUNTED_SEARCH_TRUNCATION_OPERATION_IDS.clear();
        peakCooldownWaitMs.set(0L);
        peakFlushSlotWaitMs.set(0L);
    }

    /** Snapshot reporter keys that receive structured last-run stats. */
    public static List<String> getSnapshotReporterKeys() {
        return SNAPSHOT_REPORTER_KEYS;
    }

    /**
     * Records structured metrics for the latest snapshot run of one reporter.
     *
     * <p>This compatibility overload records sink-specific flush durations as unavailable.</p>
     *
     * @param reporterKey non-blank reporter key; blank values are ignored
     * @param attempted attempted document count
     * @param success successful document count
     * @param durationMs total run wall time
     * @param finalChunkTarget final adaptive chunk target
     * @param chunks completed chunk count
     * @param totalChunkBytes estimated bytes across chunks
     * @param buildWallMs document-build wall time
     * @param buildCpuMs aggregate document-build worker time
     * @param flushMs aggregate flush wall time
     * @param buildWorkers build worker count
     */
    public static void recordSnapshotLastRun(
            String reporterKey,
            int attempted,
            int success,
            long durationMs,
            int finalChunkTarget,
            int chunks,
            long totalChunkBytes,
            long buildWallMs,
            long buildCpuMs,
            long flushMs,
            int buildWorkers) {
        recordSnapshotLastRun(
                reporterKey,
                attempted,
                success,
                durationMs,
                finalChunkTarget,
                chunks,
                totalChunkBytes,
                buildWallMs,
                buildCpuMs,
                flushMs,
                -1L,
                -1L,
                buildWorkers);
    }

    /**
     * Records structured metrics and sink-specific flush durations for one reporter.
     *
     * @param reporterKey non-blank reporter key; blank values are ignored
     * @param attempted attempted document count
     * @param success successful document count
     * @param durationMs total run wall time
     * @param finalChunkTarget final adaptive chunk target
     * @param chunks completed chunk count
     * @param totalChunkBytes estimated bytes across chunks
     * @param buildWallMs document-build wall time
     * @param buildCpuMs aggregate document-build worker time
     * @param flushMs aggregate flush wall time
     * @param fileFlushMs file-sink flush wall time, or negative when unavailable
     * @param openSearchFlushMs database-sink flush wall time, or negative when unavailable
     * @param buildWorkers build worker count
     */
    public static void recordSnapshotLastRun(
            String reporterKey,
            int attempted,
            int success,
            long durationMs,
            int finalChunkTarget,
            int chunks,
            long totalChunkBytes,
            long buildWallMs,
            long buildCpuMs,
            long flushMs,
            long fileFlushMs,
            long openSearchFlushMs,
            int buildWorkers) {
        if (reporterKey == null || reporterKey.isBlank()) {
            return;
        }
        AtomicReference<SnapshotLastRunStats> slot = lastSnapshotRuns.computeIfAbsent(
                reporterKey.trim(), unused -> new AtomicReference<>(null));
        slot.set(new SnapshotLastRunStats(
                attempted,
                success,
                durationMs,
                finalChunkTarget,
                chunks,
                totalChunkBytes,
                buildWallMs,
                buildCpuMs,
                flushMs,
                fileFlushMs,
                openSearchFlushMs,
                buildWorkers,
                System.currentTimeMillis()));
        noteSnapshotChunkTargetPeak(finalChunkTarget);
        if (SNAPSHOT_PROXY_HISTORY.equals(reporterKey)) {
            clearCurrentProxyHistoryChunkTarget();
        }
    }

    /**
     * Records summary metrics for the latest proxy-history snapshot push.
     *
     * <p>This compatibility overload records sink-specific flush durations as unavailable.</p>
     *
     * @param attempted attempted document count
     * @param success successful document count
     * @param durationMs total run wall time
     * @param finalChunkTarget final adaptive chunk target
     * @param chunks completed chunk count
     * @param totalChunkBytes estimated bytes across chunks
     * @param buildWallMs document-build wall time
     * @param buildCpuMs aggregate document-build worker time
     * @param flushMs aggregate flush wall time
     * @param buildWorkers build worker count
     */
    public static void recordProxyHistorySnapshot(
            int attempted,
            int success,
            long durationMs,
            int finalChunkTarget,
            int chunks,
            long totalChunkBytes,
            long buildWallMs,
            long buildCpuMs,
            long flushMs,
            int buildWorkers) {
        recordProxyHistorySnapshot(
                attempted,
                success,
                durationMs,
                finalChunkTarget,
                chunks,
                totalChunkBytes,
                buildWallMs,
                buildCpuMs,
                flushMs,
                -1L,
                -1L,
                buildWorkers);
    }

    /**
     * Records proxy-history metrics and sink-specific flush durations.
     *
     * @param attempted attempted document count
     * @param success successful document count
     * @param durationMs total run wall time
     * @param finalChunkTarget final adaptive chunk target
     * @param chunks completed chunk count
     * @param totalChunkBytes estimated bytes across chunks
     * @param buildWallMs document-build wall time
     * @param buildCpuMs aggregate document-build worker time
     * @param flushMs aggregate flush wall time
     * @param fileFlushMs file-sink flush wall time, or negative when unavailable
     * @param openSearchFlushMs database-sink flush wall time, or negative when unavailable
     * @param buildWorkers build worker count
     */
    public static void recordProxyHistorySnapshot(
            int attempted,
            int success,
            long durationMs,
            int finalChunkTarget,
            int chunks,
            long totalChunkBytes,
            long buildWallMs,
            long buildCpuMs,
            long flushMs,
            long fileFlushMs,
            long openSearchFlushMs,
            int buildWorkers) {
        recordSnapshotLastRun(
                SNAPSHOT_PROXY_HISTORY,
                attempted,
                success,
                durationMs,
                finalChunkTarget,
                chunks,
                totalChunkBytes,
                buildWallMs,
                buildCpuMs,
                flushMs,
                fileFlushMs,
                openSearchFlushMs,
                buildWorkers);
    }

    /** Returns the latest snapshot stats for a reporter, or {@code null} when none recorded. */
    public static SnapshotLastRunStats getSnapshotLastRun(String reporterKey) {
        if (reporterKey == null || reporterKey.isBlank()) {
            return null;
        }
        AtomicReference<SnapshotLastRunStats> slot = lastSnapshotRuns.get(reporterKey.trim());
        return slot == null ? null : slot.get();
    }

    /** Returns the latest proxy-history snapshot stats, or {@code null} when none recorded. */
    public static SnapshotLastRunStats getLastProxyHistorySnapshot() {
        return getSnapshotLastRun(SNAPSHOT_PROXY_HISTORY);
    }

    /**
     * Immutable snapshot run performance summary.
     *
     * @param attempted attempted document count
     * @param success successful document count
     * @param durationMs total run wall time
     * @param finalChunkTarget final adaptive chunk target
     * @param chunks completed chunk count
     * @param totalChunkBytes estimated bytes across chunks
     * @param buildWallMs document-build wall time
     * @param buildCpuMs aggregate document-build worker time
     * @param flushMs aggregate flush wall time
     * @param fileFlushMs file-sink flush wall time, or negative when unavailable
     * @param openSearchFlushMs database-sink flush wall time, or negative when unavailable
     * @param buildWorkers build worker count
     * @param recordedAtMs epoch-millisecond recording time
     */
    public record SnapshotLastRunStats(
            int attempted,
            int success,
            long durationMs,
            int finalChunkTarget,
            int chunks,
            long totalChunkBytes,
            long buildWallMs,
            long buildCpuMs,
            long flushMs,
            long fileFlushMs,
            long openSearchFlushMs,
            int buildWorkers,
            long recordedAtMs
    ) {
        /** Returns effective throughput in docs/sec for this snapshot, or 0 when unavailable. */
        public double docsPerSecond() {
            if (durationMs <= 0 || attempted <= 0) {
                return 0.0;
            }
            return attempted / (durationMs / 1000.0);
        }

        /** Average docs per chunk when {@code chunks > 0}, else 0. */
        public double avgChunkDocs() {
            if (chunks <= 0) {
                return 0.0;
            }
            return (double) attempted / chunks;
        }

        /** Average estimated bytes per chunk when {@code chunks > 0}, else 0. */
        public long avgChunkBytes() {
            if (chunks <= 0) {
                return 0L;
            }
            return totalChunkBytes / chunks;
        }
    }

    private static String normalizeTrafficToolType(String toolTypeKey) {
        return toolTypeKey == null || toolTypeKey.isBlank() ? "UNKNOWN" : toolTypeKey.trim();
    }

    private static final class PerIndexStats {
        final AtomicLong exportedCount = new AtomicLong(0);
        final AtomicLong noopCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong recoveredFailureCount = new AtomicLong(0);
        final AtomicLong successBytes = new AtomicLong(0);
        final AtomicLong lastLiveBulkDurationMs = new AtomicLong(-1);
        final AtomicReference<String> lastError = new AtomicReference<>(null);
        final AtomicLong retryQueueDrops = new AtomicLong(0);
        final AtomicLong permanentDrops = new AtomicLong(0);
        final AtomicLong retryAttempts = new AtomicLong(0);
        final AtomicLong bodyTruncations = new AtomicLong(0);
    }

    private static final class TrafficSourceStats {
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong recoveryCount = new AtomicLong(0);
        final AtomicLong retryQueueDrops = new AtomicLong(0);
        final AtomicLong permanentDrops = new AtomicLong(0);
    }

    private static String normalizeRepeaterMetadataSource(String metadataSource) {
        if (metadataSource == null || metadataSource.isBlank()) {
            return "none";
        }
        String normalized = metadataSource.trim();
        return REPEATER_METADATA_SOURCE_KEYS.contains(normalized) ? normalized : "none";
    }
}
