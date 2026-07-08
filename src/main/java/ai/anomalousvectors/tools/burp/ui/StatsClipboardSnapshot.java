package ai.anomalousvectors.tools.burp.ui;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.CountResponse;
import org.opensearch.client.opensearch.indices.RefreshResponse;

import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler;
import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.SystemMetrics;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClassicHttpSupport;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;

/**
 * Builds the Stats panel clipboard text from live counters (no Swing table state).
 *
 * <p>Used by the shared Copy toolbar in {@link StatsPanel}. Session stop troubleshooting emits
 * three single-line JSON INFO log entries via {@link #logSessionStopSummary()}.</p>
 */
public final class StatsClipboardSnapshot {

    private static final ObjectMapper COMPACT_JSON = new ObjectMapper();
    private static final String SUBROW_INDENT = "    ";
    private static final DecimalFormat DECIMAL_ONE =
            new DecimalFormat("0.0", DecimalFormatSymbols.getInstance(Locale.ROOT));

    private static final String[] FILE_COLUMNS =
            { "Index", "Written", "Failures", "Last Write (ms)", "Last Error" };
    private static final String[] OPEN_SEARCH_COLUMNS =
            { "Index", "Exported", "Queued", "Retry Drops", "Permanent Drops",
                    "Failures", "Last Bulk (ms)", "Last Error" };
    private static volatile OpenSearchCountResolver countResolver =
            StatsClipboardSnapshot::resolveOpenSearchIndexCounts;

    private StatsClipboardSnapshot() {}

    /**
     * Returns clipboard-equivalent text: File Counts, OpenSearch Counts, and Misc Stats sections.
     *
     * @return plain-text snapshot matching {@link StatsPanel} Copy output for enabled destinations
     */
    public static String buildClipboardText() {
        StringBuilder sb = new StringBuilder(1024);
        if (isFileSectionEnabled()) {
            sb.append("File Counts\n");
            sb.append(CardCopySupport.rowsToTsv(FILE_COLUMNS, buildFileCountRows()));
            sb.append('\n');
        }
        if (isOpenSearchSectionEnabled()) {
            sb.append("OpenSearch Counts\n");
            sb.append(CardCopySupport.rowsToTsv(OPEN_SEARCH_COLUMNS, buildOpenSearchCountRows()));
            sb.append('\n');
        }
        sb.append(CardCopySupport.sectionsToText("Misc Stats", buildMiscSections()));
        return sb.toString();
    }

    /**
     * Logs session-final Stats at INFO as three compact JSON lines (File, OpenSearch, Misc) when
     * applicable. Intended once per export Stop after the final exporter stats push.
     */
    public static void logSessionStopSummary() {
        if (isFileSectionEnabled()) {
            logCompactJsonLine("file_counts", buildFileCountsPayload());
        }
        if (isOpenSearchSectionEnabled()) {
            logCompactJsonLine("open_search_counts", buildOpenSearchCountsPayload());
        }
        logCompactJsonLine("misc_stats", buildMiscStatsPayload());
    }

    /**
     * Logs session-final Stats with refreshed OpenSearch index counts when OpenSearch is active.
     *
     * <p>Used at Stop after the final exporter stats snapshot is pushed. The live StatsPanel and
     * clipboard path intentionally keep session-export counters; this stop-only path favors
     * operator validation against OpenSearch {@code _count}.</p>
     */
    public static void logSessionStopSummaryWithOpenSearchCounts() {
        OpenSearchCountResolution counts = resolveStopOpenSearchCounts();
        if (counts.warning() != null) {
            Logger.logWarnPanelOnly("[Stats] Session stop " + counts.warning());
        }
        if (isFileSectionEnabled()) {
            logCompactJsonLine("file_counts", buildFileCountsPayload());
        }
        if (isOpenSearchSectionEnabled()) {
            logCompactJsonLine("open_search_counts", buildOpenSearchCountsPayload(counts));
        }
        logCompactJsonLine("misc_stats", buildMiscStatsPayload());
    }

    static void setOpenSearchCountResolverForTests(OpenSearchCountResolver resolver) {
        countResolver = resolver != null ? resolver : StatsClipboardSnapshot::resolveOpenSearchIndexCounts;
    }

    private static void logCompactJsonLine(String kind, Map<String, Object> payload) {
        Map<String, Object> root = new LinkedHashMap<>(payload.size() + 1);
        root.put("kind", kind);
        root.putAll(payload);
        try {
            Logger.logInfoPanelOnly("[Stats] Session stop " + COMPACT_JSON.writeValueAsString(root));
        } catch (JsonProcessingException ex) {
            Logger.logWarnPanelOnly("[Stats] Session stop " + kind + " JSON encode failed: " + ex.getMessage());
        }
    }

    private static Map<String, Object> buildFileCountsPayload() {
        Map<String, Object> payload = new LinkedHashMap<>(2);
        payload.put("columns", List.of(FILE_COLUMNS));
        payload.put("rows", buildFileCountRows());
        return payload;
    }

    private static Map<String, Object> buildOpenSearchCountsPayload() {
        return buildOpenSearchCountsPayload(OpenSearchCountResolution.sessionCounters());
    }

    private static Map<String, Object> buildOpenSearchCountsPayload(OpenSearchCountResolution countResolution) {
        Map<String, Object> payload = new LinkedHashMap<>(2);
        payload.put("columns", List.of(OPEN_SEARCH_COLUMNS));
        payload.put("rows", buildOpenSearchCountRows(countResolution.counts()));
        payload.put("count_source", countResolution.source());
        if (countResolution.warning() != null) {
            payload.put("count_warning", countResolution.warning());
        }
        return payload;
    }

    private static Map<String, Object> buildMiscStatsPayload() {
        Map<String, Object> payload = new LinkedHashMap<>(1);
        payload.put("sections", buildMiscSections());
        return payload;
    }

    private static List<String[]> buildFileCountRows() {
        List<String[]> rows = new ArrayList<>();
        List<String> sortedKeys = new ArrayList<>(FileExportStats.getIndexKeys());
        sortedKeys.sort((left, right) -> left.compareToIgnoreCase(right));
        long totalSuccess = 0;
        long totalFailure = 0;
        for (String indexKey : sortedKeys) {
            long written = FileExportStats.getWrittenCount(indexKey);
            long failure = FileExportStats.getFailureCount(indexKey);
            long lastWriteMs = FileExportStats.getLastWriteDurationMs(indexKey);
            String lastWriteStr = lastWriteMs >= 0 ? String.valueOf(lastWriteMs) : "-";
            String lastError = FileExportStats.getLastError(indexKey);
            totalSuccess += written;
            totalFailure += failure;
            rows.add(new String[] {
                    formatKeyLabel(indexKey),
                    formatWhole(written),
                    formatWhole(failure),
                    lastWriteStr,
                    lastError != null ? lastError : "-"
            });
            if ("traffic".equalsIgnoreCase(indexKey)) {
                appendFileTrafficSourceSubRows(rows);
            }
        }
        rows.add(new String[] {
                "Total", formatWhole(totalSuccess), formatWhole(totalFailure), "-", "-"
        });
        return rows;
    }

    private static void appendFileTrafficSourceSubRows(List<String[]> rows) {
        for (String sourceKey : FileExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            rows.add(new String[] {
                    SUBROW_INDENT + formatKeyLabel(sourceKey),
                    formatWhole(TrafficRouteBucket.resolveFileSourceSuccess(sourceKey)),
                    formatWhole(TrafficRouteBucket.resolveFileSourceFailure(sourceKey)),
                    "-",
                    "-"
            });
        }
    }

    private static List<String[]> buildOpenSearchCountRows() {
        return buildOpenSearchCountRows(Map.of());
    }

    private static List<String[]> buildOpenSearchCountRows(Map<String, Long> countOverrides) {
        List<String[]> rows = new ArrayList<>();
        List<String> sortedKeys = new ArrayList<>(ExportStats.getIndexKeys());
        sortedKeys.sort((left, right) -> left.compareToIgnoreCase(right));
        long totalSuccess = 0;
        long totalQueued = 0;
        long totalRetryDrops = 0;
        long totalPermanentDrops = 0;
        long totalFailure = 0;
        for (String indexKey : sortedKeys) {
            long exported = countOverrides.getOrDefault(indexKey, ExportStats.getExportedCount(indexKey));
            int queued = ExportStats.getQueueSize(indexKey);
            long retryDrops = ExportStats.getRetryQueueDrops(indexKey);
            long permanentDrops = ExportStats.getPermanentDrops(indexKey);
            long failure = ExportStats.getFailureCount(indexKey);
            String lastBulkStr = "-";
            if ("traffic".equalsIgnoreCase(indexKey)) {
                long lastBulkMs = ExportStats.getLastLiveBulkDurationMs(indexKey);
                if (lastBulkMs >= 0) {
                    lastBulkStr = String.valueOf(lastBulkMs);
                }
            }
            String lastError = ExportStats.getLastError(indexKey);
            totalSuccess += exported;
            totalQueued += queued;
            totalRetryDrops += retryDrops;
            totalPermanentDrops += permanentDrops;
            totalFailure += failure;
            rows.add(new String[] {
                    formatKeyLabel(indexKey),
                    formatWhole(exported),
                    formatWhole(queued),
                    formatWhole(retryDrops),
                    formatWhole(permanentDrops),
                    formatWhole(failure),
                    lastBulkStr,
                    lastError != null ? lastError : "-"
            });
            if ("traffic".equalsIgnoreCase(indexKey)) {
                appendOpenSearchTrafficSourceSubRows(rows);
            }
        }
        rows.add(new String[] {
                "Total",
                formatWhole(totalSuccess),
                formatWhole(totalQueued),
                formatWhole(totalRetryDrops),
                formatWhole(totalPermanentDrops),
                formatWhole(totalFailure),
                "-",
                "-"
        });
        return rows;
    }

    private static OpenSearchCountResolution resolveStopOpenSearchCounts() {
        if (!RuntimeConfig.isOpenSearchActive()) {
            return OpenSearchCountResolution.sessionCounters();
        }
        try {
            List<String> indexKeys = List.copyOf(ExportStats.getIndexKeys());
            Logger.logInfoPanelOnly("[Stats] Collecting final OpenSearch counts via refresh/_count for indexes: "
                    + formatIndexNamesForLog(indexKeys) + ".");
            Map<String, Long> counts = countResolver.resolve(indexKeys);
            return new OpenSearchCountResolution(
                    counts == null ? Map.of() : Map.copyOf(counts),
                    "opensearch_index_count",
                    null);
        } catch (RuntimeException ex) {
            String detail = ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();
            return new OpenSearchCountResolution(
                    Map.of(),
                    "session_export_counters",
                    "OpenSearch index counts unavailable at Stop; using session export counters: " + detail);
        }
    }

    private static Map<String, Long> resolveOpenSearchIndexCounts(List<String> indexKeys) {
        if (RuntimeConfig.searchDestinationKind() == ConfigState.SearchDestination.ELASTICSEARCH) {
            return resolveSearchIndexCountsOverHttp(indexKeys);
        }
        OpenSearchClient client = OpenSearchConnector.getClient(
                RuntimeConfig.openSearchUrl(),
                OpenSearchAuth.fromRuntime());
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String indexKey : indexKeys) {
            String indexName = RuntimeConfig.indexNameForKey(indexKey);
            if (indexName == null || indexName.isBlank()) {
                indexName = IndexNaming.indexNameForShortName(indexKey);
            }
            RefreshResponse refresh = refreshIndex(client, indexName);
            if (refresh.shards().failed() > 0) {
                throw new IllegalStateException("refresh failed for " + indexName);
            }
            CountResponse count = countIndex(client, indexName);
            counts.put(indexKey, count.count());
        }
        return counts;
    }

    private static Map<String, Long> resolveSearchIndexCountsOverHttp(List<String> indexKeys) {
        String baseUrl = RuntimeConfig.searchBaseUrl();
        OpenSearchAuth auth = OpenSearchAuth.fromRuntime(RuntimeConfig.searchDestinationKind());
        var client = OpenSearchConnector.getClassicHttpClient(baseUrl, auth);
        HttpHost host = OpenSearchClassicHttpSupport.hostForBaseUrl(baseUrl);
        Map<String, Long> counts = new LinkedHashMap<>();
        for (String indexKey : indexKeys) {
            String indexName = RuntimeConfig.indexNameForKey(indexKey);
            if (indexName == null || indexName.isBlank()) {
                indexName = IndexNaming.indexNameForShortName(indexKey);
            }
            refreshIndexOverHttp(client, host, auth, indexName);
            counts.put(indexKey, countIndexOverHttp(client, host, auth, indexName));
        }
        return counts;
    }

    private static void refreshIndexOverHttp(
            org.apache.hc.client5.http.impl.classic.CloseableHttpClient client,
            HttpHost host,
            OpenSearchAuth auth,
            String indexName) {
        try {
            HttpPost refresh = new HttpPost("/" + indexName + "/_refresh");
            auth.applyTo(refresh);
            client.execute(host, refresh, response -> {
                int status = response.getCode();
                if (status < 200 || status >= 300) {
                    throw new IllegalStateException("refresh failed for " + indexName + ": HTTP " + status);
                }
                return null;
            });
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("refresh failed for " + indexName + ": " + ex.getMessage(), ex);
        }
    }

    private static long countIndexOverHttp(
            org.apache.hc.client5.http.impl.classic.CloseableHttpClient client,
            HttpHost host,
            OpenSearchAuth auth,
            String indexName) {
        try {
            HttpGet count = new HttpGet("/" + indexName + "/_count");
            auth.applyTo(count);
            return client.execute(host, count, response -> {
                int status = response.getCode();
                String body;
                try {
                    body = response.getEntity() == null
                            ? ""
                            : EntityUtils.toString(response.getEntity(), java.nio.charset.StandardCharsets.UTF_8);
                } catch (ParseException e) {
                    throw new java.io.IOException("Failed to parse count response for " + indexName, e);
                }
                if (status < 200 || status >= 300) {
                    throw new IllegalStateException("count failed for " + indexName + ": HTTP " + status);
                }
                JsonNode root = COMPACT_JSON.readTree(body);
                return root.path("count").asLong();
            });
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("count failed for " + indexName + ": " + ex.getMessage(), ex);
        }
    }

    private static String formatIndexNamesForLog(List<String> indexKeys) {
        List<String> names = new ArrayList<>();
        for (String indexKey : indexKeys) {
            String indexName = RuntimeConfig.indexNameForKey(indexKey);
            if (indexName == null || indexName.isBlank()) {
                indexName = IndexNaming.indexNameForShortName(indexKey);
            }
            names.add(indexName);
        }
        return String.join(", ", names);
    }

    private static RefreshResponse refreshIndex(OpenSearchClient client, String indexName) {
        try {
            return client.indices().refresh(r -> r.index(indexName));
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("refresh failed for " + indexName + ": " + ex.getMessage(), ex);
        }
    }

    private static CountResponse countIndex(OpenSearchClient client, String indexName) {
        try {
            return client.count(c -> c.index(indexName));
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("count failed for " + indexName + ": " + ex.getMessage(), ex);
        }
    }

    @FunctionalInterface
    interface OpenSearchCountResolver {
        Map<String, Long> resolve(List<String> indexKeys);
    }

    private record OpenSearchCountResolution(
            Map<String, Long> counts,
            String source,
            String warning) {

        private static OpenSearchCountResolution sessionCounters() {
            return new OpenSearchCountResolution(Map.of(), "session_export_counters", null);
        }
    }

    private static void appendOpenSearchTrafficSourceSubRows(List<String[]> rows) {
        for (String sourceKey : ExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            rows.add(new String[] {
                    SUBROW_INDENT + formatKeyLabel(sourceKey),
                    formatWhole(TrafficRouteBucket.resolveOpenSearchSourceSuccess(sourceKey)),
                    "-",
                    "-",
                    "-",
                    formatWhole(TrafficRouteBucket.resolveOpenSearchSourceFailure(sourceKey)),
                    "-",
                    "-"
            });
        }
    }

    private static Map<String, Map<String, String>> buildMiscSections() {
        boolean fileVisible = isFileSectionEnabled();
        boolean openSearchVisible = isOpenSearchSectionEnabled();
        Map<String, Map<String, String>> sections = new LinkedHashMap<>();
        sections.put("Global", Map.of(
                "Export Running", RuntimeConfig.isExportRunning() ? "Yes" : "No"));
        sections.put("Process", buildProcessSection(SystemMetrics.snapshot()));
        if (openSearchVisible) {
            sections.put("OpenSearch Session", buildOpenSearchSessionSection());
            sections.put("Parameter Integrity", buildParameterIntegritySection());
            sections.put("OpenSearch Traffic", buildOpenSearchTrafficSection());
            sections.put("OpenSearch Spill", buildOpenSearchSpillSection());
            sections.put("OpenSearch Retry", buildOpenSearchRetrySection());
            sections.put("OpenSearch Run Peaks", buildOpenSearchRunPeaksSection());
        }
        if (fileVisible) {
            sections.put("Files", buildFilesSection());
        }
        return sections;
    }

    private static Map<String, String> buildProcessSection(SystemMetrics.Snapshot snapshot) {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Heap Used / Max", formatBytesPairWithPercent(snapshot.heapUsedBytes(), snapshot.heapMaxBytes()));
        rows.put("Heap Committed", formatBytesWithPercentOf(snapshot.heapCommittedBytes(), snapshot.heapMaxBytes()));
        rows.put("Non-Heap Used", snapshot.nonHeapUsedBytes() >= 0
                ? formatHumanReadableBytes(snapshot.nonHeapUsedBytes()) : "n/a");
        rows.put("Direct Buffer Used", snapshot.directBufferUsedBytes() >= 0
                ? formatHumanReadableBytes(snapshot.directBufferUsedBytes()) : "n/a");
        rows.put("Mapped Buffer Used", snapshot.mappedBufferUsedBytes() >= 0
                ? formatHumanReadableBytes(snapshot.mappedBufferUsedBytes()) : "n/a");
        rows.put("Threads (Live / Peak)", formatIntPair(snapshot.threadCount(), snapshot.peakThreadCount()));
        rows.put("GC (Count / Time)", snapshot.gcCollectionCount() >= 0 && snapshot.gcCollectionTimeMs() >= 0
                ? formatWhole(snapshot.gcCollectionCount()) + " / "
                        + formatDurationMsCompact(snapshot.gcCollectionTimeMs())
                : "n/a");
        rows.put("Process CPU Load", Double.isNaN(snapshot.processCpuLoad())
                ? "n/a"
                : DECIMAL_ONE.format(snapshot.processCpuLoad() * 100.0) + "%");
        return rows;
    }

    private static Map<String, String> buildOpenSearchSessionSection() {
        long totalSuccess = ExportStats.getTotalSuccessCount();
        long totalFailure = ExportStats.getTotalFailureCount();
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Throughput (10s)", DECIMAL_ONE.format(ExportStats.getThroughputDocsPerSecLast10s()) + " docs/s");
        rows.put("Exported Docs", formatWhole(totalSuccess) + " docs");
        rows.put("Exported Size", formatHumanReadableBytes(ExportStats.getTotalExportedBytes()));
        rows.put("Exported Failures", formatWhole(totalFailure) + " failures");
        rows.put("Last Success", StatsPanelFormatters.formatRelativeTime(ExportStats.getOpenSearchLastSuccessAtMs()));
        rows.put("Consecutive Failures", formatWhole(ExportStats.getOpenSearchConsecutiveFailures()));
        rows.put("Permanent Drops", formatWhole(ExportStats.getTotalPermanentDrops()));
        return rows;
    }

    private static Map<String, String> buildParameterIntegritySection() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Mis-gate Suspects", formatWhole(ExportStats.getDocsBodyEnumerationMisgateSuspect()));
        rows.put("Skipped BODY Enumeration", formatWhole(ExportStats.getDocsWithSkippedBodyEnumeration()));
        rows.put("Wire BODY Replaced", formatWhole(ExportStats.getDocsWireBodyParamsReplaced()));
        rows.put("Skip-path Rescued", formatWhole(ExportStats.getDocsSkipPathBodyRescued()));
        rows.put("Supplemental BODY Used", formatWhole(ExportStats.getDocsSupplementalBodyParamsUsed()));
        rows.put("Supplemental Rejected (non-form)",
                formatWhole(ExportStats.getDocsSupplementalRejectedNonForm()));
        rows.put("Wire BODY Dropped (entries)", formatWhole(ExportStats.getWireBodyParamsDroppedTotal()));
        return rows;
    }

    private static Map<String, String> buildOpenSearchTrafficSection() {
        int trafficQueueDocs = TrafficExportQueue.getCurrentSize();
        long trafficQueueBytes = TrafficExportQueue.getCurrentBytesEstimate();
        int proxyChunkTarget = ExportStats.getCurrentProxyHistoryChunkTarget();
        String proxyChunkText;
        if (proxyChunkTarget >= 0) {
            proxyChunkText = formatWhole(proxyChunkTarget);
        } else {
            ExportStats.SnapshotLastRunStats proxySnapshot = ExportStats.getLastProxyHistorySnapshot();
            proxyChunkText = proxySnapshot != null ? formatWhole(proxySnapshot.finalChunkTarget()) : "-";
        }
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Bulk In-Flight", formatWhole(ExportStats.getBulkInFlight()));
        rows.put("Shared Batch Size", formatWhole(BatchSizeController.getInstance().getCurrentBatchSize()));
        rows.put("Proxy History Chunk Target", proxyChunkText);
        rows.put("Traffic Queue Size", formatWhole(trafficQueueDocs));
        rows.put("Traffic Queue Bytes (est.)", StatsPanelFormatters.formatBytesHuman(trafficQueueBytes));
        rows.put("Queue Drops", formatWhole(ExportStats.getTrafficQueueDrops()));
        rows.put("Pending Orphans", formatWhole(TrafficHttpHandler.pendingOrphansSize()));
        rows.put("Repeater Metadata Sources", ExportStats.describeRepeaterMetadataSourceCounts());
        return rows;
    }

    private static Map<String, String> buildOpenSearchSpillSection() {
        int spillDocs = TrafficExportQueue.getCurrentSpillSize();
        long spillBytes = TrafficExportQueue.getCurrentSpillBytes();
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Queue", StatsPanelFormatters.formatSpillQueue(spillDocs, spillBytes));
        rows.put("Oldest Age (s)",
                DECIMAL_ONE.format(TrafficExportQueue.getCurrentSpillOldestAgeMs() / 1000.0));
        rows.put("Enqueued / Dequeued / Dropped",
                formatWhole(ExportStats.getTrafficSpillEnqueued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDequeued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDrops()));
        rows.put("Drop Reasons",
                formatWhole(ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest")) + " / "
                        + formatWhole(ExportStats.getTrafficDropReasonCount("queue_contention_drop")) + " / "
                        + formatWhole(ExportStats.getTrafficDropReasonCount("spill_requeue_failed_drop")) + " / "
                        + formatWhole(ExportStats.getTrafficSpillExpiredPruned()));
        return rows;
    }

    private static Map<String, String> buildOpenSearchRetrySection() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Queue Depth", StatsPanelFormatters.formatRetryQueueDepthSummary());
        rows.put("Oldest Queued Age", StatsPanelFormatters.formatOldestQueuedAgeSummary());
        return rows;
    }

    private static Map<String, String> buildOpenSearchRunPeaksSection() {
        int peakChunkTarget = ExportStats.getPeakSnapshotChunkTarget();
        long peakFlushMs = ExportStats.getPeakSnapshotFlushMs();
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Peak Traffic Queue", StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakTrafficQueueDocs(), ExportStats.getPeakTrafficQueueBytes()));
        rows.put("Peak Spill Queue", StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakSpillDocs(), ExportStats.getPeakSpillBytes()));
        rows.put("Peak Retry Queue", StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakRetryQueueDocs(), ExportStats.getPeakRetryQueueBytes()));
        rows.put("Peak Snapshot Chunk Target", peakChunkTarget > 0 ? formatWhole(peakChunkTarget) : "—");
        rows.put("Peak Snapshot Flush (ms)", peakFlushMs > 0 ? formatWhole(peakFlushMs) : "—");
        return rows;
    }

    private static Map<String, String> buildFilesSection() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("File Total Size Exported", formatHumanReadableBytes(FileExportStats.getTotalExportedBytes()));
        rows.put("File Total Docs Exported", formatWhole(FileExportStats.getTotalSuccessCount()));
        rows.put("File Total Failures", formatWhole(FileExportStats.getTotalFailureCount()));
        return rows;
    }

    private static boolean isFileSectionEnabled() {
        return RuntimeConfig.isAnyFileExportEnabled();
    }

    private static boolean isOpenSearchSectionEnabled() {
        var current = RuntimeConfig.getState();
        return current != null && current.sinks() != null && current.sinks().osEnabled();
    }

    private static String formatKeyLabel(String key) {
        if (key == null || key.isBlank()) {
            return "";
        }
        String[] parts = key.toLowerCase(Locale.ROOT).replace('_', ' ').split("\\s+");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(Character.toUpperCase(part.charAt(0))).append(part.substring(1));
        }
        return sb.toString();
    }

    private static String formatWhole(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    private static String formatHumanReadableBytes(long bytes) {
        long safeBytes = Math.max(0L, bytes);
        double value = safeBytes;
        String unit = "B";
        if (safeBytes >= 1024L * 1024L * 1024L) {
            value = safeBytes / (1024.0 * 1024.0 * 1024.0);
            unit = "GB";
        } else if (safeBytes >= 1024L * 1024L) {
            value = safeBytes / (1024.0 * 1024.0);
            unit = "MB";
        } else if (safeBytes >= 1024L) {
            value = safeBytes / 1024.0;
            unit = "KB";
        }
        if ("B".equals(unit)) {
            return formatWhole(safeBytes) + " " + unit;
        }
        return DECIMAL_ONE.format(value) + " " + unit;
    }

    private static String formatBytesPair(long used, long max) {
        String usedText = used >= 0 ? formatHumanReadableBytes(used) : "n/a";
        String maxText = max > 0 ? formatHumanReadableBytes(max) : "n/a";
        return usedText + " / " + maxText;
    }

    private static String formatBytesPairWithPercent(long used, long max) {
        String paired = formatBytesPair(used, max);
        if (used < 0 || max <= 0) {
            return paired;
        }
        return paired + " (" + formatPercentOfMax(used, max) + ")";
    }

    private static String formatBytesWithPercentOf(long value, long max) {
        if (value < 0) {
            return "n/a";
        }
        if (max <= 0) {
            return formatHumanReadableBytes(value);
        }
        return formatHumanReadableBytes(value) + " (" + formatPercentOfMax(value, max) + ")";
    }

    private static String formatPercentOfMax(long numerator, long denominator) {
        double pct = (numerator * 100.0) / denominator;
        return DECIMAL_ONE.format(pct) + "%";
    }

    private static String formatIntPair(int live, int peak) {
        String liveText = live >= 0 ? formatWhole(live) : "n/a";
        String peakText = peak >= 0 ? formatWhole(peak) : "n/a";
        return liveText + " / " + peakText;
    }

    private static String formatDurationMsCompact(long millis) {
        long safe = Math.max(0L, millis);
        if (safe < 1_000L) {
            return formatWhole(safe) + " ms";
        }
        if (safe < 60_000L) {
            return DECIMAL_ONE.format(safe / 1_000.0) + " s";
        }
        return DECIMAL_ONE.format(safe / 60_000.0) + " m";
    }
}
