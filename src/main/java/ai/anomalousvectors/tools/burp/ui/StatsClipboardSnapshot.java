package ai.anomalousvectors.tools.burp.ui;

import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler;
import ai.anomalousvectors.tools.burp.sinks.ProxyLiveMetadataCorrelator;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.SystemMetrics;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkRateLimitBackoff;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Builds the Stats panel clipboard text from live counters (no Swing table state).
 *
 * <p>Used by the shared Copy toolbar in {@link StatsPanel}. Session stop troubleshooting emits
 * file and miscellaneous single-line JSON INFO entries via {@link #logSessionStopSummary()}.
 * Database counts remain available in the database and are not read back during Stop.</p>
 *
 * <p>Counters are sampled independently, so output is a non-atomic operational snapshot rather
 * than a transactionally consistent view.</p>
 */
public final class StatsClipboardSnapshot {

    private static final ObjectMapper COMPACT_JSON = new ObjectMapper();
    private StatsClipboardSnapshot() {}

    /**
     * Returns clipboard-equivalent text: File Counts, Database Counts, and Misc Stats sections.
     *
     * <p>May run on the EDT or a background thread, provided no other method in this class is
     * executing concurrently.</p>
     *
     * @return plain-text snapshot matching {@link StatsPanel} Copy output for enabled destinations
     */
    public static String buildClipboardText() {
        StringBuilder sb = new StringBuilder(1024);
        if (isFileSectionEnabled()) {
            SinkCountTableSnapshot fileSnapshot = SinkCountTableSnapshot.file();
            sb.append("File Counts\n");
            sb.append(CardCopySupport.rowsToTsv(
                    fileSnapshot.columns().toArray(String[]::new), fileSnapshot.textRows()));
            sb.append('\n');
        }
        if (isDatabaseSectionEnabled()) {
            SinkCountTableSnapshot databaseSnapshot = SinkCountTableSnapshot.database();
            sb.append("Database Counts\n");
            sb.append(CardCopySupport.rowsToTsv(
                    databaseSnapshot.columns().toArray(String[]::new), databaseSnapshot.textRows()));
            sb.append('\n');
        }
        sb.append(CardCopySupport.sectionsToText("Misc Stats", buildMiscSections()));
        return sb.toString();
    }

    /**
     * Logs session-final file and miscellaneous Stats after final exporter stats are pushed.
     *
     * <p>May run on the Stop worker, provided no other method in this class is executing
     * concurrently. Emits INFO lines to the Log panel; JSON encoding failures are converted to a
     * WARN line and are not thrown.</p>
     */
    public static void logSessionStopSummary() {
        if (isFileSectionEnabled()) {
            logCompactJsonLine("file_counts", buildFileCountsPayload());
        }
        logCompactJsonLine("misc_stats", buildMiscStatsPayload());
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
        SinkCountTableSnapshot snapshot = SinkCountTableSnapshot.file();
        Map<String, Object> payload = new LinkedHashMap<>(2);
        payload.put("columns", snapshot.columns());
        payload.put("rows", snapshot.textRows());
        return payload;
    }


    private static Map<String, Object> buildMiscStatsPayload() {
        Map<String, Object> payload = new LinkedHashMap<>(1);
        payload.put("sections", buildMiscSections());
        return payload;
    }

    private static Map<String, Map<String, String>> buildMiscSections() {
        boolean fileVisible = isFileSectionEnabled();
        boolean openSearchVisible = isDatabaseSectionEnabled();
        Map<String, Map<String, String>> sections = new LinkedHashMap<>();
        sections.put("Overview", buildOverviewSection(fileVisible, openSearchVisible));
        sections.put("Process", buildProcessSection(SystemMetrics.snapshot()));
        if (openSearchVisible) {
            sections.put("Database Session", buildOpenSearchSessionSection());
            sections.put("Parameter Integrity", buildParameterIntegritySection());
            sections.put("Database Traffic", buildOpenSearchTrafficSection());
            sections.put("Database Retry", buildOpenSearchRetrySection());
            sections.put("Database Capacity", buildOpenSearchCapacitySection());
            sections.put("Database Run Peaks", buildOpenSearchRunPeaksSection());
        }
        if (RuntimeConfig.isAnyTrafficExportEnabled()) {
            sections.put("Traffic Spill", buildOpenSearchSpillSection());
            sections.put("Proxy Correlation", buildProxyCorrelationSection());
        }
        if (fileVisible) {
            sections.put("Files", buildFilesSection());
        }
        return sections;
    }

    private static Map<String, String> buildOverviewSection(boolean fileVisible, boolean openSearchVisible) {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Export Running", RuntimeConfig.isExportRunning() ? "Yes" : "No");
        if (openSearchVisible) {
            rows.put("Soft Outage", StatsPanelFormatters.formatSoftOutage(
                    IndexingRetryCoordinator.getInstance().isSoftCapacityOutage()));
            rows.put("Authorization Failures", StatsPanelFormatters.formatAuthorizationRecovery());
        }
        if (RuntimeConfig.isAnyTrafficExportEnabled()) {
            rows.put("Traffic Spill Status", StatsPanelFormatters.formatSpillStatus(
                    TrafficExportQueue.currentSpillStatus()));
        }
        if (openSearchVisible) {
            rows.put("Database Exported Size",
                    formatHumanReadableBytes(ExportStats.getTotalExportedBytes()));
        }
        if (fileVisible) {
            rows.put("Files Exported Size",
                    formatHumanReadableBytes(FileExportStats.getTotalExportedBytes()));
        }
        return rows;
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
                : StatsPanelFormatters.formatOneDecimal(snapshot.processCpuLoad() * 100.0) + "%");
        return rows;
    }

    private static Map<String, String> buildOpenSearchSessionSection() {
        long totalSuccess = ExportStats.getTotalSuccessCount();
        long totalFailure = ExportStats.getTotalFailureCount();
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Throughput (10s)",
                StatsPanelFormatters.formatOneDecimal(ExportStats.getThroughputDocsPerSecLast10s()) + " docs/s");
        rows.put("Exported Docs", formatWhole(totalSuccess) + " docs");
        rows.put("Exported Failures", formatWhole(totalFailure));
        rows.put("Count Basis", "Session counters; no Stop readback");
        rows.put("Last Success", StatsPanelFormatters.formatRelativeTime(ExportStats.getOpenSearchLastSuccessAtMs()));
        rows.put("Consecutive Failures", formatWhole(ExportStats.getOpenSearchConsecutiveFailures()));
        rows.put("Permanent Drops", formatWhole(ExportStats.getTotalPermanentDrops()));
        rows.put("Permanent Drop Reasons", StatsPanelFormatters.formatPermanentDropReasons());
        rows.put("Body Truncations", formatWhole(ExportStats.getSearchBodyPrefixTruncations()));
        rows.put("Body Truncations by Index", StatsPanelFormatters.formatBodyTruncationsByIndex());
        rows.put("Recovered Failures", formatWhole(ExportStats.getTotalRecoveredFailureCount()));
        rows.put("Retry Drain Pushes", formatWhole(ExportStats.getTotalRetryAttempts()));
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
                StatsPanelFormatters.formatOneDecimal(TrafficExportQueue.getCurrentSpillOldestAgeMs() / 1000.0));
        rows.put("Enqueued / Dequeued / Dropped",
                formatWhole(ExportStats.getTrafficSpillEnqueued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDequeued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDrops()));
        long spillRejectNew = ExportStats.getTrafficDropReasonCount("spill_full_reject_new")
                + ExportStats.getTrafficDropReasonCount("spill_low_disk_reject_new")
                + ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest")
                + ExportStats.getTrafficDropReasonCount("spill_low_disk_drop_oldest");
        rows.put("Drop Reasons",
                formatWhole(spillRejectNew) + " / "
                        + formatWhole(ExportStats.getTrafficDropReasonCount("spill_requeue_failed_drop")
                                + ExportStats.getTrafficDropReasonCount("spill_requeue_low_disk_drop")) + " / "
                        + formatWhole(ExportStats.getTrafficSpillExpiredPruned()));
        return rows;
    }

    private static Map<String, String> buildProxyCorrelationSection() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Proxy / HTTP Request Callbacks",
                formatWhole(ProxyLiveMetadataCorrelator.proxyRequestCallbacks())
                        + " / " + formatWhole(ProxyLiveMetadataCorrelator.httpProxyRequests()));
        rows.put("HTTP Marked / Responses",
                formatWhole(ProxyLiveMetadataCorrelator.httpMarkedRequests())
                        + " / " + formatWhole(ProxyLiveMetadataCorrelator.httpProxyResponses()));
        rows.put("Unmarked Tracked / Pre-Run",
                formatWhole(ProxyLiveMetadataCorrelator.httpUnmarkedTrackedResponses())
                        + " / " + formatWhole(
                                ProxyLiveMetadataCorrelator.httpUnmarkedUntrackedResponses()));
        rows.put("History Lookups / Matched Rows",
                formatWhole(ProxyLiveMetadataCorrelator.historyLookupAttempts())
                        + " / " + formatWhole(
                                ProxyLiveMetadataCorrelator.historyLookupMatchedRows()));
        rows.put("Pending Memory", formatWhole(ProxyLiveMetadataCorrelator.pendingMemoryCount())
                + " / " + StatsPanelFormatters.formatBytesHuman(
                        ProxyLiveMetadataCorrelator.pendingMemoryBytes()));
        rows.put("Pending Durable", formatWhole(ProxyLiveMetadataCorrelator.pendingDurableCount())
                + " / " + StatsPanelFormatters.formatBytesHuman(
                        ProxyLiveMetadataCorrelator.pendingDurableBytes()));
        rows.put("Bound / Eligible", formatWhole(ProxyLiveMetadataCorrelator.boundTotal())
                + " / " + formatWhole(ProxyLiveMetadataCorrelator.eligibleTotal()));
        rows.put("Durable Spool Total", formatWhole(ProxyLiveMetadataCorrelator.durableSpooledTotal()));
        rows.put("Lookup / Cleanup Failures", formatWhole(ProxyLiveMetadataCorrelator.lookupFailures())
                + " / " + formatWhole(ProxyLiveMetadataCorrelator.cleanupFailures()));
        rows.put("Spool / Explicit Failures", formatWhole(ProxyLiveMetadataCorrelator.spoolFailures())
                + " / " + formatWhole(ProxyLiveMetadataCorrelator.explicitFailures()));
        return rows;
    }

    private static Map<String, String> buildOpenSearchRetrySection() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Queue Depth", StatsPanelFormatters.formatRetryQueueDepthSummary());
        rows.put("Oldest Queued Age", StatsPanelFormatters.formatOldestQueuedAgeSummary());
        return rows;
    }

    private static Map<String, String> buildOpenSearchCapacitySection() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Bulk Byte Budget",
                StatsPanelFormatters.formatBytesHuman(StatsPanelFormatters.displayedBulkByteBudget()));
        rows.put("Snapshot Flush Cap", formatWhole(StatsPanelFormatters.displayedSnapshotFlushCap()));
        rows.put("Snapshot Build-Ahead", StatsPanelFormatters.formatSnapshotBuildAhead());
        rows.put("Cooldown Remaining", StatsPanelFormatters.formatCooldownRemaining(
                BulkRateLimitBackoff.remainingCooldownMs()));
        rows.put("Pressure Streak", formatWhole(BulkRateLimitBackoff.pressureStreak()));
        rows.put("Soft Outage Entries", formatWhole(ExportStats.getSoftOutageEntries()));
        rows.put("Capacity Events", formatWhole(ExportStats.getCapacityPressureEvents()));
        return rows;
    }

    private static Map<String, String> buildOpenSearchRunPeaksSection() {
        int peakChunkTarget = ExportStats.getPeakSnapshotChunkTarget();
        long peakFlushMs = ExportStats.getPeakSnapshotFlushMs();
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Peak Traffic Queue", StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakTrafficQueueDocs(), ExportStats.getPeakTrafficQueueBytes()));
        rows.put("Peak Traffic Spill", StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakSpillDocs(), ExportStats.getPeakSpillBytes()));
        rows.put("Peak Retry Queue", StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakRetryQueueDocs(), ExportStats.getPeakRetryQueueBytes()));
        rows.put("Peak Snapshot Chunk Target", peakChunkTarget > 0 ? formatWhole(peakChunkTarget) : "—");
        rows.put("Peak Snapshot Flush (ms)", peakFlushMs > 0 ? formatWhole(peakFlushMs) : "—");
        rows.put("Peak Snapshot Build-Ahead", StatsPanelFormatters.formatPeakSnapshotBuildAhead());
        long peakCooldownWaitMs = ExportStats.getPeakCooldownWaitMs();
        rows.put("Peak Cooldown Wait (ms)", peakCooldownWaitMs > 0 ? formatWhole(peakCooldownWaitMs) : "—");
        long peakFlushSlotWaitMs = ExportStats.getPeakFlushSlotWaitMs();
        rows.put("Peak Flush Slot Wait (ms)", peakFlushSlotWaitMs > 0 ? formatWhole(peakFlushSlotWaitMs) : "—");
        return rows;
    }

    private static Map<String, String> buildFilesSection() {
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("File Total Docs Exported", formatWhole(FileExportStats.getTotalSuccessCount()));
        rows.put("File Total Failures", formatWhole(FileExportStats.getTotalFailureCount()));
        return rows;
    }

    private static boolean isFileSectionEnabled() {
        return RuntimeConfig.isAnyFileExportEnabled();
    }

    private static boolean isDatabaseSectionEnabled() {
        var current = RuntimeConfig.getState();
        boolean configured = current != null && current.sinks() != null && current.sinks().databaseEnabled();
        return configured || RuntimeConfig.shouldRetainSearchStatsVisibility();
    }

    private static String formatWhole(long value) {
        return StatsPanelFormatters.formatWhole(value);
    }

    private static String formatHumanReadableBytes(long bytes) {
        return StatsPanelFormatters.formatBytesKbMbGb(bytes);
    }

    private static String formatBytesPairWithPercent(long used, long max) {
        return StatsPanelFormatters.formatBytesPairWithPercent(used, max);
    }

    private static String formatBytesWithPercentOf(long value, long max) {
        return StatsPanelFormatters.formatBytesWithPercentOf(value, max);
    }

    private static String formatIntPair(int live, int peak) {
        return StatsPanelFormatters.formatIntPair(live, peak);
    }

    private static String formatDurationMsCompact(long millis) {
        return StatsPanelFormatters.formatDurationMsCompact(millis);
    }
}
