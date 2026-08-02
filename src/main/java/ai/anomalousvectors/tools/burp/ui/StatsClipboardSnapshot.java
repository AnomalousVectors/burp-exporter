package ai.anomalousvectors.tools.burp.ui;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler;
import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
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
 * <p>This class is not thread-safe because its shared number formatter is mutable. Copy actions on
 * the EDT and Stop-summary generation on the Stop worker must be serialized and must not overlap.
 * Counters are sampled independently, so output is a non-atomic operational snapshot rather than
 * a transactionally consistent view.</p>
 */
public final class StatsClipboardSnapshot {

    private static final ObjectMapper COMPACT_JSON = new ObjectMapper();
    private static final String SUBROW_INDENT = "    ";
    private static final DecimalFormat DECIMAL_ONE =
            new DecimalFormat("0.0", DecimalFormatSymbols.getInstance(Locale.ROOT));

    private static final String[] FILE_COLUMNS =
            { "Index", "Written", "Failures", "Retry Attempts",
                    "Baseline", "Appended", "Final Size", "Integrity",
                    "Last Append (ms)", "Last Error" };
    private static final String[] OPEN_SEARCH_COLUMNS =
            { "Index", "Exported", "Failures", "Queued", "Recovered Failures",
                    "Retry Drops", "Permanent Drops", "Last Bulk (ms)", "Last Error" };

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
            sb.append("File Counts\n");
            sb.append(CardCopySupport.rowsToTsv(FILE_COLUMNS, buildFileCountRows()));
            sb.append('\n');
        }
        if (isDatabaseSectionEnabled()) {
            sb.append("Database Counts\n");
            sb.append(CardCopySupport.rowsToTsv(OPEN_SEARCH_COLUMNS, buildOpenSearchCountRows()));
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
        Map<String, Object> payload = new LinkedHashMap<>(2);
        payload.put("columns", List.of(FILE_COLUMNS));
        payload.put("rows", buildFileCountRows());
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
        long totalRetryAttempts = 0;
        long totalBaselineBytes = 0;
        long totalAppendedBytes = 0;
        long totalFinalBytes = 0;
        boolean anyArtifacts = false;
        boolean anyIntegrityFailure = false;
        boolean anyIntegrityPending = false;
        for (String indexKey : sortedKeys) {
            long written = FileExportStats.getWrittenCount(indexKey);
            long failure = FileExportStats.getFailureCount(indexKey);
            long retryAttempts = FileExportStats.getRetryAttemptCount(indexKey);
            long artifactCount = FileExportStats.getArtifactCount(indexKey);
            long baselineBytes = FileExportStats.getArtifactBaselineBytes(indexKey);
            long appendedBytes = FileExportStats.getExportedBytes(indexKey);
            long finalBytes = FileExportStats.getArtifactFinalBytes(indexKey);
            FileExportStats.ArtifactIntegrity integrity =
                    FileExportStats.getArtifactIntegrity(indexKey);
            boolean selected = artifactCount > 0L;
            long lastWriteMs = FileExportStats.getLastWriteDurationMs(indexKey);
            String lastWriteStr = lastWriteMs >= 0 ? String.valueOf(lastWriteMs) : "-";
            String lastError = FileExportStats.getLastError(indexKey);
            totalSuccess += written;
            totalFailure += failure;
            totalRetryAttempts += retryAttempts;
            totalBaselineBytes += baselineBytes;
            totalAppendedBytes += appendedBytes;
            totalFinalBytes += finalBytes;
            anyArtifacts |= selected;
            anyIntegrityFailure |= integrity == FileExportStats.ArtifactIntegrity.FAILED;
            anyIntegrityPending |= integrity == FileExportStats.ArtifactIntegrity.PENDING;
            rows.add(new String[] {
                    formatKeyLabel(indexKey),
                    formatWhole(written),
                    formatWhole(failure),
                    formatWhole(retryAttempts),
                    selected ? StatsPanelFormatters.formatBytesHuman(baselineBytes) : "-",
                    selected ? StatsPanelFormatters.formatBytesHuman(appendedBytes) : "-",
                    integrity == FileExportStats.ArtifactIntegrity.OK
                                    || integrity == FileExportStats.ArtifactIntegrity.FAILED
                            ? StatsPanelFormatters.formatBytesHuman(finalBytes)
                            : "-",
                    fileIntegrityLabel(integrity),
                    lastWriteStr,
                    lastError != null ? lastError : "-"
            });
            if ("traffic".equalsIgnoreCase(indexKey)) {
                appendFileTrafficSourceSubRows(rows);
            }
        }
        rows.add(new String[] {
                "Total",
                formatWhole(totalSuccess),
                formatWhole(totalFailure),
                formatWhole(totalRetryAttempts),
                anyArtifacts ? StatsPanelFormatters.formatBytesHuman(totalBaselineBytes) : "-",
                anyArtifacts ? StatsPanelFormatters.formatBytesHuman(totalAppendedBytes) : "-",
                !anyArtifacts || anyIntegrityPending
                        ? "-"
                        : StatsPanelFormatters.formatBytesHuman(totalFinalBytes),
                !anyArtifacts
                        ? "Not selected"
                        : anyIntegrityFailure ? "Failed" : anyIntegrityPending ? "Pending" : "OK",
                "-",
                "-"
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
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-"
            });
        }
    }

    private static String fileIntegrityLabel(FileExportStats.ArtifactIntegrity integrity) {
        return switch (integrity) {
            case PENDING -> "Pending";
            case OK -> "OK";
            case FAILED -> "Failed";
            case NOT_SELECTED -> "Not selected";
        };
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
        long totalRecovered = 0;
        for (String indexKey : sortedKeys) {
            long exported = countOverrides.getOrDefault(indexKey, ExportStats.getExportedCount(indexKey));
            int queued = ExportStats.getQueueSize(indexKey);
            long retryDrops = ExportStats.getRetryQueueDrops(indexKey);
            long permanentDrops = ExportStats.getPermanentDrops(indexKey);
            long failure = ExportStats.getFailureCount(indexKey);
            long recovered = ExportStats.getRecoveredFailureCount(indexKey);
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
            totalRecovered += recovered;
            rows.add(new String[] {
                    formatKeyLabel(indexKey),
                    formatWhole(exported),
                    formatWhole(failure),
                    formatWhole(queued),
                    formatWhole(recovered),
                    formatWhole(retryDrops),
                    formatWhole(permanentDrops),
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
                formatWhole(totalFailure),
                formatWhole(totalQueued),
                formatWhole(totalRecovered),
                formatWhole(totalRetryDrops),
                formatWhole(totalPermanentDrops),
                "-",
                "-"
        });
        return rows;
    }

    private static void appendOpenSearchTrafficSourceSubRows(List<String[]> rows) {
        for (String sourceKey : ExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            long sourceFailure = TrafficRouteBucket.resolveOpenSearchSourceFailure(sourceKey);
            long sourceRecovered = TrafficRouteBucket.resolveOpenSearchSourceRecovery(sourceKey);
            rows.add(new String[] {
                    SUBROW_INDENT + formatKeyLabel(sourceKey),
                    formatWhole(TrafficRouteBucket.resolveOpenSearchSourceSuccess(sourceKey)),
                    formatWhole(sourceFailure),
                    formatWhole(ExportStats.getTrafficDisplaySourceQueueSize(sourceKey)),
                    formatWhole(sourceRecovered),
                    formatWhole(TrafficRouteBucket.resolveOpenSearchSourceRetryQueueDrops(sourceKey)),
                    formatWhole(TrafficRouteBucket.resolveOpenSearchSourcePermanentDrops(sourceKey)),
                    "-",
                    "-"
            });
        }
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
            rows.put("Database Exported Size",
                    formatHumanReadableBytes(ExportStats.getTotalExportedBytes()));
        }
        if (fileVisible) {
            rows.put("Files Exported Size",
                    formatHumanReadableBytes(FileExportStats.getTotalExportedBytes()));
        }
        if (RuntimeConfig.isAnyTrafficExportEnabled()) {
            rows.put("Traffic Spill Status", StatsPanelFormatters.formatSpillStatus(
                    TrafficExportQueue.currentSpillStatus()));
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
                : DECIMAL_ONE.format(snapshot.processCpuLoad() * 100.0) + "%");
        return rows;
    }

    private static Map<String, String> buildOpenSearchSessionSection() {
        long totalSuccess = ExportStats.getTotalSuccessCount();
        long totalFailure = ExportStats.getTotalFailureCount();
        Map<String, String> rows = new LinkedHashMap<>();
        rows.put("Throughput (10s)", DECIMAL_ONE.format(ExportStats.getThroughputDocsPerSecLast10s()) + " docs/s");
        rows.put("Exported Docs", formatWhole(totalSuccess) + " docs");
        rows.put("Exported Failures", formatWhole(totalFailure));
        rows.put("Count Basis", "Session counters; no Stop readback");
        rows.put("Authorization Recovery", StatsPanelFormatters.formatAuthorizationRecovery());
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
                DECIMAL_ONE.format(TrafficExportQueue.getCurrentSpillOldestAgeMs() / 1000.0));
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
