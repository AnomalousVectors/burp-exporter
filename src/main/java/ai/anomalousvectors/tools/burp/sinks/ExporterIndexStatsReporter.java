package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.SystemMetrics;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotFlushExecutor;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Periodically pushes exporter stats snapshots to the Exporter index.
 *
 * <p>Started when export startup reaches the exporter-stats phase; runs on a single daemon
 * scheduler. Snapshots are emitted only while export is running, the {@code exporter} source is
 * enabled, the {@code stats} sub-option is selected, and at least one sink is active. The
 * interval is read from {@link RuntimeConfig#exporterStatsIntervalSeconds()} so UI changes can
 * reschedule the reporter without restarting the extension.</p>
 *
 * <p>Delivery is fire-and-forget: failures are not pushed back into the Exporter index to avoid
 * feedback loops. Set {@link #ENABLED} to {@code false} to disable the reporter for diagnostics or
 * focused testing.</p>
 *
 * <p>{@code stats_snapshot} {@code event.data} uses a nested layout ({@code jvm}, {@code export},
 * {@code indexes}, {@code traffic}, {@code stats}, optional {@code proxy_history_last_run}).
 * Attribution maps include only non-zero counters; file attribution is omitted when file export is
 * off; failure attribution is omitted when traffic has no failures.</p>
 */
public final class ExporterIndexStatsReporter {

    /** When false, no scheduler is started and no documents are pushed. */
    public static final boolean ENABLED = true;

    /** OpenSearch field path for {@code event.data.export.running} on stats snapshots. */
    public static final String EXPORTER_FINAL_RUNNING_FIELD = "event.data.export.running";

    private static final String SCHEMA_VERSION = "1";
    private static final String EVENT_TYPE = "stats_snapshot";

    /**
     * Single-owner scheduler for the periodic exporter-stats push.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} on {@link #start()} and torn down
     * by {@link #stop()} during UI stop or extension unload. Recreated on the next
     * {@link #start()} when {@link #refreshScheduleForCurrentState()} detects an interval change.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-stats");
    private static volatile int scheduledIntervalSeconds = ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS;
    private static volatile String lastPeriodicFailureDetail;

    private ExporterIndexStatsReporter() {}

    /**
     * Pushes one stats snapshot immediately while export is running.
     *
     * <p>Safe to call from any thread. Returns immediately when export is stopped, the exporter
     * stats sub-option is disabled, or no sink is enabled. This is an on-demand push, not the
     * scheduled periodic ticker.</p>
     */
    public static void pushSnapshotNow() {
        if (!ENABLED) {
            return;
        }
        pushSnapshotInternal(SnapshotPushKind.ON_DEMAND);
    }

    /**
     * Pushes a final stats snapshot at export Stop with {@code event.data.export.running=false}.
     *
     * <p>Bypasses the export-running gate and the retry coordinator {@code isExportReady} check
     * via {@link OpenSearchClientWrapper#pushDocumentDuringShutdown}. Returns a skip outcome when
     * exporter stats are disabled or no sink is enabled.</p>
     *
     * @return push outcome for logging at Stop or unload
     */
    public static ExporterStatsPushOutcome pushFinalSnapshotNow() {
        if (!ENABLED) {
            return ExporterStatsPushOutcome.skippedDisabled();
        }
        return pushSnapshotInternal(SnapshotPushKind.FINAL);
    }

    /**
     * Returns whether a final stats snapshot should be attempted on extension unload.
     *
     * <p>True only while an export run is still active and unload must substitute for normal Stop.
     * A completed Stop already wrote its final snapshot; writing another during a later extension
     * unload could auto-create a deleted Exporter index with destination defaults.</p>
     *
     * @return {@code true} when {@link #pushFinalSnapshotNow()} is worth attempting before pool close
     */
    public static boolean shouldAttemptFinalPushOnUnload() {
        if (!ENABLED
                || !RuntimeConfig.isExportRunning()
                || !RuntimeConfig.isExporterStatsEnabled()) {
            return false;
        }
        if (!RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_EXPORTER)) {
            return false;
        }
        if (!RuntimeConfig.isAnySinkEnabled()) {
            return false;
        }
        for (String key : ExportStats.getIndexKeys()) {
            if (ExportStats.getExportedCount(key) > 0) {
                return true;
            }
        }
        return ExportStats.getDocsBodyEnumerationMisgateSuspect() > 0
                || ExportStats.getDocsWireBodyParamsReplaced() > 0
                || ExportStats.getDocsSupplementalBodyParamsUsed() > 0;
    }

    /**
     * Starts the periodic stats reporter if not already running.
     *
     * <p>Safe to call from any thread. Uses a single daemon scheduler and the current runtime
     * interval from {@link RuntimeConfig#exporterStatsIntervalSeconds()}. Returns immediately when
     * {@link #ENABLED} is {@code false} or exporter stats are disabled.</p>
     */
    public static void start() {
        if (!ENABLED || SCHEDULER.isStarted() || !RuntimeConfig.isExporterStatsEnabled()) {
            return;
        }
        synchronized (ExporterIndexStatsReporter.class) {
            if (SCHEDULER.isStarted() || !RuntimeConfig.isExporterStatsEnabled()) {
                return;
            }
            int intervalSeconds = RuntimeConfig.exporterStatsIntervalSeconds();
            RuntimeConfig.ExportRunToken token = RuntimeConfig.currentExportRunToken();
            SCHEDULER.getOrStart().scheduleAtFixedRate(
                    () -> {
                        if (RuntimeConfig.isExportRunActive(token)) {
                            pushPeriodicSnapshot();
                        }
                    },
                    intervalSeconds,
                    intervalSeconds,
                    TimeUnit.SECONDS);
            scheduledIntervalSeconds = intervalSeconds;
        }
    }

    /**
     * Stops the periodic stats scheduler.
     *
     * <p>Safe to call from any thread. The next {@link #start()} call creates a fresh scheduler.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
        lastPeriodicFailureDetail = null;
    }

    /**
     * Reconciles the scheduler with the current runtime exporter configuration.
     *
     * <p>Safe to call from any thread. Stops the scheduler when exporter stats are disabled or
     * export is stopped, starts it when newly enabled, and recreates it when the interval changes.</p>
     */
    public static void refreshScheduleForCurrentState() {
        if (!RuntimeConfig.isExportRunning() || !RuntimeConfig.isExporterStatsEnabled()) {
            stop();
            return;
        }
        int currentIntervalSeconds = RuntimeConfig.exporterStatsIntervalSeconds();
        if (!SCHEDULER.isStarted()) {
            start();
            return;
        }
        if (scheduledIntervalSeconds != currentIntervalSeconds) {
            stop();
            start();
        }
    }

    private static void pushPeriodicSnapshot() {
        pushSnapshotInternal(SnapshotPushKind.PERIODIC);
    }

    /**
     * Distinguishes scheduled periodic stats pushes from on-demand and Stop-time finals.
     */
    private enum SnapshotPushKind {
        PERIODIC,
        ON_DEMAND,
        FINAL
    }

    private static ExporterStatsPushOutcome pushSnapshotInternal(SnapshotPushKind kind) {
        boolean finalSnapshot = kind == SnapshotPushKind.FINAL;
        try {
            if (!finalSnapshot && !RuntimeConfig.isExportRunning()) {
                return ExporterStatsPushOutcome.skippedDisabled();
            }
            if (!finalSnapshot && ExportAdmissionController.shouldPauseExporterNonFinal()) {
                return ExporterStatsPushOutcome.skippedDisabled();
            }
            if (!RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_EXPORTER) || !RuntimeConfig.isExporterStatsEnabled()) {
                return ExporterStatsPushOutcome.skippedDisabled();
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return ExporterStatsPushOutcome.skippedNoSink();
            }
            String baseUrl = RuntimeConfig.searchBaseUrl();
            boolean openSearchActive = RuntimeConfig.isSearchActive();
            String indexName = RuntimeConfig.indexNameForKey("exporter");
            Map<String, Object> doc = buildSnapshotDoc(finalSnapshot);
            OpenSearchClientWrapper.ShutdownDocumentPushResult pushResult;
            if (finalSnapshot) {
                pushResult = OpenSearchClientWrapper.pushDocumentDuringShutdown(
                        baseUrl, indexName, "exporter", doc, true);
            } else {
                boolean ok = OpenSearchClientWrapper.pushDocument(
                        baseUrl, indexName, "exporter", doc);
                pushResult = new OpenSearchClientWrapper.ShutdownDocumentPushResult(
                        ok, ok ? null : (openSearchActive ? "OpenSearch push returned false" : "file sink write failed"));
            }
            boolean ok = pushResult.success();
            SingleDocOutcomeRecorder.record("exporter", ok, openSearchActive,
                    "Exporter stats snapshot push failed");
            if (!ok) {
                String reason = pushResult.resolvedFailureDetail();
                if (finalSnapshot || shouldLogPeriodicFailure(openSearchActive, reason)) {
                    Logger.logWarnPanelOnly(statsFailurePrefix(kind)
                            + "Exporter stats: push failed"
                            + " index=" + indexName
                            + " reason=" + reason + ".");
                }
                return ExporterStatsPushOutcome.failed(reason);
            }
            lastPeriodicFailureDetail = null;
            return ExporterStatsPushOutcome.success();
        } catch (RuntimeException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (finalSnapshot || shouldLogPeriodicFailure(RuntimeConfig.isSearchActive(), msg)) {
                Logger.logWarnPanelOnly(statsFailurePrefix(kind)
                        + "Exporter stats: push failed"
                        + " reason=" + msg + ".");
            }
            return ExporterStatsPushOutcome.failed(msg);
        }
    }

    private static String statsFailurePrefix(SnapshotPushKind kind) {
        return kind == SnapshotPushKind.PERIODIC
                ? "[PeriodicExport] "
                : "[SnapshotExport] ";
    }

    private static boolean shouldLogPeriodicFailure(boolean openSearchActive, String reason) {
        if (!openSearchActive) {
            return false;
        }
        String normalized = reason == null || reason.isBlank() ? "unknown" : reason;
        if (normalized.equals(lastPeriodicFailureDetail)) {
            return false;
        }
        lastPeriodicFailureDetail = normalized;
        return true;
    }

    private static Map<String, Object> buildSnapshotDoc(boolean finalSnapshot) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("jvm", buildJvmSection(SystemMetrics.snapshot()));
        data.put("export", buildExportSection(finalSnapshot));
        data.put("indexes", buildIndexesSection(finalSnapshot));
        data.put("traffic", buildTrafficSection());
        data.put("stats", buildStatsSection());
        Map<String, Object> snapshotLastRuns = buildSnapshotLastRunsSection();
        if (!snapshotLastRuns.isEmpty()) {
            data.put("snapshot_last_runs", snapshotLastRuns);
        }
        ExportStats.SnapshotLastRunStats proxySnapshot = ExportStats.getLastProxyHistorySnapshot();
        if (proxySnapshot != null) {
            data.put("proxy_history_last_run", buildSnapshotLastRunSection(proxySnapshot));
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("level", "INFO");
        event.put("source", "burp-exporter");
        event.put("thread", Thread.currentThread().getName());
        event.put("type", EVENT_TYPE);
        event.put("data", data);
        event.put("summary", EVENT_TYPE);
        doc.put("event", event);
        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    private static Map<String, Object> buildJvmSection(SystemMetrics.Snapshot sys) {
        Map<String, Object> jvm = new LinkedHashMap<>();
        jvm.put("heap_used_bytes", sys.heapUsedBytes());
        if (sys.heapCommittedBytes() >= 0) {
            jvm.put("heap_committed_bytes", sys.heapCommittedBytes());
        }
        jvm.put("heap_max_bytes", sys.heapMaxBytes());
        if (sys.nonHeapUsedBytes() >= 0) {
            jvm.put("non_heap_used_bytes", sys.nonHeapUsedBytes());
        }
        if (sys.nonHeapMaxBytes() >= 0) {
            jvm.put("non_heap_max_bytes", sys.nonHeapMaxBytes());
        }
        if (sys.directBufferUsedBytes() >= 0) {
            jvm.put("direct_buffer_used_bytes", sys.directBufferUsedBytes());
        }
        if (sys.mappedBufferUsedBytes() >= 0) {
            jvm.put("mapped_buffer_used_bytes", sys.mappedBufferUsedBytes());
        }
        if (sys.threadCount() >= 0) {
            jvm.put("thread_count", sys.threadCount());
        }
        if (sys.peakThreadCount() >= 0) {
            jvm.put("peak_thread_count", sys.peakThreadCount());
        }
        if (!Double.isNaN(sys.processCpuLoad())) {
            jvm.put("process_cpu_load", sys.processCpuLoad());
        }
        long gcCount = sys.gcCollectionCount();
        if (gcCount >= 0) {
            jvm.put("gc_collection_count", gcCount);
        }
        long gcTimeMs = sys.gcCollectionTimeMs();
        if (gcTimeMs >= 0) {
            jvm.put("gc_collection_time_ms", gcTimeMs);
        }
        return jvm;
    }

    private static Map<String, Object> buildExportSection(boolean finalSnapshot) {
        Map<String, Object> export = new LinkedHashMap<>();
        boolean exportRunning = !finalSnapshot && RuntimeConfig.isExportRunning();
        export.put("running", exportRunning);
        export.put("batch_size", ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController.getInstance()
                .getCurrentBatchSize());
        export.put("throughput_docs_per_sec_60", ExportStats.getThroughputDocsPerSecLast60s());
        long startToFirstTrafficMs = ExportStats.getStartToFirstTrafficMs();
        if (startToFirstTrafficMs >= 0) {
            export.put("start_to_first_traffic_ms", startToFirstTrafficMs);
        }
        int lastBulkTarget = ExportStats.getLastBulkTargetBatch();
        if (lastBulkTarget >= 0) {
            export.put("bulk_target_batch_last", lastBulkTarget);
        }
        int lastBulkAttempted = ExportStats.getLastBulkAttemptedDocs();
        if (lastBulkAttempted >= 0) {
            export.put("bulk_attempted_docs_last", lastBulkAttempted);
        }
        return export;
    }

    private static Map<String, Object> buildIndexesSection(boolean finalSnapshot) {
        Map<String, Object> indexes = new LinkedHashMap<>();
        for (String key : ExportStats.getIndexKeys()) {
            Map<String, Object> index = new LinkedHashMap<>();
            long exported = exportedCountForSnapshot(key, finalSnapshot);
            index.put("exported", exported);
            index.put("count", exported);
            index.put("bytes", ExportStats.getExportedBytes(key));
            long failures = ExportStats.getFailureCount(key);
            if (failures > 0) {
                index.put("failures", failures);
            }
            long bodyTruncations = ExportStats.getSearchBodyPrefixTruncations(key);
            if (bodyTruncations > 0) {
                index.put("body_truncations", bodyTruncations);
            }
            if (RuntimeConfig.isAnyFileExportEnabled()) {
                long written = FileExportStats.getWrittenCount(key);
                if (written > 0) {
                    index.put("file_written", written);
                }
                long fileFailures = FileExportStats.getFailureCount(key);
                if (fileFailures > 0) {
                    index.put("file_failures", fileFailures);
                }
                long fileRetryAttempts = FileExportStats.getRetryAttemptCount(key);
                if (fileRetryAttempts > 0) {
                    index.put("file_retry_attempts", fileRetryAttempts);
                }
            }
            indexes.put(key, index);
        }
        return indexes;
    }

    private static long exportedCountForSnapshot(String key, boolean finalSnapshot) {
        long exported = ExportStats.getExportedCount(key);
        if (finalSnapshot && "exporter".equals(key) && RuntimeConfig.isSearchActive()) {
            return exported + 1L;
        }
        return exported;
    }

    private static Map<String, Object> buildTrafficSection() {
        Map<String, Object> traffic = new LinkedHashMap<>();
        traffic.put("queue_size", TrafficExportQueue.getCurrentSize());
        traffic.put("queue_bytes_estimate", TrafficExportQueue.getCurrentBytesEstimate());
        traffic.put("active_drain_batches", TrafficExportQueue.getActiveDrainBatches());
        traffic.put("queue_drops", ExportStats.getTrafficQueueDrops());
        traffic.put("spill", buildTrafficSpillSection());
        traffic.put("proxy_correlation", buildProxyCorrelationSection());
        long fallbackHits = ExportStats.getTrafficToolSourceFallbacks();
        if (fallbackHits > 0) {
            traffic.put("tool_source_fallback_hits", fallbackHits);
        }
        long lastBulkMs = ExportStats.getLastLiveBulkDurationMs("traffic");
        if (lastBulkMs >= 0) {
            traffic.put("last_live_bulk_duration_ms", lastBulkMs);
        }
        Map<String, Object> lastBulkShape = buildLastLiveBulkShapeSection();
        if (!lastBulkShape.isEmpty()) {
            traffic.put("last_live_bulk_shape", lastBulkShape);
        }
        Map<String, Object> attribution = buildTrafficAttribution();
        if (!attribution.isEmpty()) {
            traffic.put("attribution", attribution);
        }
        return traffic;
    }

    private static Map<String, Object> buildProxyCorrelationSection() {
        Map<String, Object> correlation = new LinkedHashMap<>();
        correlation.put("proxy_request_callbacks", ProxyLiveMetadataCorrelator.proxyRequestCallbacks());
        correlation.put("http_proxy_requests", ProxyLiveMetadataCorrelator.httpProxyRequests());
        correlation.put("http_marked_requests", ProxyLiveMetadataCorrelator.httpMarkedRequests());
        correlation.put("http_proxy_responses", ProxyLiveMetadataCorrelator.httpProxyResponses());
        correlation.put(
                "http_unmarked_tracked_responses",
                ProxyLiveMetadataCorrelator.httpUnmarkedTrackedResponses());
        correlation.put(
                "http_unmarked_prerun_responses",
                ProxyLiveMetadataCorrelator.httpUnmarkedUntrackedResponses());
        correlation.put("history_lookup_attempts", ProxyLiveMetadataCorrelator.historyLookupAttempts());
        correlation.put(
                "history_lookup_matched_rows",
                ProxyLiveMetadataCorrelator.historyLookupMatchedRows());
        correlation.put("eligible_total", ProxyLiveMetadataCorrelator.eligibleTotal());
        correlation.put("bound_total", ProxyLiveMetadataCorrelator.boundTotal());
        correlation.put("pending_memory_count", ProxyLiveMetadataCorrelator.pendingMemoryCount());
        correlation.put("pending_memory_bytes", ProxyLiveMetadataCorrelator.pendingMemoryBytes());
        correlation.put("pending_durable_count", ProxyLiveMetadataCorrelator.pendingDurableCount());
        correlation.put("pending_durable_bytes", ProxyLiveMetadataCorrelator.pendingDurableBytes());
        correlation.put("durable_spooled_total", ProxyLiveMetadataCorrelator.durableSpooledTotal());
        correlation.put("lookup_failures", ProxyLiveMetadataCorrelator.lookupFailures());
        correlation.put("cleanup_failures", ProxyLiveMetadataCorrelator.cleanupFailures());
        correlation.put("spool_failures", ProxyLiveMetadataCorrelator.spoolFailures());
        correlation.put("explicit_failures", ProxyLiveMetadataCorrelator.explicitFailures());
        return correlation;
    }

    private static Map<String, Object> buildTrafficSpillSection() {
        Map<String, Object> spill = new LinkedHashMap<>();
        spill.put("count", TrafficExportQueue.getCurrentSpillSize());
        spill.put("bytes", TrafficExportQueue.getCurrentSpillBytes());
        spill.put("oldest_age_ms", TrafficExportQueue.getCurrentSpillOldestAgeMs());
        spill.put("recovered_count", TrafficExportQueue.getRecoveredSpillCount());
        spill.put("recovered_bytes", TrafficExportQueue.getRecoveredSpillBytes());
        return spill;
    }

    private static Map<String, Object> buildLastLiveBulkShapeSection() {
        Map<String, Object> shape = new LinkedHashMap<>();
        int targetBatch = ExportStats.getLastBulkTargetBatch();
        if (targetBatch >= 0) {
            shape.put("target_batch", targetBatch);
        }
        int attemptedDocs = ExportStats.getLastBulkAttemptedDocs();
        if (attemptedDocs >= 0) {
            shape.put("attempted_docs", attemptedDocs);
        }
        return shape;
    }

    private static Map<String, Object> buildTrafficAttribution() {
        Map<String, Object> attribution = new LinkedHashMap<>();
        boolean includeFailures = ExportStats.getFailureCount("traffic") > 0;
        if (RuntimeConfig.isSearchActive()) {
            Map<String, Object> openSearch = buildSinkAttribution(
                    ExportStats::getTrafficSourceSuccessCount,
                    ExportStats::getTrafficSourceFailureCount,
                    ExportStats::getTrafficToolTypeSuccessCount,
                    ExportStats::getTrafficToolTypeFailureCount,
                    includeFailures);
            if (!openSearch.isEmpty()) {
                attribution.put("opensearch", openSearch);
            }
        }
        if (RuntimeConfig.isAnyFileExportEnabled()) {
            Map<String, Object> file = buildSinkAttribution(
                    FileExportStats::getTrafficSourceSuccessCount,
                    FileExportStats::getTrafficSourceFailureCount,
                    FileExportStats::getTrafficToolTypeSuccessCount,
                    FileExportStats::getTrafficToolTypeFailureCount,
                    includeFailures);
            if (!file.isEmpty()) {
                attribution.put("file", file);
            }
        }
        return attribution;
    }

    private static Map<String, Object> buildSinkAttribution(
            Function<String, Long> sourceSuccess,
            Function<String, Long> sourceFailure,
            Function<String, Long> toolTypeSuccess,
            Function<String, Long> toolTypeFailure,
            boolean includeFailures) {
        Map<String, Object> sink = new LinkedHashMap<>();
        Map<String, Object> sources = sparseCounts(ExportStats.getTrafficSourceKeys(), sourceSuccess);
        if (!sources.isEmpty()) {
            sink.put("source", sources);
        }
        Map<String, Object> toolTypes = sparseCounts(ExportStats.getTrafficToolTypeKeys(), toolTypeSuccess);
        if (!toolTypes.isEmpty()) {
            sink.put("tool_type", toolTypes);
        }
        if (includeFailures) {
            Map<String, Object> sourceFailures = sparseCounts(ExportStats.getTrafficSourceKeys(), sourceFailure);
            if (!sourceFailures.isEmpty()) {
                sink.put("source_failures", sourceFailures);
            }
            Map<String, Object> toolTypeFailures = sparseCounts(ExportStats.getTrafficToolTypeKeys(), toolTypeFailure);
            if (!toolTypeFailures.isEmpty()) {
                sink.put("tool_type_failures", toolTypeFailures);
            }
        }
        return sink;
    }

    private static Map<String, Object> buildStatsSection() {
        Map<String, Object> stats = new LinkedHashMap<>();
        long retryDrops = ExportStats.getTotalRetryQueueDrops();
        if (retryDrops > 0) {
            stats.put("retry_queue_drops_total", retryDrops);
        }
        long permanentDrops = ExportStats.getTotalPermanentDrops();
        if (permanentDrops > 0) {
            stats.put("permanent_drops_total", permanentDrops);
        }
        Map<String, Long> permanentDropReasons = ExportStats.getPermanentDropReasonCounts();
        if (!permanentDropReasons.isEmpty()) {
            stats.put("permanent_drop_reason_counts", permanentDropReasons);
        }
        long retryAttempts = ExportStats.getTotalRetryAttempts();
        if (retryAttempts > 0) {
            stats.put("retry_drain_pushes_total", retryAttempts);
        }
        long synthesizedDropped = ExportStats.getSynthesizedBodyParamsDropped();
        if (synthesizedDropped > 0) {
            stats.put("synthesized_body_params_dropped_total", synthesizedDropped);
        }
        long bodyParamsDropped = ExportStats.getBodyParamsDroppedTotal();
        if (bodyParamsDropped > 0) {
            stats.put("body_params_dropped_total", bodyParamsDropped);
        }
        long docsBodyTruncated = ExportStats.getDocsBodyParamsTruncated();
        if (docsBodyTruncated > 0) {
            stats.put("docs_with_body_params_truncated_total", docsBodyTruncated);
        }
        long misgateSuspects = ExportStats.getDocsBodyEnumerationMisgateSuspect();
        if (misgateSuspects > 0) {
            stats.put("docs_body_enumeration_misgate_suspect_total", misgateSuspects);
        }
        long skippedBodyEnumeration = ExportStats.getDocsWithSkippedBodyEnumeration();
        if (skippedBodyEnumeration > 0) {
            stats.put("docs_with_skipped_body_enumeration_total", skippedBodyEnumeration);
        }
        long wireReplaced = ExportStats.getDocsWireBodyParamsReplaced();
        if (wireReplaced > 0) {
            stats.put("docs_wire_body_params_replaced_total", wireReplaced);
        }
        long wireDropped = ExportStats.getWireBodyParamsDroppedTotal();
        if (wireDropped > 0) {
            stats.put("wire_body_params_dropped_total", wireDropped);
        }
        long supplementalUsed = ExportStats.getDocsSupplementalBodyParamsUsed();
        if (supplementalUsed > 0) {
            stats.put("docs_supplemental_body_params_used_total", supplementalUsed);
        }
        long supplementalRejected = ExportStats.getDocsSupplementalRejectedNonForm();
        if (supplementalRejected > 0) {
            stats.put("docs_supplemental_rejected_non_form_total", supplementalRejected);
        }
        long skipRescued = ExportStats.getDocsSkipPathBodyRescued();
        if (skipRescued > 0) {
            stats.put("docs_skip_path_body_rescued_total", skipRescued);
        }
        Map<String, Object> bodyParamsSourceCounts = sparseLongCounts(ExportStats.getBodyParamsSourceCounts());
        if (!bodyParamsSourceCounts.isEmpty()) {
            stats.put("body_params_source_counts", bodyParamsSourceCounts);
        }
        Map<String, Object> bodyParamsSkipReasonCounts = sparseLongCounts(ExportStats.getBodyParamsSkipReasonCounts());
        if (!bodyParamsSkipReasonCounts.isEmpty()) {
            stats.put("body_params_skip_reason_counts", bodyParamsSkipReasonCounts);
        }
        Map<String, Object> bodyParamsEncodingCounts = sparseLongCounts(ExportStats.getBodyParamsEncodingCounts());
        if (!bodyParamsEncodingCounts.isEmpty()) {
            stats.put("body_params_encodings_counts", bodyParamsEncodingCounts);
        }
        Map<String, Object> repeaterSources = sparseRepeaterMetadataSources();
        if (!repeaterSources.isEmpty()) {
            stats.put("repeater_live_metadata_sources", repeaterSources);
        }
        stats.put("snapshot_flush_executor", buildSnapshotFlushExecutorSection());
        stats.put("snapshot_build_ahead", buildSnapshotBuildAheadSection());
        Map<String, Object> runPeaks = buildRunPeaksSection();
        if (!runPeaks.isEmpty()) {
            stats.put("run_peaks", runPeaks);
        }
        return stats;
    }

    private static Map<String, Object> buildSnapshotBuildAheadSection() {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("current_reserved_bytes", ExportStats.getSnapshotBuildAheadReservedBytes());
        section.put("current_reserved_permits", ExportStats.getSnapshotBuildAheadReservedPermits());
        section.put("peak_reserved_bytes", ExportStats.getPeakSnapshotBuildAheadReservedBytes());
        section.put("peak_reserved_permits", ExportStats.getPeakSnapshotBuildAheadReservedPermits());
        section.put("capacity_bytes", SnapshotExportEngine.maxBuildAheadBytes());
        section.put("capacity_permits", SnapshotExportEngine.maxBuildAheadPermits());
        return section;
    }

    private static Map<String, Object> buildRunPeaksSection() {
        Map<String, Object> peaks = new LinkedHashMap<>();
        int peakTrafficDocs = ExportStats.getPeakTrafficQueueDocs();
        long peakTrafficBytes = ExportStats.getPeakTrafficQueueBytes();
        if (peakTrafficDocs > 0 || peakTrafficBytes > 0) {
            peaks.put("traffic_queue_docs", peakTrafficDocs);
            peaks.put("traffic_queue_bytes", peakTrafficBytes);
        }
        int peakSpillDocs = ExportStats.getPeakSpillDocs();
        long peakSpillBytes = ExportStats.getPeakSpillBytes();
        if (peakSpillDocs > 0 || peakSpillBytes > 0) {
            peaks.put("spill_docs", peakSpillDocs);
            peaks.put("spill_bytes", peakSpillBytes);
        }
        int peakRetryDocs = ExportStats.getPeakRetryQueueDocs();
        long peakRetryBytes = ExportStats.getPeakRetryQueueBytes();
        if (peakRetryDocs > 0 || peakRetryBytes > 0) {
            peaks.put("retry_queue_docs", peakRetryDocs);
            peaks.put("retry_queue_bytes", peakRetryBytes);
        }
        int peakChunkTarget = ExportStats.getPeakSnapshotChunkTarget();
        if (peakChunkTarget > 0) {
            peaks.put("snapshot_chunk_target", peakChunkTarget);
        }
        long peakFlushMs = ExportStats.getPeakSnapshotFlushMs();
        if (peakFlushMs > 0) {
            peaks.put("snapshot_flush_ms", peakFlushMs);
        }
        return peaks;
    }

    private static Map<String, Object> buildSnapshotFlushExecutorSection() {
        SnapshotFlushExecutor.Snapshot snapshot = SnapshotFlushExecutor.stats();
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("flush", buildExecutorPoolSection(snapshot.flush()));
        section.put("dual_sink", buildExecutorPoolSection(snapshot.dualSink()));
        return section;
    }

    private static Map<String, Object> buildExecutorPoolSection(SnapshotFlushExecutor.PoolStats stats) {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("pool_size", stats.poolSize());
        section.put("active_count", stats.activeCount());
        section.put("queue_size", stats.queueSize());
        section.put("task_count", stats.taskCount());
        section.put("completed_task_count", stats.completedTaskCount());
        return section;
    }

    private static Map<String, Object> sparseRepeaterMetadataSources() {
        Map<String, Object> sources = new LinkedHashMap<>();
        for (String key : ExportStats.getRepeaterMetadataSourceKeys()) {
            long count = ExportStats.getRepeaterMetadataSourceCount(key);
            if (count > 0) {
                sources.put(key, count);
            }
        }
        return sources;
    }

    private static Map<String, Object> buildSnapshotLastRunsSection() {
        Map<String, Object> runs = new LinkedHashMap<>();
        for (String reporterKey : ExportStats.getSnapshotReporterKeys()) {
            ExportStats.SnapshotLastRunStats snapshot = ExportStats.getSnapshotLastRun(reporterKey);
            if (snapshot != null) {
                runs.put(reporterKey, buildSnapshotLastRunSection(snapshot));
            }
        }
        return runs;
    }

    private static Map<String, Object> buildSnapshotLastRunSection(ExportStats.SnapshotLastRunStats snapshot) {
        Map<String, Object> run = new LinkedHashMap<>();
        run.put("attempted", snapshot.attempted());
        run.put("success", snapshot.success());
        run.put("duration_ms", snapshot.durationMs());
        run.put("docs_per_sec", snapshot.docsPerSecond());
        run.put("final_chunk_target", snapshot.finalChunkTarget());
        if (snapshot.chunks() > 0) {
            run.put("chunks", snapshot.chunks());
            run.put("avg_chunk_docs", snapshot.avgChunkDocs());
            run.put("avg_chunk_bytes", snapshot.avgChunkBytes());
        }
        if (snapshot.buildWallMs() >= 0L) {
            run.put("build_wall_ms", snapshot.buildWallMs());
        }
        if (snapshot.buildCpuMs() >= 0L) {
            run.put("build_cpu_ms", snapshot.buildCpuMs());
        }
        if (snapshot.flushMs() >= 0L) {
            run.put("flush_ms", snapshot.flushMs());
        }
        if (snapshot.fileFlushMs() >= 0L) {
            run.put("file_flush_ms", snapshot.fileFlushMs());
        }
        if (snapshot.openSearchFlushMs() >= 0L) {
            run.put("search_flush_ms", snapshot.openSearchFlushMs());
        }
        if (snapshot.buildWorkers() > 0) {
            run.put("build_workers", snapshot.buildWorkers());
        }
        return run;
    }

    private static Map<String, Object> sparseCounts(List<String> keys, Function<String, Long> valueForKey) {
        Map<String, Object> counts = new LinkedHashMap<>();
        for (String key : keys) {
            long value = valueForKey.apply(key);
            if (value > 0) {
                counts.put(key, value);
            }
        }
        return counts;
    }

    private static Map<String, Object> sparseLongCounts(Map<String, Long> counts) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (counts == null || counts.isEmpty()) {
            return out;
        }
        for (Map.Entry<String, Long> entry : counts.entrySet()) {
            if (entry.getValue() != null && entry.getValue() > 0) {
                out.put(entry.getKey(), entry.getValue());
            }
        }
        return out;
    }

}
