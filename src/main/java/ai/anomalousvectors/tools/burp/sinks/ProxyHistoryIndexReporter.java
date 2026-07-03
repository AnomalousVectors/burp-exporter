package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.concurrent.EdtMonitor;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/**
 * Pushes Proxy History items to the traffic index once when Start is clicked and
 * "Proxy History" is selected. Runs in the background in batches; no recurring push.
 * For ongoing traffic after that, use Proxy. Respects scope (All / Burp / Custom).
 */
public final class ProxyHistoryIndexReporter {

    private static final String SCHEMA_VERSION = "1";
    private static final long BULK_MAX_BYTES = 5L * 1024 * 1024;

    /**
     * Single-owner scheduler for proxy-history snapshot work.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} the first time a snapshot is
     * scheduled and torn down deterministically by {@link #stop()} during UI stop or extension
     * unload. Matches the lazy/stop pattern used by every other reporter in this package.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-history-scheduler");

    private ProxyHistoryIndexReporter() {}

    /**
     * Stops the proxy-history scheduler so the extension unloads cleanly.
     *
     * <p>Safe to call from any thread and safe to call more than once. A subsequent
     * {@link #pushSnapshotNow()} lazily starts a fresh scheduler via {@link LazyScheduler}.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
    }

    /**
     * Schedules a one-time push of all current proxy history items (on Start), after a short delay.
     *
     * <p>Safe to call from any thread; work runs on a background thread. No-op if export is not
     * running, no sink is enabled, or PROXY_HISTORY is not selected.</p>
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnyTrafficExportEnabled()) {
                return;
            }
            List<String> trafficTypes = RuntimeConfig.getState().trafficToolTypes();
            if (trafficTypes == null || !trafficTypes.contains("proxy_history")) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.proxy() == null) {
                return;
            }
            MontoyaApi apiRef = api;
            SCHEDULER.getOrStart().execute(() -> {
                if (!RuntimeConfig.isExportRunning()) return;
                String activeBaseUrl = RuntimeConfig.openSearchUrl();
                pushItems(apiRef, activeBaseUrl);
            });
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] ProxyHistory: push failed: " + msg);
        }
    }

    /**
     * Pushes proxy-history items using bounded, streaming chunks.
     *
     * <p>Runs only on the reporter scheduler thread. This method avoids building the full
     * history payload in memory by flushing chunks when either doc-count or estimated payload
     * size thresholds are reached.</p>
     *
     * @param api Burp API reference
     * @param baseUrl OpenSearch base URL
     */
    private static void pushItems(MontoyaApi api, String baseUrl) {
        boolean openSearchActive = RuntimeConfig.isOpenSearchActive();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forRoute(route);
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (history == null || history.isEmpty()) {
            TrafficStartupBacklogSummary.complete(
                    TrafficStartupBacklogSummary.Component.PROXY_HISTORY,
                    0,
                    baseline);
            return;
        }

        long startNs = System.nanoTime();
        int chunkTarget = SnapshotBatchTuning.initialTarget();
        int buildWorkers = SnapshotExportEngine.defaultBuildWorkers();
        ExportStats.setCurrentProxyHistoryChunkTarget(chunkTarget);
        String trafficIndexName = TrafficRouteBucket.trafficIndexName();
        String trafficIndexKey = TrafficRouteBucket.INDEX_KEY;
        SnapshotScopeCache scopeCache = new SnapshotScopeCache(api);
        ConfigState.State state = RuntimeConfig.getState();
        AtomicInteger skippedScope = new AtomicInteger();

        // {@link EdtMonitor} captures stack traces when the EDT misses its tick deadline during
        // large snapshots. Completion is logged once via {@link SnapshotSummary#logInfo}.
        SnapshotPacing.resetCountersForSnapshot();
        EdtMonitor.start();
        try {
        long startGcMs = totalGcCollectionTimeMs();
        Logger.logInfoPanelOnly("[StartupExport] ProxyHistory: exporting backlog: " + history.size() + " item(s).");
        Logger.logDebug("[SnapshotExport] ProxyHistory: start wt=" + nowWallClock()
                + " items=" + history.size()
                + " initial_chunk_target=" + chunkTarget
                + " build_workers=" + buildWorkers
                + " heap_used_mib=" + heapUsedMib()
                + " gc_time_ms=" + startGcMs);

        SnapshotExportEngine.Result exportResult = SnapshotExportEngine.run(
                history,
                buildWorkers,
                BULK_MAX_BYTES,
                chunkTarget,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                baseUrl,
                trafficIndexName,
                trafficIndexKey,
                item -> {
                    Map<String, Object> doc = buildDocument(item, state, scopeCache, skippedScope);
                    if (doc == null) {
                        return null;
                    }
                    return ExportDocumentIdentity.prepare(trafficIndexName, trafficIndexKey, doc);
                },
                (chunk, outcome, nextChunkTarget) -> {
                    recordChunkOutcome(route, openSearchActive, outcome);
                    ExportStats.setCurrentProxyHistoryChunkTarget(nextChunkTarget);
                });

        long durationMs = (System.nanoTime() - startNs) / 1_000_000;
        ExportStats.recordProxyHistorySnapshot(
                exportResult.attempted(),
                exportResult.success(),
                durationMs,
                exportResult.finalChunkTarget(),
                exportResult.chunks(),
                exportResult.totalChunkBytes(),
                exportResult.buildWallMs(),
                exportResult.buildCpuMs(),
                exportResult.flushMs(),
                exportResult.fileFlushMs(),
                exportResult.openSearchFlushMs(),
                exportResult.buildWorkers());
        Logger.logDebug(SnapshotPacing.summaryLine("ProxyHistory")
                + " wt=" + nowWallClock()
                + " elapsed_ms=" + durationMs
                + " build_wall_ms=" + exportResult.buildWallMs()
                + " build_cpu_ms=" + exportResult.buildCpuMs()
                + " flush_ms=" + exportResult.flushMs()
                + " build_workers=" + exportResult.buildWorkers()
                + " chunks=" + exportResult.chunks());
        SnapshotSummary.logInfo(
                "ProxyHistory",
                baseline,
                exportResult.attempted(),
                durationMs,
                exportResult.buildWallMs(),
                exportResult.flushMs(),
                openSearchActive,
                RuntimeConfig.isAnyFileExportEnabled());
        int skippedScopeCount = skippedScope.get();
        if (skippedScopeCount > 0) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, skippedScopeCount);
        }
        Logger.logInfoPanelOnly("[SnapshotExport] ProxyHistory: backlog filters: seen="
                + history.size()
                + " exported=" + exportResult.attempted()
                + " skipped_scope=" + skippedScopeCount
                + " in " + durationMs + "ms.");
        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_HISTORY,
                exportResult.attempted(),
                baseline);
        } finally {
            EdtMonitor.stop();
            if (ExportStats.getCurrentProxyHistoryChunkTarget() >= 0) {
                ExportStats.clearCurrentProxyHistoryChunkTarget();
            }
        }
    }

    /**
     * Returns a worker-side wall-clock timestamp ({@code HH:mm:ss.SSS}) captured on the calling
     * thread. Embedded into snapshot diagnostic log lines so we can compute the EDT delivery lag by
     * comparing this value with the {@code [yyyy-MM-dd HH:mm:ss]} prefix that the LogPanel
     * appends when it renders the entry on the EDT.
     */
    private static String nowWallClock() {
        return EdtMonitor.WallClock.format(System.currentTimeMillis());
    }

    private static long totalGcCollectionTimeMs() {
        long sum = 0L;
        try {
            for (var bean : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) {
                long t = bean.getCollectionTime();
                if (t > 0L) {
                    sum += t;
                }
            }
        } catch (RuntimeException ignored) {
            // Fall through with whatever we accumulated.
        }
        return sum;
    }

    private static long heapUsedMib() {
        Runtime rt = Runtime.getRuntime();
        long bytes = rt.totalMemory() - rt.freeMemory();
        return bytes / (1024L * 1024L);
    }

    private static void recordChunkOutcome(
            TrafficRouteBucket.Route route,
            boolean openSearchActive,
            BulkPushOutcome outcome) {
        TrafficRouteBucket.recordBulkOutcome(
                route, outcome, openSearchActive, "Proxy history chunk");
    }

    private static ProxyHistoryWorkItem toWorkItem(
            ProxyHttpRequestResponse item,
            ConfigState.State state,
            SnapshotScopeCache scopeCache,
            AtomicInteger skippedScope) {
        if (item == null) {
            return null;
        }
        HttpRequest request = item.finalRequest();
        if (request == null) {
            return null;
        }
        HttpService service = item.httpService();
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        String url = RequestResponseDocBuilder.buildBestEffortUrl(request, service, requestDoc, "ProxyHistory");
        boolean burpInScope = scopeCache.isInScope(url);
        if (!ScopeFilter.shouldExport(state, url, burpInScope)) {
            skippedScope.incrementAndGet();
            return null;
        }
        return new ProxyHistoryWorkItem(item, service, requestDoc, url, burpInScope);
    }

    private static Map<String, Object> buildDocument(
            ProxyHttpRequestResponse item,
            ConfigState.State state,
            SnapshotScopeCache scopeCache,
            AtomicInteger skippedScope) {
        ProxyHistoryWorkItem work = toWorkItem(item, state, scopeCache, skippedScope);
        return buildDocument(work);
    }

    private static Map<String, Object> buildDocument(ProxyHistoryWorkItem work) {
        if (work == null) {
            return null;
        }
        ProxyHttpRequestResponse item = work.item();
        HttpRequest request = item.finalRequest();
        if (request == null) {
            return null;
        }
        HttpService service = work.service();
        Map<String, Object> requestDoc = work.requestDoc();
        String url = work.url();
        boolean burpInScope = work.burpInScope();
        requestDoc.put("url", HttpMessageDocSupport.urlObject(url, service));
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));

        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy History");
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", item.id());
        burp.put("proxy", BurpProxyFields.forProxyHistory(item));
        burp.put("timing", BurpTimingFields.fromProxyHistory(item));
        BurpAnnotationFields.put(burp, item.annotations());
        document.put("burp", burp);
        document.put("request", requestDoc);

        HttpResponse response = item.response();
        if (response != null) {
            document.put("response", RequestResponseDocBuilder.buildTrafficResponseDoc(response));
        } else {
            document.put("response", RequestResponseDocBuilder.emptyTrafficResponseDoc());
        }
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());

        document.put("meta", ExportMetaFields.meta(
                SCHEMA_VERSION));

        // HTTP docs from Proxy History are not websocket messages.
        return document;
    }

    private record ProxyHistoryWorkItem(
            ProxyHttpRequestResponse item,
            HttpService service,
            Map<String, Object> requestDoc,
            String url,
            boolean burpInScope) {
    }
}
