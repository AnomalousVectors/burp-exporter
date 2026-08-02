package ai.anomalousvectors.tools.burp.sinks;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.Collections;
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
import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
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
    private static final Object STARTUP_BACKLOG_LOCK = new Object();
    private static volatile StartupBacklogState startupBacklog;

    /**
     * Reporter-local scheduler retained for deterministic lifecycle cleanup.
     *
     * <p>Startup backlog slices run through {@link StartupSnapshotCoordinator}; {@link #stop()}
     * also terminates any reporter-local work owned by this scheduler.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-history-scheduler");

    private ProxyHistoryIndexReporter() {}

    /**
     * Stops the proxy-history scheduler so the extension unloads cleanly.
     *
     * <p>Safe to call from any thread and safe to call more than once. Also discards the
     * coordinator-backed startup state so a late slice cannot resume the stopped backlog.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
        synchronized (STARTUP_BACKLOG_LOCK) {
            startupBacklog = null;
        }
    }

    /**
     * Schedules a one-time push of all current proxy history items on Start.
     *
     * <p>Safe to call from any thread; work runs in cooperative background slices through
     * {@link StartupSnapshotCoordinator}. No-op if export is not running, no sink is enabled, or
     * {@code proxy_history} is not selected.</p>
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
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            // After Findings/Sitemap on the ordered startup queue (ConfigPanel submission order).
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.PROXY_HISTORY,
                    token,
                    "ProxyHistory",
                    () -> runStartupBacklogSlice(apiRef, token));
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] ProxyHistory: push failed: " + msg);
        }
    }

    /**
     * Runs one token-scoped Proxy History startup slice.
     *
     * <p>State selection and offset changes occur under {@link #STARTUP_BACKLOG_LOCK}; document
     * preparation and delivery run outside the lock. The state identity and run token are checked
     * again before results are committed so Stop or a later run cannot accept stale completion.</p>
     */
    private static void runStartupBacklogSlice(MontoyaApi api, ExportRunToken token) {
        if (!RuntimeConfig.isExportRunActive(token)) {
            return;
        }
        StartupBacklogState state;
        List<ProxyHttpRequestResponse> slice;
        int sliceStart;
        synchronized (STARTUP_BACKLOG_LOCK) {
            state = startupBacklog;
            if (state == null) {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                List<ProxyHttpRequestResponse> captured = history == null
                        ? List.of()
                        : Collections.unmodifiableList(new ArrayList<>(history));
                TrafficRouteBucket.Route route = TrafficRouteBucket.proxyHistorySnapshot();
                state = new StartupBacklogState(
                        captured,
                        RuntimeConfig.getState(),
                        new SnapshotScopeCache(api),
                        route,
                        SnapshotSummary.forRoute(route),
                        token);
                startupBacklog = state;
                Logger.logInfoPanelOnly("[StartupExport] ProxyHistory: exporting backlog: "
                        + captured.size() + " item(s) with adaptive startup slices.");
                SnapshotPacing.resetCountersForSnapshot();
            }
            if (state.offset >= state.history.size()) {
                finishStartupBacklogLocked(state);
                return;
            }
            int sliceTarget = StartupSnapshotCoordinator.nextSliceItemCount(
                    StartupSnapshotCoordinator.Lane.PROXY_HISTORY);
            sliceStart = state.offset;
            int end = Math.min(state.offset + sliceTarget, state.history.size());
            slice = state.history.subList(state.offset, end);
        }

        EdtMonitor.start();
        SnapshotExportEngine.Result result;
        long sliceStartedNanos = System.nanoTime();
        try {
            result = exportStartupSlice(state, slice);
        } finally {
            EdtMonitor.stop();
        }
        long elapsedMs = (System.nanoTime() - sliceStartedNanos) / 1_000_000L;
        boolean more;
        synchronized (STARTUP_BACKLOG_LOCK) {
            if (startupBacklog != state || !RuntimeConfig.isExportRunActive(token)) {
                return;
            }
            state.add(result);
            state.offset += slice.size();
            more = state.offset < state.history.size();
            if (!more) {
                finishStartupBacklogLocked(state);
            }
        }
        StartupSnapshotCoordinator.recordSliceOutcome(
                StartupSnapshotCoordinator.Lane.PROXY_HISTORY,
                "ProxyHistory",
                sliceStart,
                slice.size(),
                result.totalChunkBytes(),
                elapsedMs,
                more);
        if (more) {
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.PROXY_HISTORY,
                    token,
                    "ProxyHistory",
                    () -> runStartupBacklogSlice(api, token));
        }
    }

    private static SnapshotExportEngine.Result exportStartupSlice(
            StartupBacklogState state,
            List<ProxyHttpRequestResponse> slice) {
        String trafficIndexName = TrafficRouteBucket.trafficIndexName();
        int chunkTarget = state.finalChunkTarget > 0
                ? state.finalChunkTarget
                : SnapshotBatchTuning.initialTarget();
        ExportStats.setCurrentProxyHistoryChunkTarget(chunkTarget);
        return SnapshotExportEngine.run(
                state.token,
                slice,
                SnapshotExportEngine.defaultBuildWorkers(),
                BulkByteBudget.currentMaxBytes(),
                chunkTarget,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                RuntimeConfig.searchBaseUrl(),
                trafficIndexName,
                TrafficRouteBucket.INDEX_KEY,
                item -> {
                    Map<String, Object> doc =
                            buildDocument(item, state.config, state.scopeCache, state.skippedScope);
                    return doc == null
                            ? null
                            : ExportDocumentIdentity.prepare(
                                    trafficIndexName, TrafficRouteBucket.INDEX_KEY, doc);
                },
                (chunk, outcome, nextChunkTarget) -> {
                    recordChunkOutcome(state.route, RuntimeConfig.isSearchActive(), outcome);
                    ExportStats.setCurrentProxyHistoryChunkTarget(nextChunkTarget);
                });
    }

    /**
     * Finalizes the current startup backlog while {@link #STARTUP_BACKLOG_LOCK} is held.
     */
    private static void finishStartupBacklogLocked(StartupBacklogState state) {
        startupBacklog = null;
        ExportStats.clearCurrentProxyHistoryChunkTarget();
        if (!RuntimeConfig.isExportRunActive(state.token)) {
            return;
        }
        long durationMs = (System.nanoTime() - state.startNs) / 1_000_000L;
        ExportStats.recordProxyHistorySnapshot(
                state.attempted,
                state.success,
                durationMs,
                state.finalChunkTarget,
                state.chunks,
                state.totalChunkBytes,
                state.buildWallMs,
                state.buildCpuMs,
                state.flushMs,
                state.fileFlushMs,
                state.openSearchFlushMs,
                state.buildWorkers);
        SnapshotSummary.logInfo(
                "ProxyHistory",
                state.baseline,
                state.attempted,
                durationMs,
                state.buildWallMs,
                state.flushMs,
                RuntimeConfig.isSearchActive(),
                RuntimeConfig.isAnyFileExportEnabled());
        int skipped = state.skippedScope.get();
        if (skipped > 0) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, skipped);
        }
        Logger.logInfoPanelOnly("[SnapshotExport] ProxyHistory: backlog filters: seen="
                + state.history.size() + " exported=" + state.attempted
                + " skipped_scope=" + skipped + " in " + durationMs + "ms.");
        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_HISTORY,
                state.attempted,
                state.baseline,
                state.token);
    }

    /**
     * Mutable aggregate owned by the serialized coordinator lane.
     *
     * <p>References and offsets are guarded by {@link #STARTUP_BACKLOG_LOCK}; one coordinator
     * slice at a time updates the accumulated result fields.</p>
     */
    private static final class StartupBacklogState {
        private final List<ProxyHttpRequestResponse> history;
        private final ConfigState.State config;
        private final SnapshotScopeCache scopeCache;
        private final TrafficRouteBucket.Route route;
        private final SnapshotSummary.Baseline baseline;
        private final ExportRunToken token;
        private final AtomicInteger skippedScope = new AtomicInteger();
        private final long startNs = System.nanoTime();
        private int offset;
        private int attempted;
        private int success;
        private int chunks;
        private long totalChunkBytes;
        private long buildWallMs;
        private long buildCpuMs;
        private long flushMs;
        private long fileFlushMs;
        private long openSearchFlushMs;
        private int finalChunkTarget;
        private int buildWorkers;

        private StartupBacklogState(
                List<ProxyHttpRequestResponse> history,
                ConfigState.State config,
                SnapshotScopeCache scopeCache,
                TrafficRouteBucket.Route route,
                SnapshotSummary.Baseline baseline,
                ExportRunToken token) {
            this.history = history;
            this.config = config;
            this.scopeCache = scopeCache;
            this.route = route;
            this.baseline = baseline;
            this.token = token;
        }

        private void add(SnapshotExportEngine.Result result) {
            attempted += result.attempted();
            success += result.success();
            chunks += result.chunks();
            totalChunkBytes += result.totalChunkBytes();
            buildWallMs += result.buildWallMs();
            buildCpuMs += result.buildCpuMs();
            flushMs += result.flushMs();
            fileFlushMs += result.fileFlushMs();
            openSearchFlushMs += result.openSearchFlushMs();
            finalChunkTarget = result.finalChunkTarget();
            buildWorkers = result.buildWorkers();
        }
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
