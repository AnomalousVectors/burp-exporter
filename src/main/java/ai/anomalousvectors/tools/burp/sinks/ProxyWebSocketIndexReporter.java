package ai.anomalousvectors.tools.burp.sinks;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotPacing;
import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;

/**
 * Exports Burp Proxy WebSocket history frames ({@link ProxyWebSocketMessage}) to the traffic index.
 *
 * <p>This reporter owns only the one-shot {@code proxy_history} snapshot. Live Proxy frames use
 * {@link ProxyWebSocketLiveHandler}; live non-Proxy frames use {@link ToolWebSocketLiveHandler}.</p>
 */
public final class ProxyWebSocketIndexReporter {

    private static final Object STARTUP_BACKLOG_LOCK = new Object();
    private static volatile StartupBacklogState startupBacklog;
    private static volatile ExportRunToken historicSnapshotRunToken;
    private static volatile boolean historicSnapshotRequested;

    private ProxyWebSocketIndexReporter() {}

    /** Clears per-run historic-snapshot state. */
    public static void stop() {
        synchronized (STARTUP_BACKLOG_LOCK) {
            historicSnapshotRunToken = null;
            historicSnapshotRequested = false;
            startupBacklog = null;
        }
    }

    private static boolean shouldRunHistoricSnapshot() {
        return RuntimeConfig.isExportReady()
                && RuntimeConfig.isAnyTrafficExportEnabled()
                && trafficSelectionAllowsHistoricWebSockets();
    }

    /**
     * Requests one export-run-scoped snapshot of all selected proxy WebSocket history.
     *
     * <p>Safe to call from any thread. The method submits cooperative background slices and
     * returns without waiting. Repeated calls in the same run are ignored; failures are logged
     * without propagating to the caller.</p>
     */
    public static void pushHistoricSnapshotNow() {
        try {
            if (!shouldRunHistoricSnapshot()) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            MontoyaApi apiRef = api;
            ExportRunToken token = RuntimeConfig.currentExportRunToken();
            synchronized (STARTUP_BACKLOG_LOCK) {
                ensureHistoricSnapshotStateForRunLocked(token);
                if (historicSnapshotRequested) {
                    return;
                }
                historicSnapshotRequested = true;
                // Last in the ordered startup queue (after Findings, Sitemap, Proxy History).
                StartupSnapshotCoordinator.submit(
                        StartupSnapshotCoordinator.Lane.PROXY_WEBSOCKET,
                        token,
                        "ProxyWebSocket",
                        () -> runStartupBacklogSlice(apiRef, token));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[SnapshotExport] ProxyWebSocket: historic snapshot failed: " + msg);
        }
    }

    private static void ensureHistoricSnapshotStateForRunLocked(ExportRunToken token) {
        if (Objects.equals(historicSnapshotRunToken, token)) {
            return;
        }
        historicSnapshotRunToken = token;
        historicSnapshotRequested = false;
        startupBacklog = null;
    }

    /**
     * Runs one token-scoped proxy WebSocket startup slice.
     *
     * <p>State selection and offset changes occur under {@link #STARTUP_BACKLOG_LOCK}; document
     * preparation and delivery run outside the lock. State identity and run activity are checked
     * again before results are committed.</p>
     */
    private static void runStartupBacklogSlice(MontoyaApi api, ExportRunToken token) {
        if (!RuntimeConfig.isExportRunActive(token)) {
            return;
        }
        StartupBacklogState state;
        List<ProxyWebSocketMessage> slice;
        int sliceStart;
        synchronized (STARTUP_BACKLOG_LOCK) {
            state = startupBacklog;
            if (state == null) {
                List<ProxyWebSocketMessage> history = safeWebSocketHistory(api);
                List<ProxyWebSocketMessage> captured =
                        Collections.unmodifiableList(new ArrayList<>(history));
                TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocketHistory();
                state = new StartupBacklogState(
                        captured,
                        route,
                        SnapshotSummary.forRoute(route),
                        token);
                startupBacklog = state;
                Logger.logInfoPanelOnly("[StartupExport] ProxyWebSocket: exporting history backlog: "
                        + captured.size() + " frame(s) with adaptive startup slices.");
                SnapshotPacing.resetCountersForSnapshot();
            }
            if (state.offset >= state.history.size()) {
                finishStartupBacklogLocked(state);
                return;
            }
            int sliceTarget = StartupSnapshotCoordinator.nextSliceItemCount(
                    StartupSnapshotCoordinator.Lane.PROXY_WEBSOCKET);
            sliceStart = state.offset;
            int end = Math.min(state.offset + sliceTarget, state.history.size());
            slice = state.history.subList(state.offset, end);
        }

        long sliceStartedNanos = System.nanoTime();
        SnapshotExportEngine.Result result = exportStartupSlice(api, state, slice);
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
                StartupSnapshotCoordinator.Lane.PROXY_WEBSOCKET,
                "ProxyWebSocket",
                sliceStart,
                slice.size(),
                result.totalChunkBytes(),
                elapsedMs,
                more);
        if (more) {
            StartupSnapshotCoordinator.submit(
                    StartupSnapshotCoordinator.Lane.PROXY_WEBSOCKET,
                    token,
                    "ProxyWebSocket",
                    () -> runStartupBacklogSlice(api, token));
        }
    }

    private static SnapshotExportEngine.Result exportStartupSlice(
            MontoyaApi api,
            StartupBacklogState state,
            List<ProxyWebSocketMessage> slice) {
        String indexName = TrafficRouteBucket.trafficIndexName();
        AtomicInteger processed = new AtomicInteger();
        return SnapshotExportEngine.run(
                state.token,
                slice,
                SnapshotExportEngine.defaultBuildWorkers(),
                BulkByteBudget.currentMaxBytes(),
                state.finalChunkTarget > 0
                        ? state.finalChunkTarget
                        : SnapshotBatchTuning.initialTarget(),
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                RuntimeConfig.searchBaseUrl(),
                indexName,
                TrafficRouteBucket.INDEX_KEY,
                msg -> {
                    if (!RuntimeConfig.isExportRunActive(state.token)) {
                        return null;
                    }
                    SnapshotPacing.paceItem(processed.getAndIncrement());
                    Map<String, Object> doc = buildDocument(api, msg);
                    return doc == null
                            ? null
                            : ExportDocumentIdentity.prepareWithTrafficRoute(
                                    indexName,
                                    TrafficRouteBucket.INDEX_KEY,
                                    doc,
                                    state.route.key());
                },
                (chunk, outcome, nextChunkTarget) -> TrafficRouteBucket.recordBulkOutcome(
                        state.route,
                        outcome,
                        RuntimeConfig.isSearchActive(),
                        "Proxy WebSocket bulk push"));
    }

    /**
     * Finalizes startup state while {@link #STARTUP_BACKLOG_LOCK} is held.
     *
     * <p>Only an active run records the snapshot result and completes startup accounting.</p>
     */
    private static void finishStartupBacklogLocked(StartupBacklogState state) {
        startupBacklog = null;
        if (!RuntimeConfig.isExportRunActive(state.token)) {
            return;
        }
        long durationMs = (System.nanoTime() - state.startNs) / 1_000_000L;
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_PROXY_WEBSOCKET,
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
                "ProxyWebSocket",
                state.baseline,
                state.attempted,
                durationMs,
                state.buildWallMs,
                state.flushMs,
                RuntimeConfig.isSearchActive(),
                RuntimeConfig.isAnyFileExportEnabled());
        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                state.attempted,
                state.baseline,
                state.token);
    }

    /**
     * Mutable aggregate owned by the serialized proxy WebSocket coordinator lane.
     *
     * <p>References and offsets are guarded by {@link #STARTUP_BACKLOG_LOCK}; one coordinator
     * slice at a time updates the accumulated result fields.</p>
     */
    private static final class StartupBacklogState {
        private final List<ProxyWebSocketMessage> history;
        private final TrafficRouteBucket.Route route;
        private final SnapshotSummary.Baseline baseline;
        private final ExportRunToken token;
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
                List<ProxyWebSocketMessage> history,
                TrafficRouteBucket.Route route,
                SnapshotSummary.Baseline baseline,
                ExportRunToken token) {
            this.history = history;
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

    static List<ProxyWebSocketMessage> safeWebSocketHistory(MontoyaApi api) {
        try {
            if (api == null) {
                return List.of();
            }
            var proxy = api.proxy();
            if (proxy == null) {
                return List.of();
            }
            List<ProxyWebSocketMessage> history = proxy.webSocketHistory();
            return history != null ? history : List.of();
        } catch (Throwable ignored) {
            return List.of();
        }
    }

    static Map<String, Object> buildDocument(MontoyaApi api, ProxyWebSocketMessage ws) {
        if (ws == null) {
            return null;
        }
        HttpRequest upgrade = ws.upgradeRequest();
        ZonedDateTime t = ws.time();
        String wsTime = t == null ? null : t.toInstant().toString();
        ByteArray payload = ws.payload();
        ByteArray edited = ws.editedPayload();
        byte[] editedBytes = edited == null ? null : edited.getBytes();
        boolean isEdited = editedBytes != null;
        byte[] payloadBytes = isEdited
                ? editedBytes
                : (payload == null ? null : payload.getBytes());
        return WebSocketTrafficDocumentBuilder.build(new WebSocketTrafficDocumentBuilder.Input(
                api,
                upgrade,
                "ProxyWebSocket",
                "Proxy WebSocket",
                ws.id(),
                ws.listenerPort(),
                ws.webSocketId(),
                ws.id(),
                ws.direction() == null ? null : ws.direction().name(),
                payloadBytes,
                null,
                isEdited,
                null,
                wsTime,
                ws.annotations() != null && ws.annotations().hasNotes() ? ws.annotations().notes() : null,
                ws.annotations() != null && ws.annotations().hasHighlightColor()
                        ? (ws.annotations().highlightColor() == null ? null : ws.annotations().highlightColor().name())
                        : null));
    }

    static boolean trafficSelectionAllowsHistoricWebSockets() {
        List<String> trafficTypes = trafficToolTypes();
        return trafficTypes != null && trafficTypes.contains("proxy_history");
    }

    private static List<String> trafficToolTypes() {
        return RuntimeConfig.getState() == null ? null : RuntimeConfig.getState().trafficToolTypes();
    }

}
