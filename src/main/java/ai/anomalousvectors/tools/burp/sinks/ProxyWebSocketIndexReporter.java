package ai.anomalousvectors.tools.burp.sinks;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
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
 * <ul>
 *   <li><b>Proxy History</b> ({@code proxy_history}): one-shot full {@code webSocketHistory()} export
 *       on Start, then stop.</li>
 *   <li><b>Proxy</b> ({@code proxy}): recurring diff poll (default 10s) of {@code webSocketHistory()}
 *       for frames after the last poll cursor; new frames are offered to
 *       {@link TrafficExportQueue}. The poll stops when export stops or {@code proxy} is deselected
 *       ({@link #refreshLivePollScheduleForCurrentState()}).</li>
 * </ul>
 *
 * <p>Non-proxy live WebSocket traffic uses {@link ToolWebSocketLiveHandler}.</p>
 */
public final class ProxyWebSocketIndexReporter {

    private static final int LIVE_POLL_INTERVAL_SECONDS = 10;
    private static final LazyScheduler HISTORIC_SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-websocket-historic");
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-websocket-reporter");
    private static final AtomicBoolean runInProgress = new AtomicBoolean();
    private static volatile int liveHistoryCursor;
    private static volatile String liveHistoryTailKey;
    private static final Object STARTUP_BACKLOG_LOCK = new Object();
    private static volatile StartupBacklogState startupBacklog;
    private static volatile ExportRunToken historicSnapshotRunToken;
    private static volatile boolean historicSnapshotRequested;
    private static volatile boolean historicSnapshotFinished;
    private static volatile boolean livePollRequested;

    private ProxyWebSocketIndexReporter() {}

    /**
     * Starts the recurring diff poll for live proxy WebSocket frames.
     *
     * <p>No-op unless export is ready, traffic export is enabled, and {@code proxy} is selected.
     * Does not run when only {@code proxy_history} is selected. When historic capture is also
     * selected, records the live-poll request but defers scheduler startup until the run-scoped
     * historic seed finishes. Safe to call from any thread and returns without waiting.</p>
     */
    public static void startLivePoll() {
        livePollRequested = true;
        ensureHistoricSnapshotStateForRun(RuntimeConfig.currentExportRunToken());
        if (trafficSelectionAllowsHistoricWebSockets() && !historicSnapshotFinished) {
            return;
        }
        if (!shouldRunLivePoll()) {
            return;
        }
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        SCHEDULER.startRecurring(
                () -> {
                    if (RuntimeConfig.isExportRunActive(token)) {
                        pushNewItemsOnly();
                    }
                },
                LIVE_POLL_INTERVAL_SECONDS,
                LIVE_POLL_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Reconciles the live diff poll with the current runtime traffic selection.
     *
     * <p>Safe to call from any thread. Stops the scheduler when export is stopped, traffic export is
     * disabled, or {@code proxy} is deselected. When {@code proxy_history} is selected during a run,
     * queues its sliced historic seed once and keeps live polling stopped until that seed
     * completes.</p>
     */
    public static void refreshLivePollScheduleForCurrentState() {
        if (!shouldRunLivePoll()) {
            stopLivePollScheduler();
            return;
        }
        livePollRequested = true;
        ensureHistoricSnapshotStateForRun(RuntimeConfig.currentExportRunToken());
        if (trafficSelectionAllowsHistoricWebSockets() && !historicSnapshotFinished) {
            pushHistoricSnapshotNow();
            return;
        }
        if (!SCHEDULER.isStarted()) {
            startLivePoll();
        }
    }

    /** Starts live polling when export state allows it (compat entry point for UI startup). */
    public static void startLivePollAfterCurrentHistorySeed(boolean ignoredIncludeWhenHistoricSelected) {
        if (!shouldRunLivePoll()) {
            stopLivePollScheduler();
            return;
        }
        startLivePoll();
    }

    /** Stops only the recurring poll scheduler. */
    public static void stopLivePollScheduler() {
        SCHEDULER.stop();
    }

    /** Stops schedulers and clears per-run poll cursor state. */
    public static void stop() {
        HISTORIC_SCHEDULER.stop();
        stopLivePollScheduler();
        liveHistoryCursor = 0;
        liveHistoryTailKey = null;
        runInProgress.set(false);
        livePollRequested = false;
        synchronized (STARTUP_BACKLOG_LOCK) {
            historicSnapshotRunToken = null;
            historicSnapshotRequested = false;
            historicSnapshotFinished = false;
            startupBacklog = null;
        }
    }

    static boolean shouldRunLivePoll() {
        return RuntimeConfig.isExportReady()
                && RuntimeConfig.isAnyTrafficExportEnabled()
                && trafficSelectionAllowsLiveProxyWebSocketPoll();
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

    private static void ensureHistoricSnapshotStateForRun(ExportRunToken token) {
        synchronized (STARTUP_BACKLOG_LOCK) {
            ensureHistoricSnapshotStateForRunLocked(token);
        }
    }

    private static void ensureHistoricSnapshotStateForRunLocked(ExportRunToken token) {
        if (Objects.equals(historicSnapshotRunToken, token)) {
            return;
        }
        historicSnapshotRunToken = token;
        historicSnapshotRequested = false;
        historicSnapshotFinished = false;
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
                TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
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
                            : ExportDocumentIdentity.prepare(
                                    indexName, TrafficRouteBucket.INDEX_KEY, doc);
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
     * <p>Only the matching active run advances the live-history cursor and enables live polling.</p>
     */
    private static void finishStartupBacklogLocked(StartupBacklogState state) {
        startupBacklog = null;
        if (!RuntimeConfig.isExportRunActive(state.token)) {
            return;
        }
        liveHistoryCursor = Math.max(liveHistoryCursor, state.history.size());
        liveHistoryTailKey = lastHistoryKey(state.history);
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
        if (!Objects.equals(historicSnapshotRunToken, state.token)) {
            return;
        }
        historicSnapshotFinished = true;
        if (livePollRequested) {
            startLivePoll();
        }
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

    static void pushNewItemsOnly() {
        try {
            if (!shouldRunLivePoll()) {
                stopLivePollScheduler();
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            pushItems(api, false);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            Logger.logWarnPanelOnly("[LiveTraffic] ProxyWebSocket: live poll failed: " + msg);
        }
    }

    private static void pushItems(MontoyaApi api, boolean pushAll) {
        if (!runInProgress.compareAndSet(false, true)) {
            return;
        }
        try {
            List<ProxyWebSocketMessage> history = safeWebSocketHistory(api);
            if (history == null || history.isEmpty()) {
                if (pushAll) {
                    TrafficStartupBacklogSummary.complete(
                            TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                            0,
                            SnapshotSummary.forRoute(TrafficRouteBucket.proxyWebSocket()),
                            RuntimeConfig.currentExportRunToken());
                }
                return;
            }
            if (pushAll) {
                pushHistoricSnapshotItems(api, history);
            } else {
                pushLivePollItems(api, history);
            }
        } finally {
            runInProgress.set(false);
        }
    }

    private static void pushHistoricSnapshotItems(MontoyaApi api, List<ProxyWebSocketMessage> history) {
        long startNs = System.nanoTime();
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocket();
        SnapshotSummary.Baseline baseline = SnapshotSummary.forRoute(route);
        Logger.logInfoPanelOnly("[StartupExport] ProxyWebSocket: exporting history backlog: "
                + history.size() + " frame(s).");
        SnapshotPacing.resetCountersForSnapshot();
        AtomicInteger processed = new AtomicInteger();

        String activeBaseUrl = RuntimeConfig.searchBaseUrl();
        String indexName = TrafficRouteBucket.trafficIndexName();
        String indexKey = TrafficRouteBucket.INDEX_KEY;
        boolean openSearchActive = RuntimeConfig.isSearchActive();
        int chunkTarget = SnapshotBatchTuning.initialTarget();
        int buildWorkers = SnapshotExportEngine.defaultBuildWorkers();
        SnapshotExportEngine.Result exportResult = SnapshotExportEngine.run(
                history,
                buildWorkers,
                BulkByteBudget.currentMaxBytes(),
                chunkTarget,
                SnapshotBatchTuning::applyLiveBackpressure,
                SnapshotBatchTuning.chunkTargetAdjuster(),
                activeBaseUrl,
                indexName,
                indexKey,
                msg -> {
                    if (!shouldRunHistoricSnapshot()) {
                        return null;
                    }
                    SnapshotPacing.paceItem(processed.getAndIncrement());
                    Map<String, Object> doc = buildDocument(api, msg);
                    if (doc == null) {
                        return null;
                    }
                    return ExportDocumentIdentity.prepare(indexName, indexKey, doc);
                },
                (chunk, outcome, nextChunkTarget) -> TrafficRouteBucket.recordBulkOutcome(
                        route,
                        outcome,
                        openSearchActive,
                        "Proxy WebSocket bulk push"));

        liveHistoryCursor = Math.max(liveHistoryCursor, history.size());
        liveHistoryTailKey = lastHistoryKey(history);
        long durationMs = (System.nanoTime() - startNs) / 1_000_000L;
        ExportStats.recordSnapshotLastRun(
                ExportStats.SNAPSHOT_PROXY_WEBSOCKET,
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
        Logger.logDebug(SnapshotPacing.summaryLine("ProxyWebSocket")
                + " attempted=" + exportResult.attempted()
                + " duration_ms=" + durationMs
                + " build_wall_ms=" + exportResult.buildWallMs()
                + " flush_ms=" + exportResult.flushMs());
        SnapshotSummary.logInfo(
                "ProxyWebSocket",
                baseline,
                exportResult.attempted(),
                durationMs,
                exportResult.buildWallMs(),
                exportResult.flushMs(),
                openSearchActive,
                RuntimeConfig.isAnyFileExportEnabled());
        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.PROXY_WEBSOCKET,
                exportResult.attempted(),
                baseline,
                RuntimeConfig.currentExportRunToken());
    }

    private static void pushLivePollItems(MontoyaApi api, List<ProxyWebSocketMessage> history) {
        String currentTailKey = lastHistoryKey(history);
        int startIndex;
        if (history.size() == liveHistoryCursor && Objects.equals(currentTailKey, liveHistoryTailKey)) {
            return;
        }
        if (liveHistoryCursor < 0 || liveHistoryCursor > history.size() || history.size() == liveHistoryCursor) {
            startIndex = 0;
        } else {
            startIndex = liveHistoryCursor;
        }
        int nextCursor = startIndex;
        for (int i = startIndex; i < history.size(); i++) {
            if (!shouldRunLivePoll()) {
                break;
            }
            ProxyWebSocketMessage msg = history.get(i);
            Map<String, Object> doc = buildDocument(api, msg);
            if (doc == null) {
                nextCursor = i + 1;
                continue;
            }
            if (TrafficExportQueue.offerAccepted(doc)) {
                nextCursor = i + 1;
            } else {
                break;
            }
        }
        liveHistoryCursor = nextCursor;
        liveHistoryTailKey = currentTailKey;
    }

    private static String lastHistoryKey(List<ProxyWebSocketMessage> history) {
        if (history == null || history.isEmpty()) {
            return null;
        }
        return messageKey(history.get(history.size() - 1));
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
                isEdited,
                wsTime,
                ws.annotations() != null && ws.annotations().hasNotes() ? ws.annotations().notes() : null,
                ws.annotations() != null && ws.annotations().hasHighlightColor()
                        ? (ws.annotations().highlightColor() == null ? null : ws.annotations().highlightColor().name())
                        : null));
    }

    static String messageKey(ProxyWebSocketMessage ws) {
        return ws.webSocketId() + ":" + ws.id();
    }

    static boolean trafficSelectionAllowsHistoricWebSockets() {
        List<String> trafficTypes = trafficToolTypes();
        return trafficTypes != null && trafficTypes.contains("proxy_history");
    }

    static boolean trafficSelectionAllowsLiveProxyWebSocketPoll() {
        List<String> trafficTypes = trafficToolTypes();
        return trafficTypes != null && trafficTypes.contains("proxy");
    }

    private static List<String> trafficToolTypes() {
        return RuntimeConfig.getState() == null ? null : RuntimeConfig.getState().trafficToolTypes();
    }

}
