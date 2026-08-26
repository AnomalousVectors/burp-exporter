package ai.anomalousvectors.tools.burp.sinks;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
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
 *       for frames after the run's asynchronously captured baseline; new frames are offered to
 *       {@link TrafficExportQueue}. The poll stops when export stops or {@code proxy} is
 *       deselected ({@link #refreshLivePollScheduleForCurrentState()}).</li>
 * </ul>
 *
 * <p>Non-proxy live WebSocket traffic uses {@link ToolWebSocketLiveHandler}.</p>
 */
public final class ProxyWebSocketIndexReporter {

    private static final int LIVE_POLL_INTERVAL_SECONDS = 10;
    private static final LazyScheduler BASELINE_SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-websocket-baseline");
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-proxy-websocket-reporter");
    private static final AtomicBoolean runInProgress = new AtomicBoolean();
    private static volatile int liveHistoryCursor;
    private static volatile String liveHistoryTailKey;
    private static final Object LIVE_BASELINE_LOCK = new Object();
    private static volatile ExportRunToken liveBaselineRunToken;
    private static volatile boolean liveBaselineRequested;
    private static volatile boolean liveBaselineFinished;
    private static volatile long liveBaselineGeneration;
    private static final Object STARTUP_BACKLOG_LOCK = new Object();
    private static volatile StartupBacklogState startupBacklog;
    private static volatile ExportRunToken historicSnapshotRunToken;
    private static volatile boolean historicSnapshotRequested;
    private static volatile boolean historicSnapshotFinished;
    private static volatile boolean livePollRequested;

    private ProxyWebSocketIndexReporter() {}

    /**
     * Starts live proxy WebSocket capture after establishing the current history boundary.
     *
     * <p>No-op unless export is ready, traffic export is enabled, and {@code proxy} is selected.
     * Does not run when only {@code proxy_history} is selected. With live-only capture, the
     * existing history boundary is captured off the caller thread and skipped. When historic
     * capture is also selected, the live poll starts from the completed snapshot boundary. Safe
     * to call from any thread and returns without waiting.</p>
     */
    public static void startLivePoll() {
        livePollRequested = true;
        ExportRunToken token = RuntimeConfig.currentExportRunToken();
        ensureHistoricSnapshotStateForRun(token);
        ensureLiveBaselineStateForRun(token);
        if (trafficSelectionAllowsHistoricWebSockets() && !historicSnapshotFinished) {
            return;
        }
        if (!shouldRunLivePoll()) {
            return;
        }
        if (!trafficSelectionAllowsHistoricWebSockets() && !liveBaselineFinished) {
            requestLiveBaseline(token);
            return;
        }
        startRecurringLivePoll(token);
    }

    private static void startRecurringLivePoll(ExportRunToken token) {
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
     * disabled, or {@code proxy} is deselected. A newly enabled live source first captures and
     * skips the current history boundary. When {@code proxy_history} is selected during a run,
     * queues its sliced historic snapshot once and keeps live polling stopped until that snapshot
     * completes.</p>
     */
    public static void refreshLivePollScheduleForCurrentState() {
        if (!shouldRunLivePoll()) {
            stopLivePollScheduler();
            resetLiveBaselineForCurrentRun();
            return;
        }
        livePollRequested = true;
        ensureHistoricSnapshotStateForRun(RuntimeConfig.currentExportRunToken());
        if (trafficSelectionAllowsHistoricWebSockets() && !historicSnapshotFinished) {
            resetLiveBaselineForCurrentRun();
            pushHistoricSnapshotNow();
            return;
        }
        startLivePoll();
    }

    /** Stops only the recurring poll scheduler. */
    public static void stopLivePollScheduler() {
        SCHEDULER.stop();
    }

    /** Stops baseline and poll schedulers and clears per-run cursor state. */
    public static void stop() {
        BASELINE_SCHEDULER.stop();
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
        synchronized (LIVE_BASELINE_LOCK) {
            liveBaselineRunToken = null;
            liveBaselineRequested = false;
            liveBaselineFinished = false;
            liveBaselineGeneration++;
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

    private static void ensureLiveBaselineStateForRun(ExportRunToken token) {
        synchronized (LIVE_BASELINE_LOCK) {
            if (Objects.equals(liveBaselineRunToken, token)) {
                return;
            }
            liveBaselineRunToken = token;
            liveBaselineRequested = false;
            liveBaselineFinished = false;
            liveBaselineGeneration++;
        }
    }

    private static void resetLiveBaselineForCurrentRun() {
        synchronized (LIVE_BASELINE_LOCK) {
            liveBaselineRunToken = RuntimeConfig.currentExportRunToken();
            liveBaselineRequested = false;
            liveBaselineFinished = false;
            liveBaselineGeneration++;
        }
    }

    private static void requestLiveBaseline(ExportRunToken token) {
        MontoyaApi api = MontoyaApiProvider.get();
        if (api == null) {
            return;
        }
        long generation;
        synchronized (LIVE_BASELINE_LOCK) {
            if (!Objects.equals(liveBaselineRunToken, token)
                    || liveBaselineRequested
                    || liveBaselineFinished) {
                return;
            }
            liveBaselineRequested = true;
            generation = liveBaselineGeneration;
        }
        try {
            BASELINE_SCHEDULER.getOrStart()
                    .execute(() -> seedLiveBaseline(api, token, generation));
        } catch (RejectedExecutionException e) {
            synchronized (LIVE_BASELINE_LOCK) {
                if (Objects.equals(liveBaselineRunToken, token)
                        && liveBaselineGeneration == generation) {
                    liveBaselineRequested = false;
                }
            }
        }
    }

    private static void seedLiveBaseline(
            MontoyaApi api, ExportRunToken token, long generation) {
        List<ProxyWebSocketMessage> history = safeWebSocketHistory(api);
        synchronized (LIVE_BASELINE_LOCK) {
            if (!Objects.equals(liveBaselineRunToken, token)
                    || liveBaselineGeneration != generation
                    || !RuntimeConfig.isExportRunActive(token)
                    || !shouldRunLivePoll()
                    || trafficSelectionAllowsHistoricWebSockets()) {
                if (Objects.equals(liveBaselineRunToken, token)
                        && liveBaselineGeneration == generation) {
                    liveBaselineRequested = false;
                }
                return;
            }
            liveHistoryCursor = history.size();
            liveHistoryTailKey = lastHistoryKey(history);
            liveBaselineFinished = true;
        }
        Logger.logInfoPanelOnly("[LiveTraffic] ProxyWebSocket: skipped "
                + history.size()
                + " pre-existing history frame(s); live capture starts at the current tail.");
        startRecurringLivePoll(token);
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
     * <p>Only the matching active run advances the live-history cursor and enables live polling.</p>
     */
    private static void finishStartupBacklogLocked(StartupBacklogState state) {
        startupBacklog = null;
        if (!RuntimeConfig.isExportRunActive(state.token)) {
            return;
        }
        liveHistoryCursor = state.history.size();
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
                            SnapshotSummary.forRoute(TrafficRouteBucket.proxyWebSocketHistory()),
                            RuntimeConfig.currentExportRunToken());
                } else {
                    liveHistoryCursor = 0;
                    liveHistoryTailKey = null;
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
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocketHistory();
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
                    return ExportDocumentIdentity.prepareWithTrafficRoute(
                            indexName, indexKey, doc, route.key());
                },
                (chunk, outcome, nextChunkTarget) -> TrafficRouteBucket.recordBulkOutcome(
                        route,
                        outcome,
                        openSearchActive,
                        "Proxy WebSocket bulk push"));

        liveHistoryCursor = history.size();
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
        if (history.size() == liveHistoryCursor && Objects.equals(currentTailKey, liveHistoryTailKey)) {
            return;
        }
        int startIndex = indexAfterKnownBoundary(history);
        if (startIndex < 0) {
            liveHistoryCursor = history.size();
            liveHistoryTailKey = currentTailKey;
            Logger.logWarnPanelOnly("[LiveTraffic] ProxyWebSocket: the prior live-history boundary "
                    + "is no longer retained; skipped "
                    + history.size()
                    + " frame(s) to prevent historical replay.");
            return;
        }
        int nextCursor = startIndex;
        String nextTailKey = liveHistoryTailKey;
        TrafficRouteBucket.Route route = TrafficRouteBucket.proxyWebSocketLive();
        for (int i = startIndex; i < history.size(); i++) {
            if (!shouldRunLivePoll()) {
                break;
            }
            ProxyWebSocketMessage msg = history.get(i);
            Map<String, Object> doc = buildDocument(api, msg);
            if (doc == null) {
                nextCursor = i + 1;
                nextTailKey = messageKey(msg);
                continue;
            }
            if (TrafficExportQueue.offerAccepted(doc, route)) {
                nextCursor = i + 1;
                nextTailKey = messageKey(msg);
            } else {
                break;
            }
        }
        liveHistoryCursor = nextCursor;
        liveHistoryTailKey = nextTailKey;
    }

    private static int indexAfterKnownBoundary(List<ProxyWebSocketMessage> history) {
        if (liveHistoryTailKey == null) {
            return liveHistoryCursor == 0 ? 0 : -1;
        }
        for (int i = history.size() - 1; i >= 0; i--) {
            if (liveHistoryTailKey.equals(messageKey(history.get(i)))) {
                return i + 1;
            }
        }
        return -1;
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
