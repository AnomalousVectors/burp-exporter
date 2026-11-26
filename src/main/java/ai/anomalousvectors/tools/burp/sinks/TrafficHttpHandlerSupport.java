package ai.anomalousvectors.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.StringKeyedMaps;
import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.search.SearchEndpoint;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Shared implementation for live HTTP traffic capture.
 *
 * <p>{@link TrafficHttpHandler} handles general HTTP callbacks and
 * {@link TrafficProxyHttpHandler} handles native Proxy callbacks. This package-private support
 * class shares document construction, namespaced admission and orphan lifecycle between them.</p>
 */
class TrafficHttpHandlerSupport implements HttpHandler {

    private static final String SCHEMA_VERSION = "1";

    /** Request-only publication delay, not proof that a response can no longer arrive. */
    private static final long ORPHAN_TIMEOUT_MS = 120_000L;
    private static final int ORPHAN_CHECK_INTERVAL_SECONDS = 30;

    private static final Object ORPHAN_LIFECYCLE_LOCK = new Object();
    private static final ConcurrentHashMap<MessageKey, PendingOrphan> pendingOrphans = new ConcurrentHashMap<>();
    // Request-stage eligibility can change before response capture. Keep exact run membership,
    // but reclaim old payload-free receipts only under pressure; never wait for capacity.
    private static LiveRequestReceipts requestAdmissions = new LiveRequestReceipts(ORPHAN_TIMEOUT_MS);

    // Native Proxy and general HTTP IDs belong to different Burp namespaces, even when equal.
    record MessageKey(boolean nativeProxy, int id) {}

    /**
     * Scheduler that periodically flushes orphaned (response-less) requests as no-response documents.
     *
     * <p>Created lazily by {@link #ensureOrphanSchedulerStarted()} the first time a request is
     * tracked and cleared by {@link #stop()} during UI stop or extension unload. A subsequent
     * tracked request recreates the executor so the extension does not leak a scheduler thread
     * after unload.</p>
     */
    private static final LazyScheduler ORPHAN_SCHEDULER =
            new LazyScheduler("burp-exporter-orphan-export");

    /**
     * Starts the orphan flush scheduler on first use.
     *
     * <p>Safe to call from any thread; {@link LazyScheduler#startRecurring} guarantees that the
     * executor and its {@code scheduleAtFixedRate} registration occur at most once per
     * lazy-start cycle even under concurrent callers. {@link #stop()} clears
     * {@link #ORPHAN_SCHEDULER}, so a subsequent tracked request recreates the scheduler.</p>
     */
    private static void ensureOrphanSchedulerStarted() {
        ORPHAN_SCHEDULER.startRecurring(
                TrafficHttpHandlerSupport::flushOrphanedRequests,
                ORPHAN_CHECK_INTERVAL_SECONDS,
                ORPHAN_CHECK_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Stops the orphan flush scheduler and clears tracked pending requests.
     *
     * <p>Safe to call from any thread and safe to call more than once. The scheduler is recreated
     * lazily on the next tracked request via {@link LazyScheduler#getOrStart()}.</p>
     */
    public static void stop() {
        LiveRequestReceipts.Snapshot pressure;
        synchronized (ORPHAN_LIFECYCLE_LOCK) {
            pressure = requestAdmissions.takePressureSummary(true);
            clearPendingPayloads();
            requestAdmissions.clear();
        }
        logReceiptPressure(pressure);
        ORPHAN_SCHEDULER.stop();
        LiveTrafficPreparation.stop();
    }

    private static void clearPendingPayloads() {
        for (PendingOrphan pending : pendingOrphans.values()) {
            if (pending != null) pending.releasePayload();
        }
        pendingOrphans.clear();
    }

    /**
     * Returns the current number of pending request/response orphan entries awaiting
     * correlation or timeout-driven flush. Used by Misc Stats and periodic memory-sample
     * logging. Excludes payload-free receipts retained for late responses after timeout; their
     * separate occupancy and pressure totals are exposed through {@link TrafficHttpHandler}.
     *
     * @return thread-safe current count; concurrent callbacks may change it immediately
     */
    public static int getPendingOrphansSize() {
        return pendingOrphans.size();
    }

    static LiveRequestReceipts.Snapshot receiptSnapshot() {
        synchronized (ORPHAN_LIFECYCLE_LOCK) {
            return requestAdmissions.snapshot(RuntimeConfig.currentExportRunToken());
        }
    }

    private static void logReceiptPressure(LiveRequestReceipts.Snapshot snapshot) {
        if (snapshot == null) return;
        Logger.logWarnPanelOnly("[Traffic] Live request receipt pressure: retained=" + snapshot.retained()
                + "/" + snapshot.capacity() + ", peak=" + snapshot.peak()
                + ", reclaimed=" + snapshot.reclaimed() + ", rejected=" + snapshot.rejected()
                + "; reclaimed receipts no longer admit late responses; rejected requests were not admitted to callback capture."
                + " Burp traffic continued without waiting for capture capacity.");
    }

    /** Whether traffic from this tool source should be exported (user-selected tool types only). */
    private static boolean shouldExportTrafficByToolSource(ToolType toolType) {
        return RuntimeConfig.trafficExportGate().includesToolType(RuntimeConfig.normalizedToolTypeKey(toolType));
    }

    /**
     * Whether null/unknown tool-source traffic should be exported.
     *
     * <p>Some Burp flows do not provide tool source on response/request callbacks. We allow these
     * events when Proxy export is enabled so normal browser-driven Proxy traffic is not dropped.</p>
     */
    private static boolean shouldExportNullToolSourceTraffic() {
        return RuntimeConfig.trafficExportGate().includesToolType("proxy");
    }

    private static boolean shouldStillExportPendingOrphan(PendingOrphan pending) {
        if (pending == null) {
            return false;
        }
        if (shouldExportTrafficByToolSource(pending.toolType)) {
            return true;
        }
        return pending.toolType == null && shouldExportNullToolSourceTraffic();
    }

    /**
     * True if the request is to the configured search database base URL (same host and port).
     * Used when tool type is EXTENSIONS to exclude this extension's own export traffic.
     */
    private static boolean isRequestToConfiguredOpenSearch(String requestHost, int requestPort) {
        String baseUrl = RuntimeConfig.searchBaseUrl();
        if (baseUrl == null || baseUrl.isBlank() || requestHost == null || requestHost.isEmpty()) {
            return false;
        }
        try {
            SearchEndpoint endpoint = SearchEndpoint.parse(baseUrl);
            return endpoint.host().equalsIgnoreCase(requestHost) && endpoint.effectivePort() == requestPort;
        } catch (Exception e) {
            return false;
        }
    }

    /** {@inheritDoc} */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            return handleHttpRequestToBeSentSafely(request);
        } catch (RuntimeException e) {
            Logger.logError("[Traffic] Request callback failed safely: error="
                    + e.getClass().getSimpleName()
                    + "; Burp traffic continued; request-only capture is unavailable.");
            return RequestToBeSentAction.continueWith(request);
        }
    }

    private RequestToBeSentAction handleHttpRequestToBeSentSafely(HttpRequestToBeSent request) {
        ToolSource source = request.toolSource();
        ToolType type = source == null ? null : source.toolType();
        // Native Proxy owns this tool's documents and listener metadata; never publish both views.
        if (type != ToolType.PROXY) {
            captureRequest(request, new MessageKey(false, request.messageId()), type,
                    request.annotations(), null);
        }
        return RequestToBeSentAction.continueWith(request);
    }

    /** Captures a native sent request without correlating it to general HTTP or History IDs. */
    final void captureNativeRequest(HttpRequest request, int id, Annotations annotations, Integer port) {
        captureRequest(request, new MessageKey(true, id), ToolType.PROXY, annotations, port);
    }

    private void captureRequest(HttpRequest request, MessageKey key, ToolType toolType,
            Annotations annotations, Integer listenerPort) {
        RuntimeConfig.ExportRunToken runToken = RuntimeConfig.currentExportRunToken();
        RuntimeConfig.TrafficExportGate trafficGate = RuntimeConfig.trafficExportGate();
        if (!RuntimeConfig.isExportReady() || RuntimeConfig.isExportStopping()
                || !trafficGate.anyTrafficExportEnabled()) {
            return;
        }
        long requestSentMs = System.currentTimeMillis();
        if (toolType == ToolType.PROXY || toolType == null) {
            StreamingProxyRecovery.requestObserved();
        }
        LiveRequestReceipts.Receipt receipt;
        LiveRequestReceipts.Snapshot pressure;
        synchronized (ORPHAN_LIFECYCLE_LOCK) {
            if (!RuntimeConfig.isExportRunActive(runToken) || RuntimeConfig.isExportStopping()) {
                return;
            }
            if (requestAdmissions.beginRun(runToken)) clearPendingPayloads();
            receipt = requestAdmissions.admit(key, requestSentMs, toolType, runToken, listenerPort);
            pressure = requestAdmissions.takePressureSummary(false);
        }
        logReceiptPressure(pressure);
        if (receipt == null) return;
        boolean payloadAttached = false;
        LiveTrafficPreparation.Capture capture = null;
        try {
            boolean burpInScope = request.isInScope();
            ConfigState.State state = RuntimeConfig.getState();
            if (scopeRejectsWithoutUrl(state, burpInScope)) {
                ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1);
                return;
            }
            if (!(toolType == null ? shouldExportNullToolSourceTraffic() : shouldExportTrafficByToolSource(toolType))) {
                ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 1);
                return;
            }
            if (toolType == ToolType.EXTENSIONS) {
                HttpService svc = request.httpService();
                if (svc != null && isRequestToConfiguredOpenSearch(svc.host(), svc.port())) {
                    ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SELF_OPENSEARCH, 1);
                    return;
                }
            }
            PreparedRequest prepared = prepareDeferredRequest(request);
            if (!ScopeFilter.shouldExport(state, prepared.url(), burpInScope)) {
                ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1);
                return;
            }
            ToolType reqToolType = toolType;
            RequestStageResolution requestStageResolution =
                    resolveRequestStageResolution(
                            request,
                            reqToolType,
                            RepeaterTabsIndexReporter::currentRepeaterSharedMetadataForLiveFallback);
            Map<String, Object> skeleton = buildOrphanDocumentSkeleton(
                    prepared, burpInScope,
                    requestSentMs,
                    requestStageResolution.metadataForExport(), key, toolType, annotations, listenerPort);
            if (skeleton != null) {
                capture = LiveTrafficPreparation.retain(skeleton, runToken, prepared.message());
                if (capture == null) return;
                PendingOrphan pending = new PendingOrphan(
                        skeleton,
                        requestSentMs,
                        reqToolType,
                        requestStageResolution,
                        runToken, listenerPort, capture);
                synchronized (ORPHAN_LIFECYCLE_LOCK) {
                    if (RuntimeConfig.isExportRunActive(runToken)
                            && requestAdmissions.get(key) == receipt) {
                        PendingOrphan replaced = pendingOrphans.put(key, pending);
                        if (replaced != null) replaced.releasePayload();
                        payloadAttached = true;
                        ensureOrphanSchedulerStarted();
                    }
                }
            }
        } finally {
            if (!payloadAttached && capture != null) capture.close();
            synchronized (ORPHAN_LIFECYCLE_LOCK) {
                if (!payloadAttached) requestAdmissions.releasePayload(receipt);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            return handleHttpResponseReceivedSafely(response);
        } catch (RuntimeException e) {
            Logger.logError("[Traffic] Response callback failed safely: error="
                    + e.getClass().getSimpleName()
                    + "; Burp traffic continued and this document was not exported.");
            return ResponseReceivedAction.continueWith(response);
        }
    }

    private ResponseReceivedAction handleHttpResponseReceivedSafely(HttpResponseReceived response) {
        ToolSource source = response.toolSource();
        ToolType type = source == null ? null : source.toolType();
        if (type != ToolType.PROXY) {
            captureResponse(response, response.initiatingRequest(),
                    new MessageKey(false, response.messageId()), type, response.annotations());
        }
        return ResponseReceivedAction.continueWith(response);
    }

    /** Captures the original server response with Burp's initiating sent request and native ID. */
    final void captureNativeResponse(HttpResponse response, HttpRequest request, int id, Annotations annotations) {
        captureResponse(response, request, new MessageKey(true, id), ToolType.PROXY, annotations);
    }

    private void captureResponse(HttpResponse response, HttpRequest request, MessageKey key,
            ToolType responseType, Annotations annotations) {
        PendingOrphan pending;
        synchronized (ORPHAN_LIFECYCLE_LOCK) {
            LiveRequestReceipts.Receipt receipt = requestAdmissions.remove(key);
            PendingOrphan skeleton = pendingOrphans.remove(key);
            pending = receipt == null ? null
                    : skeleton != null && skeleton.runToken.equals(receipt.runToken()) ? skeleton
                    : new PendingOrphan(null, receipt.timestamp(), receipt.toolType(),
                            RequestStageResolution.none(), receipt.runToken(), receipt.listenerPort());
            if (skeleton != null) skeleton.releasePayload();
        }
        // Pair only within the admitted run; late and duplicate responses cannot enter a new run.
        if (pending == null || !RuntimeConfig.isExportRunActive(pending.runToken)
                || !RuntimeConfig.isExportReady()) {
            return;
        }
        if (!RuntimeConfig.trafficExportGate().anyTrafficExportEnabled()) {
            return;
        }

        if (request == null) {
            return;
        }

        boolean burpInScope = request.isInScope();
        ConfigState.State state = RuntimeConfig.getState();
        if (scopeRejectsWithoutUrl(state, burpInScope)) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1);
            return;
        }

        ToolType requestFallbackType = pending.toolType;
        if (responseType == null) {
            ExportStats.recordTrafficToolSourceFallback();
        }
        // Prefer selected response source, then selected request-correlated source.
        ToolType toolType;
        if (shouldExportTrafficByToolSource(responseType)) {
            toolType = responseType;
        } else if (shouldExportTrafficByToolSource(requestFallbackType)) {
            toolType = requestFallbackType;
        } else if (responseType == null && requestFallbackType == null && shouldExportNullToolSourceTraffic()) {
            toolType = null;
        } else {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 1);
            return;
        }

        if (toolType == ToolType.EXTENSIONS || toolType == null) {
            HttpService svc = request.httpService();
            if (svc != null && isRequestToConfiguredOpenSearch(svc.host(), svc.port())) {
                ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SELF_OPENSEARCH, 1);
                return;
            }
        }

        PreparedRequest prepared = prepareDeferredRequest(request);
        if (!ScopeFilter.shouldExport(state, prepared.url(), burpInScope)) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1);
            return;
        }

        long responseReceivedMs = System.currentTimeMillis();
        Long requestSentMs = pending.timestamp;
        RepeaterMetadataFields.Metadata repeaterMetadata =
                resolveResponseStageRepeaterMetadata(
                        request,
                        response,
                        toolType,
                        pending.requestStageResolution,
                        RepeaterTabsIndexReporter::currentRepeaterSharedMetadataForLiveFallback);

        var preparedResponse = RequestResponseDocBuilder.prepareTrafficResponse(response);
        Map<String, Object> document =
                buildDocument(preparedResponse.document(), prepared, burpInScope, requestSentMs, responseReceivedMs,
                        toolType, repeaterMetadata, key, annotations, pending.listenerPort);
        if (annotations == null) {
            copyMissingAnnotationFieldsFromPendingRequest(document, pending);
        }
        LiveTrafficPreparation.submit(LiveTrafficPreparation.retain(
                document, pending.runToken, prepared.message(), preparedResponse));

    }


    /**
     * Resolves tool type for response handling with fallback to request-side metadata.
     *
     * <p>In some Burp paths, response tool source can be null. Fallback to request-side
     * correlation prevents dropping valid live traffic.</p>
     */
    static ToolType resolveResponseToolType(HttpResponseReceived response, ToolType requestFallbackType) {
        ToolSource responseSource = response == null ? null : response.toolSource();
        ToolType responseType = responseSource == null ? null : responseSource.toolType();
        return responseType != null ? responseType : requestFallbackType;
    }

    /**
     * Builds a sink-neutral traffic document synchronously from readable callback views.
     *
     * <p>Live capture invokes this on Burp's callback thread before queue admission. This helper
     * performs no destination I/O and does not acquire a Burp thread or lock.</p>
     *
     * @param response the received response (with initiating request)
     * @param request  the initiating request
     * @param burpInScope raw Burp scope state for the request
     * @return map matching traffic index mapping (never null)
     */
    Map<String, Object> buildDocument(HttpResponseReceived response, HttpRequest request, boolean burpInScope) {
        return buildDocument(
                response,
                request,
                burpInScope,
                null,
                null,
                null,
                RepeaterMetadataFields.Metadata.empty());
    }

    Map<String, Object> buildDocument(
            HttpResponseReceived response,
            HttpRequest request,
            boolean burpInScope,
            Long requestSentMs,
            Long responseReceivedMs,
            ToolType resolvedToolType,
            RepeaterMetadataFields.Metadata repeaterMetadata) {
        ToolSource toolSource = response.toolSource();
        ToolType toolType = resolvedToolType;
        if (toolType == null) {
            toolType = toolSource == null ? null : toolSource.toolType();
        }
        return buildDocument(response, prepareRequest(request), burpInScope, requestSentMs, responseReceivedMs,
                toolType, repeaterMetadata, new MessageKey(false, response.messageId()),
                response.annotations(), null);
    }

    /** Custom scope uses the prepared URL, including narrowed queries and malformed-view fallback. */
    private static boolean scopeRejectsWithoutUrl(ConfigState.State state, boolean burpInScope) {
        boolean custom = state != null && state.scopeType() != null
                && ConfigKeys.SCOPE_CUSTOM.equalsIgnoreCase(state.scopeType().trim());
        return !custom && !ScopeFilter.shouldExport(state, null, burpInScope);
    }

    // Prepared data belongs to one callback only: later handlers can still change the request.
    private record PreparedRequest(Map<String, Object> document, String url,
            RequestResponseDocBuilder.PreparedTrafficMessage message) { }

    private static PreparedRequest prepareRequest(HttpRequest request) {
        PreparedRequest prepared = prepareDeferredRequest(request);
        prepared.message().complete();
        return prepared;
    }

    private static PreparedRequest prepareDeferredRequest(HttpRequest request) {
        HttpService service = request.httpService();
        var message = RequestResponseDocBuilder.prepareTrafficRequest(request);
        Map<String, Object> requestDoc = message.document();
        String url = RequestResponseDocBuilder.buildBestEffortUrl(
                request, service, requestDoc, "TrafficHttpHandler");
        requestDoc.put("url", HttpMessageDocSupport.urlObject(url, service));
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));
        return new PreparedRequest(requestDoc, url, message);
    }

    private Map<String, Object> buildDocument(HttpResponse response, PreparedRequest prepared,
            boolean burpInScope, Long requestSentMs, Long responseReceivedMs, ToolType toolType,
            RepeaterMetadataFields.Metadata repeaterMetadata, MessageKey key,
            Annotations annotations, Integer listenerPort) {
        return buildDocument(RequestResponseDocBuilder.buildTrafficResponseDoc(response), prepared,
                burpInScope, requestSentMs, responseReceivedMs, toolType, repeaterMetadata, key,
                annotations, listenerPort);
    }

    private Map<String, Object> buildDocument(Map<String, Object> response, PreparedRequest prepared,
            boolean burpInScope, Long requestSentMs, Long responseReceivedMs, ToolType toolType,
            RepeaterMetadataFields.Metadata repeaterMetadata, MessageKey key,
            Annotations annotations, Integer listenerPort) {
        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", toolType == null ? null : toolType.toolName());
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", key.id());
        BurpAnnotationFields.put(burp, annotations);
        putLiveProxyAndTiming(
                burp,
                requestSentMs,
                responseReceivedMs, listenerPort);
        document.put("burp", burp);
        RepeaterMetadataFields.put(document, repeaterMetadata);

        document.put("request", prepared.document());
        document.put("response", response);
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());

        document.put("meta", ExportMetaFields.liveHttp(SCHEMA_VERSION, key.nativeProxy()));
        return document;
    }

    private static void copyMissingAnnotationFieldsFromPendingRequest(
            Map<String, Object> document,
            PendingOrphan pending) {
        if (document == null || pending == null || pending.documentSkeleton == null) {
            return;
        }
        copyMissingBurpField(document, pending.documentSkeleton, "notes");
        copyMissingBurpField(document, pending.documentSkeleton, "highlight");
    }

    private static void copyMissingBurpField(
            Map<String, Object> targetDocument,
            Map<String, Object> sourceDocument,
            String field) {
        Object targetBurpObject = targetDocument.get("burp");
        Object sourceBurpObject = sourceDocument.get("burp");
        if (!(targetBurpObject instanceof Map<?, ?> targetBurp)
                || !(sourceBurpObject instanceof Map<?, ?> sourceBurp)
                || targetBurp.containsKey(field)) {
            return;
        }
        Object sourceValue = sourceBurp.get(field);
        if (sourceValue != null) {
            targetDocument.put("burp", copyWithBurpField(targetBurp, field, sourceValue));
        }
    }

    private static Map<String, Object> copyWithBurpField(Map<?, ?> source, String field, Object value) {
        Map<String, Object> copy = StringKeyedMaps.copy(source);
        copy.put(field, value);
        return copy;
    }

    /**
     * Builds the document skeleton for an orphaned request (no response received).
     * Caller must hold Burp HTTP thread. Does not include {@code response}; add via
     * {@link RequestResponseDocBuilder#emptyTrafficResponseDoc()} when exporting.
     */
    Map<String, Object> buildOrphanDocumentSkeleton(
            HttpRequest request,
            long requestSentMs,
            RepeaterMetadataFields.Metadata repeaterMetadata, MessageKey key, ToolType toolType,
            Annotations annotations, Integer listenerPort) {
        return buildOrphanDocumentSkeleton(prepareRequest(request), request.isInScope(),
                requestSentMs, repeaterMetadata, key, toolType, annotations, listenerPort);
    }

    private Map<String, Object> buildOrphanDocumentSkeleton(
            PreparedRequest prepared, boolean burpInScope, long requestSentMs,
            RepeaterMetadataFields.Metadata repeaterMetadata, MessageKey key, ToolType toolType,
            Annotations annotations, Integer listenerPort) {
        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", toolType == null ? null : toolType.toolName());
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", key.id());
        BurpAnnotationFields.put(burp, annotations);
        putLiveProxyAndTiming(burp, requestSentMs, null, listenerPort);
        document.put("burp", burp);
        RepeaterMetadataFields.put(document, repeaterMetadata);

        document.put("request", prepared.document());
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());

        document.put("meta", ExportMetaFields.liveHttp(SCHEMA_VERSION, key.nativeProxy()));
        return document;
    }

    /**
     * Resolves best-effort Repeater metadata during the request stage.
     *
     * <p>Only live {@link ToolType#REPEATER} traffic participates. Ambiguous tracker matches
     * intentionally return empty metadata so identical concurrent Repeater tabs do not inherit the
     * wrong label from current UI focus.</p>
     */
    static RepeaterMetadataFields.Metadata resolveRequestStageRepeaterMetadata(HttpRequest request, ToolType toolType) {
        return resolveRequestStageRepeaterMetadata(
                request,
                toolType,
                RepeaterTabsIndexReporter::currentRepeaterSharedMetadataForLiveFallback);
    }

    /**
     * Resolves best-effort Repeater metadata during the request stage.
     *
     * @param request live request being exported
     * @param toolType Burp tool that emitted the request
     * @param liveFallbackSupplier current UI metadata supplier used only when no tracked match exists
     * @return best-effort Repeater metadata or {@link RepeaterMetadataFields.Metadata#empty()}
     */
    static RepeaterMetadataFields.Metadata resolveRequestStageRepeaterMetadata(
            HttpRequest request,
            ToolType toolType,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        return resolveRequestStageResolution(request, toolType, liveFallbackSupplier, false).metadata();
    }

    static RequestStageResolution resolveRequestStageResolution(
            HttpRequest request,
            ToolType toolType,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        return resolveRequestStageResolution(request, toolType, liveFallbackSupplier, true);
    }

    private static RequestStageResolution resolveRequestStageResolution(
            HttpRequest request,
            ToolType toolType,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier,
            boolean captureAmbiguousUiSnapshot) {
        if (toolType != ToolType.REPEATER) {
            return RequestStageResolution.none();
        }
        RepeaterLiveMetadataTracker.Resolution trackedRequest =
                RepeaterLiveMetadataTracker.resolveRequestResolution(request);
        if (trackedRequest.metadata().isPresent()) {
            logLiveRepeaterMetadataDecision(
                    "request",
                    trackedRequest.sourceLabel(),
                    trackedRequest.metadata(),
                    "reason=tracker_match");
            return RequestStageResolution.confident(trackedRequest.metadata(), trackedRequest.sourceLabel());
        }
        if (trackedRequest.ambiguous()) {
            logLiveRepeaterMetadataDecision(
                    "request",
                    RepeaterMetadataTraceLabels.AMBIGUOUS_NULL,
                    RepeaterMetadataFields.Metadata.empty(),
                    "reason=request_ambiguous trackerSource="
                            + RepeaterMetadataTraceLabels.safeValue(trackedRequest.sourceLabel()));
            RepeaterMetadataFields.Metadata requestUiSnapshot = captureAmbiguousUiSnapshot
                    ? normalizedFallbackMetadata(liveFallbackSupplier)
                    : RepeaterMetadataFields.Metadata.empty();
            return RequestStageResolution.ambiguous(trackedRequest.sourceLabel(), requestUiSnapshot);
        }
        RepeaterMetadataFields.Metadata fallbackMetadata = normalizedFallbackMetadata(liveFallbackSupplier);
        logLiveRepeaterMetadataDecision(
                "request",
                RepeaterMetadataTraceLabels.UI_FALLBACK,
                fallbackMetadata,
                fallbackMetadata.isPresent()
                        ? "reason=no_tracked_match"
                        : "reason=no_tracked_match_and_ui_unlabeled");
        return RequestStageResolution.confident(fallbackMetadata, RepeaterMetadataTraceLabels.UI_FALLBACK);
    }

    /**
     * Resolves best-effort Repeater metadata during the response stage.
     *
     * <p>The response stage first tries the stricter request+response tracker match, then reuses
     * confident request-stage metadata, and finally consults the current UI only when there was no
     * tracked signal at all.</p>
     */
    static RepeaterMetadataFields.Metadata resolveResponseStageRepeaterMetadata(
            HttpRequest request,
            HttpResponse response,
            ToolType toolType,
            RepeaterMetadataFields.Metadata requestStageMetadata) {
        return resolveResponseStageRepeaterMetadata(
                request,
                response,
                toolType,
                requestStageMetadata,
                RepeaterTabsIndexReporter::currentRepeaterSharedMetadataForLiveFallback);
    }

    /**
     * Resolves best-effort Repeater metadata during the response stage.
     *
     * @param request live request being exported
     * @param response live response being exported
     * @param toolType Burp tool that emitted the exchange
     * @param requestStageMetadata confident metadata captured earlier during request export
     * @param liveFallbackSupplier current UI metadata supplier used only when no tracked match exists
     * @return best-effort Repeater metadata or {@link RepeaterMetadataFields.Metadata#empty()}
     */
    static RepeaterMetadataFields.Metadata resolveResponseStageRepeaterMetadata(
            HttpRequest request,
            HttpResponse response,
            ToolType toolType,
            RepeaterMetadataFields.Metadata requestStageMetadata,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        return resolveResponseStageRepeaterMetadata(
                request,
                response,
                toolType,
                RequestStageResolution.fromMetadata(requestStageMetadata),
                liveFallbackSupplier);
    }

    static RepeaterMetadataFields.Metadata resolveResponseStageRepeaterMetadata(
            HttpRequest request,
            HttpResponse response,
            ToolType toolType,
            RequestStageResolution requestStageResolution,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        if (toolType != ToolType.REPEATER) {
            return RepeaterMetadataFields.Metadata.empty();
        }
        RequestStageResolution normalizedRequestStage = requestStageResolution == null
                ? RequestStageResolution.none()
                : requestStageResolution;
        RepeaterLiveMetadataTracker.Resolution exchangeResolution =
                RepeaterLiveMetadataTracker.resolveExchangeResolution(request, response);
        if (exchangeResolution.metadata().isPresent()) {
            logLiveRepeaterMetadataDecision(
                    "response",
                    exchangeResolution.sourceLabel(),
                    exchangeResolution.metadata(),
                    "reason=tracker_match");
            return exchangeResolution.metadata();
        }
        if (exchangeResolution.ambiguous()) {
            if (normalizedRequestStage.metadata().isPresent()) {
                logLiveRepeaterMetadataDecision(
                        "response",
                        RepeaterMetadataTraceLabels.REQUEST_STAGE_REUSE,
                        normalizedRequestStage.metadata(),
                        "reason=exchange_ambiguous trackerSource="
                                + RepeaterMetadataTraceLabels.safeValue(exchangeResolution.sourceLabel()));
                return normalizedRequestStage.metadata();
            }
            if (normalizedRequestStage.uiSnapshot().isPresent()) {
                logLiveRepeaterMetadataDecision(
                        "response",
                        RepeaterMetadataTraceLabels.REQUEST_STAGE_REUSE,
                        normalizedRequestStage.uiSnapshot(),
                        "reason=exchange_ambiguous request_ambiguous_ui_snapshot trackerSource="
                                + RepeaterMetadataTraceLabels.safeValue(exchangeResolution.sourceLabel()));
                return normalizedRequestStage.uiSnapshot();
            }
            logLiveRepeaterMetadataDecision(
                    "response",
                    RepeaterMetadataTraceLabels.AMBIGUOUS_NULL,
                    RepeaterMetadataFields.Metadata.empty(),
                    "reason=exchange_ambiguous trackerSource="
                            + RepeaterMetadataTraceLabels.safeValue(exchangeResolution.sourceLabel()));
            return RepeaterMetadataFields.Metadata.empty();
        }
        if (normalizedRequestStage.metadata().isPresent()) {
            logLiveRepeaterMetadataDecision(
                    "response",
                    RepeaterMetadataTraceLabels.REQUEST_STAGE_REUSE,
                    normalizedRequestStage.metadata(),
                    "reason=exchange_tracker_miss");
            return normalizedRequestStage.metadata();
        }
        if (normalizedRequestStage.uiSnapshot().isPresent()) {
            logLiveRepeaterMetadataDecision(
                    "response",
                    RepeaterMetadataTraceLabels.REQUEST_STAGE_REUSE,
                    normalizedRequestStage.uiSnapshot(),
                    "reason=exchange_tracker_miss request_ambiguous_ui_snapshot");
            return normalizedRequestStage.uiSnapshot();
        }
        return resolveTrackedRequestOrLiveFallback(request, "response", liveFallbackSupplier);
    }

    /**
     * Resolves Repeater metadata from the short-lived tracker before touching the Swing fallback.
     *
     * <p>The tracker is the authoritative source for live Repeater traffic because it is bound to
     * the observed request object. The fallback supplier is only consulted when there is no tracked
     * match. When the tracker sees multiple distinct metadata candidates for the same live request,
     * this helper returns empty metadata instead of querying the current UI selection so ambiguous
     * concurrent traffic does not inherit the wrong tab/group name.</p>
     */
    private static RepeaterMetadataFields.Metadata resolveTrackedRequestOrLiveFallback(
            HttpRequest request,
            String stage,
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        RepeaterLiveMetadataTracker.Resolution trackedRequest =
                RepeaterLiveMetadataTracker.resolveRequestResolution(request);
        if (trackedRequest.metadata().isPresent()) {
            logLiveRepeaterMetadataDecision(
                    stage,
                    trackedRequest.sourceLabel(),
                    trackedRequest.metadata(),
                    "reason=tracker_match");
            return trackedRequest.metadata();
        }
        if (trackedRequest.ambiguous()) {
            logLiveRepeaterMetadataDecision(
                    stage,
                    RepeaterMetadataTraceLabels.AMBIGUOUS_NULL,
                    RepeaterMetadataFields.Metadata.empty(),
                    "reason=request_ambiguous trackerSource="
                            + RepeaterMetadataTraceLabels.safeValue(trackedRequest.sourceLabel()));
            return RepeaterMetadataFields.Metadata.empty();
        }
        RepeaterMetadataFields.Metadata fallbackMetadata = liveFallbackSupplier == null
                ? RepeaterMetadataFields.Metadata.empty()
                : liveFallbackSupplier.get();
        RepeaterMetadataFields.Metadata normalizedFallback =
                fallbackMetadata == null ? RepeaterMetadataFields.Metadata.empty() : fallbackMetadata;
        logLiveRepeaterMetadataDecision(
                stage,
                RepeaterMetadataTraceLabels.UI_FALLBACK,
                normalizedFallback,
                normalizedFallback.isPresent()
                        ? "reason=no_tracked_match"
                        : "reason=no_tracked_match_and_ui_unlabeled");
        return normalizedFallback;
    }

    private static RepeaterMetadataFields.Metadata normalizedFallbackMetadata(
            Supplier<RepeaterMetadataFields.Metadata> liveFallbackSupplier) {
        RepeaterMetadataFields.Metadata fallbackMetadata = liveFallbackSupplier == null
                ? RepeaterMetadataFields.Metadata.empty()
                : liveFallbackSupplier.get();
        return fallbackMetadata == null ? RepeaterMetadataFields.Metadata.empty() : fallbackMetadata;
    }

    private static void logLiveRepeaterMetadataDecision(
            String stage,
            String metadataSource,
            RepeaterMetadataFields.Metadata metadata,
            String reason) {
        ExportStats.recordRepeaterMetadataSource(metadataSource);
        Logger.logTrace("[TrafficHttpHandler] Live Repeater metadata stage="
                + RepeaterMetadataTraceLabels.safeValue(stage)
                + " metadataSource=" + RepeaterMetadataTraceLabels.safeValue(metadataSource)
                + " " + RepeaterMetadataTraceLabels.describeLiveMetadata(metadata)
                + " " + RepeaterMetadataTraceLabels.safeValue(reason));
    }

    /**
     * Empty response for live orphans; same shape and {@code "No response"} phrase as Proxy History.
     */
    private static Map<String, Object> buildOrphanResponse() {
        return RequestResponseDocBuilder.emptyTrafficResponseDoc();
    }

    /**
     * Writes {@code burp.proxy} and {@code burp.timing} for live HTTP documents.
     *
     * <p>Live HTTP has no History association; History-only fields remain unavailable.
     * Both callback families retain handler wall-clock timing; native Proxy additionally supplies
     * its own listener port without a History association.</p>
     *
     * @param burp burp sub-document to mutate
     * @param requestSentMs request-sent epoch millis, or {@code null}
     * @param responseReceivedMs response-end epoch millis, or {@code null}
     * @param listenerPort native Proxy listener port, or {@code null} for unavailable metadata
     */
    private static void putLiveProxyAndTiming(
            Map<String, Object> burp,
            Long requestSentMs,
            Long responseReceivedMs, Integer listenerPort) {
        burp.put("proxy", BurpProxyFields.withoutProxyHistoryEditMetadata(listenerPort));
        burp.put("timing", BurpTimingFields.fromHandlerEpochMillis(requestSentMs, responseReceivedMs));
    }

    /**
     * Package-private entry for orphan-flush regression tests in
     * {@code ai.anomalousvectors.tools.burp.sinks}.
     */
    static void flushOrphanedRequestsForTest() {
        flushOrphanedRequests();
    }

    /**
     * Package-private entry for orphan-flush regression tests in
     * {@code ai.anomalousvectors.tools.burp.sinks}.
     */
    static void clearPendingOrphansForTest() {
        synchronized (ORPHAN_LIFECYCLE_LOCK) {
            clearPendingPayloads();
            requestAdmissions = new LiveRequestReceipts(ORPHAN_TIMEOUT_MS);
        }
    }

    static void setReceiptCacheForTest(LiveRequestReceipts cache) {
        synchronized (ORPHAN_LIFECYCLE_LOCK) {
            clearPendingPayloads();
            requestAdmissions = cache;
        }
    }

    /**
     * Package-private entry for orphan-flush regression tests in
     * {@code ai.anomalousvectors.tools.burp.sinks}.
     */
    static void registerPendingOrphanForTest(
            int messageId,
            Map<String, Object> documentSkeleton,
            ToolType toolType,
            RequestStageResolution requestStageResolution) {
        registerPendingOrphanForTest(messageId, documentSkeleton, toolType, requestStageResolution, false);
    }

    static void registerPendingOrphanForTest(int messageId, Map<String, Object> documentSkeleton,
            ToolType toolType, RequestStageResolution requestStageResolution, boolean nativeProxy) {
        PendingOrphan pending = new PendingOrphan(documentSkeleton, 0L, toolType, requestStageResolution);
        MessageKey key = new MessageKey(nativeProxy, messageId);
        synchronized (ORPHAN_LIFECYCLE_LOCK) {
            if (requestAdmissions.beginRun(pending.runToken)) clearPendingPayloads();
            if (requestAdmissions.admit(key, 0L, toolType, pending.runToken, null) == null) {
                throw new IllegalStateException("Test request was not admitted.");
            }
            pendingOrphans.put(key, pending);
        }
    }

    /**
     * Package-private entry for orphan-flush regression tests in
     * {@code ai.anomalousvectors.tools.burp.sinks}.
     */
    static boolean containsPendingOrphanForTest(int messageId) {
        return pendingOrphans.containsKey(new MessageKey(false, messageId))
                || pendingOrphans.containsKey(new MessageKey(true, messageId));
    }

    /**
     * Exports timed-out pending requests as request-only documents.
     *
     * <p>Runs on the orphan-flush daemon thread. Requests older than
     * {@link #ORPHAN_TIMEOUT_MS} receive the same empty response as Proxy History
     * ({@code status.code=0}, description {@code No response}).</p>
     */
    private static void flushOrphanedRequests() {
        try {
            flushOrphanedRequestsSafely();
        } catch (RuntimeException e) {
            Logger.logError("[Traffic] Orphan flush failed: error=" + e.getClass().getSimpleName()
                    + "; later scheduled checks will continue.");
        } finally {
            LiveRequestReceipts.Snapshot pressure;
            synchronized (ORPHAN_LIFECYCLE_LOCK) {
                pressure = requestAdmissions.takePressureSummary(false);
            }
            logReceiptPressure(pressure);
        }
    }

    private static void flushOrphanedRequestsSafely() {
        if (!RuntimeConfig.isExportReady()) {
            return;
        }
        if (!RuntimeConfig.trafficExportGate().anyTrafficExportEnabled()) {
            synchronized (ORPHAN_LIFECYCLE_LOCK) {
                pendingOrphans.forEach((key, pending) ->
                        requestAdmissions.releasePayload(requestAdmissions.get(key)));
                clearPendingPayloads();
            }
            return;
        }
        long now = System.currentTimeMillis();
        List<MessageKey> toFlush = new ArrayList<>();
        for (Map.Entry<MessageKey, PendingOrphan> e : pendingOrphans.entrySet()) {
            if (now - e.getValue().timestamp >= ORPHAN_TIMEOUT_MS) {
                toFlush.add(e.getKey());
            }
        }
        long failed = 0;
        String failureType = "";
        for (MessageKey messageId : toFlush) {
            PendingOrphan po;
            LiveRequestReceipts.Receipt receipt;
            synchronized (ORPHAN_LIFECYCLE_LOCK) {
                po = pendingOrphans.remove(messageId);
                receipt = requestAdmissions.get(messageId);
            }
            if (po == null || !RuntimeConfig.isExportRunActive(po.runToken)) {
                if (po != null) po.releasePayload();
                continue;
            }
            boolean transferred = false;
            try {
                if (!shouldStillExportPendingOrphan(po)) {
                    ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 1);
                    continue;
                }
                transferred = exportOrphan(po, receipt);
            } catch (RuntimeException e) {
                if (RuntimeConfig.isExportRunActive(po.runToken)) {
                    TrafficRouteBucket.Route route = TrafficRouteBucket.fromToolType(
                            RuntimeConfig.normalizedToolTypeKey(po.toolType));
                    if (RuntimeConfig.isSearchTrafficEnabled()) {
                        ExportStats.recordFailure("traffic", 1);
                        TrafficRouteBucket.recordDatabaseFailure(route, 1);
                    }
                    if (RuntimeConfig.isAnyFileExportEnabled()) {
                        FileExportStats.recordFailure("traffic", 1);
                        TrafficRouteBucket.recordFileFailure(route, 1);
                    }
                }
                failed++;
                failureType = e.getClass().getSimpleName();
            } finally {
                po.releasePayload();
                if (!transferred) {
                    synchronized (ORPHAN_LIFECYCLE_LOCK) {
                        requestAdmissions.releasePayload(receipt);
                    }
                }
            }
        }
        if (failed > 0) {
            Logger.logError("[Traffic] Orphan export failed: count=" + failed + ", lastError=" + failureType
                    + "; admission outcomes are unknown; these request-only attempts will not be retried."
                    + " Later responses and scheduled checks remain eligible.");
        }
    }

    /** An uncertain queue admission must never be retried as a new operation. */
    private static boolean exportOrphan(PendingOrphan po, LiveRequestReceipts.Receipt receipt) {
        Map<String, Object> doc = po.capture == null
                ? new LinkedHashMap<>(po.documentSkeleton) : po.documentSkeleton;
        long nowMs = System.currentTimeMillis();
        Object burpObj = doc.get("burp");
        if (burpObj instanceof Map<?, ?> burpMap) {
            Map<String, Object> burp = StringKeyedMaps.copy(burpMap);
            burp.put("timing", BurpTimingFields.fromHandlerEpochMillis(po.timestamp, nowMs));
            doc.put("burp", burp);
        }
        doc.put("response", buildOrphanResponse());
        if (po.capture == null) {
            TrafficExportQueue.offerForRun(doc, po.runToken);
            return false;
        } else {
            LiveTrafficPreparation.Capture capture = po.capture;
            po.capture = null;
            capture.whenClosed(() -> {
                synchronized (ORPHAN_LIFECYCLE_LOCK) {
                    requestAdmissions.releasePayload(receipt);
                }
            });
            LiveTrafficPreparation.submit(capture);
            return true;
        }
    }

    static final class PendingOrphan {
        final Map<String, Object> documentSkeleton;
        final long timestamp;
        final ToolType toolType;
        final RequestStageResolution requestStageResolution;
        final RuntimeConfig.ExportRunToken runToken;
        final Integer listenerPort;
        private LiveTrafficPreparation.Capture capture;

        PendingOrphan(
                Map<String, Object> documentSkeleton,
                long timestamp,
                ToolType toolType,
                RequestStageResolution requestStageResolution) {
            this(documentSkeleton, timestamp, toolType, requestStageResolution,
                    RuntimeConfig.currentExportRunToken());
        }

        PendingOrphan(
                Map<String, Object> documentSkeleton,
                long timestamp,
                ToolType toolType,
                RequestStageResolution requestStageResolution,
                RuntimeConfig.ExportRunToken runToken) {
            this(documentSkeleton, timestamp, toolType, requestStageResolution, runToken, null);
        }

        PendingOrphan(Map<String, Object> documentSkeleton, long timestamp, ToolType toolType,
                RequestStageResolution requestStageResolution, RuntimeConfig.ExportRunToken runToken,
                Integer listenerPort) {
            this(documentSkeleton, timestamp, toolType, requestStageResolution, runToken, listenerPort, null);
        }

        PendingOrphan(Map<String, Object> documentSkeleton, long timestamp, ToolType toolType,
                RequestStageResolution requestStageResolution, RuntimeConfig.ExportRunToken runToken,
                Integer listenerPort, LiveTrafficPreparation.Capture capture) {
            this.documentSkeleton = documentSkeleton;
            this.timestamp = timestamp;
            this.toolType = toolType;
            this.runToken = runToken;
            this.listenerPort = listenerPort;
            this.capture = capture;
            this.requestStageResolution = requestStageResolution == null
                    ? RequestStageResolution.none()
                    : requestStageResolution;
        }

        private void releasePayload() {
            if (capture != null) {
                capture.close();
                capture = null;
            }
        }
    }

    static record RequestStageResolution(
            RepeaterMetadataFields.Metadata metadata,
            String sourceLabel,
            RepeaterMetadataFields.Metadata uiSnapshot) {

        RequestStageResolution {
            metadata = metadata == null ? RepeaterMetadataFields.Metadata.empty() : metadata;
            sourceLabel = sourceLabel == null || sourceLabel.isBlank()
                    ? RepeaterMetadataTraceLabels.NONE
                    : sourceLabel.trim();
            uiSnapshot = uiSnapshot == null ? RepeaterMetadataFields.Metadata.empty() : uiSnapshot;
        }

        static RequestStageResolution none() {
            return new RequestStageResolution(
                    RepeaterMetadataFields.Metadata.empty(),
                    RepeaterMetadataTraceLabels.NONE,
                    RepeaterMetadataFields.Metadata.empty());
        }

        static RequestStageResolution confident(
                RepeaterMetadataFields.Metadata metadata,
                String sourceLabel) {
            return new RequestStageResolution(
                    metadata,
                    sourceLabel,
                    RepeaterMetadataFields.Metadata.empty());
        }

        static RequestStageResolution ambiguous(
                String sourceLabel,
                RepeaterMetadataFields.Metadata uiSnapshot) {
            return new RequestStageResolution(
                    RepeaterMetadataFields.Metadata.empty(),
                    sourceLabel,
                    uiSnapshot);
        }

        static RequestStageResolution fromMetadata(RepeaterMetadataFields.Metadata metadata) {
            return confident(metadata, RepeaterMetadataTraceLabels.REQUEST_STAGE_REUSE);
        }

        RepeaterMetadataFields.Metadata metadataForExport() {
            return metadata.isPresent() ? metadata : uiSnapshot;
        }
    }

}
