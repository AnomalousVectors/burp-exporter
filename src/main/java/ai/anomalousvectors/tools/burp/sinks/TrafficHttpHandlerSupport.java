package ai.anomalousvectors.tools.burp.sinks;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
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
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Shared implementation for live HTTP traffic capture.
 *
 * <p>{@link TrafficHttpHandler} exposes the public sink-neutral type while this package-private
 * support class keeps the larger implementation isolated from the tiny entrypoint wrapper.</p>
 */
class TrafficHttpHandlerSupport implements HttpHandler {

    private static final String SCHEMA_VERSION = "1";

    /** Delay after which a request with no response is exported as an orphan (Chromium-aligned). */
    private static final long ORPHAN_TIMEOUT_MS = 120_000L;
    private static final int ORPHAN_CHECK_INTERVAL_SECONDS = 30;
    /** Sentinel for response when no response was received (e.g. timeout). */
    private static final int ORPHAN_STATUS = 0;
    private static final String ORPHAN_REASON_PHRASE = "Timeout";

    private static final ConcurrentHashMap<Integer, PendingOrphan> pendingOrphans = new ConcurrentHashMap<>();

    /**
     * Scheduler that periodically flushes orphaned (response-less) requests as timeout documents.
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
        ORPHAN_SCHEDULER.stop();
        pendingOrphans.clear();
    }

    /**
     * Returns the current number of pending request/response orphan entries awaiting
     * correlation or timeout-driven flush. Used by Misc Stats and the periodic memory-sample
     * log to detect unbounded orphan growth (a symptom of listener misbehavior or network
     * stalls that keep responses from arriving within the orphan TTL).
     */
    public static int getPendingOrphansSize() {
        return pendingOrphans.size();
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
            URI uri = URI.create(baseUrl.trim());
            String configHost = uri.getHost();
            if (configHost == null) {
                return false;
            }
            int configPort = uri.getPort();
            if (configPort < 0) {
                configPort = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
            }
            return configHost.equalsIgnoreCase(requestHost) && configPort == requestPort;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        RuntimeConfig.TrafficExportGate trafficGate = RuntimeConfig.trafficExportGate();
        if (!RuntimeConfig.isExportReady()
                || !trafficGate.anyTrafficExportEnabled()) {
            return RequestToBeSentAction.continueWith(request);
        }
        String scopeUrl = RequestResponseDocBuilder.buildBestEffortUrl(
                request,
                request.httpService(),
                RequestResponseDocBuilder.buildTrafficRequestDoc(request),
                "TrafficHttpHandler");
        if (!ScopeFilter.shouldExport(
                RuntimeConfig.getState(), scopeUrl, request.isInScope())) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1);
            return RequestToBeSentAction.continueWith(request);
        }
        ToolSource toolSource = request.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        if (!shouldExportTrafficByToolSource(toolType)) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 1);
            return RequestToBeSentAction.continueWith(request);
        }
        if (toolType == ToolType.EXTENSIONS) {
            HttpService svc = request.httpService();
            if (svc != null && isRequestToConfiguredOpenSearch(svc.host(), svc.port())) {
                ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SELF_OPENSEARCH, 1);
                return RequestToBeSentAction.continueWith(request);
            }
        }
        long requestSentMs = System.currentTimeMillis();
        ToolSource reqToolSource = request.toolSource();
        ToolType reqToolType = reqToolSource == null ? null : reqToolSource.toolType();
        RequestStageResolution requestStageResolution =
                resolveRequestStageResolution(
                        request,
                        reqToolType,
                        RepeaterTabsIndexReporter::currentRepeaterSharedMetadataForLiveFallback);
        Map<String, Object> skeleton = buildOrphanDocumentSkeleton(
                request,
                requestSentMs,
                requestStageResolution.metadataForExport());
        if (skeleton != null) {
            pendingOrphans.put(
                    request.messageId(),
                    new PendingOrphan(skeleton, requestSentMs, reqToolType, requestStageResolution));
            ensureOrphanSchedulerStarted();
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!RuntimeConfig.isExportReady()) {
            return ResponseReceivedAction.continueWith(response);
        }
        if (!RuntimeConfig.trafficExportGate().anyTrafficExportEnabled()) {
            return ResponseReceivedAction.continueWith(response);
        }

        HttpRequest request = response.initiatingRequest();
        if (request == null) {
            return ResponseReceivedAction.continueWith(response);
        }

        boolean burpInScope = request.isInScope();
        String scopeUrl = RequestResponseDocBuilder.buildBestEffortUrl(
                request,
                request.httpService(),
                RequestResponseDocBuilder.buildTrafficRequestDoc(request),
                "TrafficHttpHandler");
        boolean inScope = ScopeFilter.shouldExport(
                RuntimeConfig.getState(), scopeUrl, burpInScope);
        if (!inScope) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1);
            return ResponseReceivedAction.continueWith(response);
        }

        PendingOrphan pending = pendingOrphans.get(response.messageId());
        ToolType requestFallbackType = pending == null ? null : pending.toolType;
        ToolSource responseSource = response.toolSource();
        ToolType responseType = responseSource == null ? null : responseSource.toolType();
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
            toolType = null; // allowed unknown source when proxy traffic export is enabled
        } else {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 1);
            pendingOrphans.remove(response.messageId());
            return ResponseReceivedAction.continueWith(response);
        }

        if (toolType == ToolType.EXTENSIONS || toolType == null) {
            HttpService svc = request.httpService();
            if (svc != null && isRequestToConfiguredOpenSearch(svc.host(), svc.port())) {
                ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SELF_OPENSEARCH, 1);
                pendingOrphans.remove(response.messageId());
                return ResponseReceivedAction.continueWith(response);
            }
        }

        long responseReceivedMs = System.currentTimeMillis();
        Long requestSentMs = pending == null ? null : pending.timestamp;
        RepeaterMetadataFields.Metadata repeaterMetadata =
                resolveResponseStageRepeaterMetadata(
                        request,
                        response,
                        toolType,
                        pending == null ? RequestStageResolution.none() : pending.requestStageResolution,
                        RepeaterTabsIndexReporter::currentRepeaterSharedMetadataForLiveFallback);

        Map<String, Object> document =
                buildDocument(response, request, burpInScope, requestSentMs, responseReceivedMs, toolType, repeaterMetadata);
        copyMissingAnnotationFieldsFromPendingRequest(document, pending);
        TrafficExportQueue.offer(document);

        pendingOrphans.remove(response.messageId());
        return ResponseReceivedAction.continueWith(response);
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
     * Builds the traffic document for OpenSearch. Caller must hold Burp HTTP thread.
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
        HttpService service = request.httpService();
        ToolSource toolSource = response.toolSource();
        ToolType toolType = resolvedToolType;
        if (toolType == null) {
            toolType = toolSource == null ? null : toolSource.toolType();
        }
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        String url = RequestResponseDocBuilder.buildBestEffortUrl(
                request,
                service,
                requestDoc,
                "TrafficHttpHandler");
        requestDoc.put("url", HttpMessageDocSupport.urlObject(url, service));
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));

        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", toolType == null ? null : toolType.toolName());
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", response.messageId());
        BurpAnnotationFields.put(burp, response.annotations());
        burp.put("timing", BurpTimingFields.fromHandlerEpochMillis(requestSentMs, responseReceivedMs));
        burp.put("proxy", BurpProxyFields.withoutProxyHistoryEditMetadata(null));
        document.put("burp", burp);
        RepeaterMetadataFields.put(document, repeaterMetadata);

        document.put("request", requestDoc);
        document.put("response", RequestResponseDocBuilder.buildTrafficResponseDoc(response));
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());

        document.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
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
     * {@link #buildOrphanResponse()} when exporting.
     */
    private Map<String, Object> buildOrphanDocumentSkeleton(
            HttpRequestToBeSent request,
            long requestSentMs,
            RepeaterMetadataFields.Metadata repeaterMetadata) {
        HttpService service = request.httpService();
        ToolSource toolSource = request.toolSource();
        ToolType toolType = toolSource == null ? null : toolSource.toolType();
        boolean burpInScope = request.isInScope();
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        String url = RequestResponseDocBuilder.buildBestEffortUrl(
                request,
                service,
                requestDoc,
                "TrafficHttpHandler");
        requestDoc.put("url", HttpMessageDocSupport.urlObject(url, service));
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));

        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", toolType == null ? null : toolType.toolName());
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", request.messageId());
        BurpAnnotationFields.put(burp, request.annotations());
        burp.put("timing", BurpTimingFields.fromHandlerEpochMillis(requestSentMs, null));
        burp.put("proxy", BurpProxyFields.withoutProxyHistoryEditMetadata(null));
        document.put("burp", burp);
        RepeaterMetadataFields.put(document, repeaterMetadata);

        document.put("request", requestDoc);
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());

        document.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
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
            HttpResponseReceived response,
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
            HttpResponseReceived response,
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
            HttpResponseReceived response,
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

    private static Map<String, Object> buildOrphanResponse() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", TrafficResponseStatusFields.of(ORPHAN_STATUS, null, ORPHAN_REASON_PHRASE));
        resp.put("protocol", TrafficProtocolFields.responseProtocol(null));
        resp.put("headers", Collections.emptyList());
        resp.put("cookies", Collections.emptyList());
        resp.put("mime_type", HttpMessageDocSupport.responseMimeType(Collections.emptyList(), null));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", 0);
        body.put("offset", 0);
        body.put("b64", null);
        body.put("text", null);
        body.put("markers", Collections.emptyList());
        resp.put("body", body);
        return resp;
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
        pendingOrphans.clear();
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
        pendingOrphans.put(
                messageId,
                new PendingOrphan(documentSkeleton, 0L, toolType, requestStageResolution));
    }

    /**
     * Package-private entry for orphan-flush regression tests in
     * {@code ai.anomalousvectors.tools.burp.sinks}.
     */
    static boolean containsPendingOrphanForTest(int messageId) {
        return pendingOrphans.containsKey(messageId);
    }

    /**
     * Exports timed-out pending requests as request-only documents.
     *
     * <p>Runs on the orphan-flush daemon thread. Requests older than
     * {@link #ORPHAN_TIMEOUT_MS} receive status code {@code 0} and description
     * {@code Timeout}.</p>
     */
    private static void flushOrphanedRequests() {
        if (!RuntimeConfig.isExportReady()) {
            return;
        }
        if (!RuntimeConfig.trafficExportGate().anyTrafficExportEnabled()) {
            pendingOrphans.clear();
            return;
        }
        long now = System.currentTimeMillis();
        List<Integer> toFlush = new ArrayList<>();
        for (Map.Entry<Integer, PendingOrphan> e : pendingOrphans.entrySet()) {
            if (now - e.getValue().timestamp >= ORPHAN_TIMEOUT_MS) {
                toFlush.add(e.getKey());
            }
        }
        for (Integer messageId : toFlush) {
            PendingOrphan po = pendingOrphans.remove(messageId);
            if (po == null) {
                continue;
            }
            if (!shouldStillExportPendingOrphan(po)) {
                ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 1);
                continue;
            }
            Map<String, Object> doc = new LinkedHashMap<>(po.documentSkeleton);
            long nowMs = System.currentTimeMillis();
            Object burpObj = doc.get("burp");
            if (burpObj instanceof Map<?, ?> burpMap) {
                Map<String, Object> burp = StringKeyedMaps.copy(burpMap);
                burp.put("timing", BurpTimingFields.fromHandlerEpochMillis(po.timestamp, nowMs));
                doc.put("burp", burp);
            }
            doc.put("response", buildOrphanResponse());
            TrafficExportQueue.offer(doc);
        }
    }

    static final class PendingOrphan {
        final Map<String, Object> documentSkeleton;
        final long timestamp;
        final ToolType toolType;
        final RequestStageResolution requestStageResolution;

        PendingOrphan(
                Map<String, Object> documentSkeleton,
                long timestamp,
                ToolType toolType,
                RequestStageResolution requestStageResolution) {
            this.documentSkeleton = documentSkeleton;
            this.timestamp = timestamp;
            this.toolType = toolType;
            this.requestStageResolution = requestStageResolution == null
                    ? RequestStageResolution.none()
                    : requestStageResolution;
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
