package ai.anomalousvectors.tools.burp.sinks;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.nio.charset.StandardCharsets;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

/**
 * Builds request and response sub-documents in the same shape as the traffic index,
 * for use by {@link TrafficHttpHandler}, {@link SitemapIndexReporter}, and findings evidence pairs.
 */
public final class RequestResponseDocBuilder {

    private RequestResponseDocBuilder() {}

    /** @see RequestResponseParametersSupport.ParametersResult */
    public record ParametersResult(
            List<Map<String, Object>> entries,
            int droppedSynthesized,
            boolean bodyEnumerationSkipped,
            int droppedUrlParams,
            String adjustedQuery,
            int droppedBodyParams,
            String bodyParamsSource,
            boolean wireBodyParamsReplaced,
            boolean skipPathBodyRescued,
            boolean wireTransformed,
            List<String> encodingsApplied,
            int wireBodyParamsDropped,
            boolean supplementalRejectedNonForm) {
        private static ParametersResult from(RequestResponseParametersSupport.ParametersResult result) {
            return new ParametersResult(
                    result.entries(),
                    result.droppedSynthesized(),
                    result.bodyEnumerationSkipped(),
                    result.droppedUrlParams(),
                    result.adjustedQuery(),
                    result.droppedBodyParams(),
                    result.bodyParamsSource(),
                    result.wireBodyParamsReplaced(),
                    result.skipPathBodyRescued(),
                    result.wireTransformed(),
                    result.encodingsApplied(),
                    result.wireBodyParamsDropped(),
                    result.supplementalRejectedNonForm());
        }

        boolean urlParamsTruncated() {
            return droppedUrlParams > 0;
        }

        boolean bodyParamsTruncated() {
            return droppedBodyParams > 0;
        }
    }

    static ParametersResult collectParameters(HttpRequest request, boolean includeBody) {
        return ParametersResult.from(RequestResponseParametersSupport.collectParameters(request, includeBody));
    }

    static ParametersResult parametersToList(List<ParsedHttpParameter> parameters, boolean includeBody) {
        return ParametersResult.from(RequestResponseParametersSupport.parametersToList(parameters, includeBody));
    }

    static void recordParameterStats(
            HttpRequest request,
            ContentType contentType,
            ParametersResult parametersResult) {
        RequestResponseParametersSupport.recordParameterStats(request, contentType, toSupport(parametersResult));
    }

    private static RequestResponseParametersSupport.ParametersResult toSupport(ParametersResult result) {
        return new RequestResponseParametersSupport.ParametersResult(
                result.entries(),
                result.droppedSynthesized(),
                result.bodyEnumerationSkipped(),
                result.droppedUrlParams(),
                result.adjustedQuery(),
                result.droppedBodyParams(),
                result.bodyParamsSource(),
                result.wireBodyParamsReplaced(),
                result.skipPathBodyRescued(),
                result.wireTransformed(),
                result.encodingsApplied(),
                result.wireBodyParamsDropped(),
                result.supplementalRejectedNonForm());
    }

    /** Bridges legacy tests that pass scalar export-stats fields. */
    static void recordParameterStats(
            HttpRequest request,
            ContentType contentType,
            int retained,
            int droppedSynthesized,
            boolean bodyEnumerationSkipped) {
        if (droppedSynthesized > 0) {
            RequestResponseParametersSupport.recordParameterStats(
                    request,
                    contentType,
                    new RequestResponseParametersSupport.ParametersResult(
                            List.of(),
                            droppedSynthesized,
                            bodyEnumerationSkipped,
                            0,
                            "",
                            0,
                            RequestResponseParametersSupport.BODY_PARAMS_SOURCE_NONE,
                            false,
                            false,
                            false,
                            List.of(),
                            0,
                            false));
        } else if (bodyEnumerationSkipped) {
            RequestResponseParametersSupport.recordParameterStats(
                    request,
                    contentType,
                    new RequestResponseParametersSupport.ParametersResult(
                            List.of(),
                            0,
                            true,
                            0,
                            "",
                            0,
                            RequestResponseParametersSupport.BODY_PARAMS_SOURCE_NONE,
                            false,
                            false,
                            false,
                            List.of(),
                            0,
                            false));
        }
    }

    static boolean shouldIncludeBodyParameters(
            ContentType contentType, List<HttpHeader> headers, String inferredContentType) {
        return shouldIncludeBodyParameters(contentType, headers, inferredContentType, null);
    }

    static boolean shouldIncludeBodyParameters(
            ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType,
            byte[] bodyBytes) {
        return RequestResponseParametersSupport.shouldIncludeBodyParameters(
                contentType, headers, inferredContentType, bodyBytes);
    }

    static String inferRequestContentType(byte[] bodyBytes, List<HttpHeader> headers) {
        return RequestResponseParametersSupport.inferRequestContentType(bodyBytes, headers);
    }

    public static List<Map<String, Object>> convertMarkersToList(List<Marker> markers) {
        return HttpMessageDocSupport.convertMarkersToList(markers);
    }

    public static List<Map<String, Object>> convertTrafficMarkersToList(List<Marker> markers) {
        return HttpMessageDocSupport.convertTrafficMarkersToList(markers);
    }

    static String statusCodeClassName(short statusCode) {
        return RequestResponseParametersSupport.statusCodeClassName(statusCode);
    }

    /**
     * Builds a flat request sub-document for callers that still need the older HTTP shape.
     *
     * <p>Malformed Montoya accessors are handled by a best-effort fallback and a DEBUG log line;
     * callers receive a partial request document instead of an exception.</p>
     *
     * @param request source request; {@code null} produces an empty fallback document
     * @return mutable request document map
     */
    public static Map<String, Object> buildRequestDoc(HttpRequest request) {
        if (request == null) {
            return buildFallbackRequestDoc(null, false);
        }
        try {
            return buildRequestDocStrict(request);
        } catch (RuntimeException e) {
            Logger.logDebug("[RequestResponseDocBuilder] request fallback due to malformed request: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return buildFallbackRequestDoc(request, false);
        }
    }

    /**
     * Builds a request sub-document for the traffic index (nested {@code content_type}, headers,
     * parameters, body).
     */
    public static Map<String, Object> buildTrafficRequestDoc(HttpRequest request) {
        if (request == null) {
            return buildFallbackRequestDoc(null, true);
        }
        try {
            return buildTrafficRequestDocStrict(request);
        } catch (RuntimeException e) {
            Logger.logDebug("[RequestResponseDocBuilder] traffic request fallback due to malformed request: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return buildFallbackRequestDoc(request, true);
        }
    }

    /**
     * Builds a request sub-document for the sitemap index using the traffic shape but URL-only
     * parameters. Burp's sitemap is a URL inventory, and avoiding unfiltered parameter enumeration
     * keeps large or content-type-spoofed bodies from materializing synthetic BODY parameters.
     */
    public static Map<String, Object> buildSitemapRequestDoc(HttpRequest request) {
        if (request == null) {
            return buildFallbackSitemapRequestDoc(null);
        }
        try {
            return buildSitemapRequestDocStrict(request);
        } catch (RuntimeException e) {
            Logger.logDebug("[RequestResponseDocBuilder] sitemap request fallback due to malformed request: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            return buildFallbackSitemapRequestDoc(request);
        }
    }

    /**
     * Resolves the best-effort request URL for top-level traffic documents.
     *
     * <p>When {@link HttpRequest#url()} throws for malformed or partially bound Repeater requests,
     * this helper reconstructs a usable URL from {@link HttpService} plus the already-recovered
     * request path so top-level fields stay aligned with the nested request document.</p>
     *
     * @param request request whose direct URL accessor may throw
     * @param service HTTP service backing the request
     * @param requestDoc already-built request sub-document, usually from {@link #buildTrafficRequestDoc(HttpRequest)}
     *     or {@link #buildSitemapRequestDoc(HttpRequest)}
     * @param logPrefix logger prefix without brackets, for example {@code "RepeaterTabs"}
     * @return direct URL when available, otherwise a best-effort reconstructed URL or {@code null}
     */
    public static String buildBestEffortUrl(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            String logPrefix) {
        if (request != null && requestDoc != null && requestDocQueryDiffersFromBurp(request, requestDoc)) {
            String narrowedPath = HttpMessageDocSupport.normalizeBlank(requestPathWithQuery(requestDoc));
            String rebuilt = reconstructAbsoluteUrl(service, narrowedPath);
            if (rebuilt != null) {
                return rebuilt;
            }
            if (narrowedPath != null) {
                return narrowedPath;
            }
        }
        String directUrl = safeRequestUrl(request, logPrefix);
        if (directUrl != null) {
            return directUrl;
        }
        String path = HttpMessageDocSupport.normalizeBlank(requestPathWithQuery(requestDoc));
        return reconstructAbsoluteUrl(service, path);
    }

    private static String reconstructAbsoluteUrl(HttpService service, String path) {
        if (path == null) {
            return null;
        }
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        if (service == null || HttpMessageDocSupport.normalizeBlank(service.host()) == null) {
            return null;
        }
        String scheme = service.secure() ? "https" : "http";
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        return scheme + "://" + service.host() + portSuffix(scheme, service.port()) + normalizedPath;
    }

    private static void applyUrlParameterCapToRequestFields(
            Map<String, Object> req,
            String method,
            String pathWithQuery,
            String pathWithoutQuery,
            String query,
            String fileExtension,
            ParametersResult parametersResult,
            boolean trafficShape) {
        String effectiveQuery = query;
        String effectivePathWithQuery = pathWithQuery;
        if (parametersResult.urlParamsTruncated()) {
            effectiveQuery = parametersResult.adjustedQuery();
            effectivePathWithQuery = RequestResponseParametersSupport.buildPathWithQuery(
                    pathWithoutQuery, effectiveQuery);
        }
        putRequestCoreFields(
                req,
                method,
                effectivePathWithQuery,
                pathWithoutQuery,
                effectiveQuery,
                fileExtension,
                trafficShape);
    }

    private static void finalizeParameterStats(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            ContentType contentType,
            List<HttpHeader> requestHeaders,
            String inferredContentType,
            byte[] bodyBytes,
            ParametersResult parametersResult) {
        recordParameterStats(request, contentType, parametersResult);
        boolean misgateSuspect = BodyEnumerationSkippedLog.isMisgateSuspect(
                contentType,
                requestHeaders,
                inferredContentType,
                bodyBytes,
                parametersResult.bodyEnumerationSkipped());
        recordParameterIntegrityStats(parametersResult, misgateSuspect);
        recordCompressedWireBodyParamsLog(request, service, requestDoc, parametersResult);
        if (parametersResult.urlParamsTruncated()) {
            UrlParameterTruncationLog.record(
                    request,
                    service,
                    requestDoc,
                    parametersResult.droppedUrlParams());
        }
        if (parametersResult.bodyParamsTruncated()) {
            BodyParameterTruncationLog.record(
                    request,
                    service,
                    requestDoc,
                    parametersResult.droppedBodyParams());
        }
        BodyEnumerationSkippedLog.evaluateAndRecord(
                request,
                service,
                requestDoc,
                contentType,
                requestHeaders,
                inferredContentType,
                bodyBytes,
                parametersResult.bodyEnumerationSkipped());
    }

    private static void recordParameterIntegrityStats(
            ParametersResult parametersResult,
            boolean misgateSuspect) {
        if (parametersResult == null) {
            return;
        }
        if (misgateSuspect) {
            ExportStats.recordBodyEnumerationMisgateSuspect();
        }
        if (parametersResult.bodyEnumerationSkipped()) {
            ExportStats.recordSkippedBodyParameterEnumeration();
        }
        String source = parametersResult.bodyParamsSource();
        if (source != null && !source.isBlank()) {
            ExportStats.recordBodyParamsSource(source);
        }
        if (parametersResult.encodingsApplied() != null) {
            for (String encoding : parametersResult.encodingsApplied()) {
                if (encoding != null && !encoding.isBlank()) {
                    ExportStats.recordBodyParamsEncoding(encoding);
                }
            }
        }
        String skipReason = resolveBodyParamsSkipReason(parametersResult, misgateSuspect);
        if (skipReason == null || skipReason.isBlank()) {
            return;
        }
        ExportStats.recordBodyParamsSkipReason(skipReason);
        switch (skipReason) {
            case "wire_replaced" -> ExportStats.recordWireBodyParamsReplaced();
            case "supplemental_added" -> ExportStats.recordSupplementalBodyParamsUsed();
            case "supplemental_rejected_non_form" -> ExportStats.recordSupplementalRejectedNonForm();
            case "skip_path_rescued" -> ExportStats.recordSkipPathBodyRescued();
            default -> {
                // misgate_binary, enumeration_skipped, wire_dropped, etc.
            }
        }
    }

    /**
     * Resolves the per-document skip/correction reason for parameter-integrity session stats.
     *
     * @param parametersResult collected parameter metadata
     * @param misgateSuspect whether the mis-gate suspect criteria matched
     * @return keyword reason, or {@code null} when no special path applied
     */
    static String resolveBodyParamsSkipReason(ParametersResult parametersResult, boolean misgateSuspect) {
        if (parametersResult.supplementalRejectedNonForm()) {
            return "supplemental_rejected_non_form";
        }
        if (parametersResult.skipPathBodyRescued()) {
            return "skip_path_rescued";
        }
        if (parametersResult.wireBodyParamsReplaced()) {
            return "wire_replaced";
        }
        if (misgateSuspect) {
            return "misgate_binary";
        }
        if (parametersResult.wireTransformed()
                && parametersResult.wireBodyParamsDropped() > 0
                && RequestResponseParametersSupport.BODY_PARAMS_SOURCE_NONE.equals(
                        parametersResult.bodyParamsSource())) {
            return "wire_dropped";
        }
        if (RequestResponseParametersSupport.BODY_PARAMS_SOURCE_SUPPLEMENTAL.equals(
                        parametersResult.bodyParamsSource())
                && !parametersResult.wireBodyParamsReplaced()) {
            return "supplemental_added";
        }
        if (parametersResult.bodyEnumerationSkipped()) {
            return "enumeration_skipped";
        }
        return null;
    }

    private static void recordCompressedWireBodyParamsLog(
            HttpRequest request,
            HttpService service,
            Map<String, Object> requestDoc,
            ParametersResult parametersResult) {
        if (parametersResult.supplementalRejectedNonForm()) {
            CompressedWireBodyParamsLog.record(
                    request,
                    service,
                    requestDoc,
                    CompressedWireBodyParamsLog.Category.SUPPLEMENTAL_REJECTED_NON_FORM);
            return;
        }
        if (parametersResult.wireBodyParamsReplaced()) {
            CompressedWireBodyParamsLog.record(
                    request, service, requestDoc, CompressedWireBodyParamsLog.Category.REPLACED);
            return;
        }
        if (parametersResult.skipPathBodyRescued()) {
            CompressedWireBodyParamsLog.record(
                    request, service, requestDoc, CompressedWireBodyParamsLog.Category.SKIP_RESCUED);
            return;
        }
        if (parametersResult.wireTransformed()
                && parametersResult.wireBodyParamsDropped() > 0
                && RequestResponseParametersSupport.BODY_PARAMS_SOURCE_NONE.equals(
                        parametersResult.bodyParamsSource())) {
            CompressedWireBodyParamsLog.record(
                    request, service, requestDoc, CompressedWireBodyParamsLog.Category.WIRE_DROPPED);
            return;
        }
        if ((RequestResponseParametersSupport.BODY_PARAMS_SOURCE_SUPPLEMENTAL.equals(
                        parametersResult.bodyParamsSource())
                || RequestResponseParametersSupport.BODY_PARAMS_SOURCE_MIXED.equals(
                        parametersResult.bodyParamsSource()))
                && !parametersResult.wireTransformed()
                && RequestResponseParametersSupport.hasBodyParameterEntry(parametersResult.entries())) {
            CompressedWireBodyParamsLog.record(
                    request, service, requestDoc, CompressedWireBodyParamsLog.Category.SUPPLEMENTAL_ADDED);
        }
    }

    private static boolean requestDocQueryDiffersFromBurp(HttpRequest request, Map<String, Object> requestDoc) {
        if (request == null || requestDoc == null) {
            return false;
        }
        try {
            String burpQuery = HttpMessageDocSupport.nullToEmpty(request.query());
            String docQuery = RequestResponseParametersSupport.requestDocQuery(requestDoc);
            return !burpQuery.equals(docQuery);
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static Map<String, Object> buildRequestDocStrict(HttpRequest request) {
        Map<String, Object> req = new LinkedHashMap<>();
        burp.api.montoya.http.message.ContentType contentType = request.contentType();
        List<HttpHeader> requestHeaders = request.headers();
        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        String inferredContentType =
                RequestResponseParametersSupport.inferRequestContentType(bodyBytes, requestHeaders, contentType);
        boolean includeBody = RequestResponseParametersSupport.shouldIncludeBodyParameters(
                contentType, requestHeaders, inferredContentType, bodyBytes);
        ParametersResult parametersResult = ParametersResult.from(
                RequestResponseParametersSupport.collectParameters(
                        request, includeBody, bodyBytes, contentType, requestHeaders));
        applyUrlParameterCapToRequestFields(
                req,
                request.method(),
                request.path(),
                request.pathWithoutQuery(),
                request.query(),
                request.fileExtension(),
                parametersResult,
                false);
        req.put("content_type", HttpMessageDocSupport.requestContentType(
                requestHeaders, contentType, inferredContentType));
        req.put("headers", HttpMessageDocSupport.headersToList(requestHeaders));
        req.put("parameters", parametersResult.entries());
        req.put("cookies", HttpMessageDocSupport.requestCookiesToList(requestHeaders));
        finalizeParameterStats(
                request, null, req, contentType, requestHeaders, inferredContentType, bodyBytes, parametersResult);

        HttpMessageDocSupport.putBodyFields(
                req,
                bodyBytes,
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                request.bodyOffset());

        req.put("markers", HttpMessageDocSupport.markersToList(request.markers()));
        return req;
    }

    private static Map<String, Object> buildTrafficRequestDocStrict(HttpRequest request) {
        Map<String, Object> req = new LinkedHashMap<>();
        burp.api.montoya.http.message.ContentType contentType = request.contentType();
        List<HttpHeader> requestHeaders = request.headers();
        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        String inferredContentType =
                RequestResponseParametersSupport.inferRequestContentType(bodyBytes, requestHeaders, contentType);
        boolean includeBody = RequestResponseParametersSupport.shouldIncludeBodyParameters(
                contentType, requestHeaders, inferredContentType, bodyBytes);
        ParametersResult parametersResult = ParametersResult.from(
                RequestResponseParametersSupport.collectParameters(
                        request, includeBody, bodyBytes, contentType, requestHeaders));
        applyUrlParameterCapToRequestFields(
                req,
                request.method(),
                request.path(),
                request.pathWithoutQuery(),
                request.query(),
                request.fileExtension(),
                parametersResult,
                true);
        req.put("content_type", HttpMessageDocSupport.requestContentType(
                requestHeaders, contentType, inferredContentType));
        req.put("headers", HttpMessageDocSupport.headersToList(requestHeaders));
        req.put("parameters", parametersResult.entries());
        req.put("cookies", HttpMessageDocSupport.requestCookiesToList(requestHeaders));
        finalizeParameterStats(
                request, null, req, contentType, requestHeaders, inferredContentType, bodyBytes, parametersResult);

        HttpMessageDocSupport.putBodyFields(
                req,
                bodyBytes,
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                request.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", HttpMessageDocSupport.trafficMarkersToList(request.markers()));
        return req;
    }

    private static Map<String, Object> buildSitemapRequestDocStrict(HttpRequest request) {
        Map<String, Object> req = new LinkedHashMap<>();
        burp.api.montoya.http.message.ContentType contentType = request.contentType();
        List<HttpHeader> requestHeaders = request.headers();
        byte[] bodyBytes = request.body() == null ? null : request.body().getBytes();
        String inferredContentType =
                RequestResponseParametersSupport.inferRequestContentType(bodyBytes, requestHeaders, contentType);
        ParametersResult parametersResult = ParametersResult.from(
                RequestResponseParametersSupport.sitemapParameters(
                        request, bodyBytes, contentType, requestHeaders));
        applyUrlParameterCapToRequestFields(
                req,
                request.method(),
                request.path(),
                request.pathWithoutQuery(),
                request.query(),
                request.fileExtension(),
                parametersResult,
                true);
        req.put("content_type", HttpMessageDocSupport.requestContentType(
                requestHeaders, contentType, inferredContentType));
        req.put("headers", HttpMessageDocSupport.headersToList(requestHeaders));
        req.put("parameters", parametersResult.entries());
        req.put("cookies", HttpMessageDocSupport.requestCookiesToList(requestHeaders));
        finalizeParameterStats(
                request, null, req, contentType, requestHeaders, inferredContentType, bodyBytes, parametersResult);

        HttpMessageDocSupport.putBodyFields(
                req,
                bodyBytes,
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                request.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", HttpMessageDocSupport.trafficMarkersToList(request.markers()));
        return req;
    }

    private static void putRequestCoreFields(
            Map<String, Object> req,
            String method,
            String pathWithQuery,
            String pathWithoutQuery,
            String query,
            String fileExtension,
            boolean trafficShape) {
        req.put("method", method);
        if (trafficShape) {
            req.put("path", TrafficRequestPathFields.from(pathWithQuery, pathWithoutQuery, query, fileExtension));
        } else {
            req.put("path", pathWithQuery);
            req.put("path_without_query", HttpMessageDocSupport.nullToEmpty(pathWithoutQuery));
            req.put("query", HttpMessageDocSupport.nullToEmpty(query));
            req.put("file_extension", HttpMessageDocSupport.nullToEmpty(fileExtension));
        }
    }

    /**
     * Resolves {@code request.path.with_query} from a traffic or legacy request sub-document.
     */
    static String requestPathWithQuery(Map<String, Object> requestDoc) {
        if (requestDoc == null) {
            return null;
        }
        Object path = requestDoc.get("path");
        if (path instanceof Map<?, ?> pathMap) {
            return HttpMessageDocSupport.stringValue(pathMap.get("with_query"));
        }
        return HttpMessageDocSupport.stringValue(path);
    }

    /**
     * Builds a request sub-document from raw bytes when Montoya accessors throw.
     *
     * <p>The fallback preserves export continuity for malformed Repeater requests by parsing the
     * raw request line and safely querying only the accessors that Burp still exposes. Missing
     * fields remain {@code null} instead of aborting the whole document.</p>
     */
    private static Map<String, Object> buildFallbackRequestDoc(HttpRequest request, boolean trafficShape) {
        RawRequestSnapshot raw = RawRequestSnapshot.from(request);
        Map<String, Object> req = new LinkedHashMap<>();
        burp.api.montoya.http.message.ContentType contentType = safeContentType(request);
        List<HttpHeader> requestHeaders = safeHeaders(request);
        String inferredContentType = RequestResponseParametersSupport.inferRequestContentType(
                raw.bodyBytes(), requestHeaders, contentType);
        ParametersResult parametersResult = safeParametersResult(
                request, contentType, requestHeaders, inferredContentType, raw.bodyBytes());
        applyUrlParameterCapToRequestFields(
                req,
                raw.method(),
                raw.path(),
                raw.pathWithoutQuery(),
                raw.query(),
                raw.fileExtension(),
                parametersResult,
                trafficShape);
        req.put("content_type", HttpMessageDocSupport.requestContentType(
                requestHeaders, contentType, inferredContentType));
        req.put("headers", HttpMessageDocSupport.headersToList(requestHeaders));
        req.put("parameters", parametersResult.entries());
        req.put("cookies", HttpMessageDocSupport.requestCookiesToList(requestHeaders));
        finalizeParameterStats(
                request, null, req, contentType, requestHeaders, inferredContentType, raw.bodyBytes(), parametersResult);

        HttpMessageDocSupport.putBodyFields(
                req,
                raw.bodyBytes(),
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                raw.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", safeTrafficMarkers(request));
        return req;
    }

    private static Map<String, Object> buildFallbackSitemapRequestDoc(HttpRequest request) {
        RawRequestSnapshot raw = RawRequestSnapshot.from(request);
        Map<String, Object> req = new LinkedHashMap<>();
        burp.api.montoya.http.message.ContentType contentType = safeContentType(request);
        List<HttpHeader> requestHeaders = safeHeaders(request);
        String inferredContentType = RequestResponseParametersSupport.inferRequestContentType(
                raw.bodyBytes(), requestHeaders, contentType);
        ParametersResult parametersResult = safeSitemapParametersResult(
                request, contentType, requestHeaders, raw.bodyBytes());
        applyUrlParameterCapToRequestFields(
                req,
                raw.method(),
                raw.path(),
                raw.pathWithoutQuery(),
                raw.query(),
                raw.fileExtension(),
                parametersResult,
                true);
        req.put("content_type", HttpMessageDocSupport.requestContentType(
                requestHeaders, contentType, inferredContentType));
        req.put("headers", HttpMessageDocSupport.headersToList(requestHeaders));
        req.put("parameters", parametersResult.entries());
        req.put("cookies", HttpMessageDocSupport.requestCookiesToList(requestHeaders));
        finalizeParameterStats(
                request, null, req, contentType, requestHeaders, inferredContentType, raw.bodyBytes(), parametersResult);

        HttpMessageDocSupport.putBodyFields(
                req,
                raw.bodyBytes(),
                requestHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        contentType == null ? null : contentType.toString(),
                        contentType == null ? null : contentType.name()),
                false,
                raw.bodyOffset());

        HttpMessageDocSupport.putRequestBodyField(req, "markers", safeTrafficMarkers(request));
        return req;
    }

    /**
     * Builds a flat response sub-document for callers that still need the older HTTP shape.
     *
     * @param response source response; must not be {@code null}
     * @return mutable response document map
     */
    public static Map<String, Object> buildResponseDoc(HttpResponse response) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status_code", (int) response.statusCode());
        resp.put("status_code_class", RequestResponseParametersSupport.statusCodeClassName(response.statusCode()));
        resp.put("status_description", response.reasonPhrase());
        resp.put("http_version", safeResponseHttpVersion(response));
        populateResponsePayload(resp, response, false);
        return resp;
    }

    /**
     * Builds a response sub-document for the traffic index ({@code status}, {@code protocol},
     * nested {@code mime_type}, headers, body, cookies).
     */
    public static Map<String, Object> buildTrafficResponseDoc(HttpResponse response) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", TrafficResponseStatusFields.from(response));
        resp.put("protocol", TrafficProtocolFields.responseProtocol(safeResponseHttpVersion(response)));
        populateResponsePayload(resp, response, true);
        return resp;
    }

    /**
     * Empty traffic-index response used when a pair has no response yet (orphans, history rows).
     */
    public static Map<String, Object> emptyTrafficResponseDoc() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", TrafficResponseStatusFields.of(0, null, "No response"));
        response.put("protocol", TrafficProtocolFields.responseProtocol(null));
        response.put("headers", List.of());
        response.put("cookies", List.of());
        response.put("mime_type", HttpMessageDocSupport.responseMimeType(List.of(), null));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("length", 0);
        body.put("offset", 0);
        body.put("b64", null);
        body.put("text", null);
        body.put("markers", List.of());
        response.put("body", body);
        return response;
    }

    private static void populateResponsePayload(
            Map<String, Object> resp,
            HttpResponse response,
            boolean trafficShape) {
        List<HttpHeader> responseHeaders = response.headers();
        resp.put("headers", HttpMessageDocSupport.headersToList(responseHeaders));
        String responseDate = HttpMessageDocSupport.headerValue(responseHeaders, "Date");
        if (responseDate != null) {
            HttpMessageDocSupport.putResponseHeaderField(resp, "date", responseDate);
        }
        resp.put("cookies", HttpMessageDocSupport.responseCookiesToList(response.cookies(), responseHeaders));
        resp.put("mime_type", HttpMessageDocSupport.responseMimeType(responseHeaders, response));

        MimeType mime = response.mimeType();
        MimeType stated = response.statedMimeType();
        MimeType inferred = response.inferredMimeType();
        boolean montoyaTextualHint = HttpMessageDocSupport.isTextualMimeHint(mime) || HttpMessageDocSupport.isTextualMimeHint(stated) || HttpMessageDocSupport.isTextualMimeHint(inferred);

        byte[] bodyBytes = response.body() == null ? null : response.body().getBytes();
        HttpMessageDocSupport.putBodyFields(
                resp,
                bodyBytes,
                responseHeaders,
                HttpMessageDocSupport.mediaTypeHints(
                        HttpMessageDocSupport.mimeTypeHint(mime),
                        HttpMessageDocSupport.mimeTypeHint(stated),
                        HttpMessageDocSupport.mimeTypeHint(inferred)),
                montoyaTextualHint,
                response.bodyOffset(),
                false);

        if (trafficShape) {
            HttpMessageDocSupport.putResponseBodyField(resp, "markers", HttpMessageDocSupport.trafficMarkersToList(response.markers()));
        } else {
            resp.put("markers", HttpMessageDocSupport.markersToList(response.markers()));
        }

        if (response instanceof HttpResponseReceived received) {
            putResponseAttributes(resp, received, trafficShape);
        }
    }

    static String safeResponseHttpVersion(HttpResponse response) {
        if (response == null) {
            return null;
        }
        try {
            return response.httpVersion();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static void putResponseAttributes(
            Map<String, Object> responseDoc,
            HttpResponseReceived response,
            boolean trafficShape) {
        AttributeType[] types = new AttributeType[] {
            AttributeType.PAGE_TITLE,
            AttributeType.LOCATION,
            AttributeType.CONTENT_LENGTH,
            AttributeType.VISIBLE_TEXT,
            AttributeType.WORD_COUNT,
            AttributeType.VISIBLE_WORD_COUNT,
            AttributeType.LINE_COUNT,
            AttributeType.COOKIE_NAMES,
            AttributeType.CANONICAL_LINK,
            AttributeType.COMMENTS,
            AttributeType.NON_HIDDEN_FORM_INPUT_TYPES,
            AttributeType.ANCHOR_LABELS,
            AttributeType.TAG_NAMES,
            AttributeType.DIV_IDS,
            AttributeType.CSS_CLASSES,
            AttributeType.INPUT_SUBMIT_LABELS,
            AttributeType.BUTTON_SUBMIT_LABELS,
            AttributeType.INPUT_IMAGE_LABELS,
            AttributeType.ETAG_HEADER,
            AttributeType.LAST_MODIFIED_HEADER,
            AttributeType.CONTENT_LOCATION,
            AttributeType.OUTBOUND_EDGE_COUNT,
            AttributeType.OUTBOUND_EDGE_TAG_NAMES
        };
        try {
            List<Attribute> attrs = response.attributes(types);
            if (attrs == null) {
                return;
            }
            for (Attribute attr : attrs) {
                if (attr == null) {
                    continue;
                }
                String bodyField = bodyDerivedResponseField(attr.type(), trafficShape);
                Object value = attributeValue(attr);
                if (bodyField != null) {
                    if (value != null) {
                        String htmlField = trafficShape ? htmlDerivedResponseBodyField(attr.type()) : null;
                        if (htmlField != null) {
                            HttpMessageDocSupport.putResponseBodyHtmlField(responseDoc, htmlField, value);
                        } else {
                            HttpMessageDocSupport.putResponseBodyField(responseDoc, bodyField, value);
                        }
                    }
                    continue;
                }
                String headerField = trafficShape ? null : headerDerivedResponseField(attr.type());
                if (headerField != null) {
                    if (value != null) {
                        HttpMessageDocSupport.putResponseHeaderField(responseDoc, headerField, value);
                    }
                    continue;
                }
                String fieldName = attributeTypeToFieldName(attr.type());
                if (trafficShape) {
                    continue;
                }
                if (fieldName == null) {
                    continue;
                }
                if (value != null) {
                    responseDoc.put(fieldName, value);
                }
            }
        } catch (Exception e) {
            Logger.logDebug("[RequestResponseDocBuilder] response.attributes() failed: " + e.getMessage());
        }
    }

    private static String attributeTypeToFieldName(AttributeType type) {
        if (type == null) {
            return null;
        }
        return type.name().toLowerCase(Locale.ROOT);
    }

    private static String bodyDerivedResponseField(AttributeType type, boolean trafficShape) {
        if (type == null) {
            return null;
        }
        return switch (type) {
            case PAGE_TITLE -> "page_title";
            case VISIBLE_TEXT -> "visible_text";
            case WORD_COUNT -> "word_count";
            case VISIBLE_WORD_COUNT -> "visible_word_count";
            case LINE_COUNT -> "line_count";
            case ANCHOR_LABELS -> "anchor_labels";
            case TAG_NAMES -> "tag_names";
            case DIV_IDS -> "div_ids";
            case CSS_CLASSES -> "css_classes";
            case BUTTON_SUBMIT_LABELS -> trafficShape ? "button_submit_labels" : null;
            case CANONICAL_LINK -> trafficShape ? "canonical_link" : null;
            case COMMENTS -> trafficShape ? "comments" : null;
            case INPUT_IMAGE_LABELS -> trafficShape ? "input_image_labels" : null;
            case INPUT_SUBMIT_LABELS -> trafficShape ? "input_submit_labels" : null;
            case NON_HIDDEN_FORM_INPUT_TYPES -> trafficShape ? "non_hidden_form_input_types" : null;
            case OUTBOUND_EDGE_COUNT -> trafficShape ? "outbound_edge_count" : null;
            case OUTBOUND_EDGE_TAG_NAMES -> trafficShape ? "outbound_edge_tag_names" : null;
            default -> null;
        };
    }

    private static String htmlDerivedResponseBodyField(AttributeType type) {
        if (type == null) {
            return null;
        }
        return switch (type) {
            case PAGE_TITLE -> "page_title";
            case VISIBLE_TEXT -> "text.visible_text";
            case VISIBLE_WORD_COUNT -> "text.visible_word_count";
            case ANCHOR_LABELS -> "links.anchor_labels";
            case CANONICAL_LINK -> "links.canonical_link";
            case OUTBOUND_EDGE_COUNT -> "links.outbound_edge_count";
            case OUTBOUND_EDGE_TAG_NAMES -> "links.outbound_edge_tag_names";
            case TAG_NAMES -> "dom.tag_names";
            case DIV_IDS -> "dom.div_ids";
            case CSS_CLASSES -> "dom.css_classes";
            case BUTTON_SUBMIT_LABELS -> "forms.button_submit_labels";
            case INPUT_IMAGE_LABELS -> "forms.input_image_labels";
            case INPUT_SUBMIT_LABELS -> "forms.input_submit_labels";
            case NON_HIDDEN_FORM_INPUT_TYPES -> "forms.non_hidden_form_input_types";
            case COMMENTS -> "comments";
            default -> null;
        };
    }

    private static String headerDerivedResponseField(AttributeType type) {
        if (type == null) {
            return null;
        }
        return switch (type) {
            case ETAG_HEADER -> "etag";
            case LAST_MODIFIED_HEADER -> "last_modified";
            case CONTENT_LOCATION -> "content_location";
            default -> null;
        };
    }


    private static Object attributeValue(Attribute attr) {
        if (attr == null) {
            return null;
        }
        return attr.value();
    }


    private static burp.api.montoya.http.message.ContentType safeContentType(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            return request.contentType();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static List<HttpHeader> safeHeaders(HttpRequest request) {
        if (request == null) {
            return List.of();
        }
        try {
            List<HttpHeader> headers = request.headers();
            return headers == null ? List.of() : headers;
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    private static ParametersResult safeParametersResult(
            HttpRequest request,
            burp.api.montoya.http.message.ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType,
            byte[] wireBodyBytes) {
        if (request == null) {
            return ParametersResult.from(RequestResponseParametersSupport.ParametersResult.EMPTY);
        }
        try {
            boolean includeBody = RequestResponseParametersSupport.shouldIncludeBodyParameters(
                    contentType, headers, inferredContentType, wireBodyBytes);
            return ParametersResult.from(RequestResponseParametersSupport.collectParameters(
                    request, includeBody, wireBodyBytes, contentType, headers));
        } catch (RuntimeException ignored) {
            return ParametersResult.from(RequestResponseParametersSupport.ParametersResult.EMPTY);
        }
    }

    private static ParametersResult safeSitemapParametersResult(
            HttpRequest request,
            burp.api.montoya.http.message.ContentType contentType,
            List<HttpHeader> headers,
            byte[] wireBodyBytes) {
        try {
            return ParametersResult.from(RequestResponseParametersSupport.sitemapParameters(
                    request, wireBodyBytes, contentType, headers));
        } catch (RuntimeException ignored) {
            return ParametersResult.from(RequestResponseParametersSupport.ParametersResult.EMPTY);
        }
    }

    private static List<Map<String, Object>> safeTrafficMarkers(HttpRequest request) {
        if (request == null) {
            return List.of();
        }
        try {
            return HttpMessageDocSupport.trafficMarkersToList(request.markers());
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    /**
     * Resolves the HTTP version for a request, including malformed requests where Montoya accessors throw.
     */
    public static String safeRequestHttpVersion(HttpRequest request) {
        if (request == null) {
            return null;
        }
        try {
            return request.httpVersion();
        } catch (RuntimeException ignored) {
            return RawRequestSnapshot.from(request).httpVersion();
        }
    }

    /**
     * Returns {@link HttpRequest#url()} when available, or {@code null} when Montoya throws.
     *
     * <p>Use this for lightweight call sites (for example scope filtering) that only need a safe
     * URL lookup without the reconstruction cost of {@link #buildBestEffortUrl}. The logged context
     * mirrors the reconstruction helper so failure reasons stay traceable across exports.</p>
     *
     * @param request request whose direct URL accessor may throw
     * @param logPrefix logger prefix without brackets, for example {@code "Sitemap"}
     * @return trimmed URL when available, otherwise {@code null}
     */
    public static String safeRequestUrl(HttpRequest request, String logPrefix) {
        try {
            return request == null ? null : HttpMessageDocSupport.normalizeBlank(request.url());
        } catch (RuntimeException e) {
            String prefix = HttpMessageDocSupport.normalizeBlank(logPrefix);
            if (prefix == null) {
                Logger.logDebug("[RequestResponseDocBuilder] Failed to resolve request URL: "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            } else {
                Logger.logDebug("[RequestResponseDocBuilder] " + prefix + ": failed to resolve request URL: "
                        + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            }
            return null;
        }
    }

    private static String portSuffix(String scheme, int port) {
        if (port <= 0) {
            return "";
        }
        if (("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443)) {
            return "";
        }
        return ":" + port;
    }

    private record RawRequestSnapshot(
            String method,
            String path,
            String pathWithoutQuery,
            String query,
            String fileExtension,
            String httpVersion,
            byte[] bodyBytes,
            int bodyOffset) {
        private static RawRequestSnapshot from(HttpRequest request) {
            byte[] rawBytes = rawBytes(request);
            int bodyOffset = bodyOffset(rawBytes);
            String requestLine = requestLine(rawBytes, bodyOffset);
            String[] parts = requestLine == null ? new String[0] : requestLine.split(" ", 3);
            String method = HttpMessageDocSupport.normalizeBlank(parts.length > 0 ? parts[0] : null);
            String path = HttpMessageDocSupport.normalizeBlank(parts.length > 1 ? parts[1] : null);
            String httpVersion = HttpMessageDocSupport.normalizeBlank(parts.length > 2 ? parts[2] : null);
            return new RawRequestSnapshot(
                    method,
                    path,
                    pathWithoutQuery(path),
                    queryPart(path),
                    fileExtension(path),
                    httpVersion,
                    bodyBytes(rawBytes, bodyOffset),
                    bodyOffset);
        }

        private static byte[] rawBytes(HttpRequest request) {
            if (request == null) {
                return null;
            }
            try {
                return request.toByteArray() == null ? null : request.toByteArray().getBytes();
            } catch (RuntimeException ignored) {
                return null;
            }
        }

        private static int bodyOffset(byte[] rawBytes) {
            if (rawBytes == null || rawBytes.length == 0) {
                return 0;
            }
            for (int i = 0; i <= rawBytes.length - 4; i++) {
                if (rawBytes[i] == '\r' && rawBytes[i + 1] == '\n'
                        && rawBytes[i + 2] == '\r' && rawBytes[i + 3] == '\n') {
                    return i + 4;
                }
            }
            for (int i = 0; i <= rawBytes.length - 2; i++) {
                if (rawBytes[i] == '\n' && rawBytes[i + 1] == '\n') {
                    return i + 2;
                }
            }
            return rawBytes.length;
        }

        private static String requestLine(byte[] rawBytes, int bodyOffset) {
            if (rawBytes == null || rawBytes.length == 0) {
                return null;
            }
            int limit = Math.min(bodyOffset, rawBytes.length);
            int lineEnd = 0;
            while (lineEnd < limit && rawBytes[lineEnd] != '\r' && rawBytes[lineEnd] != '\n') {
                lineEnd++;
            }
            if (lineEnd <= 0) {
                return null;
            }
            return new String(rawBytes, 0, lineEnd, StandardCharsets.ISO_8859_1);
        }

        private static byte[] bodyBytes(byte[] rawBytes, int bodyOffset) {
            if (rawBytes == null || bodyOffset >= rawBytes.length) {
                return null;
            }
            return Arrays.copyOfRange(rawBytes, bodyOffset, rawBytes.length);
        }

        private static String pathWithoutQuery(String path) {
            if (path == null) {
                return null;
            }
            int queryIndex = path.indexOf('?');
            return queryIndex >= 0 ? path.substring(0, queryIndex) : path;
        }

        private static String queryPart(String path) {
            if (path == null) {
                return null;
            }
            int queryIndex = path.indexOf('?');
            return queryIndex >= 0 && queryIndex + 1 < path.length()
                    ? path.substring(queryIndex + 1)
                    : null;
        }

        private static String fileExtension(String path) {
            String pathWithoutQuery = pathWithoutQuery(path);
            if (pathWithoutQuery == null || pathWithoutQuery.isBlank()) {
                return null;
            }
            int slash = pathWithoutQuery.lastIndexOf('/');
            String leaf = slash >= 0 ? pathWithoutQuery.substring(slash + 1) : pathWithoutQuery;
            int dot = leaf.lastIndexOf('.');
            return dot >= 0 && dot + 1 < leaf.length() ? leaf.substring(dot + 1) : null;
        }
    }
}
