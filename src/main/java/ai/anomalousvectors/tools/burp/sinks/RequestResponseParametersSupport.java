package ai.anomalousvectors.tools.burp.sinks;

import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

/** Request parameter collection, inference, and stats accounting. */
final class RequestResponseParametersSupport {

    private RequestResponseParametersSupport() {}

    /**
     * Hard cap on the number of parameter entries retained per request bucket.
     *
     * <p>URL, BODY, and other non-URL parameter types each use separate caps so one bucket cannot
     * evict another.</p>
     */
    static final int PARAMETERS_HARD_CAP = 1_000;
    /**
     * Maximum {@link HttpParameterType#URL} parameter entries retained per request.
     *
     * <p>When exceeded, structured {@code request.parameters} and aligned path/query/url string
     * fields are rebuilt from the retained URL parameters only.</p>
     */
    static final int URL_PARAMETERS_CAP = PARAMETERS_HARD_CAP;
    /** Maximum {@link HttpParameterType#BODY} parameter entries retained per request. */
    static final int BODY_PARAMETERS_CAP = PARAMETERS_HARD_CAP;

    /** {@link ExportStats} body_params_source tally when BODY rows came from Burp unchanged. */
    static final String BODY_PARAMS_SOURCE_BURP = "burp";
    /** {@link ExportStats} body_params_source tally when all BODY rows came from supplemental parse. */
    static final String BODY_PARAMS_SOURCE_SUPPLEMENTAL = "supplemental";
    /** {@link ExportStats} body_params_source tally when supplemental BODY plus Burp non-BODY rows. */
    static final String BODY_PARAMS_SOURCE_MIXED = "mixed";
    /** {@link ExportStats} body_params_source tally when no BODY rows were exported. */
    static final String BODY_PARAMS_SOURCE_NONE = "none";

    /** Non-URL parameter types enumerated by the typed-accessor fast path. */
    static final HttpParameterType[] NON_URL_PARAMETER_TYPES = new HttpParameterType[] {
            HttpParameterType.JSON,
            HttpParameterType.XML,
            HttpParameterType.XML_ATTRIBUTE,
            HttpParameterType.MULTIPART_ATTRIBUTE
    };

    static String statusCodeClassName(short statusCode) {
        for (StatusCodeClass c : StatusCodeClass.values()) {
            if (c.contains(statusCode)) {
                return c.name();
            }
        }
        return null;
    }

    /**
     * Decides whether BODY parameters should be collected from Burp's unfiltered
     * {@link HttpRequest#parameters()} path.
     *
     * @param bodyBytes optional raw body bytes for declared-form gate tightening; may be {@code null}
     */
    static boolean shouldIncludeBodyParameters(
            ContentType contentType,
            List<HttpHeader> headers,
            String inferredContentType,
            byte[] bodyBytes) {
        if (HttpMessageDocSupport.INFERRED_CT_BINARY.equals(inferredContentType)) {
            if (bodyBytes != null && bodyBytes.length > 0) {
                boolean declaredForm = isDeclaredFormOrMultipart(
                        contentType, headers, resolvePrimaryMediaType(contentType, headers));
                BodyContentEncodingSupport.ResolvedBody resolved = resolveBodyForExport(
                        bodyBytes, headers, declaredForm, true);
                byte[] logical = resolved.logicalBytes();
                if (declaredForm
                        && HttpMessageDocSupport.looksLikeTextPayload(
                                logical,
                                HttpMessageDocSupport.charsetFromContentType(
                                        HttpMessageDocSupport.headerValue(headers, "Content-Type")))) {
                    return true;
                }
            }
            return false;
        }
        String declaredName = contentType == null ? null : contentType.name();
        if ("URL_ENCODED".equals(declaredName) || "MULTIPART".equals(declaredName)) {
            return true;
        }
        if ("JSON".equals(declaredName) || "XML".equals(declaredName) || "AMF".equals(declaredName)) {
            return false;
        }
        String primary = resolvePrimaryMediaType(contentType, headers);
        return !HttpMessageDocSupport.isExplicitlyBinaryMediaType(primary);
    }

    /**
     * Returns whether the declared Content-Type indicates form or multipart submission.
     *
     * @param primary resolved primary media type; may be {@code null}
     */
    static boolean isDeclaredFormOrMultipart(
            ContentType contentType,
            List<HttpHeader> headers,
            String primary) {
        String declaredName = contentType == null ? null : contentType.name();
        if ("URL_ENCODED".equals(declaredName) || "MULTIPART".equals(declaredName)) {
            return true;
        }
        if (primary == null) {
            primary = resolvePrimaryMediaType(contentType, headers);
        }
        if (primary == null || primary.isBlank()) {
            return false;
        }
        return primary.contains("urlencoded")
                || primary.contains("www-form-urlencoded")
                || primary.startsWith("multipart/");
    }

    /**
     * Resolves the primary media type from Burp's declared content type and request headers.
     */
    static String resolvePrimaryMediaType(ContentType contentType, List<HttpHeader> headers) {
        String declaredName = contentType == null ? null : contentType.name();
        String header = contentType == null ? null : contentType.toString();
        String primary = HttpMessageDocSupport.primaryMediaType(header, HttpMessageDocSupport.mediaTypeHints(declaredName));
        if (primary == null) {
            primary = HttpMessageDocSupport.mediaType(header, null);
        }
        if (primary == null && headers != null) {
            for (HttpHeader h : headers) {
                if (h != null && h.name() != null && "content-type".equalsIgnoreCase(h.name())) {
                    primary = HttpMessageDocSupport.mediaType(h.value(), null);
                    if (primary != null) {
                        break;
                    }
                }
            }
        }
        return primary;
    }

    private static BodyContentEncodingSupport.ResolvedBody resolveBodyForExport(
            byte[] wireBytes,
            List<HttpHeader> headers,
            boolean declaredFormOrMultipart,
            boolean allowDeclaredFormGzipSniff) {
        return BodyContentEncodingSupport.resolveForExport(
                wireBytes,
                headers,
                declaredFormOrMultipart,
                allowDeclaredFormGzipSniff);
    }

    /**
     * Computes the traffic {@code request.content_type.inferred} verdict from body bytes alone.
     */
    static String inferRequestContentType(byte[] bodyBytes, List<HttpHeader> headers) {
        return inferRequestContentType(bodyBytes, headers, null);
    }

    /**
     * Computes {@code request.content_type.inferred} from wire body bytes, optionally
     * decompressing when {@code Content-Encoding} or declared-form gzip magic applies.
     *
     * @param bodyBytes wire body bytes; {@code null} treated as empty
     * @param headers request headers
     * @param contentType Burp declared content type; may be {@code null}
     */
    static String inferRequestContentType(
            byte[] bodyBytes,
            List<HttpHeader> headers,
            ContentType contentType) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return HttpMessageDocSupport.INFERRED_CT_EMPTY;
        }
        boolean declaredForm = isDeclaredFormOrMultipart(
                contentType, headers, resolvePrimaryMediaType(contentType, headers));
        BodyContentEncodingSupport.ResolvedBody resolved = resolveBodyForExport(
                bodyBytes, headers, declaredForm, true);
        return inferRequestContentTypeFromLogicalBytes(resolved.logicalBytes(), headers);
    }

    private static String inferRequestContentTypeFromLogicalBytes(byte[] bodyBytes, List<HttpHeader> headers) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return HttpMessageDocSupport.INFERRED_CT_EMPTY;
        }
        int scanLen = Math.min(bodyBytes.length, HttpMessageDocSupport.TEXT_SNIFF_BYTES);
        byte[] sample;
        if (scanLen == bodyBytes.length) {
            sample = bodyBytes;
        } else {
            sample = new byte[scanLen];
            System.arraycopy(bodyBytes, 0, sample, 0, scanLen);
        }
        if (HttpMessageDocSupport.containsNul(sample)) {
            return HttpMessageDocSupport.INFERRED_CT_BINARY;
        }
        Charset charset = HttpMessageDocSupport.charsetFromContentType(HttpMessageDocSupport.headerValue(headers, "Content-Type"));
        String decoded = HttpMessageDocSupport.decodeTextWithFallback(sample, charset);
        if (decoded == null || !HttpMessageDocSupport.hasLowControlCharacterRatio(decoded)) {
            return HttpMessageDocSupport.INFERRED_CT_BINARY;
        }
        int i = 0;
        int n = decoded.length();
        while (i < n && Character.isWhitespace(decoded.charAt(i))) {
            i++;
        }
        if (i >= n) {
            return HttpMessageDocSupport.INFERRED_CT_TEXT;
        }
        char first = decoded.charAt(i);
        if (first == '{' || first == '[') {
            return HttpMessageDocSupport.INFERRED_CT_JSON;
        }
        if (first == '<') {
            return HttpMessageDocSupport.INFERRED_CT_XML;
        }
        if (first == '-' && i + 1 < n && decoded.charAt(i + 1) == '-') {
            return HttpMessageDocSupport.INFERRED_CT_MULTIPART;
        }
        return HttpMessageDocSupport.INFERRED_CT_TEXT;
    }

    /**
     * Result of converting Burp's request parameters into the doc representation.
     *
     * <p>{@code droppedUrlParams} and {@code adjustedQuery} are set when
     * {@link #URL_PARAMETERS_CAP} truncated URL parameters. {@code droppedBodyParams} is set when
     * {@link #BODY_PARAMETERS_CAP} truncated BODY parameters. Export metadata fields feed
     * {@code session.*} and session stats.</p>
     */
    record ParametersResult(
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

        static final ParametersResult EMPTY = pack(
                List.of(),
                0,
                false,
                0,
                "",
                0,
                BODY_PARAMS_SOURCE_NONE,
                false,
                false,
                false,
                List.of(),
                0,
                false);

    }

    static boolean isDeclaredUrlEncoded(ContentType contentType, List<HttpHeader> headers) {
        String declaredName = contentType == null ? null : contentType.name();
        if ("URL_ENCODED".equals(declaredName)) {
            return true;
        }
        String primary = resolvePrimaryMediaType(contentType, headers);
        if (primary == null || primary.isBlank()) {
            return false;
        }
        return primary.contains("urlencoded") || primary.contains("www-form-urlencoded");
    }

    /**
     * Collects request parameters for the doc representation, choosing between Burp's unfiltered
     * {@link HttpRequest#parameters()} and the typed-by-type fast path based on whether BODY
     * entries are wanted.
     */
    static ParametersResult collectParameters(HttpRequest request, boolean includeBody) {
        return collectParameters(request, includeBody, null, null, null);
    }

    /**
     * Collects request parameters, optionally supplementing Burp's BODY list from decompressed
     * urlencoded bytes when Burp did not enumerate compressed form bodies.
     *
     * @param wireBodyBytes optional wire body for supplemental parsing; may be {@code null}
     * @param contentType declared content type for supplemental parsing; may be {@code null}
     * @param headers request headers for charset and decompression; may be {@code null}
     */
    static ParametersResult collectParameters(
            HttpRequest request,
            boolean includeBody,
            byte[] wireBodyBytes,
            ContentType contentType,
            List<HttpHeader> headers) {
        if (request == null) {
            return ParametersResult.EMPTY;
        }
        if (includeBody) {
            return collectParametersIncludeBody(request, wireBodyBytes, contentType, headers);
        }
        return collectParametersSkipBody(request, wireBodyBytes, contentType, headers);
    }

    private static ParametersResult collectParametersIncludeBody(
            HttpRequest request,
            byte[] wireBodyBytes,
            ContentType contentType,
            List<HttpHeader> headers) {
        ParametersResult burp = parametersToList(request.parameters(), true);
        UrlEncodedWireContext wireContext = resolveUrlEncodedWireContext(wireBodyBytes, contentType, headers);
        if (wireContext != null && wireContext.resolved().transformed()) {
            ParametersResult supplemental = parseUrlEncodedBodyParameters(wireContext.logicalBytes(), headers);
            ParametersResult burpWithoutBody = withoutBodyEntries(burp);
            int burpBodyDropped = countBodyEntries(burp.entries());
            List<String> encodings = wireContext.resolved().encodingsApplied();
            if (supplemental.supplementalRejectedNonForm()) {
                return withExportMetadata(
                        burpWithoutBody,
                        BODY_PARAMS_SOURCE_NONE,
                        false,
                        false,
                        true,
                        encodings,
                        burpBodyDropped,
                        true);
            }
            if (!supplemental.entries().isEmpty()) {
                ParametersResult merged = merge(burpWithoutBody, supplemental);
                String source = hasRetainedNonBodyEntries(burpWithoutBody.entries())
                        ? BODY_PARAMS_SOURCE_MIXED
                        : BODY_PARAMS_SOURCE_SUPPLEMENTAL;
                return withExportMetadata(
                        merged,
                        source,
                        true,
                        false,
                        true,
                        encodings,
                        burpBodyDropped);
            }
            return withExportMetadata(
                    burpWithoutBody,
                    BODY_PARAMS_SOURCE_NONE,
                    false,
                    false,
                    true,
                    encodings,
                    burpBodyDropped);
        }
        if (!hasBodyParameterEntry(burp.entries())) {
            ParametersResult supplemental = supplementalUrlEncodedBodyParameters(
                    wireBodyBytes, contentType, headers);
            if (supplemental.entries().isEmpty()) {
                return withExportMetadata(
                        burp,
                        inferBodyParamsSource(burp.entries()),
                        false,
                        false,
                        wireContext != null && wireContext.resolved().transformed(),
                        wireContext == null ? List.of() : wireContext.resolved().encodingsApplied(),
                        0);
            }
            ParametersResult merged = merge(burp, supplemental);
            String source = hasRetainedNonBodyEntries(burp.entries())
                    ? BODY_PARAMS_SOURCE_MIXED
                    : BODY_PARAMS_SOURCE_SUPPLEMENTAL;
            return withExportMetadata(merged, source, false, false, false, List.of(), 0);
        }
        return withExportMetadata(
                burp,
                BODY_PARAMS_SOURCE_BURP,
                false,
                false,
                false,
                List.of(),
                0);
    }

    private static ParametersResult collectParametersSkipBody(
            HttpRequest request,
            byte[] wireBodyBytes,
            ContentType contentType,
            List<HttpHeader> headers) {
        ParametersResult urlPart = capUrlParameters(safeUrlParameters(request));
        List<ParsedHttpParameter> merged = new ArrayList<>();
        for (HttpParameterType type : NON_URL_PARAMETER_TYPES) {
            try {
                if (!request.hasParameters(type)) {
                    continue;
                }
                List<ParsedHttpParameter> typed = request.parameters(type);
                if (typed == null || typed.isEmpty()) {
                    continue;
                }
                merged.addAll(typed);
                if (merged.size() >= PARAMETERS_HARD_CAP) {
                    break;
                }
            } catch (RuntimeException ignored) {
                // Per-type accessor may throw on malformed inputs; skip that type and keep going.
            }
        }
        ParametersResult nonUrlPart = parametersToListNonUrl(merged, false);
        ParametersResult base = merge(urlPart, new ParametersResult(
                nonUrlPart.entries(),
                nonUrlPart.droppedSynthesized(),
                true,
                nonUrlPart.droppedUrlParams(),
                nonUrlPart.adjustedQuery(),
                nonUrlPart.droppedBodyParams(),
                BODY_PARAMS_SOURCE_NONE,
                false,
                false,
                false,
                List.of(),
                0,
                false));
        if (!isDeclaredUrlEncoded(contentType, headers) || wireBodyBytes == null || wireBodyBytes.length == 0) {
            return base;
        }
        ParametersResult supplemental = supplementalUrlEncodedBodyParameters(
                wireBodyBytes, contentType, headers);
        if (supplemental.supplementalRejectedNonForm() || supplemental.entries().isEmpty()) {
            return base;
        }
        ParametersResult rescued = merge(base, supplemental);
        String source = hasRetainedNonBodyEntries(base.entries())
                ? BODY_PARAMS_SOURCE_MIXED
                : BODY_PARAMS_SOURCE_SUPPLEMENTAL;
        UrlEncodedWireContext wireContext = resolveUrlEncodedWireContext(wireBodyBytes, contentType, headers);
        return withExportMetadata(
                rescued,
                source,
                false,
                true,
                wireContext != null && wireContext.resolved().transformed(),
                wireContext == null ? List.of() : wireContext.resolved().encodingsApplied(),
                0);
    }

    static ParametersResult sitemapParameters(
            HttpRequest request,
            byte[] wireBodyBytes,
            ContentType contentType,
            List<HttpHeader> headers) {
        ParametersResult urlPart = sitemapUrlParameters(request);
        ParametersResult supplemental = supplementalUrlEncodedBodyParameters(
                wireBodyBytes, contentType, headers);
        if (supplemental.entries().isEmpty()) {
            return urlPart;
        }
        ParametersResult merged = merge(urlPart, supplemental);
        String source = hasRetainedNonBodyEntries(urlPart.entries())
                ? BODY_PARAMS_SOURCE_MIXED
                : BODY_PARAMS_SOURCE_SUPPLEMENTAL;
        return withExportMetadata(merged, source, false, false, false, List.of(), 0);
    }

    static boolean hasBodyParameterEntry(List<Map<String, Object>> entries) {
        if (entries == null || entries.isEmpty()) {
            return false;
        }
        for (Map<String, Object> entry : entries) {
            if (entry != null && "BODY".equals(HttpMessageDocSupport.stringValue(entry.get("type")))) {
                return true;
            }
        }
        return false;
    }

    private static ParametersResult supplementalUrlEncodedBodyParameters(
            byte[] wireBodyBytes,
            ContentType contentType,
            List<HttpHeader> headers) {
        if (wireBodyBytes == null || wireBodyBytes.length == 0) {
            return ParametersResult.EMPTY;
        }
        if (!isDeclaredFormOrMultipart(contentType, headers, resolvePrimaryMediaType(contentType, headers))) {
            return ParametersResult.EMPTY;
        }
        BodyContentEncodingSupport.ResolvedBody resolved =
                resolveBodyForExport(wireBodyBytes, headers, true, true);
        byte[] logical = resolved.logicalBytes();
        if (!HttpMessageDocSupport.looksLikeTextPayload(
                logical,
                HttpMessageDocSupport.charsetFromContentType(
                        HttpMessageDocSupport.headerValue(headers, "Content-Type")))) {
            return ParametersResult.EMPTY;
        }
        return parseUrlEncodedBodyParameters(logical, headers);
    }

    /**
     * Parses {@code application/x-www-form-urlencoded} body bytes into BODY parameter entries.
     *
     * <p>Rejects logical bodies that look like JSON/protobuf batches mis-declared as form data.
     * Invalid parameter names are dropped; when the body shape is non-form, returns empty entries
     * with {@link ParametersResult#supplementalRejectedNonForm()} {@code true}.</p>
     */
    static ParametersResult parseUrlEncodedBodyParameters(byte[] logicalBodyBytes, List<HttpHeader> headers) {
        if (logicalBodyBytes == null || logicalBodyBytes.length == 0) {
            return ParametersResult.EMPTY;
        }
        java.nio.charset.Charset charset = HttpMessageDocSupport.charsetFromContentType(
                HttpMessageDocSupport.headerValue(headers, "Content-Type"));
        String decoded = HttpMessageDocSupport.decodeTextWithFallback(logicalBodyBytes, charset);
        if (decoded == null || decoded.isBlank()) {
            return ParametersResult.EMPTY;
        }
        String trimmed = decoded.trim();
        if (!looksLikeUrlEncodedFormLogicalBody(trimmed)) {
            return supplementalRejectedNonFormResult();
        }
        if (trimmed.indexOf('=') < 0) {
            return ParametersResult.EMPTY;
        }
        String[] pairs = trimmed.split("&", -1);
        List<Map<String, Object>> out = new ArrayList<>(Math.min(pairs.length, BODY_PARAMETERS_CAP));
        int dropped = 0;
        for (String pair : pairs) {
            if (pair == null || pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            String decodedName = decodeUrlEncodedComponent(name);
            if (!isValidUrlEncodedParamName(decodedName)) {
                continue;
            }
            if (out.size() >= BODY_PARAMETERS_CAP) {
                dropped++;
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>(3);
            entry.put("name", decodedName);
            entry.put("value", decodeUrlEncodedComponent(value));
            entry.put("type", HttpParameterType.BODY.name());
            out.add(entry);
        }
        if (out.isEmpty()) {
            return supplementalRejectedNonFormResult();
        }
        return pack(out, 0, false, 0, "", dropped, null, false, false, false, List.of(), 0, false);
    }

    /**
     * Returns whether decoded logical body bytes look like urlencoded form rather than JSON/protobuf.
     *
     * @param decodedTrim decoded body text after trim
     * @return {@code false} when the body starts like a JSON array or object
     */
    static boolean looksLikeUrlEncodedFormLogicalBody(String decodedTrim) {
        if (decodedTrim == null || decodedTrim.isEmpty()) {
            return false;
        }
        char first = decodedTrim.charAt(0);
        if (first == '[' || first == '{') {
            return false;
        }
        return !decodedTrim.startsWith("[[");
    }

    /**
     * Returns whether a parsed urlencoded parameter name is safe to export.
     *
     * <p>Values may contain brackets or JSON; only names are validated.</p>
     *
     * @param name decoded parameter name
     * @return {@code false} for empty, bracket-prefixed, or control-character names
     */
    static boolean isValidUrlEncodedParamName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        char first = name.charAt(0);
        if (first == '[' || first == '{') {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char ch = name.charAt(i);
            if (ch < 0x20 || ch == 0x7f) {
                return false;
            }
        }
        return true;
    }

    private static ParametersResult supplementalRejectedNonFormResult() {
        return pack(List.of(), 0, false, 0, "", 0, null, false, false, false, List.of(), 0, true);
    }

    private static String decodeUrlEncodedComponent(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    /**
     * Converts {@code request.parameters()} to the exported list form, optionally filtering
     * synthesized {@code BODY}-typed entries and enforcing non-URL caps.
     */
    static ParametersResult parametersToList(List<ParsedHttpParameter> parameters, boolean includeBody) {
        if (parameters == null || parameters.isEmpty()) {
            return ParametersResult.EMPTY;
        }
        List<ParsedHttpParameter> urlParameters = new ArrayList<>();
        List<ParsedHttpParameter> nonUrlParameters = new ArrayList<>();
        for (ParsedHttpParameter parameter : parameters) {
            if (parameter != null && parameter.type() == HttpParameterType.URL) {
                urlParameters.add(parameter);
            } else if (parameter != null && parameter.type() != HttpParameterType.COOKIE) {
                nonUrlParameters.add(parameter);
            }
        }
        return merge(capUrlParameters(urlParameters), parametersToListNonUrl(nonUrlParameters, includeBody));
    }

    static ParametersResult sitemapUrlParameters(HttpRequest request) {
        return capUrlParameters(safeUrlParameters(request));
    }

    /**
     * Rebuilds {@code path.with_query} from {@code pathWithoutQuery} and a narrowed query string.
     */
    static String buildPathWithQuery(String pathWithoutQuery, String query) {
        String normalizedPath = HttpMessageDocSupport.nullToEmpty(pathWithoutQuery);
        String normalizedQuery = query == null ? "" : query;
        if (normalizedQuery.isEmpty()) {
            return normalizedPath;
        }
        if (normalizedPath.isEmpty()) {
            return "?" + normalizedQuery;
        }
        return normalizedPath + "?" + normalizedQuery;
    }

    /**
     * Reads the query string from a built request sub-document.
     */
    static String requestDocQuery(Map<String, Object> requestDoc) {
        if (requestDoc == null) {
            return "";
        }
        Object path = requestDoc.get("path");
        if (path instanceof Map<?, ?> pathMap) {
            return HttpMessageDocSupport.nullToEmpty(HttpMessageDocSupport.stringValue(pathMap.get("query")));
        }
        return HttpMessageDocSupport.nullToEmpty(HttpMessageDocSupport.stringValue(requestDoc.get("query")));
    }

    static void recordParameterStats(
            HttpRequest request,
            ContentType contentType,
            ParametersResult parametersResult) {
        if (parametersResult.droppedSynthesized() > 0) {
            ExportStats.recordSynthesizedBodyParamsDropped(parametersResult.droppedSynthesized());
        }
        if (parametersResult.bodyParamsSource() != null) {
            ExportStats.recordBodyParamsSource(parametersResult.bodyParamsSource());
        }
        for (String encoding : parametersResult.encodingsApplied()) {
            if (encoding != null && !encoding.isBlank()) {
                ExportStats.recordBodyParamsEncoding(encoding);
            }
        }
        if (parametersResult.wireBodyParamsDropped() > 0) {
            ExportStats.recordWireBodyParamsDropped(parametersResult.wireBodyParamsDropped());
        }
    }

    private static ParametersResult capUrlParameters(List<ParsedHttpParameter> urlParameters) {
        if (urlParameters == null || urlParameters.isEmpty()) {
            return ParametersResult.EMPTY;
        }
        List<Map<String, Object>> out = new ArrayList<>(Math.min(urlParameters.size(), URL_PARAMETERS_CAP));
        int dropped = 0;
        for (ParsedHttpParameter parameter : urlParameters) {
            if (parameter == null) {
                continue;
            }
            if (out.size() >= URL_PARAMETERS_CAP) {
                dropped++;
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>(3);
            entry.put("name", parameter.name());
            entry.put("value", parameter.value());
            entry.put("type", HttpParameterType.URL.name());
            out.add(entry);
        }
        String adjustedQuery = buildQueryStringFromUrlEntries(out);
        return pack(out, 0, false, dropped, adjustedQuery, 0, null, false, false, false, List.of(), 0, false);
    }

    private static ParametersResult parametersToListNonUrl(
            List<ParsedHttpParameter> parameters,
            boolean includeBody) {
        if (parameters == null || parameters.isEmpty()) {
            return ParametersResult.EMPTY;
        }
        List<Map<String, Object>> out = new ArrayList<>();
        int droppedSynthesized = 0;
        int bodyKept = 0;
        int bodyDropped = 0;
        int otherKept = 0;
        for (ParsedHttpParameter parameter : parameters) {
            if (parameter == null) {
                continue;
            }
            HttpParameterType type = parameter.type();
            if (type == HttpParameterType.COOKIE) {
                continue;
            }
            if (type == HttpParameterType.BODY) {
                if (!includeBody) {
                    droppedSynthesized++;
                    continue;
                }
                if (bodyKept >= BODY_PARAMETERS_CAP) {
                    bodyDropped++;
                    continue;
                }
                bodyKept++;
            } else {
                if (otherKept >= PARAMETERS_HARD_CAP) {
                    continue;
                }
                otherKept++;
            }
            Map<String, Object> entry = new LinkedHashMap<>(3);
            entry.put("name", parameter.name());
            entry.put("value", parameter.value());
            entry.put("type", type == null ? null : type.name());
            out.add(entry);
        }
        return pack(out, droppedSynthesized, false, 0, "", bodyDropped, null, false, false, false, List.of(), 0, false);
    }

    private static ParametersResult merge(ParametersResult urlPart, ParametersResult nonUrlPart) {
        List<Map<String, Object>> merged = new ArrayList<>(urlPart.entries().size() + nonUrlPart.entries().size());
        merged.addAll(urlPart.entries());
        merged.addAll(nonUrlPart.entries());
        String source = nonUrlPart.bodyParamsSource() != null
                ? nonUrlPart.bodyParamsSource()
                : urlPart.bodyParamsSource() != null
                        ? urlPart.bodyParamsSource()
                        : inferBodyParamsSource(merged);
        return pack(
                merged,
                nonUrlPart.droppedSynthesized(),
                nonUrlPart.bodyEnumerationSkipped(),
                urlPart.droppedUrlParams(),
                urlPart.adjustedQuery(),
                nonUrlPart.droppedBodyParams(),
                source,
                nonUrlPart.wireBodyParamsReplaced() || urlPart.wireBodyParamsReplaced(),
                nonUrlPart.skipPathBodyRescued() || urlPart.skipPathBodyRescued(),
                nonUrlPart.wireTransformed() || urlPart.wireTransformed(),
                nonUrlPart.encodingsApplied().isEmpty()
                        ? urlPart.encodingsApplied()
                        : nonUrlPart.encodingsApplied(),
                nonUrlPart.wireBodyParamsDropped() + urlPart.wireBodyParamsDropped(),
                nonUrlPart.supplementalRejectedNonForm() || urlPart.supplementalRejectedNonForm());
    }

    private static List<ParsedHttpParameter> safeUrlParameters(HttpRequest request) {
        if (request == null) {
            return List.of();
        }
        try {
            List<ParsedHttpParameter> parameters = request.parameters(HttpParameterType.URL);
            return parameters == null ? List.of() : parameters;
        } catch (RuntimeException ignored) {
            return List.of();
        }
    }

    static String buildQueryStringFromUrlEntries(List<Map<String, Object>> urlEntries) {
        if (urlEntries == null || urlEntries.isEmpty()) {
            return "";
        }
        StringBuilder query = new StringBuilder();
        boolean first = true;
        for (Map<String, Object> entry : urlEntries) {
            if (entry == null) {
                continue;
            }
            if (!first) {
                query.append('&');
            }
            first = false;
            query.append(encodeQueryComponent(HttpMessageDocSupport.stringValue(entry.get("name"))));
            query.append('=');
            query.append(encodeQueryComponent(HttpMessageDocSupport.stringValue(entry.get("value"))));
        }
        return query.toString();
    }

    private record UrlEncodedWireContext(
            BodyContentEncodingSupport.ResolvedBody resolved, byte[] logicalBytes) {}

    private static UrlEncodedWireContext resolveUrlEncodedWireContext(
            byte[] wireBodyBytes,
            ContentType contentType,
            List<HttpHeader> headers) {
        if (wireBodyBytes == null || wireBodyBytes.length == 0 || !isDeclaredUrlEncoded(contentType, headers)) {
            return null;
        }
        BodyContentEncodingSupport.ResolvedBody resolved =
                resolveBodyForExport(wireBodyBytes, headers, true, true);
        return new UrlEncodedWireContext(resolved, resolved.logicalBytes());
    }

    private static ParametersResult withoutBodyEntries(ParametersResult result) {
        if (result == null || result.entries().isEmpty()) {
            return result == null ? ParametersResult.EMPTY : result;
        }
        List<Map<String, Object>> kept = new ArrayList<>(result.entries().size());
        for (Map<String, Object> entry : result.entries()) {
            if (entry != null && !"BODY".equals(HttpMessageDocSupport.stringValue(entry.get("type")))) {
                kept.add(entry);
            }
        }
        return withExportMetadata(
                new ParametersResult(
                        kept,
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
                        result.supplementalRejectedNonForm()),
                inferBodyParamsSource(kept),
                result.wireBodyParamsReplaced(),
                result.skipPathBodyRescued(),
                result.wireTransformed(),
                result.encodingsApplied(),
                result.wireBodyParamsDropped());
    }

    private static int countBodyEntries(List<Map<String, Object>> entries) {
        if (entries == null || entries.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (Map<String, Object> entry : entries) {
            if (entry != null && "BODY".equals(HttpMessageDocSupport.stringValue(entry.get("type")))) {
                count++;
            }
        }
        return count;
    }

    private static boolean hasRetainedNonBodyEntries(List<Map<String, Object>> entries) {
        if (entries == null || entries.isEmpty()) {
            return false;
        }
        for (Map<String, Object> entry : entries) {
            if (entry == null) {
                continue;
            }
            String type = HttpMessageDocSupport.stringValue(entry.get("type"));
            if (type != null && !"BODY".equals(type)) {
                return true;
            }
        }
        return false;
    }

    private static String inferBodyParamsSource(List<Map<String, Object>> entries) {
        return hasBodyParameterEntry(entries) ? BODY_PARAMS_SOURCE_BURP : BODY_PARAMS_SOURCE_NONE;
    }

    private static ParametersResult withExportMetadata(
            ParametersResult base,
            String bodyParamsSource,
            boolean wireBodyParamsReplaced,
            boolean skipPathBodyRescued,
            boolean wireTransformed,
            List<String> encodingsApplied,
            int wireBodyParamsDropped) {
        return withExportMetadata(
                base,
                bodyParamsSource,
                wireBodyParamsReplaced,
                skipPathBodyRescued,
                wireTransformed,
                encodingsApplied,
                wireBodyParamsDropped,
                base.supplementalRejectedNonForm());
    }

    private static ParametersResult withExportMetadata(
            ParametersResult base,
            String bodyParamsSource,
            boolean wireBodyParamsReplaced,
            boolean skipPathBodyRescued,
            boolean wireTransformed,
            List<String> encodingsApplied,
            int wireBodyParamsDropped,
            boolean supplementalRejectedNonForm) {
        return pack(
                base.entries(),
                base.droppedSynthesized(),
                skipPathBodyRescued ? false : base.bodyEnumerationSkipped(),
                base.droppedUrlParams(),
                base.adjustedQuery(),
                base.droppedBodyParams(),
                bodyParamsSource,
                wireBodyParamsReplaced,
                skipPathBodyRescued,
                wireTransformed,
                encodingsApplied == null ? List.of() : List.copyOf(encodingsApplied),
                wireBodyParamsDropped,
                supplementalRejectedNonForm);
    }

    private static ParametersResult pack(
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
        String resolvedSource = bodyParamsSource == null ? inferBodyParamsSource(entries) : bodyParamsSource;
        return new ParametersResult(
                entries,
                droppedSynthesized,
                bodyEnumerationSkipped,
                droppedUrlParams,
                adjustedQuery == null ? "" : adjustedQuery,
                droppedBodyParams,
                resolvedSource,
                wireBodyParamsReplaced,
                skipPathBodyRescued,
                wireTransformed,
                encodingsApplied == null ? List.of() : encodingsApplied,
                wireBodyParamsDropped,
                supplementalRejectedNonForm);
    }

    private static String encodeQueryComponent(String value) {
        String normalized = value == null ? "" : value;
        return URLEncoder.encode(normalized, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
