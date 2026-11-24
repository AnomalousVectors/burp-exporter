package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.stringObjectMapList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers the synthesized-BODY-parameter filter, BODY/URL caps, and content-type gate behavior.
 */
class RequestResponseDocBuilderParametersFilterTest {

    private final List<LoggedEvent> events = new CopyOnWriteArrayList<>();
    private final Logger.LogListener listener = (level, message) -> events.add(new LoggedEvent(level, message));

    @BeforeEach
    public void registerLogListener() {
        ExportStats.resetForTests();
        Logger.resetState();
        Logger.registerListener(listener);
    }

    @AfterEach
    public void unregisterLogListener() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        ExportStats.resetForTests();
        UrlParameterTruncationLog.clearRunState();
        BodyParameterTruncationLog.clearRunState();
        BodyEnumerationSkippedLog.clearRunState();
        CompressedWireBodyParamsLog.clearRunState();
        events.clear();
    }

    @Test
    void parametersToList_includeBodyTrue_keepsEverything() {
        List<ParsedHttpParameter> input = List.of(
                param("u", "1", HttpParameterType.URL),
                param("c", "2", HttpParameterType.COOKIE),
                param("b1", "", HttpParameterType.BODY),
                param("b2", "", HttpParameterType.BODY),
                param("null-type", "x", null));

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries()).hasSize(4);
        assertThat(result.entries()).extracting(e -> e.get("type"))
                .containsExactly("URL", "BODY", "BODY", null);
        assertThat(result.droppedSynthesized()).isZero();
    }

    @Test
    void parametersToList_includeBodyFalse_dropsBodyOnly() {
        List<ParsedHttpParameter> input = List.of(
                param("u", "1", HttpParameterType.URL),
                param("c", "2", HttpParameterType.COOKIE),
                param("b1", "", HttpParameterType.BODY),
                param("b2", "", HttpParameterType.BODY),
                param("null-type", "x", null));

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, false);

        assertThat(result.entries())
                .extracting(e -> e.get("type"))
                .containsExactly("URL", null);
        assertThat(result.droppedSynthesized()).isEqualTo(2);
    }

    @Test
    void parametersToList_emptyOrNullInput_returnsEmptyResult() {
        assertThat(RequestResponseDocBuilder.parametersToList(null, false).entries()).isEmpty();
        assertThat(RequestResponseDocBuilder.parametersToList(List.of(), true).entries()).isEmpty();
    }

    @Test
    void parametersToList_hardCap_truncatesBodyToCap() {
        int cap = RequestResponseParametersSupport.BODY_PARAMETERS_CAP;
        List<ParsedHttpParameter> input = new ArrayList<>();
        input.add(param("u", "1", HttpParameterType.URL));
        input.add(param("c", "2", HttpParameterType.COOKIE));
        for (int i = 0; i < cap + 10; i++) {
            input.add(param("b" + i, "", HttpParameterType.BODY));
        }

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries()).hasSize(cap + 1);
        assertThat(result.droppedBodyParams()).isEqualTo(10);
        assertThat(result.droppedSynthesized()).isZero();
        assertThat(result.bodyParamsTruncated()).isTrue();
    }

    @Test
    void parametersToList_urlCap_truncatesUrlParamsOnly() {
        int cap = RequestResponseParametersSupport.URL_PARAMETERS_CAP;
        List<ParsedHttpParameter> input = new java.util.ArrayList<>(cap + 5);
        for (int i = 0; i < cap + 5; i++) {
            input.add(param("u" + i, "v", HttpParameterType.URL));
        }

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries()).hasSize(cap);
        assertThat(result.droppedUrlParams()).isEqualTo(5);
        assertThat(result.droppedSynthesized()).isZero();
        assertThat(result.adjustedQuery()).isNotEmpty();
        assertThat(result.urlParamsTruncated()).isTrue();
    }

    @Test
    void parametersToList_urlCap_doesNotTruncateBodyParams() {
        int cap = RequestResponseParametersSupport.URL_PARAMETERS_CAP;
        List<ParsedHttpParameter> input = new java.util.ArrayList<>(cap + 1);
        for (int i = 0; i < cap - 1; i++) {
            input.add(param("u" + i, "v", HttpParameterType.URL));
        }
        input.add(param("b1", "", HttpParameterType.BODY));
        input.add(param("b2", "", HttpParameterType.BODY));

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.parametersToList(input, true);

        assertThat(result.entries()).hasSize(cap + 1);
        assertThat(result.droppedUrlParams()).isZero();
        assertThat(result.droppedSynthesized()).isZero();
    }

    @Test
    void shouldIncludeBodyParameters_formEnumValues_returnTrue() {
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.URL_ENCODED, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.MULTIPART, List.of(), HttpMessageDocSupport.INFERRED_CT_MULTIPART)).isTrue();
    }

    @Test
    void shouldIncludeBodyParameters_declaredFormInferredBinaryWithTextBody_returnsTrue() {
        byte[] body = "name=value&other=thing".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.URL_ENCODED,
                List.of(),
                HttpMessageDocSupport.INFERRED_CT_BINARY,
                body)).isTrue();
    }

    @Test
    void shouldIncludeBodyParameters_declaredFormButInferredBinary_returnsFalse() {
        // The Google federatedcompute case: Content-Type: application/x-www-form-urlencoded on a
        // raw protobuf body. Declared says form, inference sees binary, gate must drop BODY.
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.URL_ENCODED, List.of(), HttpMessageDocSupport.INFERRED_CT_BINARY)).isFalse();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.MULTIPART, List.of(), HttpMessageDocSupport.INFERRED_CT_BINARY)).isFalse();
    }

    @Test
    void shouldIncludeBodyParameters_declaredNonFormTextual_returnsFalse() {
        // JSON / XML / AMF should not legitimately emit BODY params; drop regardless of inference.
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.JSON, List.of(), HttpMessageDocSupport.INFERRED_CT_JSON)).isFalse();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.XML, List.of(), HttpMessageDocSupport.INFERRED_CT_XML)).isFalse();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.AMF, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isFalse();
    }

    @Test
    void shouldIncludeBodyParameters_noneOrUnknownEnum_withoutHeader_returnsTrue() {
        // Absent/unknown declared + no header + non-binary body preserves legacy headerless-form behavior.
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.NONE, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                ContentType.UNKNOWN, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, null, HttpMessageDocSupport.INFERRED_CT_EMPTY)).isTrue();
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, List.of(), HttpMessageDocSupport.INFERRED_CT_TEXT)).isTrue();
    }

    @Test
    void shouldIncludeBodyParameters_headerFallback_binaryReturnsFalse() {
        assertBinaryHeaderFiltered("application/protobuf");
        assertBinaryHeaderFiltered("application/x-protobuf");
        assertBinaryHeaderFiltered("application/grpc");
        assertBinaryHeaderFiltered("application/octet-stream");
        assertBinaryHeaderFiltered("image/png");
        assertBinaryHeaderFiltered("application/zip");
        assertBinaryHeaderFiltered("application/gzip");
    }

    @Test
    void shouldIncludeBodyParameters_headerFallback_multipartReturnsTrue() {
        assertTextualHeaderKept("multipart/form-data; boundary=abc");
    }

    @Test
    void shouldIncludeBodyParameters_headerFallback_textualReturnsTrue() {
        assertTextualHeaderKept("application/x-www-form-urlencoded");
        assertTextualHeaderKept("text/plain");
        assertTextualHeaderKept("text/html; charset=utf-8");
    }

    @Test
    void inferRequestContentType_emptyOrNull_returnsEmpty() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(null, null))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_EMPTY);
        assertThat(RequestResponseDocBuilder.inferRequestContentType(new byte[0], List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_EMPTY);
    }

    @Test
    void inferRequestContentType_nulBytes_returnsBinary() {
        byte[] bytes = new byte[]{0x01, 0x02, 0x00, 0x03, 0x04};
        assertThat(RequestResponseDocBuilder.inferRequestContentType(bytes, List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_BINARY);
    }

    @Test
    void inferRequestContentType_highControlCharRatio_returnsBinary() {
        byte[] bytes = new byte[64];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = 0x01;
        }
        assertThat(RequestResponseDocBuilder.inferRequestContentType(bytes, List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_BINARY);
    }

    @Test
    void inferRequestContentType_jsonObject_returnsJson() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "  {\"a\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_JSON);
    }

    @Test
    void inferRequestContentType_jsonArray_returnsJson() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "[1,2,3]".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_JSON);
    }

    @Test
    void inferRequestContentType_xml_returnsXml() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "<?xml version=\"1.0\"?><root/>".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_XML);
    }

    @Test
    void inferRequestContentType_multipart_returnsMultipart() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "--boundary123\r\nContent-Disposition: form-data".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_MULTIPART);
    }

    @Test
    void inferRequestContentType_plainText_returnsText() {
        assertThat(RequestResponseDocBuilder.inferRequestContentType(
                "name=value&other=thing".getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of()))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_TEXT);
    }

    @Test
    void recordParameterStats_droppedSynthesized_statsOnlyNoLog() throws Exception {
        HttpRequest request = mockRequest("POST", "https://example.test/api");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterStats(
                        request, ContentType.JSON, 10, 4_999, false));

        assertThat(events).isEmpty();
        assertThat(ExportStats.getSynthesizedBodyParamsDropped()).isEqualTo(4_999);
    }

    @Test
    void recordParameterStats_highDroppedSynthesized_statsOnlyNoLog() throws Exception {
        HttpRequest request = mockRequest("POST", "https://example.test/upload");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterStats(
                        request, ContentType.URL_ENCODED, 2, 5_000, false));

        assertThat(events).isEmpty();
        assertThat(ExportStats.getSynthesizedBodyParamsDropped()).isEqualTo(5_000);
    }

    @Test
    void recordParameterStats_highRetained_statsOnlyNoLog() throws Exception {
        HttpRequest request = mockRequest("GET", "https://example.test/search");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterStats(
                        request, ContentType.JSON, 5_000, 0, false));

        assertThat(events).isEmpty();
        assertThat(ExportStats.getSynthesizedBodyParamsDropped()).isZero();
    }

    private static void assertBinaryHeaderFiltered(String contentTypeHeader) {
        List<HttpHeader> headers = List.of(header("Content-Type", contentTypeHeader));
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, headers, HttpMessageDocSupport.INFERRED_CT_TEXT))
                .as("header '%s' should classify body as binary", contentTypeHeader)
                .isFalse();
    }

    private static void assertTextualHeaderKept(String contentTypeHeader) {
        List<HttpHeader> headers = List.of(header("Content-Type", contentTypeHeader));
        assertThat(RequestResponseDocBuilder.shouldIncludeBodyParameters(
                null, headers, HttpMessageDocSupport.INFERRED_CT_TEXT))
                .as("header '%s' should classify body as textual", contentTypeHeader)
                .isTrue();
    }

    @Test
    void collectParameters_includeBodyFalse_usesTypedAccessors_andNeverCallsUnfilteredParameters() {
        // Build mocks BEFORE nesting them inside when(...).thenReturn(...) — Mockito otherwise
        // raises UnfinishedStubbingException when a stubbed method is created inside another
        // stubbing call.
        ParsedHttpParameter url1 = param("q", "1", HttpParameterType.URL);
        ParsedHttpParameter url2 = param("page", "2", HttpParameterType.URL);
        List<ParsedHttpParameter> urlParams = List.of(url1, url2);
        HttpRequest request = mock(HttpRequest.class);
        when(request.hasParameters(HttpParameterType.URL)).thenReturn(true);
        when(request.parameters(HttpParameterType.URL)).thenReturn(urlParams);
        when(request.hasParameters(HttpParameterType.JSON)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML_ATTRIBUTE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.MULTIPART_ATTRIBUTE)).thenReturn(false);

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(request, false);

        assertThat(result.entries()).hasSize(2);
        assertThat(result.droppedSynthesized()).isZero();
        assertThat(result.bodyEnumerationSkipped()).isTrue();
        verify(request, never()).parameters();
        verify(request, never()).parameters(HttpParameterType.BODY);
    }

    @Test
    void collectParameters_includeBodyTrue_callsUnfilteredParameters_andDoesNotMarkSkipped() {
        ParsedHttpParameter urlParam = param("u", "1", HttpParameterType.URL);
        ParsedHttpParameter bodyParam = param("b1", "x", HttpParameterType.BODY);
        List<ParsedHttpParameter> all = List.of(urlParam, bodyParam);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(all);

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(request, true);

        assertThat(result.entries()).hasSize(2);
        assertThat(result.bodyEnumerationSkipped()).isFalse();
        verify(request).parameters();
    }

    @Test
    void collectParameters_nullRequest_returnsEmpty() {
        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(null, false);
        assertThat(result.entries()).isEmpty();
        assertThat(result.bodyEnumerationSkipped()).isFalse();
    }

    @Test
    void collectParameters_includeBodyFalse_swallowsTypedAccessorThrows_andCollectsRest() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.hasParameters(HttpParameterType.URL)).thenReturn(true);
        when(request.parameters(HttpParameterType.URL)).thenThrow(new RuntimeException("malformed url params"));
        when(request.hasParameters(HttpParameterType.JSON)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML_ATTRIBUTE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.MULTIPART_ATTRIBUTE)).thenReturn(false);

        RequestResponseDocBuilder.ParametersResult result =
                RequestResponseDocBuilder.collectParameters(request, false);

        assertThat(result.entries()).isEmpty();
        assertThat(result.bodyEnumerationSkipped()).isTrue();
        verify(request, never()).parameters();
    }

    @Test
    void recordParameterStats_skippedBody_underThreshold_doesNotBumpExportAckCounter() throws Exception {
        HttpRequest request = mockRequest("POST", "https://example.test/binary-misdeclared");

        SwingUtilities.invokeAndWait(() ->
                RequestResponseDocBuilder.recordParameterStats(
                        request, ContentType.URL_ENCODED, /* retained */ 3, /* dropped */ 0,
                        /* bodyEnumerationSkipped */ true));

        assertThat(events).isEmpty();
        assertThat(ExportStats.getDocsWithSkippedBodyEnumeration()).isZero();
        assertThat(ExportStats.getSynthesizedBodyParamsDropped()).isZero();
    }

    @Test
    void buildTrafficRequestDoc_urlCap_alignsPathQueryWithParameters() {
        int cap = RequestResponseParametersSupport.URL_PARAMETERS_CAP;
        List<ParsedHttpParameter> urlParams = new ArrayList<>(cap + 3);
        StringBuilder fullQuery = new StringBuilder();
        for (int i = 0; i < cap + 3; i++) {
            urlParams.add(param("p" + i, "v" + i, HttpParameterType.URL));
            if (i > 0) {
                fullQuery.append('&');
            }
            fullQuery.append("p").append(i).append("=v").append(i);
        }
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(urlParams);
        when(request.method()).thenReturn("GET");
        when(request.pathWithoutQuery()).thenReturn("/fuzz");
        when(request.path()).thenReturn("/fuzz?" + fullQuery);
        when(request.query()).thenReturn(fullQuery.toString());
        when(request.url()).thenReturn("https://example.test/fuzz?" + fullQuery);
        when(request.contentType()).thenReturn(ContentType.NONE);
        when(request.headers()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.fileExtension()).thenReturn("");

        Map<String, Object> doc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);

        List<Map<String, Object>> parameters = stringObjectMapList(doc.get("parameters"));
        assertThat(parameters).hasSize(cap);
        Map<?, ?> path = (Map<?, ?>) doc.get("path");
        String expectedQuery = RequestResponseParametersSupport.buildQueryStringFromUrlEntries(parameters);
        assertThat(path.get("query")).isEqualTo(expectedQuery);
        assertThat(path.get("with_query")).isEqualTo("/fuzz?" + expectedQuery);
        assertThat(ExportStats.getDocsUrlParamsTruncated()).isEqualTo(1);
        assertThat(ExportStats.getUrlParamsDroppedTotal()).isEqualTo(3);
    }

    private static HttpRequest mockRequest(String method, String url) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn(method);
        when(request.url()).thenReturn(url);
        return request;
    }

    private static ParsedHttpParameter param(String name, String value, HttpParameterType type) {
        ParsedHttpParameter p = mock(ParsedHttpParameter.class);
        when(p.name()).thenReturn(name);
        when(p.value()).thenReturn(value);
        when(p.type()).thenReturn(type);
        return p;
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        when(h.name()).thenReturn(name);
        when(h.value()).thenReturn(value);
        return h;
    }

    @Test
    void inferRequestContentType_gzipUrlencodedForm_returnsText() throws Exception {
        byte[] plain = "org_id=test&ja=123".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/x-www-form-urlencoded"),
                header("Content-Encoding", "gzip"));

        assertThat(RequestResponseParametersSupport.inferRequestContentType(
                gzip, headers, ContentType.URL_ENCODED))
                .isEqualTo(HttpMessageDocSupport.INFERRED_CT_TEXT);
    }

    @Test
    void parseUrlEncodedBodyParameters_decodesPairs() {
        byte[] body = "a=1&b=hello%20world".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.parseUrlEncodedBodyParameters(
                        body, List.of(header("Content-Type", "application/x-www-form-urlencoded")));

        assertThat(result.entries()).hasSize(2);
        assertThat(result.entries().get(0)).containsEntry("name", "a").containsEntry("type", "BODY");
        assertThat(result.entries().get(1)).containsEntry("value", "hello world");
    }

    @Test
    void parseUrlEncodedBodyParameters_scansEmptyBareAndDuplicatePairsInOrder() {
        byte[] body = "&&first=1&&bare&first=two=three&empty=&last=4&&"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);

        var result = RequestResponseParametersSupport.parseUrlEncodedBodyParameters(body, List.of());

        assertThat(result.entries()).extracting(row -> row.get("name"))
                .containsExactly("first", "bare", "first", "empty", "last");
        assertThat(result.entries()).extracting(row -> row.get("value"))
                .containsExactly("1", "", "two=three", "", "4");
        assertThat(result.droppedBodyParams()).isZero();
    }

    @Test
    void parseUrlEncodedBodyParameters_capCountsOnlyValidNonemptyNames() {
        int cap = RequestResponseParametersSupport.BODY_PARAMETERS_CAP;
        StringBuilder body = new StringBuilder("&&=ignored&%5Bbad=ignored&");
        for (int i = 0; i < cap; i++) {
            body.append("field").append(i).append("=value&");
        }
        body.append("&%00=ignored&%5Bbad=ignored&=ignored&extra=1&bare&tail=%GG&&");

        var result = RequestResponseParametersSupport.parseUrlEncodedBodyParameters(
                body.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of());

        assertThat(result.entries()).hasSize(cap);
        assertThat(result.entries().getFirst()).containsEntry("name", "field0");
        assertThat(result.entries().getLast()).containsEntry("name", "field" + (cap - 1));
        assertThat(result.droppedBodyParams()).isEqualTo(3);
    }

    @Test
    void parseUrlEncodedBodyParameters_malformedNameAfterCapDoesNotDiscardRetainedRows() {
        String body = "valid=value&".repeat(RequestResponseParametersSupport.BODY_PARAMETERS_CAP) + "%GG=value";

        var result = RequestResponseParametersSupport.parseUrlEncodedBodyParameters(
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), List.of());
        assertThat(result.entries()).hasSize(RequestResponseParametersSupport.BODY_PARAMETERS_CAP);
        assertThat(result.droppedBodyParams()).isEqualTo(1);
    }

    @Test
    void collectParameters_gzipFormWithoutBurpBodyParams_supplementsBodyParameters() throws Exception {
        byte[] plain = "org_id=abc&sid=xyz".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        ParsedHttpParameter urlParam = param("k", "v", HttpParameterType.URL);
        List<ParsedHttpParameter> urlOnly = List.of(urlParam);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(urlOnly);
        when(request.parameters(HttpParameterType.URL)).thenReturn(urlOnly);
        when(request.hasParameters(HttpParameterType.COOKIE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.JSON)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML_ATTRIBUTE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.MULTIPART_ATTRIBUTE)).thenReturn(false);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/x-www-form-urlencoded"),
                header("Content-Encoding", "gzip"));

        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.collectParameters(
                        request, true, gzip, ContentType.URL_ENCODED, headers);

        assertThat(result.entries())
                .extracting(e -> e.get("type"))
                .contains("URL", "BODY");
        assertThat(result.entries().stream().filter(e -> "BODY".equals(e.get("type"))).count()).isEqualTo(2);
        assertThat(result.bodyEnumerationSkipped()).isFalse();
    }

    @Test
    void collectParameters_gzipFormWithGarbageBurpBody_replacesWithSupplemental() throws Exception {
        byte[] plain = "org_id=abc&sid=xyz".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        ParsedHttpParameter garbageBody = param("\u001f\u008b", "", HttpParameterType.BODY);
        ParsedHttpParameter urlParam = param("k", "v", HttpParameterType.URL);
        List<ParsedHttpParameter> burpParams = List.of(urlParam, garbageBody);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(burpParams);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/x-www-form-urlencoded"),
                header("Content-Encoding", "gzip"));

        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.collectParameters(
                        request, true, gzip, ContentType.URL_ENCODED, headers);

        assertThat(result.wireBodyParamsReplaced()).isTrue();
        assertThat(result.bodyParamsSource()).isEqualTo(RequestResponseParametersSupport.BODY_PARAMS_SOURCE_MIXED);
        assertThat(result.wireTransformed()).isTrue();
        assertThat(result.encodingsApplied()).containsExactly("gzip");
        assertThat(result.wireBodyParamsDropped()).isEqualTo(1);
        assertThat(result.entries().stream().filter(e -> "BODY".equals(e.get("type"))))
                .extracting(e -> e.get("name"))
                .containsExactly("org_id", "sid");
    }

    @Test
    void collectParameters_skipPathDeclaredUrlencoded_rescuesSupplementalBody() throws Exception {
        byte[] plain = "a=1&b=2".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        ParsedHttpParameter urlParam = param("q", "x", HttpParameterType.URL);
        List<ParsedHttpParameter> urlParams = List.of(urlParam);
        HttpRequest request = mock(HttpRequest.class);
        when(request.hasParameters(HttpParameterType.URL)).thenReturn(true);
        when(request.parameters(HttpParameterType.URL)).thenReturn(urlParams);
        when(request.hasParameters(HttpParameterType.COOKIE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.JSON)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.XML_ATTRIBUTE)).thenReturn(false);
        when(request.hasParameters(HttpParameterType.MULTIPART_ATTRIBUTE)).thenReturn(false);
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/x-www-form-urlencoded"),
                header("Content-Encoding", "gzip"));

        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.collectParameters(
                        request, false, gzip, ContentType.URL_ENCODED, headers);

        assertThat(result.bodyEnumerationSkipped()).isFalse();
        assertThat(result.skipPathBodyRescued()).isTrue();
        assertThat(result.bodyParamsSource()).isEqualTo(RequestResponseParametersSupport.BODY_PARAMS_SOURCE_MIXED);
        assertThat(result.entries().stream().filter(e -> "BODY".equals(e.get("type"))).count()).isEqualTo(2);
    }

    @Test
    void buildTrafficRequestDoc_gzipForm_putsRequestExportMetadata() throws Exception {
        byte[] plain = "field=value".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of());
        when(request.method()).thenReturn("POST");
        when(request.pathWithoutQuery()).thenReturn("/submit");
        when(request.path()).thenReturn("/submit");
        when(request.query()).thenReturn("");
        when(request.url()).thenReturn("https://example.test/submit");
        when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        HttpHeader contentTypeHeader = header("Content-Type", "application/x-www-form-urlencoded");
        HttpHeader encodingHeader = header("Content-Encoding", "gzip");
        when(request.headers()).thenReturn(List.of(contentTypeHeader, encodingHeader));
        burp.api.montoya.core.ByteArray body = mock(burp.api.montoya.core.ByteArray.class);
        when(body.getBytes()).thenReturn(gzip);
        when(request.body()).thenReturn(body);
        when(request.markers()).thenReturn(List.of());
        when(request.fileExtension()).thenReturn("");

        Map<String, Object> doc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);

        assertThat(doc).doesNotContainKey("export");
        assertThat(ExportStats.getDocsWireBodyParamsReplaced()).isEqualTo(1);
        assertThat(ExportStats.getBodyParamsSkipReasonCounts().get("wire_replaced")).isEqualTo(1L);
        assertThat(ExportStats.getDocsBodyEnumerationMisgateSuspect()).isZero();
    }

    @Test
    void buildTrafficRequestDoc_misgateBinary_recordsMisgateSessionStats() throws Exception {
        byte[] bodyBytes = new byte[] {0x00, 0x01, 0x02, 0x03};
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of());
        when(request.method()).thenReturn("POST");
        when(request.pathWithoutQuery()).thenReturn("/collect");
        when(request.path()).thenReturn("/collect");
        when(request.query()).thenReturn("");
        when(request.url()).thenReturn("https://app-measurement.com/a/collect");
        when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        HttpHeader contentTypeHeader = header("Content-Type", "application/x-www-form-urlencoded");
        when(request.headers()).thenReturn(List.of(contentTypeHeader));
        burp.api.montoya.core.ByteArray body = mock(burp.api.montoya.core.ByteArray.class);
        when(body.getBytes()).thenReturn(bodyBytes);
        when(request.body()).thenReturn(body);
        when(request.markers()).thenReturn(List.of());
        when(request.fileExtension()).thenReturn("");

        Map<String, Object> doc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);

        assertThat(doc).doesNotContainKey("export");
        assertThat(ExportStats.getDocsBodyEnumerationMisgateSuspect()).isEqualTo(1);
        assertThat(ExportStats.getDocsWithSkippedBodyEnumeration()).isEqualTo(1);
        assertThat(ExportStats.getBodyParamsSkipReasonCounts().get("misgate_binary")).isEqualTo(1L);
    }

    @Test
    void resolveBodyParamsSkipReason_prioritizesRescueOverMisgate() {
        RequestResponseDocBuilder.ParametersResult rescued =
                new RequestResponseDocBuilder.ParametersResult(
                        List.of(),
                        0,
                        false,
                        0,
                        "",
                        0,
                        RequestResponseParametersSupport.BODY_PARAMS_SOURCE_MIXED,
                        false,
                        true,
                        false,
                        List.of(),
                        0,
                        false);
        assertThat(RequestResponseDocBuilder.resolveBodyParamsSkipReason(rescued, true))
                .isEqualTo("skip_path_rescued");
    }

    @Test
    void parseUrlEncodedBodyParameters_rejectsJsonArrayBody() {
        byte[] json = "[[1,2,3]]".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.parseUrlEncodedBodyParameters(json, List.of());

        assertThat(result.supplementalRejectedNonForm()).isTrue();
        assertThat(result.entries()).isEmpty();
    }

    @Test
    void parseUrlEncodedBodyParameters_acceptsBracketInValue() {
        byte[] body = "data=%5B%5B1%2C2%5D%5D".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.parseUrlEncodedBodyParameters(body, List.of());

        assertThat(result.supplementalRejectedNonForm()).isFalse();
        assertThat(result.entries()).hasSize(1);
        assertThat(result.entries().get(0).get("name")).isEqualTo("data");
        assertThat(result.entries().get(0).get("value")).isEqualTo("[[1,2]]");
    }

    @Test
    void parseUrlEncodedBodyParameters_rejectsBracketPrefixedName() {
        byte[] body = "%5B%5B=1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.parseUrlEncodedBodyParameters(body, List.of());

        assertThat(result.supplementalRejectedNonForm()).isTrue();
        assertThat(result.entries()).isEmpty();
    }

    @Test
    void collectParameters_jsonDeclaredAsForm_rejectsSupplementalOnWireReplace() throws Exception {
        byte[] plain = "[[1,2,3]]".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        ParsedHttpParameter garbageBody = param("\u001f\u008b", "", HttpParameterType.BODY);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of(garbageBody));
        List<HttpHeader> headers = List.of(
                header("Content-Type", "application/x-www-form-urlencoded"),
                header("Content-Encoding", "gzip"));

        RequestResponseParametersSupport.ParametersResult result =
                RequestResponseParametersSupport.collectParameters(
                        request, true, gzip, ContentType.URL_ENCODED, headers);

        assertThat(result.supplementalRejectedNonForm()).isTrue();
        assertThat(result.wireBodyParamsReplaced()).isFalse();
        assertThat(result.entries().stream().filter(e -> "BODY".equals(e.get("type")))).isEmpty();
    }

    @Test
    void buildTrafficRequestDoc_supplementalRejected_setsSkipReason() throws Exception {
        byte[] plain = "[[1,2]]".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        ParsedHttpParameter garbageBody = param("\u001f\u008b", "", HttpParameterType.BODY);
        CompressedWireBodyParamsLog.startForCurrentRun();
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of(garbageBody));
        when(request.method()).thenReturn("POST");
        when(request.pathWithoutQuery()).thenReturn("/log");
        when(request.path()).thenReturn("/log");
        when(request.query()).thenReturn("");
        when(request.url()).thenReturn("https://play.google.com/log");
        when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        HttpHeader contentTypeHeader = header("Content-Type", "application/x-www-form-urlencoded");
        HttpHeader encodingHeader = header("Content-Encoding", "gzip");
        when(request.headers()).thenReturn(List.of(contentTypeHeader, encodingHeader));
        burp.api.montoya.core.ByteArray body = mock(burp.api.montoya.core.ByteArray.class);
        when(body.getBytes()).thenReturn(gzip);
        when(request.body()).thenReturn(body);
        when(request.markers()).thenReturn(List.of());
        when(request.fileExtension()).thenReturn("");

        Map<String, Object> doc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        CompressedWireBodyParamsLog.flushStartupSummary();
        flushLogListeners();

        assertThat(doc).doesNotContainKey("export");
        assertThat(ExportStats.getDocsSupplementalRejectedNonForm()).isEqualTo(1);
        assertThat(ExportStats.getBodyParamsSkipReasonCounts().get("supplemental_rejected_non_form")).isEqualTo(1L);
        assertThat(events)
                .anySatisfy(event -> assertThat(event.message())
                        .contains("supplemental_rejected_non_form=1/1 url(s)")
                        .doesNotContain("wire_dropped=1/1 url(s)"));
    }

    private static byte[] gzipBytes(byte[] input) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try (java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(out)) {
            gzip.write(input);
        }
        return out.toByteArray();
    }

    private static void flushLogListeners() throws Exception {
        SwingUtilities.invokeAndWait(() -> {});
    }

    private record LoggedEvent(String level, String message) {
        LoggedEvent {
            level = level == null ? "" : level;
            message = message == null ? "" : message;
        }
    }
}
