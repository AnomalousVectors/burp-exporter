package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.call;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;

/**
 * Asserts that {@link TrafficHttpHandler#buildDocument} produces a document with the expected
 * top-level and nested shape for the traffic index mapping.
 */
class TrafficHttpHandlerDocumentTest {

    private final TrafficHttpHandler handler = new TrafficHttpHandler();
    private final HttpRequest request = mock(HttpRequest.class);
    private final HttpResponseReceived response = mock(HttpResponseReceived.class);
    private final HttpService service = mock(HttpService.class);

    {
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        when(request.url()).thenReturn("https://example.com/path?q=1");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/path?q=1");
        when(request.pathWithoutQuery()).thenReturn("/path");
        when(request.query()).thenReturn("q=1");
        when(request.fileExtension()).thenReturn("");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.bodyOffset()).thenReturn(0);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(ContentType.NONE);
        ByteArray requestBytes = byteArray("GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
        when(request.toByteArray()).thenReturn(requestBytes);

        when(response.initiatingRequest()).thenReturn(request);
        when(response.messageId()).thenReturn(1);
        when(response.toolSource()).thenReturn(null);
        when(response.annotations()).thenReturn(null);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.cookies()).thenReturn(List.of());
        when(response.mimeType()).thenReturn(MimeType.HTML);
        when(response.statedMimeType()).thenReturn(MimeType.HTML);
        when(response.inferredMimeType()).thenReturn(MimeType.HTML);
        when(response.body()).thenReturn(null);
        when(response.bodyOffset()).thenReturn(0);
        when(response.bodyToString()).thenReturn("");
        when(response.markers()).thenReturn(List.of());
        when(response.attributes(any(AttributeType[].class))).thenReturn(List.of());
        ByteArray responseBytes = byteArray("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        when(response.toByteArray()).thenReturn(responseBytes);
    }

    @Test
    void buildDocument_hasRequiredTopLevelKeys() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        assertThat(doc).containsKeys("burp", "request", "response", "websocket", "meta");
        assertThat(requestProtocol(doc))
                .containsEntry("http_version", "HTTP/1.1");
        Map<?, ?> requestUrl = nestedMap(nestedMap(doc, "request"), "url");
        assertThat(requestUrl.get("raw")).isEqualTo("https://example.com/path?q=1");
        assertThat(requestUrl.get("text")).isEqualTo("https://example.com/path?q=1");
        assertThat(requestUrl.get("scheme")).isEqualTo("https");
        assertThat(requestUrl.get("host")).isEqualTo("example.com");
        assertThat(requestUrl.get("port")).isEqualTo(443);
        assertThat(requestUrl.get("path")).isEqualTo("/path");
        assertThat(requestUrl.get("query")).isEqualTo("q=1");
        assertThat(requestProtocol(doc)).doesNotContainKey("transport");
        assertThat(requestProtocol(doc)).doesNotContainKey("sub");
        assertThat(requestProtocol(doc)).doesNotContainKey("application");
        assertThat(websocket(doc)).containsEntry("is_websocket", false);
        assertThat(burpRepeater(doc)).containsKeys("tab_name", "tab_group");
        assertThat(doc.containsKey("scheme")).isFalse();
        assertThat(doc.containsKey("protocol")).isFalse();
        assertThat(doc.containsKey("status")).isFalse();
        assertThat(doc.containsKey("status_code")).isFalse();
        assertThat(doc.containsKey("url")).isFalse();
        assertThat(doc.containsKey("host")).isFalse();
        assertThat(doc.containsKey("port")).isFalse();
        assertThat(doc.containsKey("http_version")).isFalse();
        assertThat(doc.containsKey("tool")).isFalse();
        assertThat(doc.containsKey("burp_in_scope")).isFalse();
        assertThat(doc.containsKey("message_id")).isFalse();
        assertThat(doc.containsKey("path")).isFalse();
        assertThat(doc.containsKey("method")).isFalse();
        assertThat(doc.containsKey("mime_type")).isFalse();
    }

    @Test
    void buildDocument_reservesRepeaterMetadataFields_forFutureLiveEnrichment() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        assertThat(burpRepeater(doc)).containsEntry("tab_name", null);
        assertThat(burpRepeater(doc)).containsEntry("tab_group", null);
    }

    @Test
    void buildDocument_exportsHttpResponseNotesAsBurpNotes() {
        Annotations responseAnnotations = mock(Annotations.class);
        when(responseAnnotations.hasNotes()).thenReturn(true);
        when(responseAnnotations.notes()).thenReturn("analyst note");
        when(responseAnnotations.hasHighlightColor()).thenReturn(false);
        when(response.annotations()).thenReturn(responseAnnotations);

        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> burp = nestedMap(doc, "burp");
        assertThat(burp.get("notes")).isEqualTo("analyst note");
    }

    @Test
    void buildDocument_liveHttpTimingDoesNotInventTimeToFirstByte() {
        Map<String, Object> doc = handler.buildDocument(
                response,
                request,
                true,
                100L,
                175L,
                ToolType.PROXY,
                RepeaterMetadataFields.Metadata.empty());

        Map<?, ?> timing = nestedMap(nestedMap(doc, "burp"), "timing");
        assertThat(timing.get("req_sent_to_res_end")).isEqualTo(75L);
        assertThat(timing.containsKey("req_sent_to_res_start")).isTrue();
        assertThat(timing.get("req_sent_to_res_start")).isNull();
        assertThat(timing.containsKey("duration_ms")).isFalse();
        assertThat(timing.containsKey("time_to_first_byte_ms")).isFalse();
        assertThat(timing.containsKey("response_start_latency_ms")).isFalse();
    }

    @Test
    void buildDocument_placesOnlyHtmlSpecificResponseAttributesUnderBodyHtml() {
        Attribute wordCount = mock(Attribute.class);
        when(wordCount.type()).thenReturn(AttributeType.WORD_COUNT);
        when(wordCount.value()).thenReturn(7);
        Attribute visibleWordCount = mock(Attribute.class);
        when(visibleWordCount.type()).thenReturn(AttributeType.VISIBLE_WORD_COUNT);
        when(visibleWordCount.value()).thenReturn(2);
        Attribute inputSubmitLabels = mock(Attribute.class);
        when(inputSubmitLabels.type()).thenReturn(AttributeType.INPUT_SUBMIT_LABELS);
        when(inputSubmitLabels.value()).thenReturn(1);
        when(response.attributes(any(AttributeType[].class)))
                .thenReturn(List.of(wordCount, visibleWordCount, inputSubmitLabels));

        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> body = nestedMap(nestedMap(doc, "response"), "body");
        Map<?, ?> html = nestedMap(body, "html");
        Map<?, ?> htmlText = nestedMap(html, "text");
        Map<?, ?> htmlForms = nestedMap(html, "forms");
        assertThat(body.get("word_count")).isEqualTo(7);
        assertThat(htmlText.get("visible_word_count")).isEqualTo(2);
        assertThat(htmlForms.get("input_submit_labels")).isEqualTo(1);
        assertThat(html.containsKey("word_count")).isFalse();
        assertThat(body.containsKey("visible_word_count")).isFalse();
        assertThat(body.containsKey("input_submit_labels")).isFalse();
    }

    @Test
    void buildDocument_doesNotEmitRemovedResponseConvenienceAttributes() {
        Attribute location = mock(Attribute.class);
        when(location.type()).thenReturn(AttributeType.LOCATION);
        when(location.value()).thenReturn(1);
        Attribute contentLength = mock(Attribute.class);
        when(contentLength.type()).thenReturn(AttributeType.CONTENT_LENGTH);
        when(contentLength.value()).thenReturn(42);
        Attribute cookieNames = mock(Attribute.class);
        when(cookieNames.type()).thenReturn(AttributeType.COOKIE_NAMES);
        when(cookieNames.value()).thenReturn(1);
        Attribute etag = mock(Attribute.class);
        when(etag.type()).thenReturn(AttributeType.ETAG_HEADER);
        when(etag.value()).thenReturn(3);
        Attribute lastModified = mock(Attribute.class);
        when(lastModified.type()).thenReturn(AttributeType.LAST_MODIFIED_HEADER);
        when(lastModified.value()).thenReturn(4);
        Attribute contentLocation = mock(Attribute.class);
        when(contentLocation.type()).thenReturn(AttributeType.CONTENT_LOCATION);
        when(contentLocation.value()).thenReturn(5);
        when(response.attributes(any(AttributeType[].class)))
                .thenReturn(List.of(location, contentLength, cookieNames, etag, lastModified, contentLocation));

        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> responseDoc = nestedMap(doc, "response");
        assertMissingKeys(responseDoc, "location", "content_length", "cookie_names", "etag_header",
                "last_modified_header", "content_location");
        assertThat(responseDoc.containsKey("headers")).isTrue();
        assertThat(responseDoc.containsKey("cookies")).isTrue();
    }

    @Test
    void buildDocument_writesLiveRepeaterMetadata_whenProvided() {
        Map<String, Object> doc = handler.buildDocument(
                response,
                request,
                true,
                1L,
                2L,
                ToolType.REPEATER,
                new RepeaterMetadataFields.Metadata("Tab 7", "Group X"));

        assertThat(burpRepeater(doc)).containsEntry("tab_name", "Tab 7");
        assertThat(burpRepeater(doc)).containsEntry("tab_group", "Group X");
    }

    @Test
    void buildDocument_requestHasExpectedShape() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> req = nestedMap(doc, "request");
        assertThat(req).isNotNull();
        assertContainsKeys(req, "url", "method", "path", "protocol", "headers", "parameters",
                "cookies", "content_type", "body");
        assertThat(req.containsKey("host")).isFalse();
        assertThat(req.containsKey("port")).isFalse();
        assertThat(req.containsKey("header")).isFalse();
        assertThat(req.containsKey("markers")).isFalse();
        assertContainsKeys(nestedMap(req, "body"), "markers");
        Map<?, ?> burp = nestedMap(doc, "burp");
        Map<?, ?> proxy = nestedMap(burp, "proxy");
        assertThat(proxy.containsKey("is_edited")).isFalse();
        Map<?, ?> reqBody = nestedMap(req, "body");
        assertContainsKeys(reqBody, "length", "offset", "b64", "text");
        assertContainsKeys(nestedMap(req, "content_type"), "raw", "media_type", "burp_declared", "burp_enum", "inferred");
        assertThat(req.get("method")).isEqualTo("GET");
        Map<?, ?> url = nestedMap(req, "url");
        assertThat(url.get("raw")).isEqualTo("https://example.com/path?q=1");
        assertThat(url.get("scheme")).isEqualTo("https");
        assertThat(url.get("host")).isEqualTo("example.com");
        assertThat(url.get("port")).isEqualTo(443);
        Map<?, ?> path = nestedMap(req, "path");
        assertThat(path.get("with_query")).isEqualTo("/path?q=1");
        assertThat(path.get("without_query")).isEqualTo("/path");
        assertThat(path.get("query")).isEqualTo("q=1");
    }

    @Test
    void buildDocument_bodyMarkersUseTrafficFieldNames() {
        Range requestRange = mock(Range.class);
        when(requestRange.startIndexInclusive()).thenReturn(1);
        when(requestRange.endIndexExclusive()).thenReturn(3);
        Marker requestMarker = mock(Marker.class);
        when(requestMarker.range()).thenReturn(requestRange);
        Range responseRange = mock(Range.class);
        when(responseRange.startIndexInclusive()).thenReturn(5);
        when(responseRange.endIndexExclusive()).thenReturn(8);
        Marker responseMarker = mock(Marker.class);
        when(responseMarker.range()).thenReturn(responseRange);
        when(request.markers()).thenReturn(List.of(requestMarker));
        when(response.markers()).thenReturn(List.of(responseMarker));

        Map<String, Object> doc = handler.buildDocument(response, request, true);

        List<?> requestMarkers = (List<?>) nestedMap(nestedMap(doc, "request"), "body").get("markers");
        Map<?, ?> firstRequestMarker = (Map<?, ?>) requestMarkers.get(0);
        assertThat(firstRequestMarker.get("start_inclusive")).isEqualTo(1);
        assertThat(firstRequestMarker.get("end_exclusive")).isEqualTo(3);
        assertThat(firstRequestMarker.containsKey("start_index_inclusive")).isFalse();
        assertThat(firstRequestMarker.containsKey("end_index_exclusive")).isFalse();
        List<?> responseMarkers = (List<?>) nestedMap(nestedMap(doc, "response"), "body").get("markers");
        Map<?, ?> firstResponseMarker = (Map<?, ?>) responseMarkers.get(0);
        assertThat(firstResponseMarker.get("start_inclusive")).isEqualTo(5);
        assertThat(firstResponseMarker.get("end_exclusive")).isEqualTo(8);
        assertThat(firstResponseMarker.containsKey("start_index_inclusive")).isFalse();
        assertThat(firstResponseMarker.containsKey("end_index_exclusive")).isFalse();
    }

    @Test
    void buildDocument_usesRawRequestLineFallback_whenRequestAccessorsThrow() {
        when(request.url()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.method()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.path()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.pathWithoutQuery()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.query()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.fileExtension()).thenThrow(new IllegalArgumentException("URL is invalid."));
        when(request.httpVersion()).thenThrow(new IllegalArgumentException("URL is invalid."));
        ByteArray malformedRequestBytes = byteArray("POST /fallback/path?q=1 HTTP/2\r\nHost: example.com\r\n\r\n");
        when(request.toByteArray()).thenReturn(malformedRequestBytes);

        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> req = nestedMap(doc, "request");
        Map<?, ?> url = nestedMap(req, "url");
        assertThat(url.get("raw")).isEqualTo("https://example.com/fallback/path?q=1");
        assertThat(url.get("scheme")).isEqualTo("https");
        assertThat(url.get("host")).isEqualTo("example.com");
        assertThat(url.get("port")).isEqualTo(443);
        assertThat(req.get("method")).isEqualTo("POST");
        Map<?, ?> path = nestedMap(req, "path");
        assertThat(path.get("with_query")).isEqualTo("/fallback/path?q=1");
        assertThat(path.get("without_query")).isEqualTo("/fallback/path");
        assertThat(path.get("query")).isEqualTo("q=1");
        Map<?, ?> protocol = nestedMap(req, "protocol");
        assertThat(protocol.get("http_version")).isEqualTo("HTTP/2");
        assertThat(protocol.containsKey("scheme")).isFalse();
    }

    @Test
    void buildDocument_responseHasExpectedShape() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> resp = nestedMap(doc, "response");
        assertThat(resp).isNotNull();
        assertContainsKeys(resp, "status", "protocol", "headers", "cookies", "mime_type", "body");
        assertThat(resp.containsKey("header")).isFalse();
        assertThat(resp.containsKey("markers")).isFalse();
        Map<?, ?> respStatus = nestedMap(resp, "status");
        assertContainsKeys(respStatus, "code", "code_class", "description");
        Map<?, ?> respProtocol = nestedMap(resp, "protocol");
        assertContainsKeys(respProtocol, "http_version");
        Map<?, ?> respBody = nestedMap(resp, "body");
        assertContainsKeys(respBody, "length", "offset", "b64", "text", "markers");
        assertContainsKeys(nestedMap(resp, "mime_type"), "raw_content_type", "media_type", "burp",
                "stated", "inferred_body");
        assertThat(respStatus.get("code")).isEqualTo(200);
        assertThat(respStatus.get("code_class")).isEqualTo("CLASS_2XX_SUCCESS");
        assertThat(respStatus.get("description")).isEqualTo("OK");
    }

    @Test
    void buildDocument_exportsTrafficHeadersAsOrderedRows() {
        HttpHeader host = mock(HttpHeader.class);
        when(host.name()).thenReturn("Host");
        when(host.value()).thenReturn("ip.me");
        HttpHeader forwardedFor = mock(HttpHeader.class);
        when(forwardedFor.name()).thenReturn("X-Forwarded-For");
        when(forwardedFor.value()).thenReturn("203.0.113.10");
        HttpHeader forwardedForTwo = mock(HttpHeader.class);
        when(forwardedForTwo.name()).thenReturn("x-forwarded-for");
        when(forwardedForTwo.value()).thenReturn("203.0.113.11");
        HttpHeader cookie = mock(HttpHeader.class);
        when(cookie.name()).thenReturn("Cookie");
        when(cookie.value()).thenReturn("sid=abc; theme=dark");
        when(request.headers()).thenReturn(List.of(host, forwardedFor, forwardedForTwo, cookie));

        HttpHeader server = mock(HttpHeader.class);
        when(server.name()).thenReturn("Server");
        when(server.value()).thenReturn("nginx/1.18.0");
        HttpHeader date = mock(HttpHeader.class);
        when(date.name()).thenReturn("Date");
        when(date.value()).thenReturn("Tue, 15 Nov 1994 08:12:31 GMT");
        HttpHeader setCookieOne = mock(HttpHeader.class);
        when(setCookieOne.name()).thenReturn("Set-Cookie");
        when(setCookieOne.value()).thenReturn(
                "a=1; Domain=example.com; Path=/; Max-Age=2592000000; Secure; HttpOnly; SameSite=Lax; Partitioned");
        HttpHeader setCookieTwo = mock(HttpHeader.class);
        when(setCookieTwo.name()).thenReturn("set-cookie");
        when(setCookieTwo.value()).thenReturn(
                "b=2; Expires=Fri Sep 18 2026 01:39:10 GMT+0000 (Coordinated Universal Time)");
        when(response.headers()).thenReturn(List.of(server, date, setCookieOne, setCookieTwo));

        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> requestDoc = nestedMap(doc, "request");
        List<?> requestHeaders = (List<?>) requestDoc.get("headers");
        assertThat(requestHeaders).hasSize(4);
        Map<?, ?> firstRequestHeader = (Map<?, ?>) requestHeaders.get(0);
        assertThat(firstRequestHeader.get("name")).isEqualTo("host");
        assertThat(firstRequestHeader.get("raw")).isEqualTo("Host");
        assertThat(firstRequestHeader.get("value")).isEqualTo("ip.me");
        assertThat(firstRequestHeader.get("ordinal")).isEqualTo(0);
        Map<?, ?> secondRequestHeader = (Map<?, ?>) requestHeaders.get(1);
        assertThat(secondRequestHeader.get("name")).isEqualTo("x-forwarded-for");
        assertThat(secondRequestHeader.get("value")).isEqualTo("203.0.113.10");
        assertThat(secondRequestHeader.get("ordinal")).isEqualTo(1);
        Map<?, ?> thirdRequestHeader = (Map<?, ?>) requestHeaders.get(2);
        assertThat(thirdRequestHeader.get("name")).isEqualTo("x-forwarded-for");
        assertThat(thirdRequestHeader.get("value")).isEqualTo("203.0.113.11");
        assertThat(thirdRequestHeader.get("ordinal")).isEqualTo(2);
        List<?> requestCookies = (List<?>) requestDoc.get("cookies");
        assertThat(requestCookies).hasSize(2);
        Map<?, ?> firstRequestCookie = (Map<?, ?>) requestCookies.get(0);
        assertThat(firstRequestCookie.get("name")).isEqualTo("sid");
        assertThat(firstRequestCookie.get("value")).isEqualTo("abc");
        assertThat(firstRequestCookie.get("raw")).isEqualTo("sid=abc");
        assertThat(firstRequestCookie.get("ordinal")).isEqualTo(0);
        Map<?, ?> secondRequestCookie = (Map<?, ?>) requestCookies.get(1);
        assertThat(secondRequestCookie.get("name")).isEqualTo("theme");
        assertThat(secondRequestCookie.get("value")).isEqualTo("dark");
        assertThat(secondRequestCookie.get("ordinal")).isEqualTo(1);
        assertThat(nestedMap(requestDoc, "content_type").containsKey("inferred")).isTrue();
        assertThat(requestDoc.containsKey("header")).isFalse();

        Map<?, ?> responseDoc = nestedMap(doc, "response");
        List<?> responseHeaders = (List<?>) responseDoc.get("headers");
        assertThat(responseHeaders).hasSize(4);
        Map<?, ?> firstResponseHeader = (Map<?, ?>) responseHeaders.get(0);
        assertThat(firstResponseHeader.get("name")).isEqualTo("server");
        assertThat(firstResponseHeader.get("value")).isEqualTo("nginx/1.18.0");
        assertThat(firstResponseHeader.get("ordinal")).isEqualTo(0);
        Map<?, ?> dateResponseHeader = (Map<?, ?>) responseHeaders.get(1);
        assertThat(dateResponseHeader.get("name")).isEqualTo("date");
        assertThat(dateResponseHeader.get("raw")).isEqualTo("Date");
        assertThat(dateResponseHeader.get("ordinal")).isEqualTo(1);
        assertThat(nestedMap(responseDoc, "header_attributes").get("date"))
                .isEqualTo("Tue, 15 Nov 1994 08:12:31 GMT");
        Map<?, ?> secondResponseHeader = (Map<?, ?>) responseHeaders.get(2);
        assertThat(secondResponseHeader.get("name")).isEqualTo("set-cookie");
        assertThat(secondResponseHeader.get("value")).isEqualTo(
                "a=1; Domain=example.com; Path=/; Max-Age=2592000000; Secure; HttpOnly; SameSite=Lax; Partitioned");
        assertThat(secondResponseHeader.get("ordinal")).isEqualTo(2);
        Map<?, ?> thirdResponseHeader = (Map<?, ?>) responseHeaders.get(3);
        assertThat(thirdResponseHeader.get("name")).isEqualTo("set-cookie");
        assertThat(thirdResponseHeader.get("value")).isEqualTo(
                "b=2; Expires=Fri Sep 18 2026 01:39:10 GMT+0000 (Coordinated Universal Time)");
        assertThat(thirdResponseHeader.get("ordinal")).isEqualTo(3);
        List<?> responseCookies = (List<?>) responseDoc.get("cookies");
        assertThat(responseCookies).hasSize(2);
        Map<?, ?> firstResponseCookie = (Map<?, ?>) responseCookies.get(0);
        assertThat(firstResponseCookie.get("name")).isEqualTo("a");
        assertThat(firstResponseCookie.get("value")).isEqualTo("1");
        assertThat(firstResponseCookie.get("domain")).isEqualTo("example.com");
        assertThat(firstResponseCookie.get("path")).isEqualTo("/");
        assertThat(firstResponseCookie.get("max_age")).isEqualTo("2592000000");
        assertThat(firstResponseCookie.get("secure")).isEqualTo(true);
        assertThat(firstResponseCookie.get("http_only")).isEqualTo(true);
        assertThat(firstResponseCookie.get("same_site")).isEqualTo("Lax");
        assertThat(firstResponseCookie.get("partitioned")).isEqualTo(true);
        assertThat(firstResponseCookie.get("ordinal")).isEqualTo(0);
        Map<?, ?> secondResponseCookie = (Map<?, ?>) responseCookies.get(1);
        assertThat(secondResponseCookie.get("name")).isEqualTo("b");
        assertThat(secondResponseCookie.get("expires")).isEqualTo("2026-09-18T01:39:10Z");
        assertThat(secondResponseCookie.get("raw")).isEqualTo(
                "b=2; Expires=Fri Sep 18 2026 01:39:10 GMT+0000 (Coordinated Universal Time)");
        assertThat(secondResponseCookie.get("ordinal")).isEqualTo(1);
        assertThat(nestedMap(responseDoc, "mime_type").containsKey("burp")).isTrue();
        assertThat(responseDoc.containsKey("header")).isFalse();
    }

    @Test
    void buildDocument_responseBodyText_present_forTextAndNotCompressed() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("<html>ok</html>".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("text/html; charset=UTF-8");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("<html>ok</html>");
    }

    @Test
    void buildDocument_responseBodyText_present_forVendorPlusJson() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{\"k\":1}".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("application/vnd.api+json");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("{\"k\":1}");
    }

    @Test
    void buildDocument_responseBodyText_populated_whenTextHtmlDespiteBinaryMimeHints() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("<html>agent-visible</html>".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("text/html; charset=UTF-8");
        when(response.headers()).thenReturn(List.of(ct));
        MimeType imageMime = mock(MimeType.class);
        when(imageMime.name()).thenReturn("IMAGE_PNG");
        MimeType binaryMime = mock(MimeType.class);
        when(binaryMime.name()).thenReturn("BINARY");
        when(response.mimeType()).thenReturn(imageMime);
        when(response.statedMimeType()).thenReturn(imageMime);
        when(response.inferredMimeType()).thenReturn(binaryMime);

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("<html>agent-visible</html>");
    }

    @Test
    void buildDocument_responseBodyText_populated_whenGzipCompressedHtml() throws Exception {
        byte[] plain = "<html>ok</html>".getBytes(StandardCharsets.UTF_8);
        byte[] gzip = gzipBytes(plain);
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(gzip);
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("text/html; charset=UTF-8");
        HttpHeader ce = mock(HttpHeader.class);
        when(ce.name()).thenReturn("Content-Encoding");
        when(ce.value()).thenReturn("gzip");
        when(response.headers()).thenReturn(List.of(ct, ce));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("<html>ok</html>");
        assertThat(respBody.get("b64")).isNotNull();
        assertThat(respBody.containsKey("decoded")).isFalse();
    }

    private static byte[] gzipBytes(byte[] input) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try (java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(out)) {
            gzip.write(input);
        }
        return out.toByteArray();
    }

    @Test
    void buildDocument_responseBodyText_null_forBinaryType() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(new byte[] {0x00, 0x01, 0x02, 0x03});
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("application/octet-stream");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isNull();
    }

    @Test
    void buildDocument_responseBodyText_respectsIso88591Charset() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("caf\u00e9".getBytes(StandardCharsets.ISO_8859_1));
        when(response.body()).thenReturn(body);
        HttpHeader ct = mock(HttpHeader.class);
        when(ct.name()).thenReturn("Content-Type");
        when(ct.value()).thenReturn("text/plain; charset=ISO-8859-1");
        when(response.headers()).thenReturn(List.of(ct));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("caf\u00e9");
    }

    @Test
    void buildDocument_responseBodyText_present_whenContentTypeMissing_butMontoyaMimeIsTextual() {
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        when(response.headers()).thenReturn(List.of());
        when(response.mimeType()).thenReturn(MimeType.JSON);
        when(response.statedMimeType()).thenReturn(null);
        when(response.inferredMimeType()).thenReturn(MimeType.JSON);

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> respBody = nestedMap(nestedMap(doc, "response"), "body");
        assertThat(respBody.get("text")).isEqualTo("{\"ok\":true}");
    }

    @Test
    void buildDocument_requestBodyText_present_forCustomPhpType_whenTextLike() {
        ByteArray reqBodyBytes = mock(ByteArray.class);
        when(reqBodyBytes.getBytes()).thenReturn("<?php echo 1; ?>".getBytes(StandardCharsets.UTF_8));
        when(request.body()).thenReturn(reqBodyBytes);
        HttpHeader reqCt = mock(HttpHeader.class);
        when(reqCt.name()).thenReturn("Content-Type");
        when(reqCt.value()).thenReturn("application/php; charset=UTF-8");
        when(request.headers()).thenReturn(List.of(reqCt));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> reqBody = nestedMap(nestedMap(doc, "request"), "body");
        assertThat(reqBody.get("text")).isEqualTo("<?php echo 1; ?>");
    }

    @Test
    void buildDocument_requestBodyText_present_forUnknownCustomType_whenTextLike() {
        ByteArray reqBodyBytes = mock(ByteArray.class);
        when(reqBodyBytes.getBytes()).thenReturn("user=alice&role=admin".getBytes(StandardCharsets.UTF_8));
        when(request.body()).thenReturn(reqBodyBytes);
        HttpHeader reqCt = mock(HttpHeader.class);
        when(reqCt.name()).thenReturn("Content-Type");
        when(reqCt.value()).thenReturn("application/dbm");
        when(request.headers()).thenReturn(List.of(reqCt));

        Map<String, Object> doc = handler.buildDocument(response, request, true);
        Map<?, ?> reqBody = nestedMap(nestedMap(doc, "request"), "body");
        assertThat(reqBody.get("text")).isEqualTo("user=alice&role=admin");
    }

    @Test
    void buildDocument_metaHasSchemaAndVersion() {
        Map<String, Object> doc = handler.buildDocument(response, request, true);

        Map<?, ?> meta = nestedMap(doc, "meta");
        assertThat(meta).isNotNull();
        assertContainsKeys(meta, "schema_version", "extension_version", "indexed_at");
        assertThat(meta.get("schema_version")).isEqualTo("1");
    }

    @Test
    void buildOrphanResponse_matchesProxyHistoryEmptyResponseShape() {
        Map<?, ?> responseDoc = map(callStatic(TrafficHttpHandler.class, "buildOrphanResponse"));
        Map<?, ?> historyEmpty = map(callStatic(RequestResponseDocBuilder.class, "emptyTrafficResponseDoc"));

        assertThat(responseDoc).isEqualTo(historyEmpty);
        Map<?, ?> status = nestedMap(responseDoc, "status");
        assertThat(status.get("code")).isEqualTo(0);
        assertThat(status.get("description")).isEqualTo("No response");
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        return map(parent.get(key));
    }

    private static Map<?, ?> map(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }

    private static void assertContainsKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isTrue();
        }
    }

    private static void assertMissingKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isFalse();
        }
    }

    @Test
    void resolveResponseToolType_prefersResponseToolTypeWhenPresent() {
        ToolSource responseSource = mock(ToolSource.class);
        when(responseSource.toolType()).thenReturn(ToolType.REPEATER);
        when(response.toolSource()).thenReturn(responseSource);

            assertThat(TrafficHttpHandler.resolveResponseToolType(response, ToolType.PROXY))
                .isEqualTo(ToolType.REPEATER);
    }

    @Test
    void resolveResponseToolType_fallsBackToRequestToolTypeWhenResponseMissing() {
        when(response.toolSource()).thenReturn(null);

        assertThat(TrafficHttpHandler.resolveResponseToolType(response, ToolType.PROXY))
                .isEqualTo(ToolType.PROXY);
    }

    @Test
    void resolveResponseToolType_returnsNullWhenBothMissing() {
        when(response.toolSource()).thenReturn(null);

        assertThat(TrafficHttpHandler.resolveResponseToolType(response, null)).isNull();
    }

    @Test
    void resolveRequestStageRepeaterMetadata_returnsTrackedMetadata_forRepeaterTraffic() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            null),
                    new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"),
                    now);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(request, ToolType.REPEATER))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_fallsBackToCurrentRepeaterMetadata_whenTrackerEmpty() {
        RepeaterLiveMetadataTracker.clear();
        try {
            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("GetUserToken", null)))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("GetUserToken", null));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_doesNotCallFallbackSupplier_whenTrackerResolves() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            null),
                    new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"),
                    now);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha"));
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_returnsEmpty_whenTrackerIsAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"),
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved).isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageResolution_keepsUiSnapshot_whenTrackerIsAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"),
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            TrafficHttpHandlerSupport.RequestStageResolution resolution =
                    TrafficHttpHandler.resolveRequestStageResolution(
                            request,
                            ToolType.REPEATER,
                            () -> {
                                fallbackCalls.incrementAndGet();
                                return new RepeaterMetadataFields.Metadata("ApplyCode", null);
                            });

            assertThat(resolution.metadata()).isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(resolution.uiSnapshot()).isEqualTo(new RepeaterMetadataFields.Metadata("ApplyCode", null));
            assertThat(fallbackCalls).hasValue(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveRequestStageRepeaterMetadata_prefersExactRequestIdentity_whenHashesAreAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            AtomicInteger fallbackCalls = new AtomicInteger();
            HttpRequestResponse first = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            HttpRequestResponse second = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");
            RepeaterLiveMetadataTracker.observe(
                    first,
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    second,
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    first.request(),
                    ToolType.REPEATER,
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("Tab One", "Group One"));
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void repeaterMetadataSourceCounters_recordRequestIdentityAndUiFallbackPaths() {
        ExportStats.resetForTests();
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            HttpRequestResponse tracked = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    null);
            RepeaterMetadataFields.Metadata trackedMetadata =
                    new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha");
            RepeaterLiveMetadataTracker.observe(tracked, trackedMetadata, now);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    tracked.request(),
                    ToolType.REPEATER)).isEqualTo(trackedMetadata);

            RepeaterLiveMetadataTracker.clear();

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", null)))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Fallback Tab", null));

            assertThat(ExportStats.getRepeaterMetadataSourceCount("request_identity")).isEqualTo(1);
            assertThat(ExportStats.getRepeaterMetadataSourceCount("ui_fallback")).isEqualTo(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
            ExportStats.resetForTests();
        }
    }

    @Test
    void repeaterMetadataSourceCounters_recordHashAndReusePaths() {
        ExportStats.resetForTests();
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                    new RepeaterMetadataFields.Metadata("Hash Tab", "Hash Group"),
                    now);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Hash Tab", "Hash Group"));
            assertThat(TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    RepeaterMetadataFields.Metadata.empty(),
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Hash Tab", "Hash Group"));

            RepeaterLiveMetadataTracker.clear();

            assertThat(TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"),
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));

            assertThat(ExportStats.getRepeaterMetadataSourceCount("request_hash")).isEqualTo(1);
            assertThat(ExportStats.getRepeaterMetadataSourceCount("exchange_hash")).isEqualTo(1);
            assertThat(ExportStats.getRepeaterMetadataSourceCount("request_stage_reuse")).isEqualTo(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
            ExportStats.resetForTests();
        }
    }

    @Test
    void repeaterMetadataSourceCounters_recordAmbiguousNullPath() {
        ExportStats.resetForTests();
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"),
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            assertThat(TrafficHttpHandler.resolveRequestStageRepeaterMetadata(
                    request,
                    ToolType.REPEATER,
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group")))
                    .isEqualTo(RepeaterMetadataFields.Metadata.empty());
            assertThat(ExportStats.getRepeaterMetadataSourceCount("ambiguous_null")).isEqualTo(1);
        } finally {
            RepeaterLiveMetadataTracker.clear();
            ExportStats.resetForTests();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_prefersExchangeMatch_overRequestStageFallback() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                    new RepeaterMetadataFields.Metadata("Live Tab", "Live Group"),
                    now);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group"));

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("Live Tab", "Live Group"));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_doesNotCallFallbackSupplier_whenRequestStageMetadataPresent() {
        RepeaterLiveMetadataTracker.clear();
        try {
            AtomicInteger fallbackCalls = new AtomicInteger();

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"),
                    () -> {
                        fallbackCalls.incrementAndGet();
                        return new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group");
                    });

            assertThat(resolved)
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));
            assertThat(fallbackCalls).hasValue(0);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_fallsBackToCurrentRepeaterMetadata_whenTrackerEmpty() {
        RepeaterLiveMetadataTracker.clear();
        try {
            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    RepeaterMetadataFields.Metadata.empty(),
                    () -> new RepeaterMetadataFields.Metadata("GetUserToken", null));

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("GetUserToken", null));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_reusesRequestStageUiSnapshot_whenRequestWasAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            TrafficHttpHandlerSupport.RequestStageResolution requestStageResolution =
                    TrafficHttpHandlerSupport.RequestStageResolution.ambiguous(
                            RepeaterMetadataTraceLabels.REQUEST_HASH,
                            new RepeaterMetadataFields.Metadata("ApplyCode", null));

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    requestStageResolution,
                    () -> new RepeaterMetadataFields.Metadata("380", null));

            assertThat(resolved).isEqualTo(new RepeaterMetadataFields.Metadata("ApplyCode", null));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_fallsBackToRequestStageMetadata_whenExchangeMatchAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            HttpRequestResponse exchange = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            RepeaterLiveMetadataTracker.observe(
                    exchange,
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    exchange,
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));

            assertThat(resolved)
                    .isEqualTo(new RepeaterMetadataFields.Metadata("Request Stage Tab", "Request Stage Group"));
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void resolveResponseStageRepeaterMetadata_returnsEmpty_whenExchangeAndRequestAreAmbiguous() {
        RepeaterLiveMetadataTracker.clear();
        try {
            long now = System.currentTimeMillis();
            HttpRequestResponse first = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            HttpRequestResponse second = requestResponse(
                    "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            RepeaterLiveMetadataTracker.observe(
                    first,
                    new RepeaterMetadataFields.Metadata("Tab One", "Group One"),
                    now);
            RepeaterLiveMetadataTracker.observe(
                    second,
                    new RepeaterMetadataFields.Metadata("Tab Two", "Group Two"),
                    now + 1);

            RepeaterMetadataFields.Metadata resolved = TrafficHttpHandler.resolveResponseStageRepeaterMetadata(
                    request,
                    response,
                    ToolType.REPEATER,
                    RepeaterMetadataFields.Metadata.empty(),
                    () -> new RepeaterMetadataFields.Metadata("Fallback Tab", "Fallback Group"));

            assertThat(resolved).isEqualTo(RepeaterMetadataFields.Metadata.empty());
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    @Test
    void buildOrphanDocumentSkeleton_writesRepeaterRequestStageMetadata_forRequestOnlyExports() {
        Map<String, Object> skeleton = objectMap(call(
                handler,
                "buildOrphanDocumentSkeleton",
                requestToBeSent(
                        "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        77,
                        ToolType.REPEATER),
                1L,
                new RepeaterMetadataFields.Metadata("Repeater Tab", "Group Alpha")));

        assertThat(burpRepeater(skeleton)).containsEntry("tab_name", "Repeater Tab");
        assertThat(burpRepeater(skeleton)).containsEntry("tab_group", "Group Alpha");
    }

    @Test
    void buildOrphanDocumentSkeleton_keepsRepeaterMetadataNull_forNonRepeaterTraffic_evenWhenTrackerHasData() {
        RepeaterLiveMetadataTracker.clear();
        try {
            RepeaterLiveMetadataTracker.observe(
                    requestResponse(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            null),
                    new RepeaterMetadataFields.Metadata("Tracked Tab", "Tracked Group"),
                    System.currentTimeMillis());

            Map<String, Object> skeleton = objectMap(call(
                    handler,
                    "buildOrphanDocumentSkeleton",
                    requestToBeSent(
                            "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
                            78,
                            ToolType.PROXY),
                    1L,
                    TrafficHttpHandler.resolveRequestStageRepeaterMetadata(request, ToolType.PROXY)));

            assertThat(burpRepeater(skeleton)).containsEntry("tab_name", null);
            assertThat(burpRepeater(skeleton)).containsEntry("tab_group", null);
        } finally {
            RepeaterLiveMetadataTracker.clear();
        }
    }

    private static Map<String, Object> requestProtocol(Map<String, Object> doc) {
        return objectMap(objectMap(doc.get("request")).get("protocol"));
    }

    private static Map<String, Object> websocket(Map<String, Object> doc) {
        return objectMap(doc.get("websocket"));
    }

    private static Map<String, Object> burpRepeater(Map<String, Object> doc) {
        return objectMap(objectMap(doc.get("burp")).get("repeater"));
    }

    private static Map<String, Object> objectMap(Object value) {
        if (!(value instanceof Map<?, ?> source)) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                out.put(key, entry.getValue());
            }
        }
        return out;
    }

    private static HttpRequestResponse requestResponse(String rawRequest, String rawResponse) {
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpRequest trackedRequest = mock(HttpRequest.class);
        ByteArray trackedRequestBytes = byteArray(rawRequest);
        when(trackedRequest.toByteArray()).thenReturn(trackedRequestBytes);
        when(requestResponse.request()).thenReturn(trackedRequest);
        if (rawResponse != null) {
            HttpResponseReceived trackedResponse = mock(HttpResponseReceived.class);
            ByteArray trackedResponseBytes = byteArray(rawResponse);
            when(trackedResponse.toByteArray()).thenReturn(trackedResponseBytes);
            when(requestResponse.response()).thenReturn(trackedResponse);
        }
        return requestResponse;
    }

    private static ByteArray byteArray(String value) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.getBytes(StandardCharsets.UTF_8));
        return bytes;
    }

    private static HttpRequestToBeSent requestToBeSent(String rawRequest, int messageId, ToolType toolType) {
        HttpRequestToBeSent request = mock(HttpRequestToBeSent.class);
        HttpService service = mock(HttpService.class);
        ToolSource toolSource = mock(ToolSource.class);
        ByteArray requestBytes = byteArray(rawRequest);

        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(toolSource.toolType()).thenReturn(toolType);

        when(request.toolSource()).thenReturn(toolSource);
        when(request.messageId()).thenReturn(messageId);
        when(request.isInScope()).thenReturn(true);
        when(request.url()).thenReturn("https://example.com/path?q=1");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/path?q=1");
        when(request.pathWithoutQuery()).thenReturn("/path");
        when(request.query()).thenReturn("q=1");
        when(request.fileExtension()).thenReturn("");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.bodyOffset()).thenReturn(0);
        when(request.markers()).thenReturn(List.of());
        when(request.annotations()).thenReturn(null);
        when(request.contentType()).thenReturn(ContentType.NONE);
        when(request.toByteArray()).thenReturn(requestBytes);
        return request;
    }
}
