package ai.anomalousvectors.tools.burp.sinks;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.stringObjectMapList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Covers lossless form fallback and isolation from unaffected Burp-provided parameters. */
class RequestResponseFormIntegrityTest {

    @AfterEach
    void resetCounters() {
        ParameterIntegritySessionLog.startForCurrentRun();
    }

    @ParameterizedTest
    @MethodSource("components")
    void supplementalComponentPreservesContent(String encoded, String charset, String expected) {
        byte[] bytes = ("name=" + encoded).getBytes(StandardCharsets.ISO_8859_1);
        var result = RequestResponseParametersSupport.parseUrlEncodedBodyParameters(
                bytes, List.of(contentType(charset)));

        assertThat(result.entries()).singleElement().satisfies(row ->
                assertThat(row).containsEntry("name", "name").containsEntry("value", expected));
    }

    static Stream<Arguments> components() {
        return Stream.of(
                Arguments.of("  value  ", "UTF-8", "  value  "),
                Arguments.of("%20value%20", "UTF-8", " value "),
                Arguments.of("caf%C3%A9", "UTF-8", "café"),
                Arguments.of("caf%E9", "ISO-8859-1", "café"),
                Arguments.of("price=%80", "windows-1252", "price=€"),
                Arguments.of("%82%A0", "Shift_JIS", "あ"),
                Arguments.of("a%26b%3Dc%2B+d", "UTF-8", "a&b=c+ d"),
                Arguments.of("%2526", "UTF-8", "%26"),
                Arguments.of("%GG%41", "UTF-8", "%GGA"),
                Arguments.of("tail%", "UTF-8", "tail%"),
                Arguments.of("tail%2", "UTF-8", "tail%2"),
                Arguments.of("%FF", "UTF-8", "%FF"),
                Arguments.of("%C3%28", "UTF-8", "%C3%28"),
                Arguments.of("%EF%BF%BD", "UTF-8", "�"),
                Arguments.of("", "UTF-8", ""));
    }

    @Test
    void rawAndEscapedBytesUseTheSameDeclaredCharset() {
        for (Charset charset : List.of(StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1)) {
            String escaped = charset.equals(StandardCharsets.UTF_8) ? "%C3%A9" : "%E9";
            byte[] bytes = ("literal=café&escaped=caf" + escaped).getBytes(charset);
            var result = RequestResponseParametersSupport.parseUrlEncodedBodyParameters(
                    bytes, List.of(contentType(charset.name())));
            assertThat(result.entries()).extracting(row -> row.get("value")).containsExactly("café", "café");
        }
    }

    @Test
    void malformedFieldsKeepValidUrlAndBodyRowsAndExactWireBody() {
        byte[] wire = "first=1&bad=%GG&%GG=name&last=  value  ".getBytes(StandardCharsets.UTF_8);
        ParsedHttpParameter url = parameter("query", "retained", HttpParameterType.URL);
        HttpRequest request = request(wire, List.of(url));

        Map<String, Object> doc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        var rows = stringObjectMapList(doc.get("parameters"));
        assertThat(rows).extracting(row -> row.get("name")).containsExactly("query", "first", "bad", "%GG", "last");
        assertThat(rows).extracting(row -> row.get("value")).containsExactly("retained", "1", "%GG", "name", "  value  ");
        assertThat(doc.get("body")).isInstanceOfSatisfying(Map.class, body ->
                assertThat(body.get("b64")).isEqualTo(Base64.getEncoder().encodeToString(wire)));
        verify(url, never()).nameOffsets();
        verify(url, never()).valueOffsets();
        verify(request, never()).toByteArray();
    }

    @Test
    void sitemapRetainsQueryWhenOneFormFieldIsMalformed() {
        ParsedHttpParameter url = parameter("query", "retained", HttpParameterType.URL);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters(HttpParameterType.URL)).thenReturn(List.of(url));
        var result = RequestResponseParametersSupport.sitemapParameters(request,
                "ok=1&bad=%GG&last=2".getBytes(StandardCharsets.US_ASCII),
                ContentType.URL_ENCODED, List.of(contentType("UTF-8")));

        assertThat(result.entries()).extracting(row -> row.get("name"))
                .containsExactly("query", "ok", "bad", "last");
    }

    @Test
    void suppliedBurpBodyRemainsUnchangedWithoutReparsingOrOffsetAccess() {
        ParsedHttpParameter supplied = parameter("name", "cafÃ©", HttpParameterType.BODY);
        HttpRequest request = mock(HttpRequest.class);
        when(request.parameters()).thenReturn(List.of(supplied));
        var result = RequestResponseParametersSupport.collectParameters(request, true,
                "name=caf%C3%A9".getBytes(StandardCharsets.US_ASCII), ContentType.URL_ENCODED,
                List.of(contentType("UTF-8")));

        assertThat(result.entries()).singleElement().satisfies(row ->
                assertThat(row).containsEntry("value", "cafÃ©"));
        verify(supplied, never()).nameOffsets();
        verify(supplied, never()).valueOffsets();
        verify(request, never()).toByteArray();
    }

    @Test
    void cappedQueryPreservesBurpRawEscapesPlusSignsAndDuplicateOrder() {
        var parameters = new java.util.ArrayList<ParsedHttpParameter>();
        parameters.add(parameter("na%6De", "caf%C3%A9+%26%3D%2B", HttpParameterType.URL));
        parameters.add(parameter("na%6De", "%GG%2526", HttpParameterType.URL));
        ParsedHttpParameter plain = parameter("plain", "value", HttpParameterType.URL);
        parameters.addAll(java.util.Collections.nCopies(
                RequestResponseParametersSupport.URL_PARAMETERS_CAP - 2, plain));
        parameters.add(parameter("overflow", "excluded", HttpParameterType.URL));

        var result = RequestResponseParametersSupport.parametersToList(parameters, false);

        assertThat(result.droppedUrlParams()).isEqualTo(1);
        assertThat(result.adjustedQuery()).startsWith("na%6De=caf%C3%A9+%26%3D%2B&na%6De=%GG%2526&plain=value");
        assertThat(result.adjustedQuery()).doesNotContain("%25C3", "overflow");
        assertThat(result.entries()).hasSize(RequestResponseParametersSupport.URL_PARAMETERS_CAP);
    }

    private static HttpRequest request(byte[] wire, List<ParsedHttpParameter> parameters) {
        HttpRequest request = mock(HttpRequest.class);
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(wire);
        when(request.body()).thenReturn(body);
        when(request.parameters()).thenReturn(parameters);
        when(request.method()).thenReturn("POST");
        when(request.url()).thenReturn("https://example.test/form?query=retained");
        when(request.path()).thenReturn("/form?query=retained");
        when(request.pathWithoutQuery()).thenReturn("/form");
        when(request.query()).thenReturn("query=retained");
        when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        HttpHeader header = contentType("UTF-8");
        when(request.headers()).thenReturn(List.of(header));
        return request;
    }

    private static ParsedHttpParameter parameter(String name, String value, HttpParameterType type) {
        ParsedHttpParameter parameter = mock(ParsedHttpParameter.class);
        when(parameter.name()).thenReturn(name);
        when(parameter.value()).thenReturn(value);
        when(parameter.type()).thenReturn(type);
        return parameter;
    }

    private static HttpHeader contentType(String charset) {
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn("Content-Type");
        when(header.value()).thenReturn("application/x-www-form-urlencoded; charset=" + charset);
        return header;
    }
}
