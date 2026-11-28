package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotScopeCache;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/** Scope admission and best-effort URL parity for Proxy History document preparation. */
class ProxyHistoryScopeTest {

    @ParameterizedTest
    @ValueSource(strings = {"burp", "custom", " CuStOm "})
    void rejectedRowsAvoidPayloadAccessEvenInTheMemoryEstimator(String scope) {
        ProxyHttpRequestResponse item = item("https://out.example/search?kept=value", "out.example");

        Object estimate = callStatic(ProxyHistoryIndexReporter.class, "estimateMemoryBytes",
                item, state(scope), new SnapshotScopeCache(apiInScope(false)));

        assertThat(estimate).isEqualTo(0L);
        verify(item.finalRequest(), never()).body();
        verify(item.finalRequest(), never()).toByteArray();
        verify(item.finalRequest(), never()).parameters();
        verify(item, never()).response();
    }

    @Test
    void acceptedRowsStillReceiveTheSharedSourceSizeEstimate() {
        ProxyHttpRequestResponse item = item("https://in.example/search?kept=value", "in.example");
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(4_096);
        when(item.finalRequest().body()).thenReturn(body);

        Object estimate = callStatic(ProxyHistoryIndexReporter.class, "estimateMemoryBytes",
                item, state("custom"), new SnapshotScopeCache(apiInScope(false)));

        assertThat(estimate).isEqualTo(SnapshotMemoryEstimate.proxy(item));
        assertThat((Long) estimate).isGreaterThan(4_096L);
        verify(body, never()).getBytes();
    }

    @Test
    void inconclusiveEstimatorProbeDoesNotDuplicateMalformedUrlDiagnostics() {
        ProxyHttpRequestResponse item = item("https://in.example/search?kept=value", "in.example");
        when(item.finalRequest().url()).thenThrow(new IllegalStateException("Malformed URL"));
        try (var logger = mockStatic(Logger.class)) {
            callStatic(ProxyHistoryIndexReporter.class, "estimateMemoryBytes",
                    item, state("custom"), new SnapshotScopeCache(apiInScope(false)));

            logger.verifyNoInteractions();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"burp", "custom", " CuStOm "})
    void rejectedOrdinaryUrlDoesNotPreparePayloadOrEnumerateBodyParameters(String scope) {
        ProxyHttpRequestResponse item = item("https://out.example/search?kept=value", "out.example");
        HttpRequest request = item.finalRequest();
        MontoyaApi api = apiInScope(false);
        AtomicInteger skipped = new AtomicInteger();

        assertThat(build(item, scope, api, skipped)).isNull();

        assertThat(skipped).hasValue(1);
        verify(request, never()).body();
        verify(request, never()).toByteArray();
        verify(request, never()).parameters();
        verify(request, never()).contentType();
        verify(item, never()).response();
        verify(api.scope()).isInScope("https://out.example/search?kept=value");
    }

    @ParameterizedTest
    @ValueSource(strings = {"all", "burp", "custom", " CuStOm "})
    void acceptedRequestRetainsTheCompleteRequestDocument(String scope) {
        String url = "https://in.example/search?kept=value";
        ProxyHttpRequestResponse item = item(url, "in.example");
        HttpRequest request = item.finalRequest();
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn("{\"original\":true}".getBytes(StandardCharsets.UTF_8));
        when(request.body()).thenReturn(body);
        Map<String, Object> expectedRequest = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        expectedRequest.put("url", HttpMessageDocSupport.urlObject(url, item.httpService()));
        expectedRequest.put("protocol", TrafficProtocolFields.requestProtocol("HTTP/1.1"));
        AtomicInteger skipped = new AtomicInteger();

        Map<?, ?> document = build(item, scope, apiInScope(true), skipped);

        assertThat(document).isNotNull();
        assertThat(document.get("request")).isEqualTo(expectedRequest);
        assertThat(map(document.get("burp")).get("is_in_scope")).isEqualTo(true);
        assertThat(skipped).hasValue(0);
        // Accepted items need no additional URL-parameter probe before normal preparation.
        verify(request, org.mockito.Mockito.times(2)).parameters(HttpParameterType.URL);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void unavailableDirectUrlUsesExistingReconstructionBeforeScope(boolean accessorThrows) {
        ProxyHttpRequestResponse item = item("https://in.example/search?kept=value", "in.example");
        HttpRequest request = item.finalRequest();
        if (accessorThrows) {
            when(request.url()).thenThrow(new IllegalStateException("Malformed URL"));
        } else {
            when(request.url()).thenReturn(" ");
        }
        AtomicInteger skipped = new AtomicInteger();

        Map<?, ?> document = build(item, "custom", apiInScope(false), skipped);

        assertThat(document).isNotNull();
        assertThat(map(map(document.get("request")).get("url")).get("raw"))
                .isEqualTo("https://in.example/search?kept=value");
        assertThat(skipped).hasValue(0);
    }

    @Test
    void urlParameterCapCanChangeAuthorityAndAdmitAnOtherwiseRejectedDirectUrl() {
        ProxyHttpRequestResponse item = item("https://out.example/search?kept=value", "in.example");
        List<ParsedHttpParameter> parameters = oversizedUrlParameters();
        when(item.finalRequest().parameters(HttpParameterType.URL)).thenReturn(parameters);
        AtomicInteger skipped = new AtomicInteger();

        Map<?, ?> document = build(item, "custom", apiInScope(false), skipped);

        assertThat(document).isNotNull();
        String url = (String) map(map(document.get("request")).get("url")).get("raw");
        assertThat(url).startsWith("https://in.example/search?kept=value&kept=value");
        assertThat(url).doesNotContain("dropped");
        assertThat(skipped).hasValue(0);
    }

    @Test
    void burpScopeUsesCappedQueryRatherThanRejectingTheOriginalQuery() {
        ProxyHttpRequestResponse item = item("https://in.example/search?kept=value&dropped=value", "in.example");
        List<ParsedHttpParameter> parameters = oversizedUrlParameters();
        when(item.finalRequest().parameters(HttpParameterType.URL)).thenReturn(parameters);
        MontoyaApi api = apiInScope(false);
        String narrowedUrl = "https://in.example/search?"
                + String.join("&", Collections.nCopies(RequestResponseParametersSupport.URL_PARAMETERS_CAP,
                        "kept=value"));
        when(api.scope().isInScope(narrowedUrl)).thenReturn(true);
        AtomicInteger skipped = new AtomicInteger();

        Map<?, ?> document = build(item, "burp", api, skipped);

        assertThat(document).isNotNull();
        assertThat(map(map(document.get("request")).get("url")).get("raw")).isEqualTo(narrowedUrl);
        assertThat(skipped).hasValue(0);
    }

    @Test
    void failedTypedParameterProbeLeavesTheDecisionToTheDocumentBuilder() {
        ProxyHttpRequestResponse item = item("https://out.example/search?kept=value", "in.example");
        HttpRequest request = item.finalRequest();
        when(request.parameters(HttpParameterType.URL)).thenThrow(new IllegalStateException("Unavailable view"));
        when(request.contentType()).thenReturn(ContentType.URL_ENCODED);
        List<ParsedHttpParameter> parameters = oversizedUrlParameters();
        when(request.parameters()).thenReturn(parameters);
        AtomicInteger skipped = new AtomicInteger();

        Map<?, ?> document = build(item, "custom", apiInScope(false), skipped);

        assertThat(document).isNotNull();
        assertThat(map(map(document.get("request")).get("url")).get("raw"))
                .asString().startsWith("https://in.example/search?kept=value&kept=value");
        assertThat(skipped).hasValue(0);
    }

    @Test
    void reconstructedRejectionCountsOneSkippedRow() {
        ProxyHttpRequestResponse item = item("https://out.example/search?kept=value", "out.example");
        when(item.finalRequest().url()).thenReturn(null);
        AtomicInteger skipped = new AtomicInteger();

        assertThat(build(item, "custom", apiInScope(false), skipped)).isNull();

        assertThat(skipped).hasValue(1);
        verify(item, never()).response();
    }

    @ParameterizedTest
    @ValueSource(ints = {0, RequestResponseParametersSupport.URL_PARAMETERS_CAP})
    void uncappedParameterBoundaryStillRejectsWithoutPreparingTheBody(int parameterCount) {
        ProxyHttpRequestResponse item = item("https://out.example/search?kept=value", "out.example");
        List<ParsedHttpParameter> parameters = oversizedUrlParameters().subList(0, parameterCount);
        when(item.finalRequest().parameters(HttpParameterType.URL)).thenReturn(parameters);
        AtomicInteger skipped = new AtomicInteger();

        assertThat(build(item, "custom", apiInScope(false), skipped)).isNull();

        assertThat(skipped).hasValue(1);
        verify(item.finalRequest(), never()).body();
    }

    private static Map<?, ?> build(ProxyHttpRequestResponse item, String scope, MontoyaApi api,
            AtomicInteger skipped) {
        return (Map<?, ?>) callStatic(ProxyHistoryIndexReporter.class, "buildDocument",
                item, state(scope), new SnapshotScopeCache(api), skipped);
    }

    private static ConfigState.State state(String scope) {
        return new ConfigState.State(
                List.of("traffic"), scope,
                List.of(new ConfigState.ScopeEntry("^in[.]example$", ConfigState.Kind.REGEX)),
                null, ConfigState.DEFAULT_SETTINGS_SUB, List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null);
    }

    private static MontoyaApi apiInScope(boolean inScope) {
        MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
        when(api.scope().isInScope(anyString())).thenReturn(inScope);
        return api;
    }

    private static List<ParsedHttpParameter> oversizedUrlParameters() {
        ParsedHttpParameter kept = mock(ParsedHttpParameter.class);
        when(kept.type()).thenReturn(HttpParameterType.URL);
        when(kept.name()).thenReturn("kept");
        when(kept.value()).thenReturn("value");
        ParsedHttpParameter dropped = mock(ParsedHttpParameter.class);
        when(dropped.type()).thenReturn(HttpParameterType.URL);
        when(dropped.name()).thenReturn("dropped");
        when(dropped.value()).thenReturn("value");
        List<ParsedHttpParameter> parameters = new ArrayList<>(
                Collections.nCopies(RequestResponseParametersSupport.URL_PARAMETERS_CAP, kept));
        parameters.add(dropped);
        return parameters;
    }

    private static ProxyHttpRequestResponse item(String url, String host) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(url);
        when(request.method()).thenReturn("POST");
        String query = url.substring(url.indexOf('?') + 1);
        when(request.path()).thenReturn("/search?" + query);
        when(request.pathWithoutQuery()).thenReturn("/search");
        when(request.query()).thenReturn(query);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.contentType()).thenReturn(ContentType.JSON);
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.parameters(HttpParameterType.URL)).thenReturn(List.of());
        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn(host);
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.finalRequest()).thenReturn(request);
        when(item.httpService()).thenReturn(service);
        return item;
    }

    private static Map<?, ?> map(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }
}
