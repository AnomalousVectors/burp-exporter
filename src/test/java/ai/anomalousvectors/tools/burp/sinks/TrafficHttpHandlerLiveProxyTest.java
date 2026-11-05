package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.responses.analysis.AttributeType;

/** Protects the Notes-free live path independently of any retained Proxy History rows. */
class TrafficHttpHandlerLiveProxyTest {
    private final TrafficHttpHandler handler = new TrafficHttpHandler();
    private final MontoyaApi api = mock(MontoyaApi.class);

    @BeforeEach
    void startRun() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200",
                        null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        RuntimeConfig.setExportRunning(true);
        MontoyaApiProvider.set(api);
    }

    @AfterEach
    void stopRun() {
        ExportReporterLifecycle.resetForTests();
    }

    @Test
    void originalServerPair_exportsOnceWithGeneralIdAndVerbatimReadOnlyNotes() {
        HttpRequestToBeSent request = requestToBeSent("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                41, ToolType.PROXY);
        HttpRequestToBeSent sent = requestToBeSent("GET /edited HTTP/1.1\r\nHost: example.test\r\n\r\n",
                41, ToolType.PROXY);
        when(sent.path()).thenReturn("/edited");
        when(sent.pathWithoutQuery()).thenReturn("/edited");
        HttpResponseReceived response = responseReceived(sent, 41, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
        Annotations annotations = mock(Annotations.class);
        String notes = "  automated analysis\n[[burp-exporter-correlation:v1:old-marker-literal]]\n";
        when(annotations.hasNotes()).thenReturn(true);
        when(annotations.notes()).thenReturn(notes);
        when(request.annotations()).thenReturn(annotations);
        when(response.annotations()).thenReturn(annotations);
        AtomicReference<Map<String, Object>> offered = new AtomicReference<>();
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            var token = RuntimeConfig.currentExportRunToken();
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                offered.set(call.getArgument(0));
                return true;
            });
            handler.handleHttpRequestToBeSent(request);
            handler.handleHttpResponseReceived(response);
            handler.handleHttpResponseReceived(response);
            requestAction.verify(() -> RequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response),
                    org.mockito.Mockito.times(2));
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), org.mockito.ArgumentMatchers.eq(token)));
            Map<?, ?> burp = (Map<?, ?>) offered.get().get("burp");
            assertThat(burp.get("message_id")).isEqualTo(41);
            assertThat(burp.get("reporting_tool")).isEqualTo("Proxy");
            assertThat(burp.get("notes")).isEqualTo(notes);
            Map<?, ?> proxy = (Map<?, ?>) burp.get("proxy");
            assertThat(proxy.values()).allMatch(java.util.Objects::isNull);
            Map<?, ?> requestDoc = (Map<?, ?>) offered.get().get("request");
            assertThat(((Map<?, ?>) requestDoc.get("path")).get("without_query")).isEqualTo("/edited");
            assertThat(((Map<?, ?>) offered.get().get("response")).get("body")).isNotNull();
            verify(annotations, never()).setNotes(anyString());
            verify(annotations, never()).withNotes(anyString());
            verify(api, never()).proxy();
        }
    }

    @Test
    void preStartAndPriorRunResponses_doNotLeakIntoNextRun() {
        HttpRequestToBeSent request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 42, ToolType.PROXY);
        HttpResponseReceived response = responseReceived(request, 42, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleHttpRequestToBeSent(request);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportRunning(true);
            handler.handleHttpResponseReceived(response);
            handler.handleHttpResponseReceived(response);
            queue.verifyNoInteractions();
            requestAction.verify(() -> RequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response),
                    org.mockito.Mockito.times(2));
        }
    }

    @Test
    void stopClosesNewIntakeButLetsAdmittedResponseDrain() {
        HttpRequestToBeSent request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 43, ToolType.PROXY);
        HttpRequestToBeSent afterStop = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 44, ToolType.PROXY);
        HttpResponseReceived response = responseReceived(request, 43, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleHttpRequestToBeSent(request);
            RuntimeConfig.setExportStopping(true);
            handler.handleHttpRequestToBeSent(afterStop);
            handler.handleHttpResponseReceived(response);
            assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(44)).isFalse();
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()));
            requestAction.verify(() -> RequestToBeSentAction.continueWith(afterStop));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void identicalConcurrentPairs_remainDistinctWithoutHistoryLookup() {
        HttpRequestToBeSent first = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 51, ToolType.PROXY);
        HttpRequestToBeSent second = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 52, ToolType.PROXY);
        HttpResponseReceived firstResponse = responseReceived(first, 51, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        HttpResponseReceived secondResponse = responseReceived(second, 52, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        java.util.Set<Object> ids = new java.util.HashSet<>();
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                Map<?, ?> doc = call.getArgument(0);
                ids.add(((Map<?, ?>) doc.get("burp")).get("message_id"));
                return true;
            });
            handler.handleHttpRequestToBeSent(first);
            handler.handleHttpRequestToBeSent(second);
            handler.handleHttpResponseReceived(secondResponse);
            handler.handleHttpResponseReceived(firstResponse);
            assertThat(ids).containsExactlyInAnyOrder(51, 52);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), org.mockito.Mockito.times(2));
            requestAction.verify(() -> RequestToBeSentAction.continueWith(first));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(firstResponse));
            verify(api, never()).proxy();
        }
    }

    @Test
    void responseAnnotationsDeliberatelyEmpty_doNotResurrectOldRequestNotes() {
        HttpRequestToBeSent request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 53, ToolType.PROXY);
        HttpResponseReceived response = responseReceived(request, 53, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        Annotations before = mock(Annotations.class);
        when(before.hasNotes()).thenReturn(true);
        when(before.notes()).thenReturn("removed by an owning analyst or extension");
        when(request.annotations()).thenReturn(before);
        when(response.annotations()).thenReturn(mock(Annotations.class));
        AtomicReference<Map<String, Object>> offered = new AtomicReference<>();
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                offered.set(call.getArgument(0));
                return true;
            });
            handler.handleHttpRequestToBeSent(request);
            handler.handleHttpResponseReceived(response);
            assertThat(((Map<?, ?>) offered.get().get("burp")).containsKey("notes")).isFalse();
            requestAction.verify(() -> RequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void requestOnlyTimeout_doesNotDiscardAnEventualResponseInTheSameRun() {
        HttpRequestToBeSent request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 54, ToolType.PROXY);
        HttpResponseReceived response = responseReceived(request, 54, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        TrafficHttpHandlerSupport.registerPendingOrphanForTest(54,
                Map.of("burp", Map.of("message_id", 54, "reporting_tool", "Proxy")),
                ToolType.PROXY, TrafficHttpHandlerSupport.RequestStageResolution.none());
        try (var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            handler.handleHttpResponseReceived(response);
            handler.handleHttpResponseReceived(response);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), org.mockito.Mockito.times(2));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response), org.mockito.Mockito.times(2));
            assertThat(TrafficHttpHandlerSupport.getPendingOrphansSize()).isZero();
        }
    }

    @Test
    void preStartRequest_isNotAdmittedByStartingBeforeItsResponse() {
        HttpRequestToBeSent request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 55, ToolType.PROXY);
        HttpResponseReceived response = responseReceived(request, 55, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            RuntimeConfig.setExportRunning(false);
            handler.handleHttpRequestToBeSent(request);
            RuntimeConfig.setExportRunning(true);
            handler.handleHttpResponseReceived(response);
            queue.verifyNoInteractions();
            requestAction.verify(() -> RequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void finalSentRequestBecomesEligible_afterRequestStageScopeOrToolRejection() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "custom",
                List.of(new ConfigState.ScopeEntry("edited.example.test", ConfigState.Kind.STRING)),
                RuntimeConfig.getState().sinks(), ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"), ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        HttpRequestToBeSent initial = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 56, ToolType.REPEATER);
        HttpRequestToBeSent sent = requestToBeSent("GET /edited HTTP/1.1\r\n\r\n", 56, ToolType.PROXY);
        when(sent.url()).thenReturn("https://edited.example.test/edited");
        HttpResponseReceived response = responseReceived(sent, 56, ToolType.PROXY,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleHttpRequestToBeSent(initial);
            assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(56)).isFalse();
            handler.handleHttpResponseReceived(response);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()));
            requestAction.verify(() -> RequestToBeSentAction.continueWith(initial));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response));
        }
    }

    private static HttpRequestToBeSent requestToBeSent(String rawRequest, int messageId, ToolType toolType) {
        HttpRequestToBeSent request = mock(HttpRequestToBeSent.class);
        HttpService service = mock(HttpService.class);
        ToolSource toolSource = mock(ToolSource.class);
        ByteArray requestBytes = byteArray(rawRequest);

        when(service.host()).thenReturn("example.test");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(toolSource.toolType()).thenReturn(toolType);

        when(request.toolSource()).thenReturn(toolSource);
        when(request.messageId()).thenReturn(messageId);
        when(request.isInScope()).thenReturn(true);
        when(request.url()).thenReturn("https://example.test/repeater/live");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/repeater/live");
        when(request.pathWithoutQuery()).thenReturn("/repeater/live");
        when(request.query()).thenReturn("");
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

    private static HttpResponseReceived responseReceived(
            HttpRequestToBeSent request,
            int messageId,
            ToolType toolType,
            String rawResponse) {
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        ToolSource toolSource = mock(ToolSource.class);
        ByteArray responseBytes = byteArray(rawResponse);

        when(toolSource.toolType()).thenReturn(toolType);
        when(response.initiatingRequest()).thenReturn(request);
        when(response.messageId()).thenReturn(messageId);
        when(response.toolSource()).thenReturn(toolSource);
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
        when(response.bodyToString()).thenReturn("A");
        when(response.markers()).thenReturn(List.of());
        when(response.attributes(any(AttributeType[].class))).thenReturn(List.of());
        when(response.toByteArray()).thenReturn(responseBytes);
        return response;
    }

    private static ByteArray byteArray(String value) {
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(value.getBytes(StandardCharsets.UTF_8));
        return bytes;
    }

}
