package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.responses.analysis.AttributeType;

/** Protects the Notes-free live path independently of any retained Proxy History rows. */
class TrafficHttpHandlerLiveProxyTest {
    private final TrafficProxyHttpHandler handler = new TrafficProxyHttpHandler();
    private final MontoyaApi api = mock(MontoyaApi.class);

    @BeforeEach
    void startRun() {
        LiveTrafficPreparation.setInlineForTests(true);
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
        LiveTrafficPreparation.setInlineForTests(false);
        ExportReporterLifecycle.resetForTests();
    }

    @Test
    void originalServerPair_exportsOnceWithNativeIdAndVerbatimReadOnlyNotes() {
        InterceptedRequest request = requestToBeSent("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                41);
        InterceptedRequest sent = requestToBeSent("GET /edited HTTP/1.1\r\nHost: example.test\r\n\r\n",
                41);
        when(sent.path()).thenReturn("/edited");
        when(sent.pathWithoutQuery()).thenReturn("/edited");
        InterceptedResponse response = responseReceived(sent, 41,
                "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
        Annotations annotations = mock(Annotations.class);
        String notes = "  automated analysis\n[[burp-exporter-correlation:v1:old-marker-literal]]\n";
        when(annotations.hasNotes()).thenReturn(true);
        when(annotations.notes()).thenReturn(notes);
        when(request.annotations()).thenReturn(annotations);
        when(response.annotations()).thenReturn(annotations);
        AtomicReference<Map<String, Object>> offered = new AtomicReference<>();
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            var token = RuntimeConfig.currentExportRunToken();
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                offered.set(call.getArgument(0));
                return true;
            });
            handler.handleRequestToBeSent(request);
            handler.handleResponseReceived(response);
            handler.handleResponseReceived(response);
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response),
                    org.mockito.Mockito.times(2));
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), org.mockito.ArgumentMatchers.eq(token)));
            Map<?, ?> burp = (Map<?, ?>) offered.get().get("burp");
            assertThat(burp.get("message_id")).isEqualTo(41);
            assertThat(burp.get("reporting_tool")).isEqualTo("Proxy");
            assertThat(burp.get("notes")).isEqualTo(notes);
            Map<?, ?> proxy = (Map<?, ?>) burp.get("proxy");
            assertThat(proxy.get("listener_port")).isEqualTo(8080);
            assertThat(proxy.get("history_id")).isNull();
            Map<?, ?> capture = (Map<?, ?>) ((Map<?, ?>) offered.get().get("meta")).get("capture");
            assertThat(capture.get("source")).isEqualTo("live_proxy_callback");
            Map<?, ?> requestDoc = (Map<?, ?>) offered.get().get("request");
            assertThat(((Map<?, ?>) requestDoc.get("path")).get("without_query")).isEqualTo("/edited");
            assertThat(((Map<?, ?>) offered.get().get("response")).get("body")).isNotNull();
            verify(annotations, never()).setNotes(anyString());
            verify(annotations, never()).withNotes(anyString());
            verify(api, never()).proxy();
        }
    }

    @Test
    void exhaustedCaptureBudgetSkipsCopiesButKeepsLateResponseEligibility() {
        InterceptedRequest request = requestToBeSent("POST / HTTP/1.1\r\n\r\nlarge", 781);
        ByteArray large = mock(ByteArray.class);
        when(large.length()).thenReturn(10_000_000);
        when(request.body()).thenReturn(large);
        InterceptedResponse response = responseReceived(request, 781, "HTTP/1.1 200 OK\r\n\r\nA");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            ai.anomalousvectors.tools.burp.utils.ExportAdmissionController.setMemBudgetOverrideForTests(1_000L);
            handler.handleRequestToBeSent(request);
            verify(large, never()).getBytes();
            verify(request, never()).toByteArray();
            assertThat(TrafficHttpHandler.requestReceiptStats().retained()).isEqualTo(1);
            ai.anomalousvectors.tools.burp.utils.ExportAdmissionController.setMemBudgetOverrideForTests(100_000L);
            ByteArray small = byteArray("small");
            when(request.body()).thenReturn(small);
            handler.handleResponseReceived(response);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), times(1));
            assertThat(TrafficHttpHandler.requestReceiptStats().retained()).isZero();
            assertThat(ai.anomalousvectors.tools.burp.utils.ExportAdmissionController.liveBytesHeld()).isZero();
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        } finally {
            ai.anomalousvectors.tools.burp.utils.ExportAdmissionController.setMemBudgetOverrideForTests(null);
        }
    }

    @Test
    void preStartAndPriorRunResponses_doNotLeakIntoNextRun() {
        InterceptedRequest request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 42);
        InterceptedResponse response = responseReceived(request, 42,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleRequestToBeSent(request);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportRunning(true);
            handler.handleResponseReceived(response);
            handler.handleResponseReceived(response);
            queue.verifyNoInteractions();
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response),
                    org.mockito.Mockito.times(2));
        }
    }

    @Test
    void stopClosesNewIntakeButLetsAdmittedResponseDrain() {
        InterceptedRequest request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 43);
        InterceptedRequest afterStop = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 44);
        InterceptedResponse response = responseReceived(request, 43,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleRequestToBeSent(request);
            RuntimeConfig.setExportStopping(true);
            handler.handleRequestToBeSent(afterStop);
            handler.handleResponseReceived(response);
            assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(44)).isFalse();
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()));
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(afterStop));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void identicalConcurrentPairs_remainDistinctWithoutHistoryLookup() {
        InterceptedRequest first = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 51);
        InterceptedRequest second = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 52);
        when(second.listenerInterface()).thenReturn("[::1]:8081");
        InterceptedResponse firstResponse = responseReceived(first, 51,
                "HTTP/1.1 200 OK\r\n\r\n");
        InterceptedResponse secondResponse = responseReceived(second, 52,
                "HTTP/1.1 200 OK\r\n\r\n");
        java.util.Set<Object> ids = new java.util.HashSet<>();
        Map<Object, Object> ports = new java.util.HashMap<>();
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                Map<?, ?> doc = call.getArgument(0);
                ids.add(((Map<?, ?>) doc.get("burp")).get("message_id"));
                Map<?, ?> burp = (Map<?, ?>) doc.get("burp");
                ports.put(burp.get("message_id"), ((Map<?, ?>) burp.get("proxy")).get("listener_port"));
                return true;
            });
            handler.handleRequestToBeSent(first);
            handler.handleRequestToBeSent(second);
            handler.handleResponseReceived(secondResponse);
            handler.handleResponseReceived(firstResponse);
            assertThat(ids).containsExactlyInAnyOrder(51, 52);
            assertThat(ports).containsEntry(51, 8080).containsEntry(52, 8081);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), org.mockito.Mockito.times(2));
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(first));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(firstResponse));
            verify(api, never()).proxy();
        }
    }

    @Test
    void responseAnnotationsDeliberatelyEmpty_doNotResurrectOldRequestNotes() {
        InterceptedRequest request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 53);
        InterceptedResponse response = responseReceived(request, 53,
                "HTTP/1.1 200 OK\r\n\r\n");
        Annotations before = mock(Annotations.class);
        when(before.hasNotes()).thenReturn(true);
        when(before.notes()).thenReturn("removed by an owning analyst or extension");
        when(request.annotations()).thenReturn(before);
        when(response.annotations()).thenReturn(mock(Annotations.class));
        AtomicReference<Map<String, Object>> offered = new AtomicReference<>();
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                offered.set(call.getArgument(0));
                return true;
            });
            handler.handleRequestToBeSent(request);
            handler.handleResponseReceived(response);
            assertThat(((Map<?, ?>) offered.get().get("burp")).containsKey("notes")).isFalse();
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void requestOnlyTimeout_doesNotDiscardAnEventualResponseInTheSameRun() {
        InterceptedRequest request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 54);
        InterceptedResponse response = responseReceived(request, 54,
                "HTTP/1.1 200 OK\r\n\r\n");
        TrafficHttpHandlerSupport.registerPendingOrphanForTest(54,
                Map.of("burp", Map.of("message_id", 54, "reporting_tool", "Proxy")),
                ToolType.PROXY, TrafficHttpHandlerSupport.RequestStageResolution.none(), true);
        try (var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            handler.handleResponseReceived(response);
            handler.handleResponseReceived(response);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), org.mockito.Mockito.times(2));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response), org.mockito.Mockito.times(2));
            assertThat(TrafficHttpHandlerSupport.getPendingOrphansSize()).isZero();
        }
    }

    @ParameterizedTest
    @EnumSource(value = ToolType.class, names = {"SCANNER", "INTRUDER", "EXTENSIONS", "REPEATER"})
    void otherLiveTools_rejectBeforeBodyPreparationAndRecoverAfterFinishedOrphanHandling(ToolType tool) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "all", List.of(), RuntimeConfig.getState().sinks(),
                ConfigState.DEFAULT_SETTINGS_SUB, List.of(RuntimeConfig.normalizedToolTypeKey(tool)),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        AtomicLong clock = new AtomicLong();
        TrafficHttpHandlerSupport.setReceiptCacheForTest(new LiveRequestReceipts(1, 120_000, clock::get));
        TrafficHttpHandlerSupport.registerPendingOrphanForTest(1, Map.of("burp", Map.of()),
                tool, TrafficHttpHandlerSupport.RequestStageResolution.none());
        InterceptedRequest raw = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 2);
        ToolSource source = mock(ToolSource.class);
        when(source.toolType()).thenReturn(tool);
        HttpRequestToBeSent request = mock(HttpRequestToBeSent.class,
                org.mockito.AdditionalAnswers.delegatesTo(raw));
        org.mockito.Mockito.doReturn(source).when(request).toolSource();
        InterceptedResponse received = responseReceived(raw, 2, "HTTP/1.1 200 OK\r\n\r\n");
        HttpResponseReceived response = mock(HttpResponseReceived.class,
                org.mockito.AdditionalAnswers.delegatesTo(received));
        org.mockito.Mockito.doReturn(source).when(response).toolSource();
        var general = new TrafficHttpHandler();
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            general.handleHttpRequestToBeSent(request);
            verify(raw, never()).body();
            verify(raw, never()).toByteArray();
            assertThat(TrafficHttpHandler.requestReceiptStats().rejected()).isEqualTo(1);
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            clock.set(TimeUnit.MINUTES.toNanos(3));
            general.handleHttpRequestToBeSent(request);
            general.handleHttpResponseReceived(response);
            general.handleHttpResponseReceived(response);
            assertThat(TrafficHttpHandler.requestReceiptStats().reclaimed()).isEqualTo(1);
            assertThat(TrafficHttpHandler.requestReceiptStats().retained()).isZero();
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), org.mockito.Mockito.times(2));
            requestAction.verify(() -> RequestToBeSentAction.continueWith(request), org.mockito.Mockito.times(2));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response), org.mockito.Mockito.times(2));
        }
    }

    @Test
    void inFlightOrphanFlush_isProtectedFromPressureUntilItsQueueAttemptFinishes() throws Exception {
        AtomicLong clock = new AtomicLong();
        TrafficHttpHandlerSupport.setReceiptCacheForTest(new LiveRequestReceipts(1, 120_000, clock::get));
        TrafficHttpHandlerSupport.registerPendingOrphanForTest(1, Map.of("burp", Map.of()),
                ToolType.PROXY, TrafficHttpHandlerSupport.RequestStageResolution.none(), true);
        clock.set(TimeUnit.MINUTES.toNanos(3));
        CountDownLatch flushing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        FutureTask<Void> flush = new FutureTask<>(() -> {
            try (var queue = mockStatic(TrafficExportQueue.class)) {
                queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                    flushing.countDown();
                    assertThat(release.await(10, TimeUnit.SECONDS)).isTrue();
                    return true;
                });
                TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            }
            return null;
        });
        Thread worker = new Thread(flush, "test-receipt-flush");
        worker.start();
        InterceptedRequest request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 2);
        try (var action = mockStatic(ProxyRequestToBeSentAction.class)) {
            assertThat(flushing.await(10, TimeUnit.SECONDS)).isTrue();
            handler.handleRequestToBeSent(request);
            verify(request, never()).toByteArray();
            release.countDown();
            flush.get(10, TimeUnit.SECONDS);
            handler.handleRequestToBeSent(request);
            assertThat(TrafficHttpHandler.requestReceiptStats().reclaimed()).isEqualTo(1);
            assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(2)).isTrue();
            InterceptedRequest oldRequest = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 1);
            InterceptedResponse oldResponse = responseReceived(oldRequest, 1, "HTTP/1.1 200 OK\r\n\r\n");
            try (var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                    var queue = mockStatic(TrafficExportQueue.class)) {
                handler.handleResponseReceived(oldResponse);
                queue.verifyNoInteractions();
                responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(oldResponse));
            }
            action.verify(() -> ProxyRequestToBeSentAction.continueWith(request), org.mockito.Mockito.times(2));
        } finally {
            release.countDown();
            worker.join(10_000);
        }
    }

    @Test
    void scopeRejectedReceipts_areReclaimedOnlyUnderPressureAndStopPreservesTotals() {
        AtomicLong clock = new AtomicLong();
        TrafficHttpHandlerSupport.setReceiptCacheForTest(new LiveRequestReceipts(1, 120_000, clock::get));
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "custom",
                List.of(new ConfigState.ScopeEntry("other.test", ConfigState.Kind.STRING)),
                RuntimeConfig.getState().sinks(), ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"), ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        InterceptedRequest first = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 1);
        InterceptedRequest next = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 2);
        try (var action = mockStatic(ProxyRequestToBeSentAction.class)) {
            handler.handleRequestToBeSent(first);
            clock.set(TimeUnit.HOURS.toNanos(1));
            assertThat(TrafficHttpHandler.requestReceiptStats().reclaimed()).isZero();
            handler.handleRequestToBeSent(next);
            assertThat(TrafficHttpHandler.requestReceiptStats().reclaimed()).isEqualTo(1);
            assertThat(TrafficHttpHandler.pendingOrphansSize()).isZero();
            TrafficHttpHandlerSupport.stop();
            assertThat(TrafficHttpHandler.requestReceiptStats().retained()).isZero();
            assertThat(TrafficHttpHandler.requestReceiptStats().peak()).isEqualTo(1);
            assertThat(TrafficHttpHandler.requestReceiptStats().reclaimed()).isEqualTo(1);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportRunning(true);
            assertThat(TrafficHttpHandler.requestReceiptStats().peak()).isZero();
            assertThat(TrafficHttpHandler.requestReceiptStats().reclaimed()).isZero();
            action.verify(() -> ProxyRequestToBeSentAction.continueWith(first));
            action.verify(() -> ProxyRequestToBeSentAction.continueWith(next));
        }
    }

    @Test
    void preStartRequest_isNotAdmittedByStartingBeforeItsResponse() {
        InterceptedRequest request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 55);
        InterceptedResponse response = responseReceived(request, 55,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            RuntimeConfig.setExportRunning(false);
            handler.handleRequestToBeSent(request);
            RuntimeConfig.setExportRunning(true);
            handler.handleResponseReceived(response);
            queue.verifyNoInteractions();
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void finalSentRequestBecomesEligible_afterRequestStageScopeRejection() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), "custom",
                List.of(new ConfigState.ScopeEntry("edited.example.test", ConfigState.Kind.STRING)),
                RuntimeConfig.getState().sinks(), ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"), ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        InterceptedRequest initial = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 56);
        InterceptedRequest sent = requestToBeSent("GET /edited HTTP/1.1\r\n\r\n", 56);
        when(sent.url()).thenReturn("https://edited.example.test/edited");
        InterceptedResponse response = responseReceived(sent, 56,
                "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleRequestToBeSent(initial);
            assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(56)).isFalse();
            handler.handleResponseReceived(response);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()));
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(initial));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void largeRequest_isPreparedOncePerCallbackAndFinalSentBodyIsNotCachedFromRequestStage() {
        InterceptedRequest initial = requestToBeSent("POST / HTTP/1.1\r\n\r\n", 600);
        InterceptedRequest sent = requestToBeSent("POST /edited HTTP/1.1\r\n\r\n", 600);
        ByteArray initialBody = byteArray("A".repeat(1024 * 1024));
        byte[] finalBytes = "B".repeat(1024 * 1024).getBytes(StandardCharsets.UTF_8);
        ByteArray finalBody = mock(ByteArray.class);
        when(finalBody.getBytes()).thenReturn(finalBytes);
        when(initial.body()).thenReturn(initialBody);
        when(sent.body()).thenReturn(finalBody);
        when(initial.contentType()).thenReturn(ContentType.JSON);
        when(sent.contentType()).thenReturn(ContentType.JSON);
        InterceptedResponse response = responseReceived(sent, 600, "HTTP/1.1 200 OK\r\n\r\nA");
        AtomicReference<Map<String, Object>> offered = new AtomicReference<>();
        long skippedBefore = ExportStats.getDocsWithSkippedBodyEnumeration();
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                offered.set(call.getArgument(0));
                return true;
            });
            handler.handleRequestToBeSent(initial);
            verify(initialBody).getBytes();
            handler.handleResponseReceived(response);
            verify(initialBody).getBytes();
            verify(finalBody).getBytes();
            Map<?, ?> requestDoc = (Map<?, ?>) offered.get().get("request");
            assertThat(((Map<?, ?>) requestDoc.get("body")).get("b64"))
                    .isEqualTo(Base64.getEncoder().encodeToString(finalBytes));
            assertThat(ExportStats.getDocsWithSkippedBodyEnumeration() - skippedBefore).isEqualTo(2L);
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(initial));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    @ParameterizedTest
    @CsvSource({"burp,true", "burp,false", "' BuRp ',true", "' BuRp ',false"})
    void burpScope_skipsExcludedBodyPreparationAndRechecksTheSentRequest(String scope, boolean finalInScope) {
        useScopeAndTools(scope, List.of(), List.of("proxy"));
        InterceptedRequest initial = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 601);
        when(initial.isInScope()).thenReturn(false);
        InterceptedRequest sent = requestToBeSent("GET /edited HTTP/1.1\r\n\r\n", 601);
        when(sent.isInScope()).thenReturn(finalInScope);
        InterceptedResponse response = responseReceived(sent, 601, "HTTP/1.1 200 OK\r\n\r\nA");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleRequestToBeSent(initial);
            verify(initial, never()).body();
            assertThat(TrafficHttpHandler.requestReceiptStats().retained()).isEqualTo(1);
            // The response's sent request can become eligible after the earlier callback.
            handler.handleResponseReceived(response);
            verify(initial, never()).body();
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), times(finalInScope ? 1 : 0));
            if (!finalInScope) {
                verify(sent, never()).body();
                verify(response, never()).body();
            }
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(initial));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    @ParameterizedTest
    @EnumSource(value = ToolType.class, names = {"SCANNER", "INTRUDER", "EXTENSIONS", "REPEATER"})
    void disabledGeneralTool_skipsBodiesAtBothStages(ToolType type) {
        TrafficHttpHandler general = new TrafficHttpHandler();
        HttpRequestToBeSent request = mock(HttpRequestToBeSent.class);
        HttpResponseReceived response = mock(HttpResponseReceived.class);
        ToolSource source = mock(ToolSource.class);
        when(source.toolType()).thenReturn(type);
        when(request.toolSource()).thenReturn(source);
        when(request.messageId()).thenReturn(602);
        when(request.isInScope()).thenReturn(true);
        when(response.toolSource()).thenReturn(source);
        when(response.messageId()).thenReturn(602);
        when(response.initiatingRequest()).thenReturn(request);
        try (var requestAction = mockStatic(RequestToBeSentAction.class);
                var responseAction = mockStatic(ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            general.handleHttpRequestToBeSent(request);
            general.handleHttpResponseReceived(response);
            verify(request, never()).body();
            verify(request, never()).parameters();
            verify(request, never()).toByteArray();
            verify(response, never()).body();
            queue.verifyNoInteractions();
            requestAction.verify(() -> RequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ResponseReceivedAction.continueWith(response));
        }
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void malformedCustomScope_usesTheNarrowedQueryAtBothStages(boolean matchesRetainedQuery) {
        useScopeAndTools(" CuStOm ", List.of(new ConfigState.ScopeEntry(
                matchesRetainedQuery ? "kept=value" : "dropped=value", ConfigState.Kind.STRING)), List.of("proxy"));
        InterceptedRequest request = requestToBeSent("GET /search HTTP/1.1\r\n\r\n", 603);
        when(request.httpService()).thenReturn(null);
        when(request.url()).thenThrow(new IllegalStateException("malformed URL"));
        when(request.path()).thenReturn("/search?kept=value&dropped=value");
        when(request.pathWithoutQuery()).thenReturn("/search");
        when(request.query()).thenReturn("kept=value&dropped=value");
        when(request.contentType()).thenReturn(ContentType.JSON);
        ParsedHttpParameter kept = mock(ParsedHttpParameter.class);
        when(kept.type()).thenReturn(HttpParameterType.URL);
        when(kept.name()).thenReturn("kept");
        when(kept.value()).thenReturn("value");
        ParsedHttpParameter dropped = mock(ParsedHttpParameter.class);
        when(dropped.type()).thenReturn(HttpParameterType.URL);
        List<ParsedHttpParameter> parameters = new ArrayList<>(
                Collections.nCopies(RequestResponseParametersSupport.URL_PARAMETERS_CAP, kept));
        parameters.add(dropped);
        when(request.parameters(HttpParameterType.URL)).thenReturn(parameters);
        InterceptedResponse response = responseReceived(request, 603, "HTTP/1.1 200 OK\r\n\r\nA");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleRequestToBeSent(request);
            assertThat(TrafficHttpHandlerSupport.containsPendingOrphanForTest(603))
                    .isEqualTo(matchesRetainedQuery);
            handler.handleResponseReceived(response);
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), times(matchesRetainedQuery ? 1 : 0));
            // One real parameter-preparation pass per callback, including fallback scope paths.
            verify(request, times(2)).parameters(HttpParameterType.URL);
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    private static void useScopeAndTools(String scope, List<ConfigState.ScopeEntry> entries,
            List<String> tools) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"), scope, entries,
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200",
                        null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, tools,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
    }

    private static InterceptedRequest requestToBeSent(String rawRequest, int messageId) {
        InterceptedRequest request = mock(InterceptedRequest.class);
        HttpService service = mock(HttpService.class);
        ByteArray requestBytes = byteArray(rawRequest);

        when(service.host()).thenReturn("example.test");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        when(request.listenerInterface()).thenReturn("127.0.0.1:8080");
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

    private static InterceptedResponse responseReceived(
            InterceptedRequest request,
            int messageId,
            String rawResponse) {
        InterceptedResponse response = mock(InterceptedResponse.class);
        ByteArray responseBytes = byteArray(rawResponse);

        when(response.initiatingRequest()).thenReturn(request);
        when(response.messageId()).thenReturn(messageId);
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

    @ParameterizedTest
    @CsvSource({"127.0.0.1:8080,8080", "[::1]:8081,8081", "::1:8082,8082",
            "0.0.0.0:443,443", "*:65535,65535", "host.test:1,1"})
    void listenerAddressVariants_preserveTheActualPort(String listener, int port) {
        assertThat(TrafficProxyHttpHandler.listenerPort(listener)).isEqualTo(port);
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.NullAndEmptySource
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "8080", ":8080", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:65536",
            "127.0.0.1:+8080", "127.0.0.1:eighty", "127.0.0.1: 8080", "host:999999999999"})
    void invalidOrMissingListener_doesNotGuess(String listener) {
        assertThat(TrafficProxyHttpHandler.listenerPort(listener)).isNull();
    }

    @Test
    void generalProxyCallbacks_doNotDuplicateNativeDocuments() {
        var general = new TrafficHttpHandler();
        var request = mock(burp.api.montoya.http.handler.HttpRequestToBeSent.class);
        var response = mock(burp.api.montoya.http.handler.HttpResponseReceived.class);
        var source = mock(burp.api.montoya.core.ToolSource.class);
        when(source.toolType()).thenReturn(ToolType.PROXY);
        when(request.toolSource()).thenReturn(source);
        when(response.toolSource()).thenReturn(source);
        try (var requestAction = mockStatic(burp.api.montoya.http.handler.RequestToBeSentAction.class);
                var responseAction = mockStatic(burp.api.montoya.http.handler.ResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            general.handleHttpRequestToBeSent(request);
            general.handleHttpResponseReceived(response);
            queue.verifyNoInteractions();
            requestAction.verify(() -> burp.api.montoya.http.handler.RequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> burp.api.montoya.http.handler.ResponseReceivedAction.continueWith(response));
            assertThat(TrafficHttpHandlerSupport.getPendingOrphansSize()).isZero();
        }
    }

    @Test
    void equalGeneralAndNativeIds_doNotConsumeEachOthersAdmissions() {
        TrafficHttpHandlerSupport.registerPendingOrphanForTest(61,
                Map.of("burp", Map.of("message_id", 61, "reporting_tool", "Proxy")),
                ToolType.PROXY, TrafficHttpHandlerSupport.RequestStageResolution.none());
        var request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 61);
        var response = responseReceived(request, 61, "HTTP/1.1 200 OK\r\n\r\n");
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleRequestToBeSent(request);
            handler.handleResponseReceived(response);
            assertThat(TrafficHttpHandlerSupport.getPendingOrphansSize()).isEqualTo(1);
            TrafficHttpHandlerSupport.flushOrphanedRequestsForTest();
            queue.verify(() -> TrafficExportQueue.offerForRun(any(), any()), org.mockito.Mockito.times(2));
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

    @Test
    void unusedNativeStages_preserveInterceptionAndAnnotationsWithoutExporting() {
        var request = mock(InterceptedRequest.class);
        var response = mock(InterceptedResponse.class);
        try (var requestAction = mockStatic(ProxyRequestReceivedAction.class);
                var responseAction = mockStatic(ProxyResponseToBeSentAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            handler.handleRequestReceived(request);
            handler.handleResponseToBeSent(response);
            requestAction.verify(() -> ProxyRequestReceivedAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseToBeSentAction.continueWith(response));
            queue.verifyNoInteractions();
            org.mockito.Mockito.verifyNoInteractions(request, response);
        }
    }

    @Test
    void nativeCaptureFailure_stillContinuesTheUnchangedRequest() {
        var request = mock(InterceptedRequest.class);
        when(request.httpService()).thenThrow(new IllegalStateException("unavailable"));
        try (var action = mockStatic(ProxyRequestToBeSentAction.class)) {
            handler.handleRequestToBeSent(request);
            action.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
        }
    }

    @Test
    void unavailableListenerAccessor_doesNotDiscardTheExchange() {
        var request = requestToBeSent("GET / HTTP/1.1\r\n\r\n", 62);
        var response = responseReceived(request, 62, "HTTP/1.1 200 OK\r\n\r\n");
        when(request.listenerInterface()).thenThrow(new IllegalStateException("unavailable"));
        AtomicReference<Map<String, Object>> offered = new AtomicReference<>();
        try (var requestAction = mockStatic(ProxyRequestToBeSentAction.class);
                var responseAction = mockStatic(ProxyResponseReceivedAction.class);
                var queue = mockStatic(TrafficExportQueue.class)) {
            queue.when(() -> TrafficExportQueue.offerForRun(any(), any())).thenAnswer(call -> {
                offered.set(call.getArgument(0));
                return true;
            });
            handler.handleRequestToBeSent(request);
            handler.handleResponseReceived(response);
            Map<?, ?> burp = (Map<?, ?>) offered.get().get("burp");
            assertThat(((Map<?, ?>) burp.get("proxy")).get("listener_port")).isNull();
            assertThat(burp.get("message_id")).isEqualTo(62);
            requestAction.verify(() -> ProxyRequestToBeSentAction.continueWith(request));
            responseAction.verify(() -> ProxyResponseReceivedAction.continueWith(response));
        }
    }

}
