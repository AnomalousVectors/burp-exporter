package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

class ProxyLiveMetadataCorrelatorTest {

    private static final long SENT_MS = 1_777_777_777_000L;
    private static final String TOKEN_A = "00000000-0000-0000-0000-000000000001";
    private static final String TOKEN_B = "00000000-0000-0000-0000-000000000002";

    @TempDir
    Path tempDir;

    private final AtomicLong monotonicNanos = new AtomicLong(1_000_000L);
    private final AtomicLong epochMillis = new AtomicLong(SENT_MS + 100L);
    private final List<ProxyHttpRequestResponse> history = new ArrayList<>();
    private final List<Map<String, Object>> offered = new ArrayList<>();
    private ProxyCorrelationSpool testSpool;

    @BeforeEach
    void setUp() {
        RuntimeConfig.setExportRunning(false);
        testSpool = new ProxyCorrelationSpool(tempDir.resolve("correlation"), 10_000_000L);
        configure(testSpool);
        ProxyLiveMetadataCorrelator.openRun();
    }

    @AfterEach
    void tearDown() {
        RuntimeConfig.setExportRunning(false);
        ProxyLiveMetadataCorrelator.resetForTests();
        MontoyaApiProvider.set(null);
    }

    @Test
    void tokenMarker_preservesExistingAndConcurrentNoteEdits() {
        MutableAnnotations annotations = mutableAnnotations("user note");

        assertThat(ProxyCorrelationToken.append(annotations.value, TOKEN_A)).isTrue();
        annotations.notes.set(annotations.notes.get() + "\nlater edit");

        assertThat(ProxyCorrelationToken.find(annotations.value)).contains(TOKEN_A);
        assertThat(ProxyCorrelationToken.remove(annotations.value, TOKEN_A)).isTrue();
        assertThat(annotations.notes.get()).isEqualTo("user note\nlater edit");
    }

    @Test
    void historyFallback_requiresCompleteRequestListenerAndTimeMatch() {
        HttpRequest finalRequest = mock(HttpRequest.class);
        ByteArray requestBytes = mock(ByteArray.class);
        when(finalRequest.toByteArray()).thenReturn(requestBytes);
        when(requestBytes.getBytes()).thenReturn(new byte[] {1, 2, 3});
        ProxyHttpRequestResponse row = mock(ProxyHttpRequestResponse.class);
        when(row.finalRequest()).thenReturn(finalRequest);
        when(row.listenerPort()).thenReturn(8080);
        when(row.time()).thenReturn(ZonedDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(SENT_MS), ZoneOffset.UTC));
        MutableAnnotations rowAnnotations = mutableAnnotations("");
        when(row.annotations()).thenReturn(rowAnnotations.value);

        MontoyaApi api = mock(MontoyaApi.class);
        Proxy proxy = mock(Proxy.class);
        when(api.proxy()).thenReturn(proxy);
        when(proxy.history()).thenReturn(List.of(row));
        MontoyaApiProvider.set(api);
        ProxyLiveMetadataCorrelator.HistorySource source =
                ProxyLiveMetadataCorrelator.newBurpHistorySourceForTest();
        source.lookup(Set.of(TOKEN_A), ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS);

        assertThat(source.fallbackCandidates(new byte[] {1, 2, 3}, 8080, SENT_MS))
                .containsExactly(row);
        assertThat(source.fallbackCandidates(new byte[] {1, 2, 4}, 8080, SENT_MS)).isEmpty();
        assertThat(source.fallbackCandidates(new byte[] {1, 2, 3}, 8081, SENT_MS)).isEmpty();
        assertThat(source.fallbackCandidates(
                        new byte[] {1, 2, 3},
                        8080,
                        SENT_MS - Duration.ofMinutes(2).toMillis()))
                .isEmpty();
    }

    @Test
    void uniqueFallbackCandidate_bindsWhenMarkerIsMissingFromHistory() {
        MutableAnnotations live = mutableAnnotations("");
        ProxyHttpRequestResponse row = historyRow(
                88_001,
                8080,
                mutableAnnotations("").value,
                5,
                6);
        AtomicReference<byte[]> observedRequest = new AtomicReference<>();
        ProxyLiveMetadataCorrelator.HistorySource source =
                new ProxyLiveMetadataCorrelator.HistorySource() {
                    @Override
                    public ProxyLiveMetadataCorrelator.LookupBatch lookup(
                            Set<String> tokens,
                            ProxyLiveMetadataCorrelator.LookupScope scope) {
                        return ProxyLiveMetadataCorrelator.LookupBatch.success(List.of());
                    }

                    @Override
                    public List<ProxyHttpRequestResponse> fallbackCandidates(
                            byte[] finalRequestBytes,
                            Integer listenerPort,
                            Long requestSentMs) {
                        observedRequest.set(finalRequestBytes);
                        return List.of(row);
                    }
                };
        ProxyLiveMetadataCorrelator.configureForTests(
                source,
                document -> {
                    offered.add(document);
                    return true;
                },
                testSpool,
                monotonicNanos::get,
                epochMillis::get,
                () -> TOKEN_A,
                15_000L);
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(81, TOKEN_A, 8080, live.value);
        HttpRequest request = mock(HttpRequest.class);
        ByteArray requestBytes = mock(ByteArray.class);
        when(request.toByteArray()).thenReturn(requestBytes);
        when(requestBytes.getBytes()).thenReturn(new byte[] {9, 8, 7});

        Map<String, Object> document = liveDocument(81);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                document,
                live.value,
                81,
                SENT_MS,
                null,
                request,
                null);
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(observedRequest.get()).containsExactly(9, 8, 7);
        assertThat(offered).containsExactly(document);
        assertThat(historyId(document)).isEqualTo(88_001);
    }

    @Test
    void annotationExport_redactsOnlyGeneratedMarker() {
        MutableAnnotations annotations = mutableAnnotations(
                "before\n" + ProxyCorrelationToken.marker(TOKEN_A) + "\nafter");
        Map<String, Object> burp = new LinkedHashMap<>();

        BurpAnnotationFields.put(burp, annotations.value);

        assertThat(burp.get("notes")).isEqualTo("before\nafter");
    }

    @Test
    void proxyHandlerActions_explicitlyCarryAnnotationsThroughEveryStage() {
        MutableAnnotations annotations = mutableAnnotations("user note");
        InterceptedRequest request = mock(InterceptedRequest.class);
        InterceptedResponse response = mock(InterceptedResponse.class);
        when(request.messageId()).thenReturn(7);
        when(request.annotations()).thenReturn(annotations.value);
        when(response.messageId()).thenReturn(7);
        when(response.annotations()).thenReturn(annotations.value);
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(7, TOKEN_A, 8080, annotations.value);

        ProxyRequestReceivedAction requestReceived = mock(ProxyRequestReceivedAction.class);
        ProxyRequestToBeSentAction requestToBeSent = mock(ProxyRequestToBeSentAction.class);
        ProxyResponseReceivedAction responseReceived = mock(ProxyResponseReceivedAction.class);
        ProxyResponseToBeSentAction responseToBeSent = mock(ProxyResponseToBeSentAction.class);
        try (MockedStatic<ProxyRequestReceivedAction> requestReceivedFactory =
                        mockStatic(ProxyRequestReceivedAction.class);
                MockedStatic<ProxyRequestToBeSentAction> requestToBeSentFactory =
                        mockStatic(ProxyRequestToBeSentAction.class);
                MockedStatic<ProxyResponseReceivedAction> responseReceivedFactory =
                        mockStatic(ProxyResponseReceivedAction.class);
                MockedStatic<ProxyResponseToBeSentAction> responseToBeSentFactory =
                        mockStatic(ProxyResponseToBeSentAction.class)) {
            requestReceivedFactory
                    .when(() -> ProxyRequestReceivedAction.continueWith(request, annotations.value))
                    .thenReturn(requestReceived);
            requestToBeSentFactory
                    .when(() -> ProxyRequestToBeSentAction.continueWith(request, annotations.value))
                    .thenReturn(requestToBeSent);
            responseReceivedFactory
                    .when(() -> ProxyResponseReceivedAction.continueWith(response, annotations.value))
                    .thenReturn(responseReceived);
            responseToBeSentFactory
                    .when(() -> ProxyResponseToBeSentAction.continueWith(response, annotations.value))
                    .thenReturn(responseToBeSent);

            assertThat(ProxyLiveMetadataCorrelator.instance().handleRequestReceived(request))
                    .isSameAs(requestReceived);
            assertThat(ProxyLiveMetadataCorrelator.instance().handleRequestToBeSent(request))
                    .isSameAs(requestToBeSent);
            assertThat(ProxyLiveMetadataCorrelator.instance().handleResponseReceived(response))
                    .isSameAs(responseReceived);
            assertThat(ProxyLiveMetadataCorrelator.instance().handleResponseToBeSent(response))
                    .isSameAs(responseToBeSent);
        }
    }

    @Test
    void separateHttpAndProxyCallbacks_exportCompleteUnmodifiedStageMetadata() {
        RuntimeConfig.setExportRunning(true);
        try {
            MutableAnnotations proxyReceivedAnnotations = mutableAnnotations("proxy received");
            MutableAnnotations proxySentAnnotations = mutableAnnotations("proxy sent");
            InterceptedRequest proxyRequest = mock(InterceptedRequest.class);
            ByteArray proxyReceivedBytes = mock(ByteArray.class);
            ByteArray proxySentBytes = mock(ByteArray.class);
            when(proxyRequest.messageId()).thenReturn(71);
            when(proxyRequest.annotations())
                    .thenReturn(proxyReceivedAnnotations.value, proxySentAnnotations.value);
            when(proxyRequest.toByteArray()).thenReturn(proxyReceivedBytes, proxySentBytes);
            when(proxyReceivedBytes.getBytes()).thenReturn(new byte[] {4, 5, 6});
            when(proxySentBytes.getBytes()).thenReturn(new byte[] {4, 5, 6});
            ProxyRequestReceivedAction receivedAction = mock(ProxyRequestReceivedAction.class);
            ProxyRequestToBeSentAction proxyAction = mock(ProxyRequestToBeSentAction.class);
            try (MockedStatic<ProxyRequestReceivedAction> receivedFactory =
                            mockStatic(ProxyRequestReceivedAction.class);
                    MockedStatic<ProxyRequestToBeSentAction> sentFactory =
                            mockStatic(ProxyRequestToBeSentAction.class)) {
                receivedFactory.when(() -> ProxyRequestReceivedAction.continueWith(
                                proxyRequest, proxyReceivedAnnotations.value))
                        .thenReturn(receivedAction);
                sentFactory.when(() -> ProxyRequestToBeSentAction.continueWith(
                                proxyRequest, proxySentAnnotations.value))
                        .thenReturn(proxyAction);
                assertThat(ProxyLiveMetadataCorrelator.instance()
                                .handleRequestReceived(proxyRequest))
                        .isSameAs(receivedAction);
                assertThat(ProxyLiveMetadataCorrelator.instance()
                                .handleRequestToBeSent(proxyRequest))
                        .isSameAs(proxyAction);
            }

            String proxyToken = ProxyCorrelationToken.find(proxyReceivedAnnotations.value)
                    .orElseThrow();
            assertThat(ProxyCorrelationToken.find(proxySentAnnotations.value)).contains(proxyToken);
            MutableAnnotations httpAnnotations = mutableAnnotations("http");
            HttpRequest downstreamRequest = mock(HttpRequest.class);
            ByteArray downstreamBytes = mock(ByteArray.class);
            when(downstreamRequest.toByteArray()).thenReturn(downstreamBytes);
            when(downstreamBytes.getBytes()).thenReturn(new byte[] {4, 5, 6});

            ProxyLiveMetadataCorrelator.markHttpRequest(
                    9_071, httpAnnotations.value, downstreamRequest);

            assertThat(ProxyCorrelationToken.find(httpAnnotations.value)).contains(proxyToken);

            HttpResponse upstreamResponse = mock(HttpResponse.class);
            ByteArray upstreamBytes = mock(ByteArray.class);
            when(upstreamResponse.toByteArray()).thenReturn(upstreamBytes);
            when(upstreamBytes.getBytes()).thenReturn(new byte[] {7, 8, 9});
            Map<String, Object> document = liveDocument(9_071);
            MutableAnnotations historyAnnotations =
                    mutableAnnotations(ProxyCorrelationToken.marker(proxyToken));
            history.add(historyRow(88_071, 8080, historyAnnotations.value, 5, 6));
            ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                    document,
                    httpAnnotations.value,
                    9_071,
                    SENT_MS,
                    null,
                    downstreamRequest,
                    upstreamResponse);

            InterceptedResponse proxyResponse = mock(InterceptedResponse.class);
            MutableAnnotations proxyResponseReceivedAnnotations =
                    mutableAnnotations("proxy response received");
            MutableAnnotations proxyResponseSentAnnotations =
                    mutableAnnotations("proxy response sent");
            ByteArray proxyReceivedResponseBytes = mock(ByteArray.class);
            ByteArray proxySentResponseBytes = mock(ByteArray.class);
            when(proxyResponse.messageId()).thenReturn(71);
            when(proxyResponse.annotations()).thenReturn(
                    proxyResponseReceivedAnnotations.value,
                    proxyResponseSentAnnotations.value);
            when(proxyResponse.toByteArray())
                    .thenReturn(proxyReceivedResponseBytes, proxySentResponseBytes);
            when(proxyReceivedResponseBytes.getBytes()).thenReturn(new byte[] {7, 8, 9});
            when(proxySentResponseBytes.getBytes()).thenReturn(new byte[] {7, 8, 9});
            ProxyResponseReceivedAction responseReceivedAction =
                    mock(ProxyResponseReceivedAction.class);
            ProxyResponseToBeSentAction responseSentAction = mock(ProxyResponseToBeSentAction.class);
            try (MockedStatic<ProxyResponseReceivedAction> receivedFactory =
                            mockStatic(ProxyResponseReceivedAction.class);
                    MockedStatic<ProxyResponseToBeSentAction> sentFactory =
                            mockStatic(ProxyResponseToBeSentAction.class)) {
                receivedFactory.when(() -> ProxyResponseReceivedAction.continueWith(
                                proxyResponse, proxyResponseReceivedAnnotations.value))
                        .thenReturn(responseReceivedAction);
                sentFactory.when(() -> ProxyResponseToBeSentAction.continueWith(
                                proxyResponse, proxyResponseSentAnnotations.value))
                        .thenReturn(responseSentAction);
                assertThat(ProxyLiveMetadataCorrelator.instance()
                                .handleResponseReceived(proxyResponse))
                        .isSameAs(responseReceivedAction);
                assertThat(ProxyLiveMetadataCorrelator.instance()
                                .handleResponseToBeSent(proxyResponse))
                        .isSameAs(responseSentAction);
            }

            ProxyLiveMetadataCorrelator.runReconciliationForTest();

            assertThat(offered).containsExactly(document);
            assertThat(proxy(document).get("request_change_stages")).isEqualTo(List.of());
            assertThat(proxy(document).get("response_change_stages")).isEqualTo(List.of());
        } finally {
            RuntimeConfig.setExportRunning(false);
        }
    }

    @Test
    void matchingNumericIdsAcrossCallbackFamilies_doNotCollide() {
        AtomicInteger tokenIndex = new AtomicInteger();
        ProxyLiveMetadataCorrelator.configureForTests(
                (ignored, scope) ->
                        ProxyLiveMetadataCorrelator.LookupBatch.success(List.copyOf(history)),
                document -> {
                    offered.add(document);
                    return true;
                },
                testSpool,
                monotonicNanos::get,
                epochMillis::get,
                () -> tokenIndex.getAndIncrement() == 0 ? TOKEN_A : TOKEN_B,
                15_000L);
        RuntimeConfig.setExportRunning(true);
        try {
            MutableAnnotations proxyAnnotations = mutableAnnotations("proxy");
            InterceptedRequest proxyRequest = mock(InterceptedRequest.class);
            ByteArray proxyBytes = mock(ByteArray.class);
            when(proxyRequest.messageId()).thenReturn(72);
            when(proxyRequest.annotations()).thenReturn(proxyAnnotations.value);
            when(proxyRequest.toByteArray()).thenReturn(proxyBytes);
            when(proxyBytes.getBytes()).thenReturn(new byte[] {1, 2, 3});
            ProxyRequestToBeSentAction proxyAction = mock(ProxyRequestToBeSentAction.class);
            try (MockedStatic<ProxyRequestToBeSentAction> factory =
                    mockStatic(ProxyRequestToBeSentAction.class)) {
                factory.when(() -> ProxyRequestToBeSentAction.continueWith(
                                proxyRequest, proxyAnnotations.value))
                        .thenReturn(proxyAction);
                assertThat(ProxyLiveMetadataCorrelator.instance()
                                .handleRequestToBeSent(proxyRequest))
                        .isSameAs(proxyAction);
            }
            String proxyToken = ProxyCorrelationToken.find(proxyAnnotations.value).orElseThrow();

            MutableAnnotations unrelatedHttpAnnotations = mutableAnnotations("http unrelated");
            HttpRequest unrelatedHttpRequest = mock(HttpRequest.class);
            ByteArray unrelatedHttpBytes = mock(ByteArray.class);
            when(unrelatedHttpRequest.toByteArray()).thenReturn(unrelatedHttpBytes);
            when(unrelatedHttpBytes.getBytes()).thenReturn(new byte[] {4, 5, 6});
            ProxyLiveMetadataCorrelator.markHttpRequest(
                    72, unrelatedHttpAnnotations.value, unrelatedHttpRequest);
            String unrelatedToken = ProxyCorrelationToken.find(unrelatedHttpAnnotations.value)
                    .orElseThrow();

            assertThat(unrelatedToken).isNotEqualTo(proxyToken);

            ProxyLiveMetadataCorrelator.abandonMessage(
                    72, unrelatedHttpAnnotations.value, unrelatedHttpRequest);
            MutableAnnotations matchingHttpAnnotations = mutableAnnotations("http matching");
            HttpRequest matchingHttpRequest = mock(HttpRequest.class);
            ByteArray matchingHttpBytes = mock(ByteArray.class);
            when(matchingHttpRequest.toByteArray()).thenReturn(matchingHttpBytes);
            when(matchingHttpBytes.getBytes()).thenReturn(new byte[] {1, 2, 3});
            ProxyLiveMetadataCorrelator.markHttpRequest(
                    9_072, matchingHttpAnnotations.value, matchingHttpRequest);

            assertThat(ProxyCorrelationToken.find(matchingHttpAnnotations.value))
                    .contains(proxyToken);
        } finally {
            RuntimeConfig.setExportRunning(false);
        }
    }

    @Test
    void rejectedHttpRequest_abandonsUniqueProxyStageByCompleteDownstreamBytes() {
        RuntimeConfig.setExportRunning(true);
        try {
            MutableAnnotations proxyAnnotations = mutableAnnotations("proxy");
            InterceptedRequest proxyRequest = mock(InterceptedRequest.class);
            ByteArray proxyBytes = mock(ByteArray.class);
            when(proxyRequest.messageId()).thenReturn(72);
            when(proxyRequest.annotations()).thenReturn(proxyAnnotations.value);
            when(proxyRequest.toByteArray()).thenReturn(proxyBytes);
            when(proxyBytes.getBytes()).thenReturn(new byte[] {9, 8, 7});
            ProxyRequestToBeSentAction proxyAction = mock(ProxyRequestToBeSentAction.class);
            try (MockedStatic<ProxyRequestToBeSentAction> factory =
                    mockStatic(ProxyRequestToBeSentAction.class)) {
                factory.when(() -> ProxyRequestToBeSentAction.continueWith(
                                proxyRequest, proxyAnnotations.value))
                        .thenReturn(proxyAction);
                assertThat(ProxyLiveMetadataCorrelator.instance()
                                .handleRequestToBeSent(proxyRequest))
                        .isSameAs(proxyAction);
            }

            MutableAnnotations httpAnnotations = mutableAnnotations("http");
            HttpRequest downstreamRequest = mock(HttpRequest.class);
            ByteArray downstreamBytes = mock(ByteArray.class);
            when(downstreamRequest.toByteArray()).thenReturn(downstreamBytes);
            when(downstreamBytes.getBytes()).thenReturn(new byte[] {9, 8, 7});

            ProxyLiveMetadataCorrelator.abandonMessage(
                    9_072, httpAnnotations.value, downstreamRequest);

            assertThat(ProxyCorrelationToken.find(proxyAnnotations.value)).isEmpty();
            assertThat(ProxyCorrelationToken.find(httpAnnotations.value)).isEmpty();
        } finally {
            RuntimeConfig.setExportRunning(false);
        }
    }

    @Test
    void unmarkedProxyCallbackIdCollision_createsDistinctAnnotationBackedToken() {
        RuntimeConfig.setExportRunning(true);
        try {
            ProxyLiveMetadataCorrelator.configureForTests(
                    (ignored, scope) ->
                            ProxyLiveMetadataCorrelator.LookupBatch.success(List.copyOf(history)),
                    document -> {
                        offered.add(document);
                        return true;
                    },
                    testSpool,
                    monotonicNanos::get,
                    epochMillis::get,
                    () -> TOKEN_B,
                    15_000L);
            MutableAnnotations globalHttp = mutableAnnotations("global");
            MutableAnnotations unrelatedProxy = mutableAnnotations("proxy");
            ProxyLiveMetadataCorrelator.registerLiveTokenForTest(
                    7, TOKEN_A, 8080, globalHttp.value);
            InterceptedRequest request = mock(InterceptedRequest.class);
            when(request.messageId()).thenReturn(7);
            when(request.annotations()).thenReturn(unrelatedProxy.value);
            ProxyRequestReceivedAction action = mock(ProxyRequestReceivedAction.class);
            try (MockedStatic<ProxyRequestReceivedAction> factory =
                    mockStatic(ProxyRequestReceivedAction.class)) {
                factory.when(() -> ProxyRequestReceivedAction.continueWith(
                                request, unrelatedProxy.value))
                        .thenReturn(action);

                assertThat(ProxyLiveMetadataCorrelator.instance().handleRequestReceived(request))
                        .isSameAs(action);
            }

            assertThat(ProxyCorrelationToken.find(globalHttp.value)).contains(TOKEN_A);
            assertThat(ProxyCorrelationToken.find(unrelatedProxy.value)).contains(TOKEN_B);
        } finally {
            RuntimeConfig.setExportRunning(false);
        }
    }

    @Test
    void identicalConcurrentDocuments_bindByTokenWhenHistoryIsOutOfOrder() {
        MutableAnnotations liveA = mutableAnnotations("same user note");
        MutableAnnotations liveB = mutableAnnotations("same user note");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(11, TOKEN_A, 8080, liveA.value);
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(12, TOKEN_B, 8080, liveB.value);

        Map<String, Object> documentA = liveDocument(11);
        Map<String, Object> documentB = liveDocument(12);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(documentA, liveA.value, 11, SENT_MS);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(documentB, liveB.value, 12, SENT_MS);

        MutableAnnotations historyB = mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_B));
        MutableAnnotations historyA = mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A));
        history.add(historyRow(80_002, 8080, historyB.value, 22, 55));
        history.add(historyRow(80_001, 8080, historyA.value, 11, 44));

        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).hasSize(2);
        assertThat(historyId(documentA)).isEqualTo(80_001);
        assertThat(historyId(documentB)).isEqualTo(80_002);
        assertThat(timing(documentA).get("req_sent_to_res_start")).isEqualTo(11);
        assertThat(timing(documentB).get("req_sent_to_res_start")).isEqualTo(22);
        assertThat(liveA.notes.get()).isEqualTo("same user note");
        assertThat(liveB.notes.get()).isEqualTo("same user note");
        assertThat(historyA.notes.get()).isEmpty();
        assertThat(historyB.notes.get()).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.boundTotal()).isEqualTo(2L);
    }

    @Test
    void responseAdmission_returnsBeforeBlockedHistoryWorker() throws Exception {
        CountDownLatch lookupEntered = new CountDownLatch(1);
        CountDownLatch releaseLookup = new CountDownLatch(1);
        AtomicReference<String> lookupThread = new AtomicReference<>();
        ProxyLiveMetadataCorrelator.configureForTests(
                (tokens, scope) -> {
                    lookupThread.set(Thread.currentThread().getName());
                    lookupEntered.countDown();
                    try {
                        releaseLookup.await(5L, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return ProxyLiveMetadataCorrelator.LookupBatch.success(List.copyOf(history));
                },
                document -> {
                    offered.add(document);
                    return true;
                },
                testSpool,
                System::nanoTime,
                epochMillis::get,
                () -> TOKEN_A,
                15_000L);
        ProxyLiveMetadataCorrelator.enableSchedulerForTests();
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(13, TOKEN_A, 8080, live.value);
        CountDownLatch callbackReturned = new CountDownLatch(1);
        Thread callback = new Thread(
                () -> {
                    ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                            liveDocument(13), live.value, 13, SENT_MS);
                    callbackReturned.countDown();
                },
                "simulated-burp-http-callback");

        callback.start();
        boolean returnedBeforeRelease = callbackReturned.await(1L, TimeUnit.SECONDS);
        boolean workerStarted = lookupEntered.await(1L, TimeUnit.SECONDS);
        releaseLookup.countDown();
        callback.join(1_000L);

        assertThat(returnedBeforeRelease).isTrue();
        assertThat(workerStarted).isTrue();
        assertThat(lookupThread.get()).isEqualTo("burp-exporter-proxy-token-reconcile");
    }

    @Test
    void responseAdmission_returnsBeforeBlockedSpoolWorker() throws Exception {
        CountDownLatch persistEntered = new CountDownLatch(1);
        CountDownLatch releasePersist = new CountDownLatch(1);
        ProxyCorrelationSpool blockingSpool =
                new ProxyCorrelationSpool(tempDir.resolve("blocking-spool"), 10_000_000L) {
                    @Override
                    PersistResult persist(StoredEntry entry) {
                        persistEntered.countDown();
                        try {
                            releasePersist.await(5L, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        return super.persist(entry);
                    }
                };
        ProxyLiveMetadataCorrelator.configureForTests(
                (tokens, scope) -> ProxyLiveMetadataCorrelator.LookupBatch.success(List.of()),
                document -> true,
                blockingSpool,
                System::nanoTime,
                epochMillis::get,
                () -> TOKEN_A,
                0L);
        ProxyLiveMetadataCorrelator.enableSchedulerForTests();
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(14, TOKEN_A, 8080, live.value);
        CountDownLatch callbackReturned = new CountDownLatch(1);
        Thread callback = new Thread(
                () -> {
                    ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                            liveDocument(14), live.value, 14, SENT_MS);
                    callbackReturned.countDown();
                },
                "simulated-burp-spool-callback");

        callback.start();
        boolean returnedBeforeRelease = callbackReturned.await(1L, TimeUnit.SECONDS);
        boolean workerStarted = persistEntered.await(1L, TimeUnit.SECONDS);
        releasePersist.countDown();
        callback.join(1_000L);

        assertThat(returnedBeforeRelease).isTrue();
        assertThat(workerStarted).isTrue();
    }

    @Test
    void responseAdmission_returnsBeforeBlockedQueueOfferWorker() throws Exception {
        CountDownLatch offerEntered = new CountDownLatch(1);
        CountDownLatch releaseOffer = new CountDownLatch(1);
        history.add(historyRow(
                80_014,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                1,
                2));
        ProxyLiveMetadataCorrelator.configureForTests(
                (tokens, scope) -> ProxyLiveMetadataCorrelator.LookupBatch.success(List.copyOf(history)),
                document -> {
                    offerEntered.countDown();
                    try {
                        releaseOffer.await(5L, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return true;
                },
                testSpool,
                System::nanoTime,
                epochMillis::get,
                () -> TOKEN_A,
                15_000L);
        ProxyLiveMetadataCorrelator.enableSchedulerForTests();
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(15, TOKEN_A, 8080, live.value);
        CountDownLatch callbackReturned = new CountDownLatch(1);
        Thread callback = new Thread(
                () -> {
                    ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                            liveDocument(15), live.value, 15, SENT_MS);
                    callbackReturned.countDown();
                },
                "simulated-burp-offer-callback");

        callback.start();
        boolean returnedBeforeRelease = callbackReturned.await(1L, TimeUnit.SECONDS);
        boolean workerStarted = offerEntered.await(1L, TimeUnit.SECONDS);
        releaseOffer.countDown();
        callback.join(1_000L);

        assertThat(returnedBeforeRelease).isTrue();
        assertThat(workerStarted).isTrue();
    }

    @Test
    void appendedHistorySource_cachesUnrequestedTokenRowsBeforeAdvancingCursor() {
        MontoyaApi api = mock(MontoyaApi.class);
        Proxy proxyApi = mock(Proxy.class);
        when(api.proxy()).thenReturn(proxyApi);
        ProxyHttpRequestResponse oldRow = historyRow(
                1,
                8080,
                mutableAnnotations("ordinary note").value,
                1,
                2);
        ProxyHttpRequestResponse rowA = historyRow(
                2,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                3,
                4);
        ProxyHttpRequestResponse rowB = historyRow(
                3,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_B)).value,
                5,
                6);
        when(proxyApi.history())
                .thenReturn(List.of(oldRow, rowA, rowB))
                .thenReturn(List.of(oldRow, rowA, rowB));
        MontoyaApiProvider.set(api);
        ProxyLiveMetadataCorrelator.HistorySource source =
                ProxyLiveMetadataCorrelator.newBurpHistorySourceForTest();

        try {
            ProxyLiveMetadataCorrelator.LookupBatch first = source.lookup(
                    Set.of(TOKEN_A),
                    ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS);
            ProxyLiveMetadataCorrelator.LookupBatch second = source.lookup(
                    Set.of(TOKEN_B),
                    ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS);

            assertThat(first.rows).containsExactly(rowA);
            assertThat(second.rows).containsExactly(rowB);
            verify(proxyApi, times(2)).history();
        } finally {
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void appendedHistorySource_rescansWhenHistoryTailIsReplaced() {
        MontoyaApi api = mock(MontoyaApi.class);
        Proxy proxyApi = mock(Proxy.class);
        when(api.proxy()).thenReturn(proxyApi);
        ProxyHttpRequestResponse rowA = historyRow(
                10,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                1,
                2);
        ProxyHttpRequestResponse replacement = historyRow(
                11,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_B)).value,
                3,
                4);
        when(proxyApi.history())
                .thenReturn(List.of(rowA))
                .thenReturn(List.of(replacement));
        MontoyaApiProvider.set(api);
        ProxyLiveMetadataCorrelator.HistorySource source =
                ProxyLiveMetadataCorrelator.newBurpHistorySourceForTest();

        try {
            assertThat(source.lookup(
                            Set.of(TOKEN_A),
                            ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS)
                    .rows)
                    .containsExactly(rowA);
            assertThat(source.lookup(
                            Set.of(TOKEN_B),
                            ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS)
                    .rows)
                    .containsExactly(replacement);
        } finally {
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void appendedHistorySource_readsNewSuffixAfterEstablishedCursor() {
        MontoyaApi api = mock(MontoyaApi.class);
        Proxy proxyApi = mock(Proxy.class);
        when(api.proxy()).thenReturn(proxyApi);
        ProxyHttpRequestResponse rowA = historyRow(
                20,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                1,
                2);
        ProxyHttpRequestResponse rowB = historyRow(
                21,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_B)).value,
                3,
                4);
        when(proxyApi.history())
                .thenReturn(List.of(rowA))
                .thenReturn(List.of(rowA, rowB));
        MontoyaApiProvider.set(api);
        ProxyLiveMetadataCorrelator.HistorySource source =
                ProxyLiveMetadataCorrelator.newBurpHistorySourceForTest();

        try {
            source.lookup(
                    Set.of(TOKEN_A),
                    ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS);

            assertThat(source.lookup(
                            Set.of(TOKEN_B),
                            ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS)
                    .rows)
                    .containsExactly(rowB);
        } finally {
            MontoyaApiProvider.set(null);
        }
    }

    @Test
    void freshMisses_triggerOneAllHistoryRescan() {
        List<ProxyLiveMetadataCorrelator.LookupScope> scopes = new ArrayList<>();
        MutableAnnotations historyAnnotations =
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A));
        ProxyHttpRequestResponse row = historyRow(
                80_030,
                8080,
                historyAnnotations.value,
                1,
                2);
        ProxyLiveMetadataCorrelator.configureForTests(
                (tokens, scope) -> {
                    scopes.add(scope);
                    return ProxyLiveMetadataCorrelator.LookupBatch.success(
                            scope == ProxyLiveMetadataCorrelator.LookupScope.ALL_HISTORY
                                    ? List.of(row)
                                    : List.of());
                },
                document -> {
                    offered.add(document);
                    return true;
                },
                testSpool,
                monotonicNanos::get,
                epochMillis::get,
                () -> TOKEN_A,
                15_000L);
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(30, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(30), live.value, 30, SENT_MS);

        ProxyLiveMetadataCorrelator.runReconciliationForTest();
        monotonicNanos.addAndGet(Duration.ofMillis(25).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();
        monotonicNanos.addAndGet(Duration.ofMillis(100).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(scopes).containsExactly(
                ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS,
                ProxyLiveMetadataCorrelator.LookupScope.APPENDED_ROWS,
                ProxyLiveMetadataCorrelator.LookupScope.ALL_HISTORY);
        assertThat(offered).hasSize(1);
    }

    @Test
    void oneHundredSixtyEightShuffledRows_bindOneToOneWithExactHistoryFields() {
        int exchangeCount = 168;
        List<Map<String, Object>> documents = new ArrayList<>();
        for (int index = 0; index < exchangeCount; index++) {
            String token = token(index + 1);
            int messageId = 20_000 + index;
            MutableAnnotations live = mutableAnnotations("same user note");
            ProxyLiveMetadataCorrelator.registerLiveTokenForTest(
                    messageId, token, 8080, live.value);
            Map<String, Object> document = liveDocument(messageId);
            documents.add(document);
            ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                    document, live.value, messageId, SENT_MS);
            history.add(historyRow(
                    90_000 + index,
                    8080,
                    mutableAnnotations(ProxyCorrelationToken.marker(token)).value,
                    index,
                    index + 1));
        }
        Collections.shuffle(history, new Random(7L));

        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).hasSize(exchangeCount);
        Set<Object> historyIds = new HashSet<>();
        for (int index = 0; index < exchangeCount; index++) {
            Map<String, Object> document = documents.get(index);
            Map<?, ?> proxy = proxy(document);
            Map<?, ?> timing = timing(document);
            assertThat(proxy.keySet().stream().map(String.class::cast).toList())
                    .containsExactlyInAnyOrder(
                    "history_id",
                    "listener_port",
                    "history_is_edited",
                    "request_change_stages",
                    "response_change_stages");
            assertThat(timing.keySet().stream().map(String.class::cast).toList())
                    .containsExactlyInAnyOrder(
                    "req_sent", "end", "req_sent_to_res_start", "req_sent_to_res_end");
            historyIds.add(proxy.get("history_id"));
            assertThat(proxy.get("history_id")).isEqualTo(90_000 + index);
            assertThat(proxy.get("listener_port")).isEqualTo(8080);
            assertThat(proxy.get("history_is_edited")).isEqualTo(false);
            assertThat(proxy.get("request_change_stages")).isNull();
            assertThat(proxy.get("response_change_stages")).isNull();
            assertThat(timing.get("req_sent"))
                    .isEqualTo(java.time.Instant.ofEpochMilli(SENT_MS).toString());
            assertThat(timing.get("end"))
                    .isEqualTo(java.time.Instant.ofEpochMilli(SENT_MS + index + 1L).toString());
            assertThat(timing.get("req_sent_to_res_start")).isEqualTo(index);
            assertThat(timing.get("req_sent_to_res_end")).isEqualTo(index + 1);
            assertThat(((Map<?, ?>) document.get("burp")).get("message_id"))
                    .isEqualTo(20_000 + index);
        }
        assertThat(historyIds).hasSize(exchangeCount);
        assertThat(ProxyLiveMetadataCorrelator.historyLookupAttempts()).isEqualTo(1L);
        assertThat(ProxyLiveMetadataCorrelator.historyLookupMatchedRows())
                .isEqualTo(exchangeCount);
        assertThat(ProxyLiveMetadataCorrelator.boundTotal()).isEqualTo(exchangeCount);
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
    }

    @Test
    void annotationToken_bindsWhenProxyAndHttpHandlersUseDifferentMessageIds() {
        MutableAnnotations annotations = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(11, TOKEN_A, 8080, annotations.value);
        Map<String, Object> document = liveDocument(9_011);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                document,
                annotations.value,
                9_011,
                SENT_MS);
        history.add(historyRow(
                80_011,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                12,
                45));

        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).containsExactly(document);
        assertThat(((Map<?, ?>) document.get("burp")).get("message_id")).isEqualTo(9_011);
        assertThat(historyId(document)).isEqualTo(80_011);
        assertThat(ProxyLiveMetadataCorrelator.explicitFailures()).isZero();
    }

    @Test
    void historyEpochTiming_preservesLiveCallbackTiming() {
        MutableAnnotations annotations = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(11, TOKEN_A, 8080, annotations.value);
        Map<String, Object> document = liveDocument(9_012);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                document,
                annotations.value,
                9_012,
                SENT_MS);
        history.add(historyRowWithEpochTiming(
                80_012,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value));

        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).containsExactly(document);
        assertThat(timing(document).get("req_sent"))
                .isEqualTo(java.time.Instant.ofEpochMilli(SENT_MS).toString());
        assertThat(timing(document).get("end"))
                .isEqualTo(java.time.Instant.ofEpochMilli(SENT_MS + 100L).toString());
        assertThat(timing(document).get("req_sent_to_res_start")).isNull();
        assertThat(timing(document).get("req_sent_to_res_end")).isEqualTo(100L);
    }

    @Test
    void globalHttpRequestMarker_isAuthoritativeForAdmissionAndHistoryBinding() {
        RuntimeConfig.setExportRunning(true);
        try {
            MutableAnnotations annotations = mutableAnnotations("keep");
            ProxyLiveMetadataCorrelator.markHttpRequest(9_021, annotations.value);
            String token = ProxyCorrelationToken.find(annotations.value).orElseThrow();
            Map<String, Object> document = liveDocument(9_021);
            ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                    document,
                    annotations.value,
                    9_021,
                    SENT_MS);
            history.add(historyRow(
                    80_021,
                    8080,
                    mutableAnnotations(ProxyCorrelationToken.marker(token)).value,
                    14,
                    47));

            ProxyLiveMetadataCorrelator.runReconciliationForTest();

            assertThat(offered).containsExactly(document);
            assertThat(historyId(document)).isEqualTo(80_021);
            assertThat(ProxyLiveMetadataCorrelator.httpProxyRequests()).isEqualTo(1L);
            assertThat(ProxyLiveMetadataCorrelator.httpMarkedRequests()).isEqualTo(1L);
            assertThat(ProxyLiveMetadataCorrelator.httpProxyResponses()).isEqualTo(1L);
            assertThat(ProxyLiveMetadataCorrelator.httpUnmarkedTrackedResponses()).isZero();
        } finally {
            RuntimeConfig.setExportRunning(false);
        }
    }

    @Test
    void listenerMismatch_hardRejectsTokenRow() {
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(21, TOKEN_A, 8080, live.value);
        Map<String, Object> document = liveDocument(21);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(document, live.value, 21, SENT_MS);
        history.add(historyRow(
                81_001,
                9090,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                10,
                20));

        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isEqualTo(1);
        assertThat(historyId(document)).isNull();
    }

    @Test
    void lookupFailure_doesNotBecomeNoHistoryDecision() {
        ProxyLiveMetadataCorrelator.configureForTests(
                (ignored, scope) -> ProxyLiveMetadataCorrelator.LookupBatch.failed("test failure"),
                document -> {
                    offered.add(document);
                    return true;
                },
                testSpool,
                monotonicNanos::get,
                epochMillis::get,
                () -> TOKEN_A,
                15_000L);
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(31, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(liveDocument(31), live.value, 31, SENT_MS);

        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isEqualTo(1);
        assertThat(ProxyLiveMetadataCorrelator.lookupFailures()).isGreaterThanOrEqualTo(1L);

        monotonicNanos.addAndGet(Duration.ofSeconds(16).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).hasSize(1);
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
    }

    @Test
    void correlationDeadlineExportsFinalDocumentWithoutHistoryFields() {
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(41, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(liveDocument(41), live.value, 41, SENT_MS);

        monotonicNanos.addAndGet(Duration.ofSeconds(16).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).hasSize(1);
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.pendingDurableCount()).isZero();
        assertThat(historyId(offered.get(0))).isNull();
        assertThat(live.notes.get()).isEmpty();
    }

    @Test
    void correlationDeadline_doesNotRequireDurableSpool() {
        AtomicInteger persistAttempts = new AtomicInteger();
        ProxyCorrelationSpool failingSpool =
                new ProxyCorrelationSpool(tempDir.resolve("failing-spool"), 10_000_000L) {
                    @Override
                    PersistResult persist(StoredEntry entry) {
                        persistAttempts.incrementAndGet();
                        return PersistResult.FAILED;
                    }
                };
        ProxyLiveMetadataCorrelator.configureForTests(
                (tokens, scope) -> ProxyLiveMetadataCorrelator.LookupBatch.success(List.of()),
                document -> {
                    offered.add(document);
                    return true;
                },
                failingSpool,
                monotonicNanos::get,
                epochMillis::get,
                () -> TOKEN_A,
                0L);
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(42, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(42), live.value, 42, SENT_MS);

        monotonicNanos.addAndGet(Duration.ofSeconds(16).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(persistAttempts).hasValue(0);
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(offered).hasSize(1);
    }

    @Test
    void restartRehydratesAndBindsDurableDocument() {
        configure(testSpool, 0L);
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(51, TOKEN_A, 8080, live.value);
        Map<String, Object> document = liveDocument(51);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(document, live.value, 51, SENT_MS);
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        ProxyLiveMetadataCorrelator.dropMemoryForRestartTest();
        ProxyCorrelationSpool recoveredSpool =
                new ProxyCorrelationSpool(tempDir.resolve("correlation"), 10_000_000L);
        configure(recoveredSpool);
        history.add(historyRow(
                82_001,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                13,
                34));
        ProxyLiveMetadataCorrelator.openRun();
        monotonicNanos.addAndGet(Duration.ofMinutes(1).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).hasSize(1);
        assertThat(historyId(offered.get(0))).isEqualTo(82_001);
        assertThat(recoveredSpool.count()).isZero();
    }

    @Test
    void recoveredDurableEntry_usesColdLaneInsteadOfEveryReconciliationPass() {
        configure(testSpool, 0L);
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(52, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(52), live.value, 52, SENT_MS);
        ProxyLiveMetadataCorrelator.runReconciliationForTest();
        ProxyLiveMetadataCorrelator.dropMemoryForRestartTest();
        ProxyCorrelationSpool recoveredSpool =
                new ProxyCorrelationSpool(tempDir.resolve("correlation"), 10_000_000L);
        configure(recoveredSpool);
        ProxyLiveMetadataCorrelator.openRun();

        ProxyLiveMetadataCorrelator.runReconciliationForTest();
        monotonicNanos.addAndGet(Duration.ofSeconds(59).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(ProxyLiveMetadataCorrelator.historyLookupAttempts()).isZero();

        monotonicNanos.addAndGet(Duration.ofSeconds(1).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(ProxyLiveMetadataCorrelator.historyLookupAttempts()).isEqualTo(1L);
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(offered).hasSize(1);
    }

    @Test
    void recoveredColdEntry_doesNotJoinFreshAppendLookup() {
        configure(testSpool, 0L);
        MutableAnnotations stale = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(53, TOKEN_A, 8080, stale.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(53), stale.value, 53, SENT_MS);
        ProxyLiveMetadataCorrelator.runReconciliationForTest();
        ProxyLiveMetadataCorrelator.dropMemoryForRestartTest();
        ProxyCorrelationSpool recoveredSpool =
                new ProxyCorrelationSpool(tempDir.resolve("correlation"), 10_000_000L);
        configure(recoveredSpool);
        ProxyLiveMetadataCorrelator.openRun();
        MutableAnnotations fresh = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(54, TOKEN_B, 8080, fresh.value);
        Map<String, Object> freshDocument = liveDocument(54);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                freshDocument, fresh.value, 54, SENT_MS);
        history.add(historyRow(
                82_054,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_B)).value,
                4,
                5));

        ProxyLiveMetadataCorrelator.runReconciliationForTest();
        monotonicNanos.addAndGet(Duration.ofSeconds(30).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).containsExactly(freshDocument);
        assertThat(ProxyLiveMetadataCorrelator.historyLookupAttempts()).isEqualTo(1L);
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isEqualTo(1);
    }

    @Test
    void unmarkedPreRunResponse_isIgnoredWithoutEnteringEligibilityStats() {
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(61),
                mutableAnnotations("ordinary note").value,
                61,
                null);

        assertThat(offered).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.eligibleTotal()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.explicitFailures()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.httpUnmarkedUntrackedResponses()).isEqualTo(1L);
    }

    @Test
    void unmarkedTrackedResponse_isExplicitFailureWithDiagnosticCounter() {
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(62),
                mutableAnnotations("ordinary note").value,
                62,
                SENT_MS);

        assertThat(offered).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.eligibleTotal()).isEqualTo(1L);
        assertThat(ProxyLiveMetadataCorrelator.explicitFailures()).isEqualTo(1L);
        assertThat(ProxyLiveMetadataCorrelator.httpUnmarkedTrackedResponses()).isEqualTo(1L);
    }

    @Test
    void unknownActiveMarker_isExplicitFailureAndNeverExportsIncompleteDocument() {
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(63),
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                63,
                SENT_MS);

        assertThat(offered).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.explicitFailures()).isEqualTo(1L);
    }

    @Test
    void responseAfterIntakeCloses_isIgnoredWithoutEnteringNextRunStats() {
        MutableAnnotations live = mutableAnnotations("keep");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(63, TOKEN_A, 8080, live.value);

        ProxyLiveMetadataCorrelator.closeIntake();
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(63),
                live.value,
                63,
                SENT_MS);

        assertThat(offered).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.eligibleTotal()).isZero();
        assertThat(live.notes.get()).isEqualTo("keep");
    }

    @Test
    void openRun_resetsSessionCounters() {
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(64),
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                64,
                SENT_MS);
        assertThat(ProxyLiveMetadataCorrelator.explicitFailures()).isEqualTo(1L);

        ProxyLiveMetadataCorrelator.closeAndDrainRun();
        ProxyLiveMetadataCorrelator.openRun();

        assertThat(ProxyLiveMetadataCorrelator.eligibleTotal()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.explicitFailures()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.boundTotal()).isZero();
    }

    @Test
    void closePersistsUnresolvedStateAndClosesRequestOnlyMarkers() {
        MutableAnnotations pendingResponse = mutableAnnotations("");
        MutableAnnotations requestOnly = mutableAnnotations("keep");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(71, TOKEN_A, 8080, pendingResponse.value);
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(72, TOKEN_B, 8080, requestOnly.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(71),
                pendingResponse.value,
                71,
                SENT_MS);

        ProxyLiveMetadataCorrelator.closeAndDrainRun();
        ProxyLiveMetadataCorrelator.awaitPendingPersistenceForTest();

        assertThat(testSpool.count()).isEqualTo(1);
        assertThat(ProxyCorrelationToken.find(pendingResponse.value)).contains(TOKEN_A);
        assertThat(requestOnly.notes.get()).isEqualTo("keep");
        assertThat(offered).isEmpty();
    }

    @Test
    void stopWaitsForAdmittedResponseBeforeRetiringItsMarker() throws Exception {
        MutableAnnotations live = mutableAnnotations("keep");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(73, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.ResponseLease lease =
                ProxyLiveMetadataCorrelator.beginHttpResponse();
        Thread stop = new Thread(
                ProxyLiveMetadataCorrelator::closeAndDrainRun,
                "correlation-stop-test");

        stop.start();
        long waitDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1L);
        while (ProxyLiveMetadataCorrelator.intakeOpenForTest()
                && System.nanoTime() < waitDeadline) {
            Thread.onSpinWait();
        }
        boolean waitingForResponse = stop.isAlive();
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(73), live.value, 73, SENT_MS, lease);
        lease.close();
        stop.join(2_000L);
        ProxyLiveMetadataCorrelator.awaitPendingPersistenceForTest();

        assertThat(waitingForResponse).isTrue();
        assertThat(stop.isAlive()).isFalse();
        assertThat(testSpool.count()).isEqualTo(1);
    }

    @Test
    void stopStart_retainsDurablePendingAndSeedsEligibility() {
        MutableAnnotations live = mutableAnnotations("");
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(74, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                liveDocument(74), live.value, 74, SENT_MS);

        ProxyLiveMetadataCorrelator.closeAndDrainRun();
        ProxyLiveMetadataCorrelator.awaitPendingPersistenceForTest();
        ProxyLiveMetadataCorrelator.openRun();

        assertThat(ProxyLiveMetadataCorrelator.eligibleTotal()).isEqualTo(1L);
        history.add(historyRow(
                83_074,
                8080,
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A)).value,
                7,
                8));
        monotonicNanos.addAndGet(Duration.ofMinutes(1).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).hasSize(1);
        assertThat(historyId(offered.get(0))).isEqualTo(83_074);
        assertThat(testSpool.count()).isZero();
    }

    @Test
    void offerRejection_persistsBoundEntryAndRetriesWithoutDuplicateExport() {
        AtomicInteger offers = new AtomicInteger();
        ProxyLiveMetadataCorrelator.configureForTests(
                (ignored, scope) ->
                        ProxyLiveMetadataCorrelator.LookupBatch.success(List.copyOf(history)),
                document -> {
                    if (offers.incrementAndGet() == 1) {
                        return false;
                    }
                    offered.add(document);
                    return true;
                },
                testSpool,
                monotonicNanos::get,
                epochMillis::get,
                () -> TOKEN_A,
                15_000L);
        MutableAnnotations live = mutableAnnotations("user note");
        MutableAnnotations historyAnnotations =
                mutableAnnotations(ProxyCorrelationToken.marker(TOKEN_A));
        Map<String, Object> document = liveDocument(75);
        ProxyLiveMetadataCorrelator.registerLiveTokenForTest(
                75, TOKEN_A, 8080, live.value);
        ProxyLiveMetadataCorrelator.deferUntilHistoryBound(
                document, live.value, 75, SENT_MS);
        history.add(historyRow(83_075, 8080, historyAnnotations.value, 7, 8));

        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).isEmpty();
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isEqualTo(1);
        assertThat(testSpool.count()).isEqualTo(1L);
        assertThat(ProxyLiveMetadataCorrelator.boundTotal()).isZero();
        assertThat(live.notes).hasValue("user note");
        assertThat(historyAnnotations.notes).hasValue("");

        monotonicNanos.addAndGet(Duration.ofMinutes(1).toNanos());
        ProxyLiveMetadataCorrelator.runReconciliationForTest();

        assertThat(offered).containsExactly(document);
        assertThat(offers).hasValue(2);
        assertThat(ProxyLiveMetadataCorrelator.pendingCountForTest()).isZero();
        assertThat(testSpool.count()).isZero();
        assertThat(ProxyLiveMetadataCorrelator.boundTotal()).isEqualTo(1L);
        assertThat(live.notes).hasValue("user note");
        assertThat(historyAnnotations.notes).hasValue("");
    }

    private void configure(ProxyCorrelationSpool configuredSpool) {
        configure(configuredSpool, 15_000L);
    }

    private void configure(ProxyCorrelationSpool configuredSpool, long durableThresholdMs) {
        ProxyLiveMetadataCorrelator.configureForTests(
                (ignored, scope) -> ProxyLiveMetadataCorrelator.LookupBatch.success(List.copyOf(history)),
                document -> {
                    offered.add(document);
                    return true;
                },
                configuredSpool,
                monotonicNanos::get,
                epochMillis::get,
                () -> TOKEN_A,
                durableThresholdMs);
    }

    private static Map<String, Object> liveDocument(int messageId) {
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy");
        burp.put("message_id", messageId);
        burp.put("proxy", BurpProxyFields.withoutProxyHistoryEditMetadata(null));
        burp.put("timing", BurpTimingFields.fromHandlerEpochMillis(SENT_MS, SENT_MS + 100L));
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("burp", burp);
        document.put("request", Map.of("url", Map.of("raw", "https://same.example/beacon")));
        document.put("response", Map.of("status", Map.of("code", 200)));
        return document;
    }

    private static ProxyHttpRequestResponse historyRow(
            int id,
            int listenerPort,
            Annotations annotations,
            int timeToFirstByteMs,
            int durationMs) {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        ZonedDateTime sent = ZonedDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(SENT_MS),
                ZoneOffset.UTC);
        TimingData timing = mock(TimingData.class);
        when(timing.timeRequestSent()).thenReturn(sent);
        when(timing.timeBetweenRequestSentAndStartOfResponse())
                .thenReturn(Duration.ofMillis(timeToFirstByteMs));
        when(timing.timeBetweenRequestSentAndEndOfResponse())
                .thenReturn(Duration.ofMillis(durationMs));
        when(item.id()).thenReturn(id);
        when(item.listenerPort()).thenReturn(listenerPort);
        when(item.edited()).thenReturn(false);
        when(item.time()).thenReturn(sent);
        when(item.timingData()).thenReturn(timing);
        when(item.annotations()).thenReturn(annotations);
        return item;
    }

    private static ProxyHttpRequestResponse historyRowWithEpochTiming(
            int id,
            int listenerPort,
            Annotations annotations) {
        ProxyHttpRequestResponse item = historyRow(id, listenerPort, annotations, 0, 0);
        TimingData timing = mock(TimingData.class);
        when(timing.timeRequestSent())
                .thenReturn(ZonedDateTime.ofInstant(java.time.Instant.EPOCH, ZoneOffset.UTC));
        when(timing.timeBetweenRequestSentAndStartOfResponse()).thenReturn(Duration.ZERO);
        when(timing.timeBetweenRequestSentAndEndOfResponse()).thenReturn(Duration.ZERO);
        when(item.timingData()).thenReturn(timing);
        return item;
    }

    private static Object historyId(Map<String, Object> document) {
        return proxy(document).get("history_id");
    }

    private static String token(int value) {
        return String.format("00000000-0000-0000-0000-%012d", value);
    }

    private static Map<?, ?> proxy(Map<String, Object> document) {
        return (Map<?, ?>) ((Map<?, ?>) document.get("burp")).get("proxy");
    }

    private static Map<?, ?> timing(Map<String, Object> document) {
        return (Map<?, ?>) ((Map<?, ?>) document.get("burp")).get("timing");
    }

    private static MutableAnnotations mutableAnnotations(String initialNotes) {
        Annotations annotations = mock(Annotations.class);
        AtomicReference<String> notes = new AtomicReference<>(initialNotes);
        when(annotations.hasNotes()).thenAnswer(ignored -> !notes.get().isEmpty());
        when(annotations.notes()).thenAnswer(ignored -> notes.get());
        doAnswer(invocation -> {
            notes.set(invocation.getArgument(0));
            return null;
        }).when(annotations).setNotes(anyString());
        return new MutableAnnotations(annotations, notes);
    }

    private record MutableAnnotations(Annotations value, AtomicReference<String> notes) { }
}
