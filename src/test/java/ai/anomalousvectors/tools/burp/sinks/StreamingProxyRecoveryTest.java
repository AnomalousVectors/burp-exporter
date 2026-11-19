package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.ExportLineCodec;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

/** Exercises exact-source ownership, bounded scheduling and immutable stream observations. */
class StreamingProxyRecoveryTest {
    private static final long WALL = 1_800_000_000_000L;
    private final MontoyaApi api = mock(MontoyaApi.class);
    private final Proxy proxy = mock(Proxy.class);
    private final AtomicLong clock = new AtomicLong(1_000L);
    private final List<ProxyHttpRequestResponse> rows = new ArrayList<>();
    private final List<Map<String, Object>> outputs = new ArrayList<>();
    private StreamingProxyRecovery observer;

    @BeforeEach
    void start() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStopping(false);
        RuntimeConfig.updateState(new ConfigState.State(List.of("traffic"), "all", List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        RuntimeConfig.setExportRunning(true);
        when(api.proxy()).thenReturn(proxy);
        when(proxy.history(any(ProxyHistoryFilter.class))).thenAnswer(call -> {
            ProxyHistoryFilter filter = call.getArgument(0);
            List<ProxyHttpRequestResponse> result = new ArrayList<>();
            for (ProxyHttpRequestResponse row : List.copyOf(rows)) {
                if (filter.matches(row)) result.add(row);
            }
            return result;
        });
        observer = new StreamingProxyRecovery(api, RuntimeConfig.currentExportRunToken(), clock::get,
                (document, token) -> { outputs.add(document); return true; }, WALL);
    }

    @AfterEach
    void stop() {
        ExportReporterLifecycle.resetForTests();
    }

    @Test
    void taperAndBudget_useAbsoluteAgeAndMeasuredWholeCallCost() {
        assertThat(StreamingPollPolicy.intervalMs(0L)).isEqualTo(5_000L);
        assertThat(StreamingPollPolicy.intervalMs(29_999L)).isEqualTo(5_000L);
        assertThat(StreamingPollPolicy.intervalMs(30_000L)).isEqualTo(10_000L);
        assertThat(StreamingPollPolicy.intervalMs(119_999L)).isEqualTo(10_000L);
        assertThat(StreamingPollPolicy.intervalMs(120_000L)).isEqualTo(20_000L);
        assertThat(StreamingPollPolicy.intervalMs(180_000L)).isEqualTo(30_000L);
        StreamingPollPolicy policy = new StreamingPollPolicy();
        policy.charge(1_000L, 1_800L);
        assertThat(policy.allowedAt()).isEqualTo(9_000L);
        assertThat(StreamingPollPolicy.intervalMs(0L, 8L * 1024L * 1024L)).isEqualTo(32_000L);
        assertThat(StreamingPollPolicy.intervalMs(0L, 580L)).isEqualTo(5_000L);
    }

    @Test
    void finalReadSharesRemainingTimeWithoutTakingTheDeliveryAndTeardownReserve() {
        assertThat(StreamingPollPolicy.finalReadBudgetMs(20_000L)).isEqualTo(10_000L);
        assertThat(StreamingPollPolicy.finalReadBudgetMs(15_000L)).isEqualTo(7_500L);
        assertThat(StreamingPollPolicy.finalReadBudgetMs(10_000L)).isEqualTo(4_000L);
        assertThat(StreamingPollPolicy.finalReadBudgetMs(6_001L)).isEqualTo(1L);
        assertThat(StreamingPollPolicy.finalReadBudgetMs(6_000L)).isZero();
        assertThat(StreamingPollPolicy.finalReadBudgetMs(1L)).isZero();
        assertThat(StreamingPollPolicy.finalReadBudgetMs(0L)).isZero();
    }

    @Test
    void lateFinalReadCannotPublishAfterItsOwnAllowanceEvenWithSharedStopTimeRemaining()
            throws Exception {
        observer.tick();
        ProxyHttpRequestResponse source = row(1_098, WALL + 100L);
        rows.add(source);
        clock.addAndGet(5_000L);
        observer.tick();
        outputs.clear();
        var deadline = StreamingProxyRecovery.class.getDeclaredField("finalReadDeadline");
        deadline.setAccessible(true);
        deadline.setLong(observer, clock.get() + 100L);
        HttpResponse response = source.originalResponse();
        when(source.originalResponse()).thenAnswer(call -> {
            clock.addAndGet(101L);
            body(response, "data: late tail\n\n");
            return response;
        });
        RuntimeConfig.beginExportStop();
        RuntimeConfig.setExportStopping(true);
        observer.observeFinalSnapshots();
        assertThat(outputs).isEmpty();
        assertThat(RuntimeConfig.remainingExportStopBudgetMs()).isGreaterThan(5_000L);
        assertThat(StreamingProxyRecovery.status()).contains("final_unread=1");
    }

    @Test
    void deferredBodyTracksDecodingHintsAndOffsetAndKeepsPrivateInputsOutOfExport() {
        ProxyHttpRequestResponse source = row(1_097, WALL + 100L);
        HttpResponse response = source.originalResponse();
        var prepared = RequestResponseDocBuilder.prepareTrafficResponse(response);
        String original = SnapshotFingerprint.of(prepared.bodyInputs());
        assertThat(prepared.document().get("body")).isEqualTo(Map.of("markers", List.of()));
        when(response.bodyOffset()).thenReturn(99);
        var moved = RequestResponseDocBuilder.prepareTrafficResponse(response);
        assertThat(SnapshotFingerprint.of(moved.bodyInputs())).isNotEqualTo(original);
        when(response.inferredMimeType()).thenReturn(MimeType.JSON);
        var hinted = RequestResponseDocBuilder.prepareTrafficResponse(response);
        assertThat(SnapshotFingerprint.of(hinted.bodyInputs()))
                .isNotEqualTo(SnapshotFingerprint.of(moved.bodyInputs()));
        prepared.complete();
        Map<String, Object> completed = new java.util.LinkedHashMap<>(prepared.document());
        prepared.complete();
        assertThat(prepared.document()).isEqualTo(completed);
        assertThat(((Map<?, ?>) completed.get("body")).keySet().stream().map(String::valueOf).toList())
                .contains("b64", "text", "markers").doesNotContain("sha256", "hints");
    }

    @Test
    void unchangedResponseSkipsBodyPreparationButMetadataAndSameLengthChangesDoNot() {
        observer.tick();
        ProxyHttpRequestResponse source = row(98, WALL + 100L);
        rows.add(source);
        HttpResponse response = source.originalResponse();
        try (var bodies = org.mockito.Mockito.mockStatic(HttpMessageDocSupport.class,
                org.mockito.Mockito.CALLS_REAL_METHODS)) {
            for (int i = 0; i < 3; i++) {
                clock.addAndGet(5_000L);
                observer.tick();
            }
            assertThat(outputs).hasSize(1);
            bodies.verify(() -> HttpMessageDocSupport.buildBodyContent(
                    org.mockito.ArgumentMatchers.any(byte[].class), any(), any(),
                    org.mockito.ArgumentMatchers.anyBoolean(), org.mockito.ArgumentMatchers.anyInt(),
                    org.mockito.ArgumentMatchers.eq(false)), org.mockito.Mockito.times(1));
            when(source.annotations().notes()).thenReturn("updated user notes");
            clock.addAndGet(5_000L);
            observer.tick();
            when(response.reasonPhrase()).thenReturn("Changed metadata");
            clock.addAndGet(5_000L);
            observer.tick();
            body(response, "data: b\n\n");
            clock.addAndGet(5_000L);
            observer.tick();
            assertThat(outputs).hasSize(4);
            assertThat(bodyDoc(outputs.get(0)).get("b64"))
                    .isEqualTo(bodyDoc(outputs.get(2)).get("b64"))
                    .isNotEqualTo(bodyDoc(outputs.get(3)).get("b64"));
            assertThat(capture(outputs.getLast()).get("revision")).isEqualTo(4L);
            verify(source.annotations(), never()).setNotes(any(String.class));
        }
    }

    @Test
    void slowFinalReadBeyondOneSecondStillPublishesAndLeavesDeliveryTime() throws Exception {
        ProxyHttpRequestResponse source = row(99, System.currentTimeMillis() + 100L);
        HttpResponse response = source.originalResponse();
        when(source.originalResponse()).thenAnswer(call -> {
            if (RuntimeConfig.isExportStopping()) {
                Thread.sleep(1_200L);
                body(response, "data: final tail\n\n");
            }
            return response;
        });
        rows.add(source);
        MontoyaApiProvider.set(api);
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            StreamingProxyRecovery.start();
            long initialDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3L);
            while (TrafficExportQueue.getCurrentSize() == 0 && System.nanoTime() < initialDeadline) {
                Thread.sleep(10L);
            }
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            RuntimeConfig.beginExportStop();
            RuntimeConfig.setExportStopping(true);
            StreamingProxyRecovery.stop();
            assertThat(StreamingProxyRecovery.status()).contains("final_unread=0", "snapshots=2");
            assertThat(RuntimeConfig.remainingExportStopBudgetMs()).isGreaterThan(5_000L);
        });
    }

    @Test
    void forcedStopInterruptsFinalWaitAndOldReadCannotPublishIntoRestart() throws Exception {
        var initial = new java.util.concurrent.CountDownLatch(1);
        var held = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var returned = new java.util.concurrent.CountDownLatch(1);
        ProxyHttpRequestResponse source = row(1_099, System.currentTimeMillis() + 100L);
        HttpResponse response = source.originalResponse();
        when(source.originalResponse()).thenAnswer(call -> {
            if (RuntimeConfig.isExportStopping()) {
                held.countDown();
                boolean released = false;
                while (!released) {
                    try { released = release.await(5L, java.util.concurrent.TimeUnit.SECONDS); }
                    catch (InterruptedException ignored) { /* Simulate a non-cooperative Burp read. */ }
                }
                returned.countDown();
            } else initial.countDown();
            return response;
        });
        rows.add(source);
        MontoyaApiProvider.set(api);
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            StreamingProxyRecovery.start();
            assertThat(initial.await(3L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            RuntimeConfig.beginExportStop();
            RuntimeConfig.setExportStopping(true);
            Thread owner = new Thread(() -> {
                RuntimeConfig.beginExportStopWorker(Thread.currentThread());
                try { StreamingProxyRecovery.stop(); }
                finally { RuntimeConfig.endExportStopWorker(Thread.currentThread()); }
            });
            owner.start();
            try {
                assertThat(held.await(3L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
                RuntimeConfig.requestExportStopForceAbort();
                owner.join(2_000L);
                assertThat(owner.isAlive()).isFalse();
                int admitted = TrafficExportQueue.getCurrentSize();
                RuntimeConfig.setExportRunning(false);
                RuntimeConfig.setExportStopping(false);
                RuntimeConfig.setExportRunning(true);
                String stopped = StreamingProxyRecovery.status();
                release.countDown();
                assertThat(returned.await(2L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
                var oldWorker = ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek(
                        StreamingProxyRecovery.class, "SCHEDULER");
                assertThat(oldWorker).isNull();
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(admitted);
                assertThat(StreamingProxyRecovery.status()).isEqualTo(stopped);
            } finally {
                release.countDown();
                owner.join(2_000L);
            }
        });
    }

    @Test
    void finalPassRefreshesEveryDueSmallStreamBeyondTheOrdinaryWorkSlice() {
        observer.tick();
        for (int i=0; i<32; i++) rows.add(row(1_000+i, WALL+100L));
        clock.addAndGet(5_000L);
        observer.tick();
        outputs.clear();
        for (ProxyHttpRequestResponse row : rows) {
            HttpResponse response = row.originalResponse();
            body(response, "data: complete\n\n");
            when(row.originalResponse()).thenAnswer(call -> { clock.addAndGet(10L); return response; });
        }
        RuntimeConfig.beginExportStop();
        RuntimeConfig.setExportStopping(true);
        // Match the actual UI lifecycle: accepted work still owns the valid run token.
        observer.observeFinalSnapshots();
        assertThat(outputs).hasSize(32);
        assertThat(outputs).allSatisfy(document -> {
            assertThat(capture(document).get("observation_state")).isEqualTo("stopped");
            assertThat(bodyDoc(document).get("length")).isEqualTo(16);
        });
        assertThat(StreamingProxyRecovery.status()).contains("final_unread=0");
    }

    @Test
    void grpcStatusAvailabilityIsExplicitWithoutInferringSuccessFromHttp200() {
        observer.tick();
        ProxyHttpRequestResponse source = row(95, WALL + 100L);
        rows.add(source);
        clock.addAndGet(5_000L);
        observer.tick();
        HttpResponse response = source.originalResponse();
        when(response.headerValue("Content-Type")).thenReturn("application/grpc");
        body(response, "message-one");
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(capture(outputs.getLast()).get("grpc_status_state")).isEqualTo("not_observed");
        when(response.headerValue("grpc-status")).thenReturn("7");
        body(response, "message-two");
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(capture(outputs.getLast()).get("grpc_status_state")).isEqualTo("observed");
    }

    @Test
    void grpcHeaderOnlyStatusChangePublishesWithTheSameResponseBytes() {
        observer.tick();
        ProxyHttpRequestResponse source = row(1_101, WALL + 100L);
        rows.add(source);
        clock.addAndGet(5_000L);
        observer.tick();
        HttpResponse response = source.originalResponse();
        HttpHeader type = mock(HttpHeader.class);
        when(type.name()).thenReturn("Content-Type");
        when(type.value()).thenReturn("application/grpc+proto");
        when(response.headers()).thenReturn(List.of(type));
        when(response.headerValue("Content-Type")).thenReturn("application/grpc+proto");
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(capture(outputs.getLast()).get("grpc_status_state")).isEqualTo("not_observed");
        Map<?, ?> originalBody = bodyDoc(outputs.getLast());
        HttpHeader status = mock(HttpHeader.class);
        when(status.name()).thenReturn("grpc-status");
        when(status.value()).thenReturn("7");
        when(response.headers()).thenReturn(List.of(type, status));
        when(response.headerValue("grpc-status")).thenReturn("7");
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(3);
        assertThat(capture(outputs.getLast()).get("grpc_status_state")).isEqualTo("observed");
        assertThat(bodyDoc(outputs.getLast())).isEqualTo(originalBody);
        Map<?, ?> exportedResponse = (Map<?, ?>) outputs.getLast().get("response");
        assertThat(exportedResponse.get("headers").toString()).contains("grpc-status", "7");
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(3);
    }

    @Test
    void newSmallExchangeGetsATurnBeforePreviouslyReadExpensiveExchange() {
        observer.tick();
        ProxyHttpRequestResponse expensive = row(96, WALL + 100L);
        rows.add(expensive);
        clock.addAndGet(5_000L);
        observer.tick();
        HttpResponse response = expensive.originalResponse();
        when(expensive.originalResponse()).thenAnswer(call -> { clock.addAndGet(110L); return response; });
        rows.add(row(97, WALL + 5_001L));
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(burp(outputs.getLast()).get("message_id")).isEqualTo(97);
    }

    @Test
    void ownedInitializationFailureRemainsVisibleInStatus() throws Exception {
        when(proxy.history(any(ProxyHistoryFilter.class))).thenThrow(new IllegalStateException("unavailable"));
        MontoyaApiProvider.set(api);
        StreamingProxyRecovery.start();
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3L);
        while (!StreamingProxyRecovery.status().contains("failures=1") && System.nanoTime() < deadline) {
            Thread.sleep(10L);
        }
        assertThat(StreamingProxyRecovery.status()).contains("failures=1", "snapshots=0");
    }

    @Test
    void actualUiStopCallsFinalReadWhileKeepingAcceptedRunAlive() throws Exception {
        var firstRead = new java.util.concurrent.CountDownLatch(1);
        var finalRead = new java.util.concurrent.CountDownLatch(1);
        ProxyHttpRequestResponse source = row(94, System.currentTimeMillis() + 100L);
        HttpResponse response = source.originalResponse();
        when(source.originalResponse()).thenAnswer(call -> {
            if (RuntimeConfig.isExportStopping()) finalRead.countDown(); else firstRead.countDown();
            return response;
        });
        rows.add(source);
        MontoyaApiProvider.set(api);
        var stopOwner = new java.util.concurrent.atomic.AtomicReference<java.util.concurrent.CompletableFuture<Void>>();
        var button = new java.util.concurrent.atomic.AtomicReference<javax.swing.JButton>();
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            StreamingProxyRecovery.start();
            assertThat(firstRead.await(3L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                var controls = new ai.anomalousvectors.tools.burp.ui.ConfigControlPanel(
                        new javax.swing.JTextArea(), new javax.swing.JPanel(), new javax.swing.JTextArea(),
                        new javax.swing.JPanel(), 30, 15, area -> { }, () -> { }, () -> { },
                        callbacks -> { }, callbacks -> {
                            assertThat(RuntimeConfig.currentExportRunToken().isValid()).isTrue();
                            stopOwner.set(java.util.concurrent.CompletableFuture.runAsync(StreamingProxyRecovery::stop));
                        }).build();
                button.set(findStopButton(controls));
                button.get().doClick();
            });
            javax.swing.SwingUtilities.invokeAndWait(() -> { });
            stopOwner.get().get(3L, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(finalRead.getCount()).isZero();
            assertThat(StreamingProxyRecovery.status()).contains("final_unread=0");
        });
    }

    private static javax.swing.JButton findStopButton(java.awt.Container container) {
        for (java.awt.Component child : container.getComponents()) {
            if (child instanceof javax.swing.JButton button && "control.startStop".equals(button.getName())) return button;
            if (child instanceof java.awt.Container nested) {
                javax.swing.JButton found = findStopButton(nested);
                if (found != null) return found;
            }
        }
        return null;
    }

    @Test
    void baselineAndAbsoluteWindow_excludeOldImportedAndExpiredRows() {
        ProxyHttpRequestResponse old = row(1, WALL - 1_000L);
        rows.add(old);
        observer.tick();
        clock.addAndGet(5_000L);
        rows.add(row(2, WALL + 1_000L));
        observer.tick();
        assertThat(outputs).hasSize(1);
        assertThat(burp(outputs.getFirst()).get("message_id")).isEqualTo(2);
        clock.set(305_000L);
        observer.tick();
        observer.tick();
        assertThat(outputs).hasSize(1);
        verify(old, never()).originalResponse();
    }

    @Test
    void growingAndSameLengthChangedBodies_getOrderedIndependentSnapshots() throws Exception {
        observer.tick();
        ProxyHttpRequestResponse row = row(3, WALL + 100L);
        rows.add(row);
        clock.addAndGet(5_000L);
        observer.tick();
        HttpResponse response = row.originalResponse();
        body(response, "data: b\n\n");
        clock.addAndGet(5_000L);
        observer.tick();
        body(response, "data: b\n\ndata: c\n\n");
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(3);
        assertThat(bodyDoc(outputs.get(0)).get("b64")).isNotEqualTo(bodyDoc(outputs.get(1)).get("b64"));
        assertThat(bodyDoc(outputs.get(2)).get("length")).isEqualTo(18);
        assertThat(capture(outputs.get(0)).get("id")).isEqualTo(capture(outputs.get(1)).get("id"));
        assertThat(capture(outputs.get(0)).get("revision")).isEqualTo(1L);
        assertThat(capture(outputs.get(1)).get("revision")).isEqualTo(2L);
        assertThat(capture(outputs.get(1)).get("response_state")).isEqualTo("observed_completion_unknown");
        var first = ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", outputs.get(0));
        var second = ExportDocumentIdentity.prepare("tool-burp-traffic", "traffic", outputs.get(1));
        assertThat(first.operationId()).isNotEqualTo(second.operationId());
        assertThat(ExportLineCodec.jsonDocumentLine(first.document())).contains("proxy_history_stream", "revision");
        assertThat(ExportLineCodec.bulkNdjsonLines(second).getFirst()).contains(second.operationId());
        var fitted = ExportDocumentIdentity.reprepareDerived(first, first.document());
        assertThat(fitted.operationId()).isEqualTo(first.operationId()).isNotEqualTo(second.operationId());
    }

    @Test
    void unchangedObservation_doesNotRepeatButQuietDoesNotSeal() {
        observer.tick();
        ProxyHttpRequestResponse row = row(4, WALL + 100L);
        rows.add(row);
        clock.addAndGet(5_000L);
        observer.tick();
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(1);
        clock.set(190_000L);
        when(row.originalResponse().reasonPhrase()).thenReturn("Later bytes");
        observer.tick();
        assertThat(outputs).hasSize(2);
        clock.set(305_000L);
        when(row.originalResponse().reasonPhrase()).thenReturn("Outside window");
        observer.tick();
        assertThat(outputs).hasSize(2);
    }

    @Test
    void identicalConcurrentRows_remainSeparateAndOwnTheirListenerPorts() {
        observer.tick();
        ProxyHttpRequestResponse first = row(5, WALL + 100L);
        ProxyHttpRequestResponse second = row(6, WALL + 100L);
        when(second.listenerPort()).thenReturn(9090);
        rows.addAll(List.of(first, second));
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(2);
        assertThat(capture(outputs.get(0)).get("id")).isNotEqualTo(capture(outputs.get(1)).get("id"));
        Map<?, ?> firstProxy = (Map<?, ?>) burp(outputs.get(0)).get("proxy");
        Map<?, ?> secondProxy = (Map<?, ?>) burp(outputs.get(1)).get("proxy");
        assertThat(firstProxy.get("listener_port")).isEqualTo(8080);
        assertThat(secondProxy.get("listener_port")).isEqualTo(9090);
        verify(first.annotations(), never()).setNotes(any(String.class));
        verify(first.annotations(), never()).withNotes(any(String.class));
        verify(second.annotations(), never()).setNotes(any(String.class));
        verify(second.annotations(), never()).withNotes(any(String.class));
    }

    @Test
    void noResponseThenDelayedHeaders_neverInventsAnOriginalResponse() {
        observer.tick();
        ProxyHttpRequestResponse row = row(7, WALL + 100L);
        HttpResponse response = row.originalResponse();
        when(row.mimeType()).thenReturn(MimeType.NONE);
        when(row.hasResponse()).thenReturn(false);
        when(row.originalResponse()).thenReturn(null);
        rows.add(row);
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).isEmpty();
        clock.set(70_000L);
        when(row.mimeType()).thenReturn(MimeType.SSE);
        when(row.hasResponse()).thenReturn(true);
        when(row.originalResponse()).thenReturn(response);
        observer.tick();
        assertThat(outputs).hasSize(1);
    }

    @Test
    void ordinaryResponses_areClassifiedWithoutBuildingOrDuplicatingTheirBodies() {
        observer.tick();
        ProxyHttpRequestResponse row = row(8, WALL + 100L);
        when(row.mimeType()).thenReturn(MimeType.JSON);
        HttpResponse response = row.originalResponse();
        when(response.headerValue("Content-Type")).thenReturn("application/json");
        rows.add(row);
        clock.addAndGet(5_000L);
        observer.tick();
        observer.tick();
        assertThat(outputs).isEmpty();
        verify(response, never()).body();
    }

    @Test
    void initiallyPendingOrdinaryRowsReleaseTrackingCapacityWithoutBodyReads() {
        observer.tick();
        ProxyHttpRequestResponse pending = row(85, WALL + 100L);
        when(pending.mimeType()).thenReturn(MimeType.NONE);
        when(pending.hasResponse()).thenReturn(false);
        rows.add(pending);
        clock.addAndGet(5_000L);
        observer.tick();
        when(pending.hasResponse()).thenReturn(true);
        when(pending.mimeType()).thenReturn(MimeType.JSON);
        HttpResponse response = pending.originalResponse();
        when(response.headerValue("Content-Type")).thenReturn("application/json");
        clock.addAndGet(5_000L);
        observer.tick();
        for (int id = 0; id < 256; id++) rows.add(row(200 + id, WALL + 100L));
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(256);
        verify(response, never()).body();
    }

    @Test
    void declaredSseOverridesUnrecognizedOrMisleadingInferredHistoryMime() {
        observer.tick();
        ProxyHttpRequestResponse unrecognized = row(87, WALL + 100L);
        when(unrecognized.mimeType()).thenReturn(MimeType.UNRECOGNIZED);
        ProxyHttpRequestResponse inferredJson = row(88, WALL + 100L);
        when(inferredJson.mimeType()).thenReturn(MimeType.JSON);
        when(inferredJson.originalResponse().headerValue("Content-Type"))
                .thenReturn("Text/Event-Stream; charset=utf-8");
        rows.addAll(List.of(unrecognized, inferredJson));
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(2);
    }

    @Test
    void responsePresentOutOfScopeRowsReleaseCapacityWithoutAcquiringResponses() {
        ConfigState.State state = RuntimeConfig.getState();
        RuntimeConfig.updateState(new ConfigState.State(state.dataSources(), "burp", List.of(),
                state.sinks(), ConfigState.DEFAULT_SETTINGS_SUB, List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES, null));
        observer.tick();
        ProxyHttpRequestResponse excluded = row(90, WALL + 100L);
        rows.add(excluded);
        clock.addAndGet(5_000L);
        observer.tick();
        verify(excluded, never()).originalResponse();
        for (int id = 0; id < 256; id++) {
            ProxyHttpRequestResponse included = row(500 + id, WALL + 100L);
            when(included.finalRequest().isInScope()).thenReturn(true);
            rows.add(included);
        }
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(256);
    }

    @Test
    void concurrentStopHasOneFinalReadOwner() throws Exception {
        var responseRead = new java.util.concurrent.CountDownLatch(1);
        var finalRead = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        ProxyHttpRequestResponse row = row(91, System.currentTimeMillis() + 100L);
        HttpResponse response = row.originalResponse();
        when(row.originalResponse()).thenAnswer(call -> {
            if (RuntimeConfig.isExportStopping()) {
                finalRead.countDown();
                assertThat(release.await(2L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            } else {
                responseRead.countDown();
            }
            return response;
        });
        rows.add(row);
        MontoyaApiProvider.set(api);
        StreamingProxyRecovery.start();
        assertThat(responseRead.await(2L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        RuntimeConfig.beginExportStop();
        RuntimeConfig.setExportStopping(true);
        RuntimeConfig.invalidateExportRun();
        var owner = java.util.concurrent.CompletableFuture.runAsync(StreamingProxyRecovery::stop);
        try {
            assertThat(finalRead.await(2L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            var concurrent = java.util.concurrent.CompletableFuture.runAsync(StreamingProxyRecovery::stop);
            concurrent.get(500L, java.util.concurrent.TimeUnit.MILLISECONDS);
        } finally {
            release.countDown();
        }
        owner.get(2L, java.util.concurrent.TimeUnit.SECONDS);
        assertThat(ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek(
                StreamingProxyRecovery.class, "SCHEDULER")).isNull();
    }

    @Test
    void classifiedStreamWithoutResponseDoesNotExportAProvisionalHeldRequest() {
        observer.tick();
        ProxyHttpRequestResponse pending = row(86, WALL + 100L);
        when(pending.hasResponse()).thenReturn(false);
        when(pending.originalResponse()).thenReturn(null);
        rows.add(pending);
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).isEmpty();
    }

    @Test
    void incompleteLengthIsNotConfusedWithCompletionAndEncodedLengthsRemainUnknown() {
        observer.tick();
        ProxyHttpRequestResponse row = row(80, WALL + 100L);
        when(row.originalResponse().headerValue("Content-Length")).thenReturn("231");
        rows.add(row);
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(capture(outputs.getFirst()).get("response_state")).isEqualTo("incomplete_declared_length");
        when(row.originalResponse().headerValue("Content-Encoding")).thenReturn("gzip");
        // A changed header is part of the snapshot; use a changed body to exercise this mock view.
        body(row.originalResponse(), "data: encoded\n\n");
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(capture(outputs.getLast()).get("response_state")).isEqualTo("observed_completion_unknown");
    }

    @Test
    void queueRejectionDoesNotAdvanceSnapshotRevisionOrSuppressRetryObservation() {
        AtomicLong attempts = new AtomicLong();
        observer = new StreamingProxyRecovery(api, RuntimeConfig.currentExportRunToken(), clock::get,
                (document, token) -> {
                    outputs.add(document);
                    return attempts.incrementAndGet() > 1L;
                }, WALL);
        observer.tick();
        rows.add(row(81, WALL + 100L));
        clock.addAndGet(5_000L);
        observer.tick();
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(2);
        assertThat(capture(outputs.getFirst()).get("revision")).isEqualTo(1L);
        assertThat(capture(outputs.getLast()).get("revision")).isEqualTo(1L);
    }

    @Test
    void delayedExpensiveReadCannotPublishAfterRunInvalidation() {
        observer.tick();
        ProxyHttpRequestResponse row = row(82, WALL + 100L);
        HttpResponse response = row.originalResponse();
        when(row.originalResponse()).thenAnswer(call -> {
            RuntimeConfig.invalidateExportRun();
            return response;
        });
        rows.add(row);
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).isEmpty();
    }

    @Test
    void nonCooperativeReadCrossingTheFiveMinuteDeadlineCannotPublishLateBytes() {
        observer.tick();
        ProxyHttpRequestResponse row = row(89, WALL + 100L);
        HttpResponse response = row.originalResponse();
        when(row.originalResponse()).thenAnswer(call -> {
            clock.set(302_000L);
            return response;
        });
        rows.add(row);
        clock.set(300_000L);
        observer.tick();
        assertThat(outputs).isEmpty();
    }

    @Test
    void expensivePublicReadDefersFurtherScansInsteadOfStartingMoreWorkers() {
        observer.tick();
        ProxyHttpRequestResponse row = row(83, WALL + 100L);
        HttpResponse response = row.originalResponse();
        when(row.originalResponse()).thenAnswer(call -> {
            clock.addAndGet(800L);
            return response;
        });
        rows.add(row);
        clock.set(6_000L);
        observer.tick();
        clock.set(7_000L);
        observer.tick();
        verify(proxy, org.mockito.Mockito.times(2)).history(any(ProxyHistoryFilter.class));
        clock.set(14_000L);
        observer.tick();
        verify(proxy, org.mockito.Mockito.times(3)).history(any(ProxyHistoryFilter.class));
    }

    @Test
    void finalQueueAdmissionRequiresExactStoppingRunAndLiveOwner() throws Exception {
        observer.tick();
        rows.add(row(84, WALL + 100L));
        clock.addAndGet(5_000L);
        observer.tick();
        Map<String, Object> document = outputs.getFirst();
        var token = RuntimeConfig.currentExportRunToken();
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            assertThat(TrafficExportQueue.offerStreamingObservationForRun(document, token, () -> false)).isFalse();
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            RuntimeConfig.beginExportStop();
            RuntimeConfig.setExportStopping(true);
            RuntimeConfig.invalidateExportRun();
            assertThat(TrafficExportQueue.offerStreamingObservationForRun(document, token, () -> true)).isTrue();
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            RuntimeConfig.requestExportStopForceAbort();
            assertThat(TrafficExportQueue.offerStreamingObservationForRun(document, token, () -> true)).isFalse();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStopping(false);
            RuntimeConfig.setExportRunning(true);
            assertThat(TrafficExportQueue.offerStreamingObservationForRun(document, token, () -> true)).isFalse();
        });
    }

    @Test
    void oldRunCannotPublishIntoLaterRun() {
        observer.tick();
        rows.add(row(9, WALL + 100L));
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportRunning(true);
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).isEmpty();
    }

    @Test
    void capacityIsBoundedAndNoOldCaptureIsEvictedToAdmitNewRows() {
        observer.tick();
        for (int id = 0; id < 300; id++) rows.add(row(100 + id, WALL + 100L));
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(256);
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(256);
    }

    @Test
    void readFailureDoesNotPreventOtherStreams() {
        observer.tick();
        ProxyHttpRequestResponse broken = row(10, WALL + 100L);
        when(broken.originalResponse()).thenThrow(new IllegalStateException("synthetic"));
        rows.add(broken);
        rows.add(row(11, WALL + 100L));
        clock.addAndGet(5_000L);
        observer.tick();
        assertThat(outputs).hasSize(1);
    }

    @Test
    void publicLifecycleClosesActualWorkerAndCallbacksCannotRecreateIt() throws Exception {
        MontoyaApiProvider.set(api);
        StreamingProxyRecovery.start();
        var worker = ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek(
                StreamingProxyRecovery.class, "SCHEDULER");
        assertThat(worker).isNotNull();
        StreamingProxyRecovery.stop();
        assertThat(worker.awaitTermination(2L, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        StreamingProxyRecovery.requestObserved();
        assertThat(ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek(
                StreamingProxyRecovery.class, "SCHEDULER")).isNull();
    }

    private ProxyHttpRequestResponse row(int id, long received) {
        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("example.test");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://example.test/sse");
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/sse");
        when(request.pathWithoutQuery()).thenReturn("/sse");
        when(request.httpService()).thenReturn(service);
        when(request.httpVersion()).thenReturn("HTTP/2");
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/2");
        when(response.headerValue("Content-Type")).thenReturn("text/event-stream");
        body(response, "data: a\n\n");
        ProxyHttpRequestResponse row = mock(ProxyHttpRequestResponse.class);
        when(row.id()).thenReturn(id);
        when(row.time()).thenReturn(Instant.ofEpochMilli(received).atZone(ZoneOffset.UTC));
        when(row.finalRequest()).thenReturn(request);
        when(row.httpService()).thenReturn(service);
        when(row.originalResponse()).thenReturn(response);
        when(row.hasResponse()).thenReturn(true);
        when(row.mimeType()).thenReturn(MimeType.SSE);
        when(row.listenerPort()).thenReturn(8080);
        Annotations annotations = mock(Annotations.class);
        when(annotations.notes()).thenReturn("user or automation notes");
        when(annotations.hasNotes()).thenReturn(true);
        when(row.annotations()).thenReturn(annotations);
        return row;
    }

    private static Map<?, ?> burp(Map<String, Object> document) {
        return (Map<?, ?>) document.get("burp");
    }

    private static Map<?, ?> capture(Map<String, Object> document) {
        return (Map<?, ?>) ((Map<?, ?>) document.get("meta")).get("capture");
    }

    private static Map<?, ?> bodyDoc(Map<String, Object> document) {
        return (Map<?, ?>) ((Map<?, ?>) document.get("response")).get("body");
    }

    private static void body(HttpResponse response, String text) {
        byte[] content = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.getBytes()).thenReturn(content);
        when(bytes.length()).thenReturn(content.length);
        when(response.body()).thenReturn(bytes);
        when(response.toByteArray()).thenReturn(bytes);
        when(response.bodyOffset()).thenReturn(0);
    }
}
