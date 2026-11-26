package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/** Exercises owned body snapshots, shared capacity and actual asynchronous run cancellation. */
class LiveTrafficPreparationTest {
    @AfterEach
    void cleanup() {
        RuntimeConfig.setExportRunning(false);
        LiveTrafficPreparation.setInlineForTests(false);
        LiveTrafficPreparation.stop();
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        ExportAdmissionController.resetForTests();
    }

    @Test
    void deferredRequestKeepsOriginalBodyAndHeaderValuesWithoutReparsing() {
        byte[] bytes = "one&two".getBytes(StandardCharsets.UTF_8);
        HttpRequest request = request(bytes);
        HttpHeader header = header("Content-Type", "text/plain; charset=UTF-8");
        when(request.headers()).thenReturn(List.of(header));
        var prepared = RequestResponseDocBuilder.prepareTrafficRequest(request);
        assertThat(body(prepared)).doesNotContainKey("b64");
        bytes[0] = 'X';
        when(header.value()).thenReturn("application/octet-stream");
        when(request.body()).thenThrow(new IllegalStateException("callback ended"));
        when(request.headers()).thenThrow(new IllegalStateException("callback ended"));
        prepared.complete();
        assertThat(body(prepared))
                .containsEntry("text", "one&two").containsEntry("b64", "b25lJnR3bw==");
        assertThat(prepared.retainedBodyBytes()).isZero();
    }

    @Test
    void deferredResponseOwnsBodyAndVideoDoesNotMaterializeIt() {
        byte[] bytes = "original".getBytes(StandardCharsets.UTF_8);
        HttpResponse response = response(bytes, "text/plain");
        var prepared = RequestResponseDocBuilder.prepareTrafficResponse(response);
        bytes[0] = 'X';
        when(response.body()).thenThrow(new IllegalStateException("callback ended"));
        prepared.complete();
        assertThat(body(prepared)).containsEntry("text", "original");

        HttpResponse video = response(new byte[0], "video/mp4");
        ByteArray videoBody = mock(ByteArray.class);
        when(videoBody.length()).thenReturn(100_000_000);
        when(videoBody.getBytes()).thenThrow(new AssertionError("video body must not be copied"));
        when(video.body()).thenReturn(videoBody);
        var omitted = RequestResponseDocBuilder.prepareTrafficResponse(video);
        omitted.complete();
        assertThat(body(omitted))
                .containsEntry("omitted", true).containsEntry("length", 100_000_000);
    }

    @Test
    void sharedBudgetRejectsWithoutPartialBodyAndReleasesExactlyOnce() throws Exception {
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));
            ExportAdmissionController.setMemBudgetOverrideForTests(20_000L);
            var message = RequestResponseDocBuilder.prepareTrafficRequest(request(new byte[10_000]));
            Map<String, Object> document = document(message.document());
            var token = RuntimeConfig.currentExportRunToken();
            long failures = ExportStats.getTrafficDropReasonCount("capture_capacity");
            assertThat(LiveTrafficPreparation.retain(document, token, message)).isNull();
            assertThat(ExportStats.getTrafficDropReasonCount("capture_capacity")).isEqualTo(failures + 1);
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(body(message)).doesNotContainKey("b64");
            assertThat(ExportAdmissionController.liveBytesHeld()).isZero();

            ExportAdmissionController.setMemBudgetOverrideForTests(100_000L);
            var capture = LiveTrafficPreparation.retain(document, token, message);
            assertThat(capture).isNotNull();
            ExportAdmissionController.setMemBudgetOverrideForTests(20_000L);
            capture.run();
            assertThat(TrafficExportQueue.getCurrentSpillSize()).isEqualTo(1);
            assertThat(body(message).get("b64")).isNotNull();
            capture.close();
            TrafficExportQueue.clearPendingWork();
            assertThat(ExportAdmissionController.liveBytesHeld()).isZero();

            ExportAdmissionController.setMemBudgetOverrideForTests(100_000L);
            assertThat(ExportAdmissionController.tryReserveLiveBytes(94_900L)).isTrue();
            assertThat(TrafficExportQueue.offerPreparedForTests(
                    ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity.prepare(
                            "tool-burp-traffic", "traffic", document))).isFalse();
            ExportAdmissionController.releaseLiveBytes(94_900L);
            assertThat(ExportAdmissionController.liveBytesHeld()).isZero();
        });
    }

    @Test
    void backgroundPreparationDoesNotHoldSubmitterOrRetainCancelledRun() throws Exception {
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));
            ExportAdmissionController.setMemBudgetOverrideForTests(1_000_000L);
            var token = RuntimeConfig.currentExportRunToken();
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            AtomicBoolean armed = new AtomicBoolean();
            Map<String, Object> document = spy(document(Map.of("method", "GET")));
            doAnswer(invocation -> {
                if (armed.get() && Thread.currentThread().getName().equals("burp-exporter-live-preparation")) {
                    entered.countDown();
                    boolean interrupted = false;
                    while (true) {
                        try {
                            if (release.await(5, TimeUnit.SECONDS)) break;
                            throw new IllegalStateException("Test release timed out");
                        } catch (InterruptedException e) {
                            interrupted = true;
                        }
                    }
                    if (interrupted) Thread.currentThread().interrupt();
                }
                return invocation.callRealMethod();
            }).when(document).entrySet();
            var first = LiveTrafficPreparation.retain(document, token);
            var cancelled = LiveTrafficPreparation.retain(document(Map.of("method", "GET")), token);
            assertThat(first).isNotNull();
            assertThat(cancelled).isNotNull();
            CountDownLatch firstFinished = new CountDownLatch(1);
            first.whenClosed(firstFinished::countDown);
            armed.set(true);
            try {
                assertThat(LiveTrafficPreparation.submit(first)).isTrue();
                assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
                assertThat(LiveTrafficPreparation.submit(cancelled)).isTrue();
                assertThat(LiveTrafficPreparation.isIdle()).isFalse();
                assertThat(TrafficExportQueue.awaitPendingWorkDrained(1L)).isFalse();
                RuntimeConfig.setExportRunning(false);
                LiveTrafficPreparation.stop();
                RuntimeConfig.setExportRunning(true);
                assertThat(LiveTrafficPreparation.submit(LiveTrafficPreparation.retain(
                        document(Map.of("method", "GET")), RuntimeConfig.currentExportRunToken()))).isTrue();
                release.countDown();
                awaitPreparation();
                assertThat(firstFinished.await(2, TimeUnit.SECONDS)).isTrue();
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            } finally {
                release.countDown();
            }
        });
    }

    private static void awaitPreparation() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!LiveTrafficPreparation.isIdle() && System.nanoTime() < deadline) Thread.sleep(5);
        assertThat(LiveTrafficPreparation.isIdle()).isTrue();
    }

    @Test
    void acceptedFirstTaskDoesNotDependOnApproximateExecutorActivity() throws Exception {
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            var owner = new java.util.concurrent.ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                    new java.util.concurrent.ArrayBlockingQueue<>(2), task -> new Thread(() -> {
                        entered.countDown();
                        try {
                            if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Release timed out");
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        task.run();
                    }, "held-preparation-start")) {
                /** {@inheritDoc} */
                @Override
                public int getActiveCount() {
                    // Model a zero activity estimate during the executor's first-task handoff.
                    return 0;
                }
            };
            ai.anomalousvectors.tools.burp.testutils.Reflect.setStatic(LiveTrafficPreparation.class, "executor", owner);
            ai.anomalousvectors.tools.burp.testutils.Reflect.setStatic(LiveTrafficPreparation.class, "executorToken",
                    RuntimeConfig.currentExportRunToken());
            try {
                var capture = LiveTrafficPreparation.retain(document(Map.of("method", "GET")),
                        RuntimeConfig.currentExportRunToken());
                assertThat(LiveTrafficPreparation.submit(capture)).isTrue();
                assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
                assertThat(owner.getQueue()).isEmpty();
                assertThat(owner.getActiveCount()).isZero();
                assertThat(LiveTrafficPreparation.isIdle()).isFalse();
                assertThat(TrafficExportQueue.awaitPendingWorkDrained(1L)).isFalse();
                release.countDown();
                awaitPreparation();
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            } finally {
                release.countDown();
                LiveTrafficPreparation.stop();
                assertThat(owner.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
            }
        });
    }

    @Test
    void compressedBodyReservesActualExpansionAndNeverPublishesAPartialDocument() throws Exception {
        TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
            TrafficExportQueueTestSupport.configureRunningTraffic(List.of("proxy"));
            byte[] original = "compressed payload".repeat(10_000).getBytes(StandardCharsets.UTF_8);
            java.io.ByteArrayOutputStream compressed = new java.io.ByteArrayOutputStream();
            try (var gzip = new java.util.zip.GZIPOutputStream(compressed)) {
                gzip.write(original);
            }
            HttpResponse response = response(compressed.toByteArray(), "text/plain");
            HttpHeader type = header("Content-Type", "text/plain");
            HttpHeader encoding = header("Content-Encoding", "gzip");
            when(response.headers()).thenReturn(List.of(type, encoding));
            var prepared = RequestResponseDocBuilder.prepareTrafficResponse(response);
            Map<String, Object> document = document(Map.of("method", "GET"));
            document.put("response", prepared.document());
            ExportAdmissionController.setMemBudgetOverrideForTests(100_000L);
            var capture = LiveTrafficPreparation.retain(document, RuntimeConfig.currentExportRunToken(), prepared);
            assertThat(capture).isNotNull();
            long previous = ExportStats.getTrafficDropReasonCount("preparation_capacity");
            capture.run();
            assertThat(ExportStats.getTrafficDropReasonCount("preparation_capacity")).isEqualTo(previous + 1);
            assertThat(TrafficExportQueue.getCurrentSize()).isZero();
            assertThat(ExportAdmissionController.liveBytesHeld()).isZero();

            ExportAdmissionController.setMemBudgetOverrideForTests(4_000_000L);
            var retry = RequestResponseDocBuilder.prepareTrafficResponse(response);
            document.put("response", retry.document());
            var accepted = LiveTrafficPreparation.retain(document, RuntimeConfig.currentExportRunToken(), retry);
            assertThat(accepted).isNotNull();
            accepted.run();
            assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            assertThat(body(retry)).containsEntry("text", new String(original, StandardCharsets.UTF_8));
        });
    }

    private static Map<String, Object> document(Map<String, Object> request) {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("burp", Map.of("reporting_tool", "Proxy"));
        document.put("request", request);
        return document;
    }

    private static Map<String, Object> body(RequestResponseDocBuilder.PreparedTrafficMessage message) {
        return ai.anomalousvectors.tools.burp.utils.StringKeyedMaps.nested(
                message.document(), "body", LinkedHashMap::new);
    }

    private static HttpRequest request(byte[] bytes) {
        HttpRequest request = mock(HttpRequest.class);
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(bytes);
        when(request.body()).thenReturn(body);
        when(request.method()).thenReturn("POST");
        when(request.path()).thenReturn("/h2?x=one%26two&x=last");
        when(request.pathWithoutQuery()).thenReturn("/h2");
        when(request.query()).thenReturn("x=one%26two&x=last");
        when(request.httpVersion()).thenReturn("HTTP/2");
        when(request.contentType()).thenReturn(ContentType.NONE);
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.markers()).thenReturn(List.of());
        return request;
    }

    private static HttpResponse response(byte[] bytes, String contentType) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(bytes);
        when(body.length()).thenReturn(bytes.length);
        when(response.body()).thenReturn(body);
        HttpHeader header = header("Content-Type", contentType);
        when(response.headers()).thenReturn(List.of(header));
        when(response.statusCode()).thenReturn((short) 200);
        when(response.mimeType()).thenReturn(MimeType.PLAIN_TEXT);
        when(response.cookies()).thenReturn(List.of());
        when(response.markers()).thenReturn(List.of());
        return response;
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn(name);
        when(header.value()).thenReturn(value);
        return header;
    }
}
