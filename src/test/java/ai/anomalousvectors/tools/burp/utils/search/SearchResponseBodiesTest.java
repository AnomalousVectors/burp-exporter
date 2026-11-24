package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CompletableFuture;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.apache.hc.core5.http.nio.AsyncRequestProducer;
import org.apache.hc.core5.http.nio.AsyncResponseConsumer;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.io.ModalCloseable;
import org.junit.jupiter.api.Test;

class SearchResponseBodiesTest {

    @Test
    void bulkBudgetScalesByItemCountWithoutOverflow() {
        assertThat(SearchResponseBodies.bulkLimit(-1)).isEqualTo(1024 * 1024);
        assertThat(SearchResponseBodies.bulkLimit(100)).isEqualTo(100 * 16 * 1024);
        assertThat(SearchResponseBodies.bulkLimit(Integer.MAX_VALUE)).isEqualTo(16 * 1024 * 1024);
    }

    @Test
    void classicPreservesDeclaredCharsetAndAcceptsExactLimit() throws Exception {
        try (var response = new BasicClassicHttpResponse(200)) {
            response.setEntity(new StringEntity("caf\u00e9", ContentType.create("text/plain", StandardCharsets.ISO_8859_1)));
            assertThat(SearchResponseBodies.read(response, 4)).isEqualTo("caf\u00e9");
        }
    }

    @Test
    void classicRejectsDeclaredOversizeBeforeReadingAndAbortsConnection() throws Exception {
        CountingBody input = new CountingBody(1024);
        ClassicHttpResponse response = response(200, input, 1024);
        assertThatThrownBy(() -> SearchResponseBodies.read(response, 32))
                .isInstanceOf(IOException.class).hasMessageContaining("32-byte reply budget");
        assertThat(input.read).isZero();
        verify((ModalCloseable) response).close(CloseMode.IMMEDIATE);
    }

    @Test
    void classicCountsUnknownOrFalseLengthsBeforeAnyUnboundedAllocation() throws Exception {
        for (long declared : new long[] {-1, 1}) {
            CountingBody input = new CountingBody(64L * 1024 * 1024);
            ClassicHttpResponse response = response(200, input, declared);
            assertThatThrownBy(() -> SearchResponseBodies.read(response, 1024))
                    .isInstanceOf(IOException.class);
            assertThat(input.read).isEqualTo(1025);
            verify((ModalCloseable) response).close(CloseMode.IMMEDIATE);
        }
    }

    @Test
    void classicErrorKeepsStatusAndSmallMarkedPreviewThenAbortsRemainder() throws Exception {
        CountingBody input = new CountingBody(64L * 1024 * 1024);
        ClassicHttpResponse response = response(429, input, -1);
        String preview = SearchResponseBodies.read(response);
        assertThat(preview).startsWith("x").endsWith("[Database response preview truncated]");
        assertThat(preview.length()).isLessThan(SearchResponseBodies.ERROR_PREVIEW_BYTES + 100);
        assertThat(response.getCode()).isEqualTo(429);
        assertThat(input.read).isEqualTo(SearchResponseBodies.ERROR_PREVIEW_BYTES + 1);
        verify((ModalCloseable) response).close(CloseMode.IMMEDIATE);
    }

    @Test
    void interruptedClassicReadAbortsRatherThanDrainingDuringCleanup() throws Exception {
        InputStream input = new InputStream() {
            @Override public int read() throws IOException {
                throw new java.io.InterruptedIOException("test interruption");
            }
        };
        ClassicHttpResponse response = response(200, input, -1);
        assertThatThrownBy(() -> SearchResponseBodies.read(response, 1024))
                .isInstanceOf(java.io.InterruptedIOException.class).hasMessage("test interruption");
        verify((ModalCloseable) response).close(CloseMode.IMMEDIATE);
    }

    @Test
    void legacyReaderIsBoundedAndLeavesOwnershipWithCaller() throws Exception {
        CountingBody input = new CountingBody(SearchResponseBodies.METADATA_LIMIT_BYTES + 100L);
        assertThatThrownBy(() -> SearchResponseBodies.readLegacy(input)).isInstanceOf(IOException.class);
        assertThat(input.read).isEqualTo(SearchResponseBodies.METADATA_LIMIT_BYTES + 1);
        assertThat(SearchResponseBodies.readLegacy(new ByteArrayInputStream("ok".getBytes(StandardCharsets.UTF_8))))
                .isEqualTo("ok");
    }

    @Test
    void asyncCountsMultipleDirectBuffersAndDoesNotAcknowledgePartialSuccess() throws Exception {
        var consumer = new SearchResponseBodies.BoundedConsumer(8);
        AtomicReference<SimpleHttpResponse> result = new AtomicReference<>();
        consumer.consumeResponse(new BasicHttpResponse(200), details(-1), HttpCoreContext.create(), callback(result));
        consumer.consume(ByteBuffer.wrap(new byte[4]));
        consumer.consume(ByteBuffer.allocateDirect(4));
        assertThatThrownBy(() -> consumer.consume(ByteBuffer.wrap(new byte[1])))
                .isInstanceOf(IOException.class).hasMessageContaining("8-byte reply budget");
        assertThat(result).hasNullValue();
        consumer.failed(new IOException("test"));
        consumer.releaseResources();
    }

    @Test
    void asyncRejectsOversizedDeclaredSuccessAndCompletesExactLength() throws Exception {
        var tooBig = new SearchResponseBodies.BoundedConsumer(8);
        assertThatThrownBy(() -> tooBig.consumeResponse(new BasicHttpResponse(200), details(9),
                HttpCoreContext.create(), callback(new AtomicReference<>())))
                .isInstanceOf(IOException.class);
        tooBig.releaseResources();

        var exact = new SearchResponseBodies.BoundedConsumer(8);
        AtomicReference<SimpleHttpResponse> result = new AtomicReference<>();
        exact.consumeResponse(new BasicHttpResponse(200), details(8), HttpCoreContext.create(), callback(result));
        exact.consume(ByteBuffer.wrap("12345678".getBytes(StandardCharsets.UTF_8)));
        exact.streamEnd(List.of());
        assertThat(result.get().getBodyText()).isEqualTo("12345678");
        exact.releaseResources();
    }

    @Test
    void interruptedAsyncWaitCancelsTheInFlightRequest() throws Exception {
        var future = new CompletableFuture<SimpleHttpResponse>() {
            @Override public SimpleHttpResponse get() throws InterruptedException {
                throw new InterruptedException("test interruption");
            }
        };
        CloseableHttpAsyncClient client = mock(CloseableHttpAsyncClient.class);
        when(client.execute(org.mockito.ArgumentMatchers.any(AsyncRequestProducer.class),
                org.mockito.ArgumentMatchers.<AsyncResponseConsumer<SimpleHttpResponse>>any(),
                org.mockito.ArgumentMatchers.<FutureCallback<SimpleHttpResponse>>isNull())).thenReturn(future);
        var request = SimpleRequestBuilder.get("http://example.invalid/").build();
        assertThatThrownBy(() -> SearchResponseBodies.execute(client, request, 1024))
                .isInstanceOf(InterruptedException.class);
        assertThat(future.isCancelled()).isTrue();
    }

    private static ClassicHttpResponse response(int status, InputStream input, long length) {
        ClassicHttpResponse response = mock(ClassicHttpResponse.class,
                withSettings().extraInterfaces(ModalCloseable.class));
        when(response.getCode()).thenReturn(status);
        when(response.getEntity()).thenReturn(new InputStreamEntity(input, length, ContentType.TEXT_PLAIN));
        return response;
    }

    private static EntityDetails details(long length) {
        EntityDetails details = mock(EntityDetails.class);
        when(details.getContentLength()).thenReturn(length);
        when(details.getContentType()).thenReturn("text/plain; charset=UTF-8");
        return details;
    }

    private static FutureCallback<SimpleHttpResponse> callback(AtomicReference<SimpleHttpResponse> result) {
        return new FutureCallback<>() {
            @Override public void completed(SimpleHttpResponse response) { result.set(response); }
            @Override public void failed(Exception failure) { }
            @Override public void cancelled() { }
        };
    }

    private static final class CountingBody extends InputStream {
        private final long length;
        private long read;

        private CountingBody(long length) { this.length = length; }

        @Override public int read() {
            if (read >= length) return -1;
            read++;
            return 'x';
        }

        @Override public int read(byte[] bytes, int offset, int count) {
            if (read >= length) return -1;
            int copied = (int) Math.min(count, length - read);
            java.util.Arrays.fill(bytes, offset, offset + copied, (byte) 'x');
            read += copied;
            return copied;
        }
    }
}
