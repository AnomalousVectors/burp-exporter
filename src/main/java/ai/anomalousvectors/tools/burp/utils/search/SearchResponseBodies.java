package ai.anomalousvectors.tools.burp.utils.search;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestProducer;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.nio.AsyncResponseConsumer;
import org.apache.hc.core5.http.nio.CapacityChannel;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.io.ModalCloseable;

/**
 * Bounds database-service reply acquisition independently of captured application traffic.
 *
 * <p>Stateless entry points are safe for concurrent callers. Reads and async execution block on
 * the calling transport worker. Oversized successful replies fail without partial acknowledgments;
 * oversized errors retain a small diagnostic prefix and abort the remainder.</p>
 */
public final class SearchResponseBodies {

    /** Maximum retained error prefix before diagnostic redaction and formatting. */
    static final int ERROR_PREVIEW_BYTES = 16 * 1024;
    /** Complete metadata responses may include mappings for a large existing index. */
    public static final int METADATA_LIMIT_BYTES = 8 * 1024 * 1024;
    private static final int MAX_BULK_RESPONSE_BYTES = 16 * 1024 * 1024;
    private static final String TRUNCATED = "\n[Database response preview truncated]";

    private SearchResponseBodies() { }

    /**
     * Returns a bounded acknowledgment budget based on the attempted bulk item count.
     *
     * @param itemCount attempted items; negative values are treated as zero
     * @return at least 1 MiB, allowing 16 KiB per item up to a 16 MiB ceiling
     */
    public static int bulkLimit(int itemCount) {
        return (int) Math.min(MAX_BULK_RESPONSE_BYTES,
                Math.max(1024L * 1024L, Math.max(0L, itemCount) * 16L * 1024L));
    }

    /**
     * Reads a complete metadata reply or a bounded error preview from a classic response.
     *
     * @param response response whose lifetime remains owned by the transport
     * @return decoded body; empty when no entity exists
     * @throws IOException when reading fails or a successful reply exceeds its budget
     * @throws ParseException when the response content type cannot be decoded
     */
    public static String read(ClassicHttpResponse response) throws IOException, ParseException {
        return read(response, METADATA_LIMIT_BYTES);
    }

    /**
     * Reads a database reply, aborting the connection rather than draining oversized content.
     *
     * <p>The actual stream is counted after the client's content decoding. Declared lengths only
     * provide an early rejection; missing or inaccurate lengths cannot bypass the limit.</p>
     *
     * @param response response owned by the transport
     * @param successLimit positive complete-response byte limit
     * @return complete decoded success text or a marked error prefix
     * @throws IOException when reading fails or a successful reply is oversized
     * @throws ParseException when the response content type cannot be decoded
     * @throws IllegalArgumentException when the limit is outside 1 byte through 16 MiB
     */
    public static String read(ClassicHttpResponse response, int successLimit) throws IOException, ParseException {
        requireLimit(successLimit);
        HttpEntity entity = response.getEntity();
        if (entity == null) return "";
        boolean success = isSuccess(response.getCode());
        int limit = success ? successLimit : ERROR_PREVIEW_BYTES;
        if (success && entity.getContentLength() > limit) {
            abort(response, entity);
            throw tooLarge(limit);
        }
        byte[] bytes;
        try {
            bytes = entity.getContent().readNBytes(limit + 1);
        } catch (IOException failure) {
            // An interrupted or malformed body must not be drained during normal pooled cleanup.
            try {
                abort(response, entity);
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
        boolean excess = bytes.length > limit;
        if (excess) {
            abort(response, entity);
            if (success) throw tooLarge(limit);
        }
        String text = EntityUtils.toString(new ByteArrayEntity(bytes, 0, Math.min(bytes.length, limit),
                ContentType.parse(entity.getContentType())), StandardCharsets.UTF_8, limit);
        return excess ? text + TRUNCATED : text;
    }

    /**
     * Reads a complete, already-buffered legacy transport body within the metadata budget.
     *
     * @param input response stream; its owner closes it
     * @return UTF-8 text
     * @throws IOException when reading fails or the reply exceeds the metadata limit
     */
    static String readLegacy(InputStream input) throws IOException {
        return new String(readLegacyBytes(input), StandardCharsets.UTF_8);
    }

    static byte[] readLegacyBytes(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(METADATA_LIMIT_BYTES + 1);
        if (bytes.length > METADATA_LIMIT_BYTES) throw tooLarge(METADATA_LIMIT_BYTES);
        return bytes;
    }

    static SimpleHttpResponse execute(CloseableHttpAsyncClient client, SimpleHttpRequest request,
            int successLimit) throws InterruptedException, ExecutionException {
        Future<SimpleHttpResponse> future = client.execute(SimpleRequestProducer.create(request),
                new BoundedConsumer(successLimit), null);
        try {
            return future.get();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof ResponseLimitException limit && limit.errorResponse != null) {
                return limit.errorResponse;
            }
            throw e;
        } catch (InterruptedException e) {
            future.cancel(true);
            throw e;
        }
    }

    private static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    private static IOException tooLarge(int limit) {
        return new IOException("Database response exceeded the " + limit + "-byte reply budget.");
    }

    private static void requireLimit(int limit) {
        if (limit <= 0 || limit > MAX_BULK_RESPONSE_BYTES) {
            throw new IllegalArgumentException("Database reply limit must be between 1 and 16 MiB.");
        }
    }

    private static void abort(ClassicHttpResponse response, HttpEntity entity) throws IOException {
        if (response instanceof ModalCloseable closeable) {
            closeable.close(CloseMode.IMMEDIATE);
        } else {
            // In-memory responses have no pooled connection to abort or drain.
            response.setEntity(null);
            entity.close();
        }
    }

    private static final class ResponseLimitException extends IOException {
        @Serial private static final long serialVersionUID = 1L;
        private final SimpleHttpResponse errorResponse;

        private ResponseLimitException(int limit, SimpleHttpResponse errorResponse) {
            super("Database response exceeded the " + limit + "-byte reply budget.");
            this.errorResponse = errorResponse;
        }
    }

    // Each attempt owns a consumer. Capacity, declared length and actual decoded bytes are bounded.
    static final class BoundedConsumer implements AsyncResponseConsumer<SimpleHttpResponse> {
        private final int successLimit;
        private ByteArrayOutputStream buffer = new ByteArrayOutputStream(8192);
        private SimpleHttpResponse head;
        private ContentType contentType;
        private FutureCallback<SimpleHttpResponse> callback;
        private int limit;

        BoundedConsumer(int successLimit) {
            requireLimit(successLimit);
            this.successLimit = successLimit;
        }

        @Override
        public void consumeResponse(HttpResponse response, EntityDetails details, HttpContext context,
                FutureCallback<SimpleHttpResponse> resultCallback) throws IOException {
            head = SimpleHttpResponse.copy(response);
            callback = resultCallback;
            limit = isSuccess(response.getCode()) ? successLimit : ERROR_PREVIEW_BYTES;
            if (details == null) {
                callback.completed(head);
            } else {
                contentType = ContentType.parse(details.getContentType());
                if (isSuccess(head.getCode()) && details.getContentLength() > limit) {
                    throw new ResponseLimitException(limit, null);
                }
            }
        }

        @Override
        public void informationResponse(HttpResponse response, HttpContext context) { }

        @Override
        public void updateCapacity(CapacityChannel channel) throws IOException {
            channel.update(Math.min(8192, limit - buffer.size() + 1));
        }

        @Override
        public void consume(ByteBuffer source) throws IOException {
            int allowed = Math.min(source.remaining(), limit - buffer.size());
            byte[] part = new byte[Math.min(8192, allowed)];
            while (allowed > 0) {
                int count = Math.min(part.length, allowed);
                source.get(part, 0, count);
                buffer.write(part, 0, count);
                allowed -= count;
            }
            if (source.hasRemaining()) {
                SimpleHttpResponse preview = null;
                if (!isSuccess(head.getCode())) {
                    preview = SimpleHttpResponse.copy(head);
                    preview.setBody(buffer.toString(StandardCharsets.UTF_8) + TRUNCATED, ContentType.TEXT_PLAIN);
                }
                throw new ResponseLimitException(limit, preview);
            }
        }

        @Override
        public void streamEnd(List<? extends Header> trailers) {
            head.setBody(buffer.toByteArray(), contentType);
            callback.completed(head);
        }

        @Override
        public void failed(Exception cause) {
            releaseResources();
        }

        @Override
        public void releaseResources() {
            buffer = new ByteArrayOutputStream(0);
        }
    }
}
