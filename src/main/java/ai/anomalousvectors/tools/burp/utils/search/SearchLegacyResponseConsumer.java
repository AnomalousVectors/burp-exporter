package ai.anomalousvectors.tools.burp.utils.search;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.GzipDecompressingEntity;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.nio.ContentDecoder;
import org.apache.http.nio.IOControl;
import org.apache.http.nio.protocol.AbstractAsyncResponseConsumer;
import org.apache.http.protocol.HttpContext;
import org.elasticsearch.client.HttpAsyncResponseConsumerFactory;

/**
 * Bounds the legacy Elasticsearch probe before its transport materializes a complete response.
 *
 * <p>Each request attempt owns a consumer on its I/O worker. Both declared and actual encoded
 * bytes are limited. Gzip expansion is bounded before the legacy client can materialize an error
 * message from the decoded body.</p>
 */
final class SearchLegacyResponseConsumer extends AbstractAsyncResponseConsumer<HttpResponse> {
    private ByteArrayOutputStream body = new ByteArrayOutputStream(8192);
    private final ByteBuffer chunk = ByteBuffer.allocate(8192);
    private HttpResponse response;
    private HttpEntity originalEntity;
    private ContentType contentType;

    static HttpAsyncResponseConsumerFactory factory() {
        return SearchLegacyResponseConsumer::new;
    }

    @Override
    protected void onResponseReceived(HttpResponse received) {
        response = received;
    }

    @Override
    protected void onEntityEnclosed(HttpEntity entity, ContentType type) throws IOException {
        originalEntity = entity;
        contentType = type;
        if (entity.getContentLength() > SearchResponseBodies.METADATA_LIMIT_BYTES) throw tooLarge();
    }

    @Override
    protected void onContentReceived(ContentDecoder decoder, IOControl control) throws IOException {
        while (true) {
            chunk.clear();
            chunk.limit(Math.min(chunk.capacity(), SearchResponseBodies.METADATA_LIMIT_BYTES - body.size() + 1));
            int count = decoder.read(chunk);
            if (count <= 0) return;
            if (count > SearchResponseBodies.METADATA_LIMIT_BYTES - body.size()) throw tooLarge();
            body.write(chunk.array(), 0, count);
        }
    }

    @Override
    protected HttpResponse buildResult(HttpContext context) throws IOException {
        if (originalEntity != null) {
            ByteArrayEntity entity = new ByteArrayEntity(body.toByteArray(), contentType);
            entity.setContentEncoding(originalEntity.getContentEncoding());
            if (entity.getContentEncoding() != null
                    && "gzip".equalsIgnoreCase(entity.getContentEncoding().getValue())) {
                // RestClient otherwise expands gzip before constructing its ResponseException text.
                try (var decoded = new GzipDecompressingEntity(entity).getContent()) {
                    entity = new ByteArrayEntity(SearchResponseBodies.readLegacyBytes(decoded), contentType);
                }
                response.removeHeaders("Content-Encoding");
                response.removeHeaders("Content-Length");
            }
            response.setEntity(entity);
        }
        return response;
    }

    @Override
    protected void releaseResources() {
        body = new ByteArrayOutputStream(0);
        originalEntity = null;
        response = null;
    }

    private static IOException tooLarge() {
        return new IOException("Database response exceeded the "
                + SearchResponseBodies.METADATA_LIMIT_BYTES + "-byte reply budget.");
    }
}
