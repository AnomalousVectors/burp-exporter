package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.support.ClassicResponseBuilder;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Executes OpenSearch bulk POST requests with transport selection aligned to auth mode.
 *
 * <p>Certificate authentication relies on the async HC5 client because its TLS stack presents
 * client-certificate material consistently on the OpenSearch security plugin mTLS path. For
 * certificate mode, callers still enforce the normal bulk payload caps before this class copies the
 * entity into an async request body.</p>
 */
final class OpenSearchBulkHttpExecutor {

    private OpenSearchBulkHttpExecutor() {
        throw new AssertionError("No instances");
    }

    /**
     * Posts one bulk request and returns the handled result.
     *
     * <p>Basic, API-key, bearer-token, and unauthenticated requests use the pooled classic client.
     * Certificate requests use a short-lived async client so the same TLS path as Test Connection is
     * used for bulk export.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param entity request body entity
     * @param handler classic response handler
     * @return handler result
     * @param <T> handler result type
     * @throws IOException when the request cannot be sent or the response cannot be read
     */
    static <T> T executeBulkPost(
            String baseUrl,
            String indexName,
            HttpEntity entity,
            org.apache.hc.core5.http.io.HttpClientResponseHandler<T> handler) throws IOException {
        ConfigState.SearchDestination destination = RuntimeConfig.searchDestinationKind();
        OpenSearchAuth auth = OpenSearchAuth.fromRuntime(destination);
        String path = OpenSearchClassicHttpSupport.bulkPathForIndex(indexName);
        if (auth.mode() == OpenSearchAuth.Mode.CERTIFICATE) {
            return executeCertificateBulkPost(baseUrl, path, entity, auth, destination, handler);
        }
        HttpHost host = OpenSearchClassicHttpSupport.hostForBaseUrl(baseUrl);
        HttpPost post = new HttpPost(path);
        post.setEntity(entity);
        ChunkedBulkSender.addPreemptiveAuthHeader(post);
        CloseableHttpClient client = OpenSearchConnector.getClassicHttpClient(baseUrl, auth);
        return client.execute(host, post, handler);
    }

    private static <T> T executeCertificateBulkPost(
            String baseUrl,
            String path,
            HttpEntity entity,
            OpenSearchAuth auth,
            ConfigState.SearchDestination destination,
            org.apache.hc.core5.http.io.HttpClientResponseHandler<T> handler) throws IOException {
        String normalized = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        URI uri = URI.create(normalized + path);
        boolean insecure = OpenSearchConnector.isInsecureEnabled(destination);
        try {
            URI hostUri = URI.create(normalized);
            HttpHost host = new HttpHost(hostUri.getScheme(), hostUri.getHost(), hostUri.getPort());
            try (CloseableHttpAsyncClient client =
                    OpenSearchRawGet.buildAsyncClientForBulk(host, auth, insecure, destination)) {
                client.start();
                SimpleHttpRequest request = SimpleRequestBuilder.post(uri)
                        .setBody(toByteArray(entity), ContentType.create("application/x-ndjson"))
                        .build();
                auth.applyTo(request);
                Future<SimpleHttpResponse> future = client.execute(request, null);
                SimpleHttpResponse asyncResponse = future.get();
                try (ClassicHttpResponse classicResponse = adapt(asyncResponse)) {
                    try {
                        return handler.handleResponse(classicResponse);
                    } catch (HttpException e) {
                        throw new IOException("OpenSearch certificate bulk response handling failed.", e);
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("OpenSearch certificate bulk request interrupted.", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause == null) {
                cause = e;
            }
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new IOException("OpenSearch certificate bulk request failed.", cause);
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("Failed to build OpenSearch certificate bulk client.", e);
        }
    }

    private static byte[] toByteArray(HttpEntity entity) throws IOException {
        if (entity == null) {
            return new byte[0];
        }
        if (entity instanceof ByteArrayEntity byteArrayEntity) {
            return byteArrayEntity.getContent().readAllBytes();
        }
        try (var input = entity.getContent()) {
            return input == null ? new byte[0] : input.readAllBytes();
        }
    }

    private static ClassicHttpResponse adapt(SimpleHttpResponse asyncResponse) throws IOException {
        ClassicHttpResponse response = ClassicResponseBuilder.create(asyncResponse.getCode())
                .setEntity(asyncResponse.getBody() == null
                        ? null
                        : new ByteArrayEntity(asyncResponse.getBodyBytes(), ContentType.APPLICATION_JSON))
                .build();
        for (org.apache.hc.core5.http.Header header : asyncResponse.getHeaders()) {
            response.addHeader(header);
        }
        return response;
    }
}
