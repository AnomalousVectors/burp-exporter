package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

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
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Executes search database bulk POST requests with transport selection aligned to auth mode.
 *
 * <p>Certificate authentication reuses a cached async HC5 client because its TLS stack presents
 * client-certificate material consistently on the mTLS path. Bulk bodies are sent as uncompressed
 * NDJSON; SigV4 signs those exact bytes on the wire.</p>
 *
 * <p>Thread-safe. Calls block on global pacing, connection leasing, and response completion.
 * Interruption of the certificate path restores the interrupt flag and surfaces as
 * {@link IOException}.</p>
 */
final class OpenSearchBulkHttpExecutor {

    private static final AtomicLong REQUEST_SEQUENCE = new AtomicLong();
    private static final long SLOW_REQUEST_MS = 5_000L;

    @FunctionalInterface
    interface BulkResponseHandler<T> {
        /**
         * Converts one HTTP response while its entity remains available.
         *
         * @param response response owned by the executor
         * @param requestId local correlation identifier
         * @return caller-defined result
         * @throws HttpException when response semantics cannot be handled
         * @throws IOException when the response entity cannot be read
         */
        T handleResponse(ClassicHttpResponse response, long requestId) throws HttpException, IOException;
    }

    /**
     * Signals callers to rebuild derived search copies after pacing observes a smaller budget.
     *
     * <p>No HTTP request has started when this exception is thrown.</p>
     */
    static final class LiveBudgetChangedException extends IOException {
        private final long liveBudget;

        LiveBudgetChangedException(long bodyBytes, long liveBudget) {
            super("Bulk body exceeded live byte budget after offered-load wait"
                    + " bytes=" + bodyBytes + " liveBudget=" + liveBudget);
            this.liveBudget = liveBudget;
        }

        long liveBudget() {
            return liveBudget;
        }
    }

    private OpenSearchBulkHttpExecutor() {
        throw new AssertionError("No instances");
    }

    /**
     * Posts one bulk request and returns the handled result.
     *
     * <p>Basic, API-key, bearer-token, SigV4, and unauthenticated requests use the pooled classic
     * client. Certificate requests use the cached async client so the same TLS path as Test
     * Connection is used for bulk export.</p>
     *
     * @param baseUrl search database base URL
     * @param indexName target index name
     * @param entity request body entity
     * @param handler response handler receiving the local request ID used by transport logs
     * @return handler result
     * @param <T> handler result type
     * @throws IOException when the request cannot be sent or the response cannot be read
     */
    static <T> T executeBulkPost(
            String baseUrl,
            String indexName,
            HttpEntity entity,
            BulkResponseHandler<T> handler) throws IOException {
        return executeBulkPost(baseUrl, indexName, toByteArray(entity), handler);
    }

    /**
     * Posts one bulk request from an already-materialized NDJSON body (no second entity copy).
     *
     * @param baseUrl search database base URL
     * @param indexName target index name
     * @param body bulk NDJSON bytes; may be empty
     * @param handler response handler receiving the local request ID used by transport logs
     * @return handler result
     * @param <T> handler result type
     * @throws IOException when the request cannot be sent or the response cannot be read
     */
    static <T> T executeBulkPost(
            String baseUrl,
            String indexName,
            byte[] body,
            BulkResponseHandler<T> handler) throws IOException {
        byte[] ndjson = body == null ? new byte[0] : body;
        try (OfferedLoadGovernor.Permit permit = OfferedLoadGovernor.acquire(ndjson.length)) {
            long liveBudget = Math.max(1L, BulkByteBudget.currentMaxBytes());
            if (ndjson.length > liveBudget) {
                throw new LiveBudgetChangedException(ndjson.length, liveBudget);
            }
            ConfigState.SearchDestination destination = RuntimeConfig.searchDestinationKind();
            OpenSearchAuth auth = OpenSearchAuth.fromRuntime(destination);
            String path = OpenSearchClassicHttpSupport.bulkPathForIndex(indexName);
            if (auth.mode() == OpenSearchAuth.Mode.CERTIFICATE) {
                return executeCertificateBulkPost(baseUrl, indexName, path, ndjson, auth, handler);
            }
            HttpHost host = OpenSearchClassicHttpSupport.hostForBaseUrl(baseUrl);
            HttpPost post = new HttpPost(path);
            post.setEntity(new ByteArrayEntity(ndjson, ContentType.create("application/x-ndjson")));
            ChunkedBulkSender.addPreemptiveAuthHeader(post);
            if (AmazonOpenSearchSigV4.isEnabledForRuntime()) {
                AmazonOpenSearchSigV4.sign(post, "POST", baseUrl, path, ndjson);
            }
            CloseableHttpClient client = OpenSearchConnector.getClassicHttpClient(baseUrl, auth);
            long requestId = beginRequest(
                    indexName,
                    path,
                    ndjson.length,
                    auth,
                    String.valueOf(OpenSearchConnector.CLASSIC_BULK_RESPONSE_TIMEOUT.toMilliseconds()));
            long startedNanos = System.nanoTime();
            try {
                return client.execute(host, post, response -> {
                    noteResponse(requestId, indexName, path, ndjson.length, response.getCode(), startedNanos);
                    return handler.handleResponse(response, requestId);
                });
            } catch (IOException | RuntimeException e) {
                throw transportFailure(requestId, indexName, path, ndjson.length, startedNanos, e);
            }
        }
    }

    private static <T> T executeCertificateBulkPost(
            String baseUrl,
            String indexName,
            String path,
            byte[] ndjson,
            OpenSearchAuth auth,
            BulkResponseHandler<T> handler) throws IOException {
        String normalized = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        URI uri = URI.create(normalized + path);
        long requestId = beginRequest(indexName, path, ndjson.length, auth, "120000");
        long startedNanos = System.nanoTime();
        try {
            CloseableHttpAsyncClient client = OpenSearchConnector.getAsyncHttpClient(baseUrl, auth);
            SimpleHttpRequest request = SimpleRequestBuilder.post(uri)
                    .setBody(ndjson, ContentType.create("application/x-ndjson"))
                    .build();
            auth.applyTo(request);
            Future<SimpleHttpResponse> future = client.execute(request, null);
            SimpleHttpResponse asyncResponse = future.get();
            noteResponse(requestId, indexName, path, ndjson.length, asyncResponse.getCode(), startedNanos);
            try (ClassicHttpResponse classicResponse = adapt(asyncResponse)) {
                try {
                    return handler.handleResponse(classicResponse, requestId);
                } catch (HttpException e) {
                    throw new IOException("Search database certificate bulk response handling failed.", e);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw transportFailure(requestId, indexName, path, ndjson.length, startedNanos, e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause == null) {
                cause = e;
            }
            throw transportFailure(requestId, indexName, path, ndjson.length, startedNanos, cause);
        } catch (RuntimeException e) {
            throw transportFailure(requestId, indexName, path, ndjson.length, startedNanos, e);
        }
    }

    private static long beginRequest(
            String indexName,
            String path,
            long bytes,
            OpenSearchAuth auth,
            String responseTimeoutMs) {
        long requestId = REQUEST_SEQUENCE.incrementAndGet();
        if (BulkByteBudget.isAmazonDestination() && ExportRunContext.allowsRunMutation()) {
            // internalTrace: do not notify the Log panel / exporter forwarder. Panel TRACE + Exporter
            // TRACE defaults create a feedback loop (each bulk logs → exporter doc → another bulk).
            Logger.internalTrace(RuntimeConfig.searchDestinationLogPrefix()
                    + " Bulk HTTP request started: requestId=" + requestId
                    + " index=" + safe(indexName)
                    + " path=" + path
                    + " bytes=" + bytes
                    + " auth=" + auth.mode()
                    + " responseTimeoutMs=" + responseTimeoutMs
                    + " connectTimeoutMs="
                    + OpenSearchConnector.CLASSIC_CONNECT_TIMEOUT.toMilliseconds()
                    + " connectionRequestTimeoutMs="
                    + OpenSearchConnector.CLASSIC_CONNECTION_REQUEST_TIMEOUT.toMilliseconds()
                    + ".");
        }
        return requestId;
    }

    private static void noteResponse(
            long requestId,
            String indexName,
            String path,
            long bytes,
            int status,
            long startedNanos) {
        if (!BulkByteBudget.isAmazonDestination() || !ExportRunContext.allowsRunMutation()) {
            return;
        }
        long elapsedMs = elapsedMs(startedNanos);
        // Slow Amazon responses are the usual chart-gap cause; keep them panel-visible.
        // Fast responses stay internal so they cannot flood the exporter index.
        if (elapsedMs < SLOW_REQUEST_MS) {
            Logger.internalTrace(RuntimeConfig.searchDestinationLogPrefix()
                    + " Bulk HTTP response received: requestId=" + requestId
                    + " index=" + safe(indexName)
                    + " path=" + path
                    + " bytes=" + bytes
                    + " status=" + status
                    + " elapsedMs=" + elapsedMs + ".");
            return;
        }
        String purposeHint = purposeHintForIndex(indexName);
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk HTTP slow response:"
                + " requestId=" + requestId
                + " index=" + safe(indexName)
                + " path=" + path
                + " bytes=" + bytes
                + " status=" + status
                + " elapsedMs=" + elapsedMs
                + purposeHint + ".");
    }

    /**
     * Best-effort operator hint for which export path typically owns an index.
     *
     * @param indexName full index name; may be blank
     * @return short {@code purpose=...} fragment, or empty
     */
    private static String purposeHintForIndex(String indexName) {
        if (indexName == null || indexName.isBlank()) {
            return "";
        }
        String lower = indexName.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith("-exporter") || lower.equals("exporter")) {
            return " purpose=exporter_index_write";
        }
        if (lower.endsWith("-traffic") || lower.equals("traffic")) {
            return " purpose=traffic_bulk";
        }
        if (lower.endsWith("-sitemap") || lower.equals("sitemap")) {
            return " purpose=sitemap_bulk";
        }
        if (lower.endsWith("-findings") || lower.equals("findings")) {
            return " purpose=findings_bulk";
        }
        if (lower.endsWith("-settings") || lower.equals("settings")) {
            return " purpose=settings_bulk";
        }
        return "";
    }

    private static IOException transportFailure(
            long requestId,
            String indexName,
            String path,
            long bytes,
            long startedNanos,
            Throwable failure) {
        String leaseHint = leaseOrConnectTimeoutHint(failure);
        String message = "Bulk HTTP transport failure"
                + " requestId=" + requestId
                + " index=" + safe(indexName)
                + " path=" + path
                + " bytes=" + bytes
                + " elapsedMs=" + elapsedMs(startedNanos)
                + (leaseHint.isEmpty() ? "" : " timeoutClass=" + leaseHint)
                + " cause=" + OpenSearchLogFormat.describeExceptionChain(failure);
        // Do not WARN here: Prepared/Chunked callers already emit one panel WARN with this message.
        // A second WARN doubles exporter-index volume under the default WARN level.
        return new IOException(message, failure);
    }

    /**
     * Classifies common HC5 timeout messages so operators can tell lease waits from connect hangs.
     */
    private static String leaseOrConnectTimeoutHint(Throwable failure) {
        String chain = OpenSearchLogFormat.describeExceptionChain(failure).toLowerCase();
        if (chain.contains("timeout waiting for connection")
                || chain.contains("connection request")
                || chain.contains("connection leased")) {
            return "connection-request/lease";
        }
        if (chain.contains("connect timed out")
                || chain.contains("connection timed out")
                || chain.contains("connect timeout")) {
            return "connect";
        }
        if (chain.contains("read timed out")
                || chain.contains("socket timeout")
                || chain.contains("response timeout")
                || chain.contains("failed to respond")) {
            return "response";
        }
        return "";
    }

    private static long elapsedMs(long startedNanos) {
        return Math.max(0L, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos));
    }

    private static String safe(String value) {
        return value == null || value.isBlank() ? "unknown" : value;
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
