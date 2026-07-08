package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;

import ai.anomalousvectors.tools.burp.sinks.FileExportService;
import ai.anomalousvectors.tools.burp.sinks.TrafficQueueEntry;
import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.ExportLineCodec;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Sends traffic documents to OpenSearch using a chunked POST to the standard Bulk API.
 *
 * <p>Drains prepared {@link ai.anomalousvectors.tools.burp.sinks.TrafficQueueEntry} items and
 * writes pre-built NDJSON bytes directly into the request body stream. Avoids building a full
 * batch list and full {@code BulkRequest} in memory. Uses only the production Bulk API
 * ({@code POST /&lt;index&gt;/_bulk}); not the experimental Streaming Bulk API. Thread-safe for
 * concurrent calls; each call performs one bulk request. Used only by the traffic export path.</p>
 *
 * @see <a href="https://docs.opensearch.org/latest/api-reference/document-apis/bulk/">Bulk API</a>
 */
public final class ChunkedBulkSender {

    private ChunkedBulkSender() {}

    /**
     * Result of one chunked bulk request: success count and total documents sent.
     */
    public static final class Result {
        /** Number of documents that were successfully indexed. */
        public final int successCount;
        /** Total number of documents sent in this bulk request. */
        public final int attemptedCount;
        /** Estimated payload bytes attempted in this bulk request. */
        public final long attemptedBytes;
        /** Estimated payload bytes for successful documents in this bulk request. */
        public final long successBytes;
        /** Successful traffic documents grouped by tool type. */
        public final Map<String, Integer> trafficToolTypeSuccessCounts;
        /** Failed traffic documents grouped by tool type. */
        public final Map<String, Integer> trafficToolTypeFailureCounts;
        /** Successful traffic documents grouped by source bucket. */
        public final Map<String, Integer> trafficSourceSuccessCounts;
        /** Failed traffic documents grouped by source bucket. */
        public final Map<String, Integer> trafficSourceFailureCounts;
        /** Classified OpenSearch bulk outcome when available. */
        public final BulkOutcomeBreakdown breakdown;
        /** OpenSearch bulk item failures aligned with the attempted document order. */
        public final List<OpenSearchClientWrapper.FailedItem> failedItems;

        public Result(int successCount, int attemptedCount, long attemptedBytes, long successBytes) {
            this(
                    successCount,
                    attemptedCount,
                    attemptedBytes,
                    successBytes,
                    Map.of(),
                    Map.of(),
                    Map.of(),
                    Map.of(),
                    BulkOutcomeBreakdown.classified(successCount, attemptedCount),
                    List.of());
        }

        public Result(
                int successCount,
                int attemptedCount,
                long attemptedBytes,
                long successBytes,
                Map<String, Integer> trafficToolTypeSuccessCounts,
                Map<String, Integer> trafficToolTypeFailureCounts,
                Map<String, Integer> trafficSourceSuccessCounts,
                Map<String, Integer> trafficSourceFailureCounts) {
            this(
                    successCount,
                    attemptedCount,
                    attemptedBytes,
                    successBytes,
                    trafficToolTypeSuccessCounts,
                    trafficToolTypeFailureCounts,
                    trafficSourceSuccessCounts,
                    trafficSourceFailureCounts,
                    BulkOutcomeBreakdown.classified(successCount, attemptedCount),
                    List.of());
        }

        public Result(
                int successCount,
                int attemptedCount,
                long attemptedBytes,
                long successBytes,
                Map<String, Integer> trafficToolTypeSuccessCounts,
                Map<String, Integer> trafficToolTypeFailureCounts,
                Map<String, Integer> trafficSourceSuccessCounts,
                Map<String, Integer> trafficSourceFailureCounts,
                BulkOutcomeBreakdown breakdown) {
            this(
                    successCount,
                    attemptedCount,
                    attemptedBytes,
                    successBytes,
                    trafficToolTypeSuccessCounts,
                    trafficToolTypeFailureCounts,
                    trafficSourceSuccessCounts,
                    trafficSourceFailureCounts,
                    breakdown,
                    List.of());
        }

        public Result(
                int successCount,
                int attemptedCount,
                long attemptedBytes,
                long successBytes,
                Map<String, Integer> trafficToolTypeSuccessCounts,
                Map<String, Integer> trafficToolTypeFailureCounts,
                Map<String, Integer> trafficSourceSuccessCounts,
                Map<String, Integer> trafficSourceFailureCounts,
                BulkOutcomeBreakdown breakdown,
                List<OpenSearchClientWrapper.FailedItem> failedItems) {
            this.successCount = successCount;
            this.attemptedCount = attemptedCount;
            this.attemptedBytes = attemptedBytes;
            this.successBytes = successBytes;
            this.trafficToolTypeSuccessCounts = immutableCopy(trafficToolTypeSuccessCounts);
            this.trafficToolTypeFailureCounts = immutableCopy(trafficToolTypeFailureCounts);
            this.trafficSourceSuccessCounts = immutableCopy(trafficSourceSuccessCounts);
            this.trafficSourceFailureCounts = immutableCopy(trafficSourceFailureCounts);
            this.breakdown = breakdown != null ? breakdown : BulkOutcomeBreakdown.empty();
            this.failedItems = failedItems != null ? List.copyOf(failedItems) : List.of();
        }
        public boolean isFullSuccess() { return attemptedCount > 0 && successCount == attemptedCount; }

        private static Map<String, Integer> immutableCopy(Map<String, Integer> counts) {
            if (counts == null || counts.isEmpty()) {
                return Map.of();
            }
            return Collections.unmodifiableMap(new LinkedHashMap<>(counts));
        }
    }

    /**
     * Performs one chunked bulk index request: drains from the queue (respecting batch limits),
     * writes NDJSON to {@code POST &lt;baseUrl&gt;/&lt;indexName&gt;/_bulk}, parses the response.
     *
     * <p>Documents are prepared at enqueue time. Batch is limited by
     * {@code maxBatch} doc count,
     * {@code maxBytes} estimated payload size, and {@code maxWaitMs} time. If no document
     * is available within the first {@code maxWaitMs}, returns a result with zero attempted
     * count (no request is sent).</p>
     *
     * @param baseUrl    OpenSearch base URL (e.g. {@code https://opensearch.url:9200})
     * @param indexName  target index name (e.g. {@code tool-burp-traffic})
     * @param indexKey   logical index key (for example {@code traffic})
     * @param queue      source of prepared traffic entries (prepare-on-offer)
     * @param maxBatch   maximum documents per bulk request
     * @param maxBytes   maximum estimated payload bytes per bulk request
     * @param maxWaitMs  maximum time to wait for the first document before sending
     * @return result with success and attempted counts; never {@code null}
     */
    public static Result push(
            String baseUrl,
            String indexName,
            String indexKey,
            BlockingQueue<TrafficQueueEntry> queue,
            int maxBatch,
            long maxBytes,
            long maxWaitMs) {
        TrafficQueueEntry firstEntry = pollFirstEntry(queue, maxWaitMs);
        if (firstEntry == null) {
            return new Result(0, 0, 0, 0);
        }
        HttpPost post = new HttpPost(OpenSearchClassicHttpSupport.bulkPathForIndex(indexName));
        long maxWaitNanos = maxWaitMs * 1_000_000L;
        AtomicInteger attemptedRef = new AtomicInteger(0);
        AtomicLong attemptedBytesRef = new AtomicLong(0);
        NdjsonQueueInputStream ndjsonStream = new NdjsonQueueInputStream(
                queue, firstEntry, maxBatch, maxBytes, maxWaitNanos, attemptedRef, attemptedBytesRef);
        post.setEntity(new InputStreamEntity(ndjsonStream, -1, ContentType.create("application/x-ndjson")));
        addPreemptiveAuthHeader(post);
        List<TrafficRouteBucket.Route> attemptedTrafficRoutes = ndjsonStream.attemptedTrafficRoutes();
        Result result;
        ExportStats.BulkInFlightTicket ticket = ExportStats.openBulk();
        try (ticket) {
            try {
                result = executeRequest(
                        baseUrl, post, attemptedRef, attemptedBytesRef, indexName, attemptedTrafficRoutes);
            } catch (IOException | RuntimeException e) {
                long attemptedBytes = attemptedBytesRef.get();
                Logger.logDebug("[OpenSearch] ChunkedBulkSender push failed for " + indexName + ": " + e.getMessage());
                Logger.logWarnPanelOnly("[OpenSearch] Chunked bulk push failed for " + indexName + ": "
                        + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
                result = failedResult(attemptedRef.get(), attemptedBytes, attemptedTrafficRoutes);
            } finally {
                FileExportService.emitPreparedChunk(ndjsonStream.acceptedDocumentsForFileEmit());
            }
        }
        return result;
    }

    private static Result executeRequest(
            String baseUrl,
            HttpPost post,
            AtomicInteger attemptedRef,
            AtomicLong attemptedBytesRef,
            String indexName,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes) throws IOException {
        return OpenSearchBulkHttpExecutor.executeBulkPost(
                baseUrl,
                indexName,
                post.getEntity(),
                response -> {
            int status = response.getCode();
            String responseBody;
            try {
                responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse bulk response body for " + indexName, e);
            }
            int attempted = attemptedRef.get();
            long attemptedBytes = attemptedBytesRef.get();
            if (status < 200 || status >= 300) {
                Logger.logDebug("[OpenSearch] ChunkedBulkSender bulk request failed: " + status + " " + responseBody);
                String detail = responseBody != null && responseBody.contains("request body is required")
                        ? " OpenSearch reported an empty bulk request body."
                        : "";
                Logger.logWarnPanelOnly("[OpenSearch] Chunked bulk request failed for "
                        + indexName + ": HTTP " + status + "." + detail);
                return failedResult(attempted, attemptedBytes, attemptedTrafficRoutes);
            }
            Result parsed = parseBulkResponse(responseBody, attempted, attemptedTrafficRoutes, indexName);
            long successBytes = parsed.successCount > 0 && attempted > 0
                    ? Math.round((double) attemptedBytes * parsed.successCount / attempted)
                    : 0;
            return new Result(
                    parsed.successCount,
                    parsed.attemptedCount,
                    attemptedBytes,
                    successBytes,
                    parsed.trafficToolTypeSuccessCounts,
                    parsed.trafficToolTypeFailureCounts,
                    parsed.trafficSourceSuccessCounts,
                    parsed.trafficSourceFailureCounts,
                    parsed.breakdown,
                    parsed.failedItems);
        });
    }

    /**
     * Adds a preemptive Basic Auth header when credentials are configured.
     *
     * <p>Chunked NDJSON entities are not repeatable. If authentication waits for a 401 challenge,
     * some clients cannot transparently replay the same request body. Sending Authorization on the
     * first request avoids repeated 401 loops on the live traffic bulk path.</p>
     */
    static void addPreemptiveAuthHeader(HttpPost post) {
        OpenSearchAuth.fromRuntime(RuntimeConfig.searchDestinationKind()).applyTo(post);
    }

    private static TrafficQueueEntry pollFirstEntry(BlockingQueue<TrafficQueueEntry> queue, long maxWaitMs) {
        try {
            return queue.poll(maxWaitMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    static String buildBulkUrl(String baseUrl, String indexName) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return base + "/" + indexName + "/_bulk";
    }

    /** Package-private for tests that do not need route-tracking context. */
    static Result parseBulkResponse(String responseBody, int attemptedCount) {
        return parseBulkResponse(responseBody, attemptedCount, List.of(), "");
    }

    static Result parseBulkResponse(
            String responseBody,
            int attemptedCount,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes,
            String indexName) {
        if (responseBody == null || responseBody.isBlank()) {
            return failedResult(attemptedCount, 0, attemptedTrafficRoutes);
        }
        BulkNdjsonResponseParser.ParsedBulk parsed = BulkNdjsonResponseParser.parse(responseBody, indexName);
        if (parsed.successCount() == 0 && parsed.failedItems().isEmpty() && attemptedCount > 0) {
            Logger.logWarnPanelOnly("[OpenSearch] Chunked bulk response parsing failed for "
                    + (indexName == null || indexName.isBlank() ? "unknown" : indexName) + ".");
            return failedResult(attemptedCount, 0, attemptedTrafficRoutes);
        }
        return routeAttributedResult(
                parsed.breakdown(), attemptedCount, attemptedTrafficRoutes, parsed.failedItems());
    }

    private static Result routeAttributedResult(
            BulkOutcomeBreakdown breakdown,
            int attemptedCount,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes,
            List<OpenSearchClientWrapper.FailedItem> failedItems) {
        int successCount = breakdown.successTotal();
        Map<Integer, OpenSearchClientWrapper.FailedItem> failedByIndex = new LinkedHashMap<>();
        for (OpenSearchClientWrapper.FailedItem failedItem : failedItems) {
            failedByIndex.put(failedItem.index(), failedItem);
        }
        Map<String, Integer> toolTypeSuccessCounts = new LinkedHashMap<>();
        Map<String, Integer> toolTypeFailureCounts = new LinkedHashMap<>();
        Map<String, Integer> sourceSuccessCounts = new LinkedHashMap<>();
        Map<String, Integer> sourceFailureCounts = new LinkedHashMap<>();
        for (int i = 0; i < attemptedCount; i++) {
            if (failedByIndex.containsKey(i)) {
                recordRouteCount(attemptedTrafficRoutes, i, toolTypeFailureCounts, sourceFailureCounts);
            } else {
                recordRouteCount(attemptedTrafficRoutes, i, toolTypeSuccessCounts, sourceSuccessCounts);
            }
        }
        return new Result(
                successCount,
                attemptedCount,
                0,
                0,
                toolTypeSuccessCounts,
                toolTypeFailureCounts,
                sourceSuccessCounts,
                sourceFailureCounts,
                breakdown,
                List.copyOf(failedItems));
    }

    private static Result failedResult(
            int attemptedCount,
            long attemptedBytes,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes) {
        Map<String, Integer> toolTypeFailureCounts = new LinkedHashMap<>();
        Map<String, Integer> sourceFailureCounts = new LinkedHashMap<>();
        for (int i = 0; i < attemptedTrafficRoutes.size(); i++) {
            recordRouteCount(attemptedTrafficRoutes, i, toolTypeFailureCounts, sourceFailureCounts);
        }
        return new Result(0, attemptedCount, attemptedBytes, 0, Map.of(), toolTypeFailureCounts, Map.of(), sourceFailureCounts);
    }

    private static void recordRouteCount(
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes,
            int index,
            Map<String, Integer> toolTypeCounts,
            Map<String, Integer> sourceCounts) {
        if (attemptedTrafficRoutes == null || index < 0 || index >= attemptedTrafficRoutes.size()) {
            return;
        }
        TrafficRouteBucket.Route route = attemptedTrafficRoutes.get(index);
        if (route == null) {
            return;
        }
        Map<String, Integer> target = route.kind() == TrafficRouteBucket.Kind.SOURCE
                ? sourceCounts
                : toolTypeCounts;
        Integer current = target.get(route.key());
        target.put(route.key(), current == null ? 1 : current + 1);
    }

    /**
     * InputStream that produces NDJSON by draining from a queue one document at a time.
     * Used as the body of a chunked bulk request. Only one doc's bytes are held in memory
     * at a time. Stops when batch count, size, or time limit is reached.
     */
    private static final class NdjsonQueueInputStream extends InputStream {
        private final BlockingQueue<TrafficQueueEntry> queue;
        private TrafficQueueEntry firstEntry;
        private final int maxBatch;
        private final long maxBytes;
        private final long maxWaitNanos;
        private final AtomicInteger attemptedRef;
        private final AtomicLong attemptedBytesRef;
        private final List<TrafficRouteBucket.Route> attemptedTrafficRoutes = new ArrayList<>();
        private final List<PreparedExportDocument> acceptedDocumentsForFileEmit = new ArrayList<>();

        private byte[] buffer = new byte[0];
        private int pos;
        private boolean finished;
        private final long batchStartNanos = System.nanoTime();
        private long runningBytes;

        NdjsonQueueInputStream(
                BlockingQueue<TrafficQueueEntry> queue,
                TrafficQueueEntry firstEntry,
                int maxBatch,
                long maxBytes,
                long maxWaitNanos,
                AtomicInteger attemptedRef,
                AtomicLong attemptedBytesRef) {
            this.queue = queue;
            this.firstEntry = firstEntry;
            this.maxBatch = maxBatch;
            this.maxBytes = maxBytes;
            this.maxWaitNanos = maxWaitNanos;
            this.attemptedRef = attemptedRef;
            this.attemptedBytesRef = attemptedBytesRef;
        }

        @Override
        public int read() throws IOException {
            if (finished) return -1;
            if (pos < buffer.length) return buffer[pos++] & 0xFF;
            if (!fillBuffer()) {
                finished = true;
                return -1;
            }
            return pos < buffer.length ? buffer[pos++] & 0xFF : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (finished) return -1;
            if (pos < buffer.length) {
                int toCopy = Math.min(len, buffer.length - pos);
                System.arraycopy(buffer, pos, b, off, toCopy);
                pos += toCopy;
                return toCopy;
            }
            if (!fillBuffer()) {
                finished = true;
                return -1;
            }
            int toCopy = Math.min(len, buffer.length - pos);
            System.arraycopy(buffer, pos, b, off, toCopy);
            pos += toCopy;
            return toCopy;
        }

        /** Fetches one document from the queue, serializes to NDJSON, and sets buffer. */
        private boolean fillBuffer() throws IOException {
            while (true) {
                TrafficQueueEntry entry = nextEnabledEntry();
                if (entry == null) {
                    return false;
                }
                PreparedExportDocument prepared = entry.prepared();
                long docBytes = prepared.estimatedBulkBytes();
                if (attemptedRef.get() > 0 && runningBytes + docBytes > maxBytes) {
                    queue.offer(entry);
                    return false;
                }
                byte[] ndjson = prepared.bulkNdjsonBytes();
                if (ndjson != null && ndjson.length > 0) {
                    buffer = ndjson;
                } else {
                    ByteArrayOutputStream chunk = new ByteArrayOutputStream();
                    ExportLineCodec.writeBulkNdjson(chunk, prepared);
                    buffer = chunk.toByteArray();
                }
                pos = 0;
                attemptedRef.incrementAndGet();
                runningBytes += docBytes;
                attemptedBytesRef.addAndGet(docBytes);
                attemptedTrafficRoutes.add(TrafficRouteBucket.fromDocument(prepared.document()));
                acceptedDocumentsForFileEmit.add(prepared);
                return true;
            }
        }

        private TrafficQueueEntry nextEnabledEntry() {
            while (attemptedRef.get() < maxBatch) {
                TrafficQueueEntry entry = firstEntry;
                if (entry != null) {
                    firstEntry = null;
                } else {
                    if ((System.nanoTime() - batchStartNanos) >= maxWaitNanos) {
                        return null;
                    }
                    entry = queue.poll();
                }
                if (entry == null) {
                    return null;
                }
                if (!RuntimeConfig.isExportRunning()) {
                    return entry;
                }
                RuntimeConfig.TrafficExportGate gate = RuntimeConfig.trafficExportGate();
                if (RuntimeConfig.isExportReady()
                        && gate.anyTrafficExportEnabled()
                        && TrafficRouteBucket.isRouteEnabled(
                                TrafficRouteBucket.fromDocument(entry.document()), gate)) {
                    return entry;
                }
            }
            return null;
        }

        List<TrafficRouteBucket.Route> attemptedTrafficRoutes() {
            return attemptedTrafficRoutes;
        }

        List<PreparedExportDocument> acceptedDocumentsForFileEmit() {
            return acceptedDocumentsForFileEmit;
        }
    }
}
