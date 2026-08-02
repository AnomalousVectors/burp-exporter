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
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import ai.anomalousvectors.tools.burp.sinks.FileExportService;
import ai.anomalousvectors.tools.burp.sinks.TrafficQueueEntry;
import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.ExportLineCodec;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.export.SearchBodyPrefixFitter;

/**
 * Sends traffic documents to OpenSearch using a chunked POST to the standard Bulk API.
 *
 * <p>Drains prepared {@link ai.anomalousvectors.tools.burp.sinks.TrafficQueueEntry} items into one
 * NDJSON body (single materialization for SigV4/HTTP). Avoids a full {@code BulkRequest} in
 * memory. Uses only the production Bulk API ({@code POST /&lt;index&gt;/_bulk}); not the
 * experimental Streaming Bulk API. Thread-safe for concurrent calls; each call performs one bulk
 * request. Used only by the traffic export path.</p>
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
        /** Classified search database bulk outcome when available. */
        public final BulkOutcomeBreakdown breakdown;
        /** Search database bulk item failures aligned with the attempted document order. */
        public final List<OpenSearchClientWrapper.FailedItem> failedItems;

        /**
         * Creates a result without route attribution or explicit per-item details.
         *
         * @param successCount successfully indexed documents
         * @param attemptedCount attempted documents
         * @param attemptedBytes estimated bytes attempted
         * @param successBytes estimated bytes associated with successful documents
         */
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

        /**
         * Creates a result with traffic-route attribution.
         *
         * @param successCount successfully indexed documents
         * @param attemptedCount attempted documents
         * @param attemptedBytes estimated bytes attempted
         * @param successBytes estimated bytes associated with successful documents
         * @param trafficToolTypeSuccessCounts successful documents by tool type
         * @param trafficToolTypeFailureCounts failed documents by tool type
         * @param trafficSourceSuccessCounts successful documents by source bucket
         * @param trafficSourceFailureCounts failed documents by source bucket
         */
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

        /**
         * Creates a result with route attribution and a classified outcome.
         *
         * @param successCount successfully indexed documents
         * @param attemptedCount attempted documents
         * @param attemptedBytes estimated bytes attempted
         * @param successBytes estimated bytes associated with successful documents
         * @param trafficToolTypeSuccessCounts successful documents by tool type
         * @param trafficToolTypeFailureCounts failed documents by tool type
         * @param trafficSourceSuccessCounts successful documents by source bucket
         * @param trafficSourceFailureCounts failed documents by source bucket
         * @param breakdown classified bulk outcome; {@code null} becomes empty
         */
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

        /**
         * Creates a complete result with route attribution and per-item failures.
         *
         * <p>Map and list inputs are defensively copied.</p>
         *
         * @param successCount successfully indexed documents
         * @param attemptedCount attempted documents
         * @param attemptedBytes estimated bytes attempted
         * @param successBytes estimated bytes associated with successful documents
         * @param trafficToolTypeSuccessCounts successful documents by tool type
         * @param trafficToolTypeFailureCounts failed documents by tool type
         * @param trafficSourceSuccessCounts successful documents by source bucket
         * @param trafficSourceFailureCounts failed documents by source bucket
         * @param breakdown classified bulk outcome; {@code null} becomes empty
         * @param failedItems failures aligned with request order; {@code null} becomes empty
         */
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
        /**
         * Returns whether every attempted document succeeded.
         *
         * @return {@code true} when at least one document was attempted and all succeeded
         */
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
     * count (no request is sent). The method blocks while waiting for the first entry, offered-load
     * pacing, and HTTP completion. Interruption restores the interrupt flag and returns a
     * non-success result; stale or stopped export runs do not mutate current-run state.</p>
     *
     * @param baseUrl    search-database base URL
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
        RuntimeConfig.ExportRunToken token = RuntimeConfig.currentExportRunToken();
        if (!RuntimeConfig.isExportRunActive(token)) {
            return new Result(0, 0, 0L, 0L);
        }
        return ExportRunContext.call(
                token,
                () -> pushForRun(
                        baseUrl,
                        indexName,
                        indexKey,
                        queue,
                        maxBatch,
                        maxBytes,
                        maxWaitMs));
    }

    private static Result pushForRun(
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
        long maxWaitNanos = maxWaitMs * 1_000_000L;
        AtomicInteger attemptedRef = new AtomicInteger(0);
        AtomicLong attemptedBytesRef = new AtomicLong(0);
        NdjsonQueueInputStream ndjsonStream = new NdjsonQueueInputStream(
                queue, firstEntry, maxBatch, maxBytes, maxWaitNanos, attemptedRef, attemptedBytesRef);
        // Materialize once for SigV4/HTTP; avoids stream→entity→toByteArray double buffering.
        byte[] body;
        try {
            body = ndjsonStream.readAllBytes();
        } catch (IOException e) {
            closeQuietly(ndjsonStream);
            return failedResult(attemptedRef.get(), attemptedBytesRef.get(), ndjsonStream.attemptedTrafficRoutes());
        }
        List<TrafficRouteBucket.Route> attemptedTrafficRoutes = ndjsonStream.attemptedTrafficRoutes();
        Result result;
        ExportStats.BulkInFlightTicket ticket = ExportStats.openBulk();
        try (ticket) {
            try {
                result = executeRequest(
                        baseUrl, body, attemptedRef, attemptedBytesRef, indexName, attemptedTrafficRoutes);
            } catch (OpenSearchBulkHttpExecutor.LiveBudgetChangedException e) {
                ticket.close();
                OpenSearchClientWrapper.BulkResult refitted = PreparedBulkSender.push(
                        baseUrl,
                        indexName,
                        ndjsonStream.acceptedDocumentsForFileEmit());
                result = fromPreparedBulkResult(
                        refitted,
                        attemptedRef.get(),
                        attemptedBytesRef.get(),
                        attemptedTrafficRoutes);
            } catch (IOException | RuntimeException e) {
                long attemptedBytes = attemptedBytesRef.get();
                String reason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                if (ExportRunContext.allowsRunMutation()) {
                    Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                            + " ChunkedBulkSender push failed for " + indexName + ": " + reason);
                }
                result = failedResult(attemptedRef.get(), attemptedBytes, attemptedTrafficRoutes);
                if (!ExportRunContext.allowsRunMutation()) {
                    // Stale run: preserve the transport result without logs, retry, or pressure mutation.
                } else if (OpenSearchPushCancellation.shouldSuppressPushFailure(e)) {
                    Logger.logTrace(RuntimeConfig.searchDestinationLogPrefix()
                            + " Chunked bulk cancelled for " + indexName + " ("
                            + OpenSearchPushCancellation.cancelledPushLogSuffix(e) + ")");
                } else {
                    Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                            + " Chunked bulk push failed for " + indexName + ": " + reason
                            + formatFailureAttribution(result));
                    AmazonOpenSearchPressureLog.maybeNoteTransportPressure(reason, indexName, "Chunked bulk");
                    BulkRateLimitBackoff.noteTransportPressure(reason, indexName, "Chunked bulk");
                }
            } finally {
                FileExportService.emitPreparedChunk(ndjsonStream.acceptedDocumentsForFileEmit());
            }
        }
        if (ExportRunContext.allowsRunMutation()) {
            enqueueChunkedFailuresForRetry(indexName, indexKey, ndjsonStream.acceptedDocumentsForFileEmit(), result);
        }
        closeQuietly(ndjsonStream);
        return result;
    }

    private static Result fromPreparedBulkResult(
            OpenSearchClientWrapper.BulkResult prepared,
            int attemptedCount,
            long attemptedBytes,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes) {
        OpenSearchClientWrapper.BulkResult resolved = prepared != null
                ? prepared
                : new OpenSearchClientWrapper.BulkResult(
                        BulkOutcomeBreakdown.classified(0, attemptedCount),
                        List.of());
        Result attributed = routeAttributedResult(
                resolved.breakdown(),
                attemptedCount,
                attemptedTrafficRoutes,
                resolved.failedItems);
        long successBytes = attributed.successCount > 0 && attemptedCount > 0
                ? Math.round((double) attemptedBytes * attributed.successCount / attemptedCount)
                : 0L;
        return new Result(
                attributed.successCount,
                attributed.attemptedCount,
                attemptedBytes,
                successBytes,
                attributed.trafficToolTypeSuccessCounts,
                attributed.trafficToolTypeFailureCounts,
                attributed.trafficSourceSuccessCounts,
                attributed.trafficSourceFailureCounts,
                attributed.breakdown,
                attributed.failedItems);
    }

    private static void closeQuietly(InputStream stream) {
        try {
            stream.close();
        } catch (IOException ignored) {
            // NdjsonQueueInputStream holds no OS resources; close satisfies AutoCloseable analysis.
        }
    }

    /**
     * Offers documents from a failed chunked bulk to the shared retry drain.
     *
     * <p>Chunked traffic drains entries from the live queue before the HTTP outcome is known. Without
     * this hand-off, network errors and partial item failures would remain outstanding in Stats and
     * never recover. Permanent item failures are dropped by
     * {@link IndexingRetryCoordinator#enqueueFailedPreparedDocuments}.</p>
     */
    private static void enqueueChunkedFailuresForRetry(
            String indexName,
            String indexKey,
            List<PreparedExportDocument> attemptedDocuments,
            Result result) {
        if (result == null || result.isFullSuccess() || attemptedDocuments == null || attemptedDocuments.isEmpty()) {
            return;
        }
        IndexingRetryCoordinator.getInstance().enqueueFailedPreparedDocuments(
                indexName,
                indexKey,
                attemptedDocuments,
                result.failedItems,
                result.successCount);
    }

    /**
     * Builds a compact attribution suffix for chunked bulk failure WARN lines.
     *
     * <p>Includes document count, tool-type and source failure tallies when present, and the first
     * per-item error type/reason when the search database returned item failures.</p>
     *
     * @param result failed or partial chunked result; {@code null} yields an empty string
     * @return attribution text beginning with a leading space, or empty when nothing useful is known
     */
    static String formatFailureAttribution(Result result) {
        if (result == null || result.attemptedCount <= 0) {
            return "";
        }
        StringBuilder detail = new StringBuilder(96);
        detail.append(" docs=").append(result.attemptedCount);
        String tools = summarizeCountMap(result.trafficToolTypeFailureCounts);
        if (!tools.isEmpty()) {
            detail.append(" tools=").append(tools);
        }
        String sources = summarizeCountMap(result.trafficSourceFailureCounts);
        if (!sources.isEmpty()) {
            detail.append(" sources=").append(sources);
        }
        if (result.failedItems != null && !result.failedItems.isEmpty()) {
            OpenSearchClientWrapper.FailedItem first = result.failedItems.get(0);
            detail.append(" firstError=")
                    .append(first.type() == null || first.type().isBlank() ? "unknown" : first.type())
                    .append(':')
                    .append(clampReason(first.reason()));
        }
        return detail.toString();
    }

    private static String summarizeCountMap(Map<String, Integer> counts) {
        if (counts == null || counts.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null || entry.getValue() <= 0) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return sb.toString();
    }

    private static String clampReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "unknown";
        }
        String trimmed = reason.trim().replace('\n', ' ');
        return trimmed.length() <= 160 ? trimmed : trimmed.substring(0, 157) + "...";
    }

    private static Result executeRequest(
            String baseUrl,
            byte[] body,
            AtomicInteger attemptedRef,
            AtomicLong attemptedBytesRef,
            String indexName,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes) throws IOException {
        long liveBudget = Math.max(1L, BulkByteBudget.currentMaxBytes());
        if (body.length > liveBudget) {
            String type = body.length > BulkByteBudget.ADAPTIVE_MAX_BYTES
                    ? BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE
                    : "live_bulk_budget_exceeded";
            if (!BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE.equals(type)) {
                Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                        + " Refused over-budget chunked bulk before HTTP:"
                        + " index=" + (indexName == null || indexName.isBlank() ? "unknown" : indexName)
                        + " bytes=" + body.length
                        + " liveBudget=" + liveBudget
                        + " documents=" + attemptedRef.get() + ".");
            }
            return failedResult(
                    attemptedRef.get(),
                    attemptedBytesRef.get(),
                    attemptedTrafficRoutes,
                    type,
                    "Chunked NDJSON exceeded the live bulk budget before HTTP"
                            + " fittedBytes=" + body.length
                            + " liveBudget=" + liveBudget
                            + " absoluteMax=" + BulkByteBudget.ADAPTIVE_MAX_BYTES);
        }
        return OpenSearchBulkHttpExecutor.executeBulkPost(
                baseUrl,
                indexName,
                body,
                (response, requestId) -> {
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
                Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                        + " ChunkedBulkSender bulk request failed: "
                        + OpenSearchLogFormat.formatStatusAndIndentedBody(status, responseBody));
                String detail = responseBody != null && responseBody.contains("request body is required")
                        ? " Search database reported an empty bulk request body."
                        : "";
                if (status == 401 || status == 403) {
                    detail += " Authentication rejected - verify credentials"
                            + " (bearer/API key/session token may have expired).";
                    IndexingRetryCoordinator.getInstance()
                            .noteHttpAuthorizationFailure(baseUrl, status);
                }
                Result failed = failedResult(attempted, attemptedBytes, attemptedTrafficRoutes);
                if (BulkRateLimitBackoff.isRateLimited(status)) {
                    BulkRateLimitBackoff.noteRateLimited(status, response, indexName, "Chunked bulk");
                } else {
                    Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                            + " Chunked bulk request failed for "
                            + indexName + ": HTTP " + status + "." + detail
                            + formatFailureAttribution(failed));
                    AmazonOpenSearchPressureLog.maybeNoteHttpPressure(status, indexName, "Chunked bulk");
                }
                return failed;
            }
            Result parsed = parseBulkResponse(
                    responseBody, attempted, attemptedTrafficRoutes, indexName, requestId);
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
     *
     * @param post mutable request that receives a sensitive Authorization header when configured
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

    /**
     * Builds the bulk endpoint URL without encoding the caller-provided index name.
     *
     * @param baseUrl database base URL; {@code null} becomes blank
     * @param indexName prevalidated index name
     * @return bulk endpoint URL
     */
    static String buildBulkUrl(String baseUrl, String indexName) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        return base + "/" + indexName + "/_bulk";
    }

    /**
     * Parses a response without traffic-route attribution.
     *
     * @param responseBody raw bulk response
     * @param attemptedCount expected request item count
     * @return normalized result with explicit failures for malformed or omitted items
     */
    static Result parseBulkResponse(String responseBody, int attemptedCount) {
        return parseBulkResponse(responseBody, attemptedCount, List.of(), "");
    }

    /**
     * Parses a response and attributes item outcomes to attempted traffic routes.
     *
     * @param responseBody raw bulk response
     * @param attemptedCount expected request item count
     * @param attemptedTrafficRoutes routes aligned with request order
     * @param indexName target index used in diagnostics
     * @return normalized and attributed result
     */
    static Result parseBulkResponse(
            String responseBody,
            int attemptedCount,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes,
            String indexName) {
        return parseBulkResponse(
                responseBody, attemptedCount, attemptedTrafficRoutes, indexName, -1L);
    }

    private static Result parseBulkResponse(
            String responseBody,
            int attemptedCount,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes,
            String indexName,
            long requestId) {
        if (responseBody == null || responseBody.isBlank()) {
            return failedResult(
                    attemptedCount,
                    0,
                    attemptedTrafficRoutes,
                    "bulk_response_parse_exception",
                    "Bulk response body was blank");
        }
        BulkNdjsonResponseParser.ParsedBulk parsed = BulkNdjsonResponseParser.parse(responseBody, indexName);
        if (requestId > 0L) {
            BulkNdjsonResponseParser.warnIfOutcomeFlagMismatch(parsed, indexName, requestId);
        }
        if (parsed.successCount() == 0 && parsed.failedItems().isEmpty() && attemptedCount > 0) {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Chunked bulk response parsing failed for "
                    + (indexName == null || indexName.isBlank() ? "unknown" : indexName) + ".");
            return failedResult(
                    attemptedCount,
                    0,
                    attemptedTrafficRoutes,
                    "bulk_response_parse_exception",
                    "Bulk response could not be parsed into item outcomes");
        }
        int observed = parsed.breakdown().successTotal() + parsed.breakdown().failed();
        List<OpenSearchClientWrapper.FailedItem> completedFailures =
                new ArrayList<>(parsed.failedItems());
        BulkOutcomeBreakdown completedBreakdown = parsed.breakdown();
        if (observed < attemptedCount) {
            for (int index = observed; index < attemptedCount; index++) {
                completedFailures.add(new OpenSearchClientWrapper.FailedItem(
                        index,
                        "bulk_response_incomplete",
                        "Bulk response omitted this attempted item"));
            }
            completedBreakdown = completedBreakdown.plus(
                    BulkOutcomeBreakdown.classified(0, attemptedCount - observed));
        }
        return routeAttributedResult(
                completedBreakdown, attemptedCount, attemptedTrafficRoutes, completedFailures);
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
        return failedResult(
                attemptedCount,
                attemptedBytes,
                attemptedTrafficRoutes,
                "transient_bulk_failure",
                "Bulk request failed before exact item outcomes were available");
    }

    private static Result failedResult(
            int attemptedCount,
            long attemptedBytes,
            List<TrafficRouteBucket.Route> attemptedTrafficRoutes,
            String type,
            String reason) {
        Map<String, Integer> toolTypeFailureCounts = new LinkedHashMap<>();
        Map<String, Integer> sourceFailureCounts = new LinkedHashMap<>();
        List<OpenSearchClientWrapper.FailedItem> failedItems =
                new ArrayList<>(Math.max(0, attemptedCount));
        for (int i = 0; i < attemptedTrafficRoutes.size(); i++) {
            recordRouteCount(attemptedTrafficRoutes, i, toolTypeFailureCounts, sourceFailureCounts);
        }
        for (int index = 0; index < attemptedCount; index++) {
            failedItems.add(new OpenSearchClientWrapper.FailedItem(index, type, reason));
        }
        return new Result(
                0,
                attemptedCount,
                attemptedBytes,
                0,
                Map.of(),
                toolTypeFailureCounts,
                Map.of(),
                sourceFailureCounts,
                BulkOutcomeBreakdown.classified(0, attemptedCount),
                failedItems);
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

    static void noteTrafficPrefixTruncation(PreparedExportDocument prepared, long maxBytes) {
        boolean firstTruncation = ExportStats.recordSearchBodyPrefixTruncationOnce(
                prepared.operationId(), TrafficRouteBucket.INDEX_KEY);
        if (firstTruncation) {
            Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Prefix-truncated traffic document to fit live bulk budget "
                    + maxBytes + " bytes (search path only; files sink unchanged).");
        }
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
        /** Originals for docs that entered the search NDJSON body (aligned with bulk item indexes). */
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
                PreparedExportDocument searchDoc = prepared;
                byte[] ndjson = prepared.bulkNdjsonBytes();
                if (ndjson != null && ndjson.length > 0) {
                    buffer = ndjson;
                } else {
                    ByteArrayOutputStream chunk = new ByteArrayOutputStream();
                    ExportLineCodec.writeBulkNdjson(chunk, prepared);
                    buffer = chunk.toByteArray();
                }
                long docBytes = buffer.length > 0 ? buffer.length : prepared.resolvedBulkBytes();
                if (docBytes > maxBytes) {
                    searchDoc = SearchBodyPrefixFitter.fitToBudget(prepared, maxBytes);
                    buffer = searchDoc.bulkNdjsonBytes();
                    if (buffer == null || buffer.length == 0) {
                        ByteArrayOutputStream chunk = new ByteArrayOutputStream();
                        ExportLineCodec.writeBulkNdjson(chunk, searchDoc);
                        buffer = chunk.toByteArray();
                    }
                    docBytes = buffer.length;
                    if (docBytes <= maxBytes
                            && SearchBodyPrefixFitter.didTruncate(prepared, searchDoc)) {
                        noteTrafficPrefixTruncation(prepared, maxBytes);
                    }
                }
                if (attemptedRef.get() > 0 && runningBytes + docBytes > maxBytes) {
                    queue.offer(entry);
                    buffer = new byte[0];
                    pos = 0;
                    return false;
                }
                pos = 0;
                attemptedRef.incrementAndGet();
                runningBytes += docBytes;
                attemptedBytesRef.addAndGet(docBytes);
                attemptedTrafficRoutes.add(TrafficRouteBucket.fromDocument(prepared.document()));
                // Files always receive the original prepared document (full bodies).
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
                if (!RuntimeConfig.isExportReady()) {
                    // A Stop/not-ready transition after the batch began must retain ownership of
                    // this polled document. Include it in the current attempt so the result is
                    // explicitly retried or drop-accounted instead of silently losing it.
                    return entry;
                }
                RuntimeConfig.TrafficExportGate gate = RuntimeConfig.trafficExportGate();
                if (gate.anyTrafficExportEnabled()
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
