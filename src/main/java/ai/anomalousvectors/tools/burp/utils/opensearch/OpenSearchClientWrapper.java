package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotFlushExecutor;
import ai.anomalousvectors.tools.burp.sinks.FileExportService;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionStatus;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;

import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Wraps OpenSearch connection tests and document push operations for the exporter.
 *
 * <p>This facade coordinates OpenSearch writes with file export, retry handling, and runtime
 * authentication settings so callers can use a small API surface.</p>
 */
public class OpenSearchClientWrapper {

    /**
     * Tests OpenSearch connectivity without authentication.
     *
     * @param baseUrl OpenSearch base URL
     * @return structured connection status
     */
    public static SearchConnectionStatus testConnection(String baseUrl) {
        return testConnection(baseUrl, null, null);
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Tests connectivity with optional basic auth. Performs a raw GET / so logs show the actual
     * HTTP version and status line from the wire; on 200 parses the response body for version/distribution.
     *
     * @param baseUrl OpenSearch base URL
     * @param username optional basic-auth username
     * @param password optional basic-auth password
     * @return structured connection status
     */
    public static SearchConnectionStatus testConnection(String baseUrl, String username, String password) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return testConnection(baseUrl, auth);
    }

    /** Tests connectivity with the selected upstream OpenSearch auth mode. */
    public static SearchConnectionStatus testConnection(String baseUrl, OpenSearchAuth auth) {
        OpenSearchAuth resolvedAuth = auth == null ? OpenSearchAuth.none() : auth;
        boolean credentialsProvided = resolvedAuth.mode() != OpenSearchAuth.Mode.NONE && resolvedAuth.isComplete();
        Logger.logDebug("[OpenSearch] Testing connection: url=" + baseUrl
                + ", tlsMode=" + OpenSearchTlsSupport.currentTlsMode()
                + ", pinnedCertificateLoaded=" + OpenSearchTlsSupport.hasPinnedCertificate()
                + ", credentialsProvided=" + credentialsProvided);
        OpenSearchRawGet.RawGetResult result = OpenSearchRawGet.performRawGet(baseUrl, resolvedAuth);

        // Log request/response only when we actually got an HTTP response from the server.
        // For client-side failures (e.g. SSL handshake never completed), no HTTP was exchanged — do not log reconstructed request/response.
        if (result.statusCode() > 0) {
            Logger.logDebug("[OpenSearch] Request:\n" + OpenSearchLogFormat.indentRaw(result.requestForLog()));
            String responseLog = OpenSearchLogFormat.buildRawResponseWithHeaders(
                    result.body(), result.protocol(), result.statusCode(),
                    result.reasonPhrase() != null ? result.reasonPhrase() : "",
                    result.responseHeaderLines());
            Logger.logDebug("[OpenSearch] Response:\n" + OpenSearchLogFormat.indentRaw(responseLog));
        }

        if (result.statusCode() == 200) {
            String version = "";
            String distribution = "";
            if (result.body() != null && !result.body().isBlank()) {
                try {
                    JsonNode root = JSON.readTree(result.body());
                    JsonNode ver = root.path("version");
                    version = ver.path("number").asText("");
                    distribution = ver.path("distribution").asText("");
                } catch (IOException | RuntimeException ignored) {
                    // Version JSON is optional; connection still succeeds with blank version fields.
                }
            }
            SearchConnectionStatus status = new SearchConnectionStatus(
                    "OpenSearch",
                    true,
                    distribution,
                    version,
                    "Connection successful",
                    "Success",
                    credentialsProvided ? "Successful" : "Not used",
                    OpenSearchTlsSupport.successTrustSummary(baseUrl)
            );
            Logger.logDebug("[OpenSearch] Connection test succeeded: auth=" + status.authenticationStatus()
                    + ", trust=" + status.trustStatus()
                    + ", version=" + status.version());
            return status;
        }

        String msg = result.statusCode() == 0
                ? (result.reasonPhrase() != null ? result.reasonPhrase() : "Connection failed")
                : "HTTP " + result.statusCode() + (result.reasonPhrase() != null && !result.reasonPhrase().isBlank() ? " " + result.reasonPhrase() : "");
        String trustStatus = OpenSearchTlsSupport.failureTrustSummary(baseUrl, msg);
        Logger.logErrorPanelOnly("[OpenSearch] Connection failed for " + baseUrl + ": " + msg
                + " | tlsMode=" + OpenSearchTlsSupport.currentTlsMode()
                + " | trust=" + trustStatus);
        String authStatus = switch (result.statusCode()) {
            case 401, 403 -> "Failed";
            case 0 -> "Not tested";
            default -> credentialsProvided ? "Attempted" : "Not used";
        };
        return new SearchConnectionStatus(
                "OpenSearch",
                false,
                "",
                "",
                msg,
                "Failed",
                authStatus,
                trustStatus
        );
    }

    /**
     * Tests OpenSearch connectivity without authentication, converting runtime failures into a
     * failed status result.
     *
     * @param baseUrl OpenSearch base URL
     * @return structured connection status
     */
    public static SearchConnectionStatus safeTestConnection(String baseUrl) {
        return safeTestConnection(baseUrl, null, null);
    }

    /**
     * Tests OpenSearch connectivity and converts runtime failures into a failed status result.
     *
     * @param baseUrl OpenSearch base URL
     * @param username optional basic-auth username
     * @param password optional basic-auth password
     * @return structured connection status
     */
    public static SearchConnectionStatus safeTestConnection(String baseUrl, String username, String password) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return safeTestConnection(baseUrl, auth);
    }

    /** Tests OpenSearch connectivity with selected auth and converts runtime failures into a failed status result. */
    public static SearchConnectionStatus safeTestConnection(String baseUrl, OpenSearchAuth auth) {
        try {
            return testConnection(baseUrl, auth);
        } catch (RuntimeException e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            Logger.logErrorPanelOnly(sw.toString().stripTrailing());
            String trustStatus = OpenSearchTlsSupport.failureTrustSummary(baseUrl, msg);
            Logger.logErrorPanelOnly("[OpenSearch] safeTestConnection threw for " + baseUrl
                    + ": " + msg + " | tlsMode=" + OpenSearchTlsSupport.currentTlsMode()
                    + " | trust=" + trustStatus);
            return new SearchConnectionStatus(
                    "OpenSearch",
                    false,
                    "",
                    "",
                    msg,
                    "Failed",
                    "Not tested",
                    trustStatus
            );
        }
    }

    /**
     * Pushes a single document. Delegates to the retry coordinator (one attempt, then queue on failure).
     *
     * <p>Documents are filtered to include only fields enabled in the Fields panel before push.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param document the document to index (filtered by {@link ai.anomalousvectors.tools.burp.utils.config.ExportFieldFilter})
     * @return {@code true} if indexed successfully, {@code false} otherwise
     */
    public static boolean pushDocument(String baseUrl, String indexName, String indexKey, Map<String, Object> document) {
        return pushDocumentDuringShutdown(baseUrl, indexName, indexKey, document, false).success();
    }

    /**
     * Pushes one document during export Stop or unload when {@code exportRunning} is already false.
     *
     * <p>Uses a one-shot OpenSearch index attempt (no retry queue) so final exporter stats can be
     * written after the UI sets export stopped but before connectors close.</p>
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param indexKey logical index key for stats
     * @param document document to index
     * @param duringShutdown when {@code true}, bypasses {@link RuntimeConfig#isExportReady()}
     * @return structured outcome including failure detail when available
     */
    public static ShutdownDocumentPushResult pushDocumentDuringShutdown(
            String baseUrl,
            String indexName,
            String indexKey,
            Map<String, Object> document,
            boolean duringShutdown) {
        PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, document);
        FileExportService.emit(prepared);
        if (!RuntimeConfig.isOpenSearchExportEnabled() || baseUrl == null || baseUrl.isBlank()) {
            boolean ok = RuntimeConfig.isAnyFileExportEnabled();
            return new ShutdownDocumentPushResult(ok, ok ? null : "file sink write failed");
        }
        SingleDocPushResult result = duringShutdown
                ? IndexingRetryCoordinator.getInstance().pushPreparedDocumentDuringShutdown(baseUrl, prepared)
                : IndexingRetryCoordinator.getInstance().pushPreparedDocumentWithResult(baseUrl, prepared);
        if (result.success()) {
            ExportStats.recordBulkBreakdown(indexKey, result.breakdown());
            ExportStats.recordExportedBytes(indexKey, prepared.estimatedBulkBytes());
        }
        return new ShutdownDocumentPushResult(result.success(), result.failureDetail());
    }

    /**
     * Outcome of a shutdown-tolerant single-document push.
     *
     * @param success whether the document reached the configured sink
     * @param failureDetail root failure message when {@code success} is false; may be {@code null}
     */
    public record ShutdownDocumentPushResult(boolean success, String failureDetail) {

        /**
         * Returns whether the push succeeded.
         *
         * @return {@code true} when indexed or written to file sink
         */
        public boolean succeeded() {
            return success;
        }

        /**
         * Returns a log-safe failure reason.
         *
         * @return detail string or a generic fallback when blank
         */
        public String resolvedFailureDetail() {
            if (failureDetail == null || failureDetail.isBlank()) {
                return "OpenSearch push returned false";
            }
            return failureDetail;
        }
    }

    /**
     * Pushes already-prepared documents in bulk without re-filtering or re-estimating payload size.
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param indexKey logical index key for stats and retry routing
     * @param preparedDocuments sink-ready documents from {@link ExportDocumentIdentity#prepare}
     * @return number of documents successfully indexed
     */
    public static BulkPushOutcome pushPreparedBulk(
            String baseUrl,
            String indexName,
            String indexKey,
            List<PreparedExportDocument> preparedDocuments) {
        if (preparedDocuments == null || preparedDocuments.isEmpty()) {
            return BulkPushOutcome.empty();
        }
        int attempted = preparedDocuments.size();
        boolean fileActive = RuntimeConfig.isAnyFileExportEnabled();
        boolean openSearchActive = RuntimeConfig.isOpenSearchExportEnabled()
                && baseUrl != null
                && !baseUrl.isBlank();
        if (fileActive && openSearchActive) {
            return pushPreparedBulkDualSink(baseUrl, indexName, indexKey, preparedDocuments, attempted);
        }
        if (fileActive) {
            long fileStartNs = System.nanoTime();
            FileExportService.emitPreparedChunk(preparedDocuments);
            long fileFlushMs = (System.nanoTime() - fileStartNs) / 1_000_000L;
            return BulkPushOutcome.fileOnly(attempted, fileFlushMs);
        }
        return pushPreparedBulkOpenSearchOnly(baseUrl, indexName, indexKey, preparedDocuments, attempted);
    }

    private static BulkPushOutcome pushPreparedBulkDualSink(
            String baseUrl,
            String indexName,
            String indexKey,
            List<PreparedExportDocument> preparedDocuments,
            int attempted) {
        CompletableFuture<Long> fileFuture = CompletableFuture.supplyAsync(() -> {
            long startNs = System.nanoTime();
            FileExportService.emitPreparedChunk(preparedDocuments);
            return (System.nanoTime() - startNs) / 1_000_000L;
        }, SnapshotFlushExecutor.dualSinkExecutor());
        CompletableFuture<BulkPushOutcome> openSearchFuture = CompletableFuture.supplyAsync(
                () -> pushPreparedBulkOpenSearchOnly(baseUrl, indexName, indexKey, preparedDocuments, attempted),
                SnapshotFlushExecutor.dualSinkExecutor());
        try {
            long fileFlushMs = fileFuture.get();
            BulkPushOutcome openSearchOutcome = openSearchFuture.get();
            return new BulkPushOutcome(
                    openSearchOutcome.attempted(),
                    openSearchOutcome.exportedCount(),
                    openSearchOutcome.breakdown(),
                    fileFlushMs,
                    openSearchOutcome.openSearchFlushMs());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fileFuture.cancel(true);
            openSearchFuture.cancel(true);
            return BulkPushOutcome.empty();
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            Logger.logWarnPanelOnly("[OpenSearch] Dual-sink bulk push failed for "
                    + indexName + ": "
                    + (cause != null ? cause.getMessage() : e.getMessage()));
            return BulkPushOutcome.empty();
        }
    }

    private static BulkPushOutcome pushPreparedBulkOpenSearchOnly(
            String baseUrl,
            String indexName,
            String indexKey,
            List<PreparedExportDocument> preparedDocuments,
            int attempted) {
        long totalEstimatedBytes = 0;
        for (PreparedExportDocument preparedDoc : preparedDocuments) {
            totalEstimatedBytes += preparedDoc.estimatedBulkBytes();
        }
        long osStartNs = System.nanoTime();
        BulkResult bulkResult = IndexingRetryCoordinator.getInstance()
                .pushPreparedBulkWithResult(baseUrl, indexName, preparedDocuments, indexKey);
        long openSearchFlushMs = (System.nanoTime() - osStartNs) / 1_000_000L;
        BulkOutcomeBreakdown breakdown = bulkResult.breakdown();
        int exported = breakdown.exportedCount();
        if (exported > 0) {
            long estimatedSuccessBytes = Math.round(
                    (double) totalEstimatedBytes * exported / attempted);
            ExportStats.recordExportedBytes(indexKey, estimatedSuccessBytes);
        }
        return new BulkPushOutcome(attempted, exported, breakdown, -1L, openSearchFlushMs);
    }

    /**
     * One-shot prepared bulk using pre-serialized NDJSON bytes when present. Used by the retry
     * coordinator.
     */
    static BulkResult doPushPreparedBulkWithDetails(
            String baseUrl,
            String indexName,
            List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return new BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        for (PreparedExportDocument document : documents) {
            byte[] bytes = document.bulkNdjsonBytes();
            if (bytes == null || bytes.length == 0) {
                List<Map<String, Object>> preparedDocs = new ArrayList<>(documents.size());
                for (PreparedExportDocument preparedDoc : documents) {
                    preparedDocs.add(preparedDoc.document());
                }
                BulkResult result = doPushBulkWithDetails(baseUrl, indexName, preparedDocs);
                return result;
            }
        }
        BulkResult result = PreparedBulkSender.push(baseUrl, indexName, documents);
        return result;
    }

    /**
     * Pushes documents in bulk after prepare. Delegates to the retry coordinator.
     *
     * <p>Snapshot reporters use {@link #pushPreparedBulk} directly when documents are already
     * prepared. Live traffic uses {@link ChunkedBulkSender#push} instead.</p>
     */
    public static int pushBulk(String baseUrl, String indexName, String indexKey, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            return 0;
        }
        List<PreparedExportDocument> prepared = new ArrayList<>(documents.size());
        for (Map<String, Object> doc : documents) {
            prepared.add(ExportDocumentIdentity.prepare(indexName, indexKey, doc));
        }
        return pushPreparedBulk(baseUrl, indexName, indexKey, prepared).successCount();
    }

    /** One-shot prepared document push using the shared Bulk API path. */
    static SingleDocPushResult doPushPreparedDocument(String baseUrl, PreparedExportDocument document) {
        if (document == null) {
            return new SingleDocPushResult(false, BulkOutcomeBreakdown.empty(), "document is null");
        }
        BulkResult bulkResult = doPushPreparedBulkWithDetails(baseUrl, document.indexName(), List.of(document));
        boolean success = bulkResult.successCount() > 0;
        String detail = success || bulkResult.failedItems.isEmpty()
                ? null
                : bulkResult.failedItems.get(0).reason();
        return new SingleDocPushResult(success, bulkResult.breakdown(), detail);
    }

    /**
     * One-shot bulk with per-item failure details. Response items match request order.
     */
    static BulkResult doPushBulkWithDetails(String baseUrl, String indexName, List<Map<String, Object>> documents) {
        if (documents == null || documents.isEmpty()) {
            // OpenSearch rejects empty bulk requests with "request body is required"; short-circuit
            // here so every reporter/bulk entry point shares the same guard as the chunked path.
            return new BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        ExportStats.BulkInFlightTicket ticket = ExportStats.openBulk();
        try (ticket) {
            OpenSearchClient client = OpenSearchConnector.getClient(baseUrl, OpenSearchAuth.fromRuntime());
            BulkRequest.Builder builder = new BulkRequest.Builder();
            for (Map<String, Object> doc : documents) {
                builder.operations(o -> o.index(i -> i.index(indexName).document(doc)));
            }
            BulkResponse response = client.bulk(builder.build());
            int created = 0;
            int updated = 0;
            int noop = 0;
            int failed = 0;
            List<FailedItem> failedItems = new ArrayList<>();
            final int maxLoggedPerBulk = 3;
            int i = 0;
            int logged = 0;
            for (var item : response.items()) {
                var err = item.error();
                if (err == null) {
                    BulkOutcomeBreakdown single = breakdownFromIndexResult(item.result());
                    created += single.created();
                    updated += single.updated();
                    noop += single.noop();
                } else {
                    failed++;
                    String type = err.type();
                    String reason = err.reason() != null ? err.reason() : "unknown";
                    failedItems.add(new FailedItem(i, type, reason));
                    if (logged < maxLoggedPerBulk) {
                        Logger.logError(formatBulkItemFailure(indexName, i, type, reason));
                        logged++;
                    }
                }
                i++;
            }
            if (failedItems.size() > maxLoggedPerBulk) {
                Logger.logError("[OpenSearch] Bulk item failure summary: index=" + indexName
                        + " additional=" + (failedItems.size() - maxLoggedPerBulk)
                        + " totalFailed=" + failedItems.size());
            }
            return new BulkResult(new BulkOutcomeBreakdown(created, updated, noop, failed), failedItems);
        } catch (IOException | RuntimeException e) {
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            logPushOutcome(indexName, "doPushBulk", e);
            if (!OpenSearchPushCancellation.shouldSuppressPushFailure(e) && msg.contains("request body is required")) {
                Logger.logWarnPanelOnly("[OpenSearch] Bulk request failed for "
                        + indexName + ": OpenSearch reported an empty bulk request body.");
            }
            return new BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
    }

    private static BulkOutcomeBreakdown breakdownFromIndexResult(String result) {
        if (result == null || result.isBlank()) {
            return BulkOutcomeBreakdown.assumeExported(1);
        }
        return switch (result.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "created" -> new BulkOutcomeBreakdown(1, 0, 0, 0);
            case "updated" -> new BulkOutcomeBreakdown(0, 1, 0, 0);
            case "noop" -> new BulkOutcomeBreakdown(0, 0, 1, 0);
            default -> BulkOutcomeBreakdown.assumeExported(1);
        };
    }

    /**
     * Formats one per-item bulk failure as a single structured ERROR log line.
     *
     * <p>Format is line-stable so log greps and tests can rely on it. Reason is clamped to
     * avoid a single pathological doc flooding the log panel.</p>
     */
    /**
     * Logs a cancelled push at TRACE or a real failure at DEBUG with a stable {@code [OpenSearch]} prefix.
     */
    private static void logPushOutcome(String indexName, String operation, Exception e) {
        if (OpenSearchPushCancellation.shouldSuppressPushFailure(e)) {
            Logger.logTrace("[OpenSearch] " + operation + " cancelled for " + indexName + " ("
                    + OpenSearchPushCancellation.cancelledPushLogSuffix(e) + ")");
            return;
        }
        String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        Logger.logDebug("[OpenSearch] " + operation + " failed for " + indexName + ": " + msg);
    }

    static String formatBulkItemFailure(String indexName, int opIndex, String type, String reason) {
        String clampedReason = reason == null ? "unknown" : reason;
        if (clampedReason.length() > 500) {
            clampedReason = clampedReason.substring(0, 497) + "...";
        }
        return "[OpenSearch] Bulk item failure: index=" + indexName
                + " op=" + opIndex
                + " type=" + (type == null || type.isBlank() ? "unknown" : type)
                + " reason=" + clampedReason;
    }

    /** Single failed bulk item: zero-based request index, OpenSearch error type, and reason. */
    public record FailedItem(int index, String type, String reason) {
        public FailedItem {
            type = type == null ? "unknown" : type;
            reason = reason == null ? "unknown" : reason;
        }
    }

    static final class BulkResult {
        final BulkOutcomeBreakdown breakdown;
        final List<FailedItem> failedItems;

        BulkResult(BulkOutcomeBreakdown breakdown, List<FailedItem> failedItems) {
            this.breakdown = breakdown != null ? breakdown : BulkOutcomeBreakdown.empty();
            this.failedItems = failedItems != null ? List.copyOf(failedItems) : List.of();
        }

        int successCount() {
            return breakdown.successTotal();
        }

        BulkOutcomeBreakdown breakdown() {
            return breakdown;
        }
    }

    static final class SingleDocPushResult {
        final boolean success;
        final BulkOutcomeBreakdown breakdown;
        final String failureDetail;

        SingleDocPushResult(boolean success, BulkOutcomeBreakdown breakdown, String failureDetail) {
            this.success = success;
            this.breakdown = breakdown != null ? breakdown : BulkOutcomeBreakdown.empty();
            this.failureDetail = failureDetail;
        }

        boolean success() {
            return success;
        }

        BulkOutcomeBreakdown breakdown() {
            return breakdown;
        }

        String failureDetail() {
            return failureDetail;
        }
    }
}
