package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.PreparedBulkBodies;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Posts pre-serialized snapshot bulk NDJSON to OpenSearch without rebuilding {@code BulkRequest}
 * objects from document maps on the flush thread.
 */
public final class PreparedBulkSender {

    private PreparedBulkSender() {}

    /**
     * Sends one bulk request built from prepared NDJSON bytes.
     *
     * @param baseUrl OpenSearch base URL
     * @param indexName target index name
     * @param documents prepared documents for the chunk
     * @return per-item bulk outcome; never {@code null}
     */
    static OpenSearchClientWrapper.BulkResult push(
            String baseUrl,
            String indexName,
            List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        byte[] body = PreparedBulkBodies.concatenate(documents);
        if (body.length == 0) {
            return new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        HttpPost post = new HttpPost(OpenSearchClassicHttpSupport.bulkPathForIndex(indexName));
        post.setEntity(new ByteArrayEntity(body, ContentType.create("application/x-ndjson")));
        ChunkedBulkSender.addPreemptiveAuthHeader(post);
        ExportStats.BulkInFlightTicket ticket = ExportStats.openBulk();
        try (ticket) {
            return executeRequest(post, baseUrl, indexName, documents.size());
        } catch (IOException | RuntimeException e) {
            logPushFailure(indexName, e);
            return failedBulkResult(documents.size());
        }
    }

    private static OpenSearchClientWrapper.BulkResult executeRequest(
            HttpPost post,
            String baseUrl,
            String indexName,
            int attemptedCount) throws IOException {
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
            if (status < 200 || status >= 300) {
                Logger.logDebug("[OpenSearch] PreparedBulkSender bulk request failed: " + status + " " + responseBody);
                String detail = responseBody != null && responseBody.contains("request body is required")
                        ? " OpenSearch reported an empty bulk request body."
                        : "";
                Logger.logWarnPanelOnly("[OpenSearch] Prepared bulk request failed for "
                        + indexName + ": HTTP " + status + "." + detail);
                return failedBulkResult(attemptedCount);
            }
            return parseBulkResponse(responseBody, attemptedCount, indexName);
        });
    }

    static OpenSearchClientWrapper.BulkResult parseBulkResponse(
            String responseBody,
            int attemptedCount,
            String indexName) {
        if (responseBody == null || responseBody.isBlank()) {
            return failedBulkResult(attemptedCount);
        }
        BulkNdjsonResponseParser.ParsedBulk parsed = BulkNdjsonResponseParser.parse(responseBody, indexName);
        if (parsed.successCount() == 0 && parsed.failedItems().isEmpty() && attemptedCount > 0) {
            Logger.logWarnPanelOnly("[OpenSearch] Prepared bulk response parsing failed for "
                    + (indexName == null || indexName.isBlank() ? "unknown" : indexName) + ".");
            return failedBulkResult(attemptedCount);
        }
        return new OpenSearchClientWrapper.BulkResult(parsed.breakdown(), parsed.failedItems());
    }

    private static OpenSearchClientWrapper.BulkResult failedBulkResult(int attemptedCount) {
        return new OpenSearchClientWrapper.BulkResult(
                BulkOutcomeBreakdown.classified(0, attemptedCount), List.of());
    }

    private static void logPushFailure(String indexName, Exception e) {
        if (OpenSearchPushCancellation.shouldSuppressPushFailure(e)) {
            Logger.logTrace("[OpenSearch] Prepared bulk cancelled for " + indexName + " ("
                    + OpenSearchPushCancellation.cancelledPushLogSuffix(e) + ")");
            return;
        }
        String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        Logger.logDebug("[OpenSearch] Prepared bulk failed for " + indexName + ": " + msg);
    }
}
