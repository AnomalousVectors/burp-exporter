package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;

/**
 * Parses search database bulk NDJSON HTTP response bodies into success and per-item failure details.
 *
 * <p>Shared by {@link PreparedBulkSender} and {@link ChunkedBulkSender} so snapshot, live, and
 * retry paths emit identical failure logging.</p>
 *
 * <p>Stateless and safe for concurrent callers. Item failure reasons are length-bounded by the
 * logging facade but are not secret-redacted; response bodies must not contain credentials.</p>
 */
public final class BulkNdjsonResponseParser {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_LOGGED_FAILURES = 3;

    private BulkNdjsonResponseParser() { }

    /**
     * Parsed bulk outcome with per-item failures and the response's top-level consistency signal.
     *
     * @param breakdown classified item outcomes
     * @param failedItems per-item failures aligned to request order
     * @param responseErrors top-level {@code errors} value, or {@code null} when absent/non-boolean
     * @param responseItemCount number of item outcomes present in the response
     */
    public record ParsedBulk(
            BulkOutcomeBreakdown breakdown,
            List<OpenSearchClientWrapper.FailedItem> failedItems,
            Boolean responseErrors,
            int responseItemCount) {

        public ParsedBulk {
            breakdown = breakdown != null ? breakdown : BulkOutcomeBreakdown.empty();
            failedItems = failedItems != null ? List.copyOf(failedItems) : List.of();
            responseItemCount = Math.max(0, responseItemCount);
        }

        /**
         * Returns successful item outcomes in the response.
         *
         * @return non-negative successful item count
         */
        public int successCount() {
            return breakdown.successTotal();
        }

        /**
         * Returns whether the top-level {@code errors} flag disagrees with item statuses.
         *
         * @return {@code true} when an explicit summary flag contradicts parsed failures
         */
        public boolean hasOutcomeFlagMismatch() {
            return responseErrors != null
                    && responseErrors.booleanValue() != !failedItems.isEmpty();
        }
    }

    /**
     * Parses a bulk response body.
     *
     * @param responseBody raw HTTP response body
     * @param indexName index name for structured failure logs
     * @return parsed outcome; zero success when body is blank or malformed
     *
     * <p>Logs at most three item failure reasons plus one aggregate summary.</p>
     */
    public static ParsedBulk parse(String responseBody, String indexName) {
        if (responseBody == null || responseBody.isBlank()) {
            return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of(), null, 0);
        }
        try {
            JsonNode root = JSON.readTree(responseBody);
            JsonNode items = root.get("items");
            if (items == null || !items.isArray()) {
                return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of(), responseErrors(root), 0);
            }
            return parseItems((ArrayNode) items, indexName, responseErrors(root));
        } catch (IOException | RuntimeException e) {
            Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                    + " BulkNdjsonResponseParser parse failed: " + e.getMessage());
            return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of(), null, 0);
        }
    }

    /**
     * Warns when a successful bulk response's summary flag disagrees with its item outcomes.
     *
     * <p>The local request ID correlates this rare protocol inconsistency with the matching HTTP
     * trace without logging the potentially sensitive response body.</p>
     */
    static void warnIfOutcomeFlagMismatch(ParsedBulk parsed, String indexName, long requestId) {
        if (parsed == null || !parsed.hasOutcomeFlagMismatch()) {
            return;
        }
        String effectiveIndex = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk response outcome mismatch:"
                + " requestId=" + requestId
                + " index=" + effectiveIndex
                + " responseErrors=" + parsed.responseErrors()
                + " parsedFailures=" + parsed.failedItems().size()
                + " responseItems=" + parsed.responseItemCount() + ".");
    }

    private static ParsedBulk parseItems(ArrayNode items, String indexName, Boolean responseErrors) {
        int created = 0;
        int updated = 0;
        int noop = 0;
        int failed = 0;
        List<OpenSearchClientWrapper.FailedItem> failedItems = new ArrayList<>();
        int logged = 0;
        String effectiveIndex = indexName == null || indexName.isBlank() ? "unknown" : indexName;

        for (int i = 0; i < items.size(); i++) {
            JsonNode item = items.get(i);
            JsonNode op = item.get("index");
            if (op == null) {
                op = item.get("create");
            }
            if (op == null) {
                op = item.get("update");
            }
            int status = (op != null && op.has("status")) ? op.get("status").asInt() : 0;
            if (status >= 200 && status < 300) {
                switch (classifyResult(op)) {
                    case "created" -> created++;
                    case "updated" -> updated++;
                    case "noop" -> noop++;
                    default -> updated++;
                }
            } else {
                failed++;
                JsonNode err = op != null ? op.get("error") : null;
                String type = err != null && err.has("type") ? err.get("type").asText() : "unknown";
                String reason = err != null && err.has("reason") ? err.get("reason").asText() : "unknown";
                failedItems.add(new OpenSearchClientWrapper.FailedItem(i, type, reason));
                if (logged < MAX_LOGGED_FAILURES) {
                    Logger.logError(OpenSearchClientWrapper.formatBulkItemFailure(effectiveIndex, i, type, reason));
                    logged++;
                }
            }
        }

        int totalFailed = failedItems.size();
        if (totalFailed > MAX_LOGGED_FAILURES) {
            Logger.logError(RuntimeConfig.searchDestinationLogPrefix()
                    + " Bulk item failure summary: index=" + effectiveIndex
                    + " additional=" + (totalFailed - MAX_LOGGED_FAILURES)
                    + " totalFailed=" + totalFailed);
        }
        return new ParsedBulk(
                new BulkOutcomeBreakdown(created, updated, noop, failed),
                failedItems,
                responseErrors,
                items.size());
    }

    private static Boolean responseErrors(JsonNode root) {
        if (root == null) {
            return null;
        }
        JsonNode errors = root.get("errors");
        return errors != null && errors.isBoolean() ? errors.booleanValue() : null;
    }

    private static String classifyResult(JsonNode op) {
        if (op == null || !op.has("result")) {
            return "updated";
        }
        return op.get("result").asText("updated").trim().toLowerCase(Locale.ROOT);
    }
}
