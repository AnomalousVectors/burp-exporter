package ai.anomalousvectors.tools.burp.utils.search;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Parses search database bulk JSON responses into success and per-item failure details.
 *
 * <p>Shared by {@link PreparedBulkSender} and {@link ChunkedBulkSender} so snapshot, live, and
 * retry paths emit identical failure logging.</p>
 *
 * <p>Stateless and safe for concurrent callers. Item failure reasons pass through the shared
 * destination-diagnostic boundary before logging.</p>
 */
public final class BulkNdjsonResponseParser {

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();
    private static final int MAX_LOGGED_FAILURES = 3;

    private BulkNdjsonResponseParser() { }

    // Normalize the request-order contract once; senders add only their route/result adaptation.
    static ParsedBulk parseAttempted(String body, int attemptedCount, String indexName,
            long requestId, List<PreparedExportDocument> documents) {
        if (attemptedCount < 0) throw new IllegalArgumentException("Negative attempted count");
        if (body == null || body.isBlank()) {
            return failedAttempts(attemptedCount, "bulk_response_parse_exception", "Bulk response body was blank");
        }
        ParsedBulk parsed = parse(body, indexName,
                documents != null && documents.size() == attemptedCount ? documents : null);
        if (parsed.responseItemCount() > attemptedCount) {
            // Surplus outcomes cannot establish which acknowledgments belong to this request.
            return failedAttempts(attemptedCount, "bulk_response_item_count_mismatch",
                    "Bulk response contained excess items: expected=" + attemptedCount
                            + ", received=" + parsed.responseItemCount());
        }
        if (requestId > 0L) warnIfOutcomeFlagMismatch(parsed, indexName, requestId);
        int observed = parsed.breakdown().successTotal() + parsed.breakdown().failed();
        if (observed == 0 && attemptedCount > 0) {
            String label = SearchDiagnosticText.singleLine(indexName, 256);
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Bulk response parsing failed for " + (label.isBlank() ? "unknown" : label) + ".");
            return failedAttempts(attemptedCount, "bulk_response_parse_exception",
                    "Bulk response could not be parsed into item outcomes");
        }
        if (observed == attemptedCount) return parsed;
        List<SearchClientWrapper.FailedItem> failures = new ArrayList<>(parsed.failedItems());
        for (int index = observed; index < attemptedCount; index++) {
            failures.add(new SearchClientWrapper.FailedItem(index,
                    "bulk_response_incomplete", "Bulk response omitted this attempted item"));
        }
        return new ParsedBulk(parsed.breakdown().plus(
                BulkOutcomeBreakdown.classified(0, attemptedCount - observed)), failures,
                parsed.responseErrors(), parsed.responseItemCount(), parsed.responseHasItemErrors(), parsed.noopIndexes());
    }

    private static ParsedBulk failedAttempts(int count, String type, String reason) {
        List<SearchClientWrapper.FailedItem> failures = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            failures.add(new SearchClientWrapper.FailedItem(index, type, reason));
        }
        return new ParsedBulk(BulkOutcomeBreakdown.classified(0, count), failures, null, 0);
    }

    /**
     * Parsed bulk outcome with per-item failures and the response's top-level consistency signal.
     *
     * @param breakdown classified item outcomes
     * @param failedItems per-item failures aligned to request order
     * @param responseErrors top-level {@code errors} value, or {@code null} when absent/non-boolean
     * @param responseItemCount number of item outcomes present in the response
     * @param responseHasItemErrors whether raw item statuses contain errors, before recognizing
     *                              already-present or superseded streaming revisions
     * @param noopIndexes exact request positions acknowledged without another indexed write
     */
    public record ParsedBulk(
            BulkOutcomeBreakdown breakdown,
            List<SearchClientWrapper.FailedItem> failedItems,
            Boolean responseErrors,
            int responseItemCount,
            boolean responseHasItemErrors,
            List<Integer> noopIndexes) {

        /**
         * Creates an outcome without request-aware streaming acknowledgments.
         *
         * @param breakdown classified outcomes
         * @param failedItems raw item failures
         * @param responseErrors raw top-level flag
         * @param responseItemCount raw item count
         */
        public ParsedBulk(BulkOutcomeBreakdown breakdown,
                List<SearchClientWrapper.FailedItem> failedItems,
                Boolean responseErrors, int responseItemCount) {
            this(breakdown, failedItems, responseErrors, responseItemCount,
                    failedItems != null && !failedItems.isEmpty(), List.of());
        }

        /** Normalizes absent outcomes and snapshots failure and acknowledgment lists. */
        public ParsedBulk {
            breakdown = breakdown != null ? breakdown : BulkOutcomeBreakdown.empty();
            failedItems = failedItems != null ? List.copyOf(failedItems) : List.of();
            responseItemCount = Math.max(0, responseItemCount);
            noopIndexes = List.copyOf(noopIndexes);
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
         * Returns whether the top-level {@code errors} flag disagrees with raw item statuses.
         *
         * @return {@code true} when an explicit summary flag contradicts raw item errors
         */
        public boolean hasOutcomeFlagMismatch() {
            return responseErrors != null
                    && responseErrors.booleanValue() != responseHasItemErrors;
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
        return parse(responseBody, indexName, null);
    }

    // Only prepared requests can prove that a conflict belongs to an owned versioned capture.
    // Exact item count and returned ID are mandatory; ordinary conflicts remain real failures.
    static ParsedBulk parse(String responseBody, String indexName,
            List<PreparedExportDocument> documents) {
        if (responseBody == null || responseBody.isBlank()) {
            return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of(), null, 0);
        }
        try {
            JsonNode root = JSON.readTree(responseBody);
            JsonNode items = root.get("items");
            if (items == null || !items.isArray()) {
                return new ParsedBulk(BulkOutcomeBreakdown.empty(), List.of(), responseErrors(root), 0);
            }
            return parseItems((ArrayNode) items, indexName, responseErrors(root), documents);
        } catch (RuntimeException e) {
            Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                    + " BulkNdjsonResponseParser parse failed: "
                    + SearchDiagnosticText.singleLine(e.getMessage(), 512));
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
        String effectiveIndex = SearchDiagnosticText.singleLine(indexName, 256);
        if (effectiveIndex.isBlank()) {
            effectiveIndex = "unknown";
        }
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Bulk response outcome mismatch:"
                + " requestId=" + requestId
                + " index=" + effectiveIndex
                + " responseErrors=" + parsed.responseErrors()
                + " parsedFailures=" + parsed.failedItems().size()
                + " responseItems=" + parsed.responseItemCount() + ".");
    }

    private static ParsedBulk parseItems(ArrayNode items, String indexName, Boolean responseErrors,
            List<PreparedExportDocument> documents) {
        int created = 0;
        int updated = 0;
        int noop = 0;
        int failed = 0;
        List<SearchClientWrapper.FailedItem> failedItems = new ArrayList<>();
        int logged = 0;
        List<Integer> noopIndexes = new ArrayList<>();
        boolean responseHasItemErrors = false;
        String effectiveIndex = SearchDiagnosticText.singleLine(indexName, 256);
        if (effectiveIndex.isBlank()) {
            effectiveIndex = "unknown";
        }

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
            responseHasItemErrors |= status < 200 || status >= 300;
            if (status >= 200 && status < 300) {
                switch (classifyResult(op)) {
                    case "created" -> created++;
                    case "updated" -> updated++;
                    case "noop" -> {
                        noop++;
                        noopIndexes.add(i);
                    }
                    default -> updated++;
                }
            } else if (isSupersededRevision(items.size(), documents, i, op, status)
                    && item.has("index")) {
                // The database already holds this revision or a newer one. Acknowledge without
                // counting another write, emitting a failure log, or retrying obsolete bytes.
                noop++;
                noopIndexes.add(i);
            } else {
                failed++;
                JsonNode err = op != null ? op.get("error") : null;
                String type = err != null && err.has("type") ? err.get("type").asString() : "unknown";
                String reason = err != null && err.has("reason") ? err.get("reason").asString() : "unknown";
                failedItems.add(new SearchClientWrapper.FailedItem(i, type, reason));
                if (logged < MAX_LOGGED_FAILURES) {
                    Logger.logDebug(SearchClientWrapper.formatBulkItemFailure(effectiveIndex, i, type, reason));
                    logged++;
                }
            }
        }

        int totalFailed = failedItems.size();
        if (totalFailed > MAX_LOGGED_FAILURES) {
            Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                    + " Bulk item failure summary: index=" + effectiveIndex
                    + " additional=" + (totalFailed - MAX_LOGGED_FAILURES)
                    + " totalFailed=" + totalFailed);
        }
        return new ParsedBulk(
                new BulkOutcomeBreakdown(created, updated, noop, failed),
                failedItems,
                responseErrors,
                items.size(), responseHasItemErrors, noopIndexes);
    }

    private static boolean isSupersededRevision(int itemCount,
            List<PreparedExportDocument> documents, int position, JsonNode op, int status) {
        if (status != 409 || op == null || documents == null || documents.size() != itemCount) {
            return false;
        }
        PreparedExportDocument document = documents.get(position);
        return document != null && document.searchRevision() != null
                && document.searchRevision().documentId().equals(op.path("_id").asString())
                && "version_conflict_engine_exception".equals(op.path("error").path("type").asString());
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
        return op.get("result").asString("updated").trim().toLowerCase(Locale.ROOT);
    }
}
