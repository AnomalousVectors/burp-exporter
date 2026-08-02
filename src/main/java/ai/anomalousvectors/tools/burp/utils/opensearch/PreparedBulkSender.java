package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.PreparedBulkBodies;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.export.SearchBodyPrefixFitter;

/**
 * Posts pre-serialized snapshot bulk NDJSON without rebuilding document maps on the flush thread.
 *
 * <p>Stateless and safe for concurrent callers. Sends block on offered-load pacing and HTTP
 * completion. Stale-run cancellation returns an empty outcome without mutating current-run
 * stats.</p>
 */
public final class PreparedBulkSender {

    private static final int MAX_POST_WAIT_REFITS = 3;

    private PreparedBulkSender() {}

    /**
     * Sends one or more bulk requests built from prepared NDJSON bytes.
     *
     * <p>When the concatenated body would exceed the live {@link BulkByteBudget}, splits into
     * sub-batches so callers that batch by document count (retry drain) cannot slam Hosted with
     * multi-tens-of-MiB HTTP bodies. Documents that individually exceed the live budget are
     * structurally prefix-truncated via {@link SearchBodyPrefixFitter}; HTTP is refused if the
     * fitted NDJSON still exceeds the latest live budget. If pacing observes a smaller budget
     * before HTTP starts, the derived search copies are fitted and split again. Original list
     * entries are never mutated (dual-sink file emit stays full).</p>
     *
     * @param baseUrl search database base URL
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
        if (!ExportRunContext.allowsRunMutation()) {
            return new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        long maxBytes = Math.max(1L, BulkByteBudget.currentMaxBytes());
        List<PreparedExportDocument> sendable = new ArrayList<>(documents.size());
        List<Integer> sendableOriginalIndex = new ArrayList<>(documents.size());
        List<OpenSearchClientWrapper.FailedItem> localFailures = new ArrayList<>();
        int truncatedCount = 0;
        for (int i = 0; i < documents.size(); i++) {
            PreparedExportDocument document = documents.get(i);
            if (document == null) {
                continue;
            }
            PreparedExportDocument toSend = document;
            if (BulkByteBudget.exceedsLiveBudget(document.resolvedBulkBytes())) {
                long liveBudget = Math.max(1L, BulkByteBudget.currentMaxBytes());
                toSend = SearchBodyPrefixFitter.fitToBudget(document, liveBudget);
                if (toSend.resolvedBulkBytes() > liveBudget) {
                    String type = toSend.resolvedBulkBytes() > BulkByteBudget.ADAPTIVE_MAX_BYTES
                            ? BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE
                            : "live_bulk_budget_exceeded";
                    localFailures.add(new OpenSearchClientWrapper.FailedItem(
                            i,
                            type,
                            fitFailureReason(
                                    document.resolvedBulkBytes(),
                                    toSend.resolvedBulkBytes(),
                                    liveBudget)));
                    continue;
                }
                if (SearchBodyPrefixFitter.didTruncate(document, toSend)) {
                    recordSearchTruncation(document);
                    truncatedCount++;
                }
            }
            sendable.add(toSend);
            sendableOriginalIndex.add(i);
        }
        if (truncatedCount > 0) {
            logSearchTruncations(indexName, truncatedCount, maxBytes);
        }
        if (sendable.isEmpty()) {
            return new OpenSearchClientWrapper.BulkResult(
                    BulkOutcomeBreakdown.classified(0, localFailures.size()), localFailures);
        }

        List<List<PreparedExportDocument>> parts = splitByByteBudget(sendable);
        BulkOutcomeBreakdown breakdown = BulkOutcomeBreakdown.classified(0, localFailures.size());
        List<OpenSearchClientWrapper.FailedItem> failedItems = new ArrayList<>(localFailures);
        long maxSuccessfulRequestBytes = 0L;
        int sendableOffset = 0;
        for (List<PreparedExportDocument> part : parts) {
            if (!ExportRunContext.allowsRunMutation()) {
                break;
            }
            OpenSearchClientWrapper.BulkResult partResult = pushOne(baseUrl, indexName, part);
            breakdown = breakdown.plus(partResult.breakdown());
            maxSuccessfulRequestBytes =
                    Math.max(maxSuccessfulRequestBytes, partResult.maxSuccessfulRequestBytes());
            for (OpenSearchClientWrapper.FailedItem item : partResult.failedItems) {
                int local = item.index();
                if (local < 0 || local >= part.size()) {
                    continue;
                }
                int sendableIndex = sendableOffset + local;
                int originalIndex = sendableOriginalIndex.get(sendableIndex);
                failedItems.add(new OpenSearchClientWrapper.FailedItem(
                        originalIndex, item.type(), item.reason()));
            }
            sendableOffset += part.size();
        }
        return new OpenSearchClientWrapper.BulkResult(
                breakdown, failedItems, maxSuccessfulRequestBytes);
    }

    private static void logSearchTruncations(String indexName, int count, long maxBytes) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        String index = indexName == null || indexName.isBlank() ? "unknown" : indexName;
        Logger.logInfoPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Prefix-truncated " + count
                + " document(s) to fit live bulk budget "
                + formatMib(maxBytes)
                + " for " + index
                + " (search path only; files sink unchanged).");
    }

    private static List<List<PreparedExportDocument>> splitByByteBudget(
            List<PreparedExportDocument> documents) {
        long maxBytes = Math.max(1L, BulkByteBudget.currentMaxBytes());
        List<List<PreparedExportDocument>> parts = new ArrayList<>();
        List<PreparedExportDocument> current = new ArrayList<>();
        long bytes = 0L;
        for (PreparedExportDocument document : documents) {
            if (document == null) {
                continue;
            }
            PreparedExportDocument toAdd = document;
            long docBytes = toAdd.resolvedBulkBytes();
            // Budget may have shrunk since fit; re-fit rather than skip/drop.
            if (docBytes > maxBytes) {
                toAdd = fitForSearch(toAdd);
                docBytes = toAdd.resolvedBulkBytes();
            }
            if (!current.isEmpty() && bytes + docBytes > maxBytes) {
                parts.add(current);
                current = new ArrayList<>();
                bytes = 0L;
            }
            current.add(toAdd);
            bytes += docBytes;
        }
        if (!current.isEmpty()) {
            parts.add(current);
        }
        return parts;
    }

    private static OpenSearchClientWrapper.BulkResult pushOne(
            String baseUrl,
            String indexName,
            List<PreparedExportDocument> documents) {
        return pushOne(baseUrl, indexName, documents, 0);
    }

    private static OpenSearchClientWrapper.BulkResult pushOne(
            String baseUrl,
            String indexName,
            List<PreparedExportDocument> documents,
            int postWaitRefits) {
        if (!ExportRunContext.allowsRunMutation()) {
            return new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        RefittedPart refitted = refitPartToLiveBudget(documents);
        List<PreparedExportDocument> fitted = refitted.documents();
        if (refitted.truncatedCount() > 0) {
            logSearchTruncations(indexName, refitted.truncatedCount(), refitted.liveBudget());
        }
        byte[] body = PreparedBulkBodies.concatenate(fitted);
        if (body.length == 0) {
            return new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        long maxBytes = Math.max(1L, BulkByteBudget.currentMaxBytes());
        if (body.length > maxBytes && fitted.size() > 1) {
            BulkOutcomeBreakdown breakdown = BulkOutcomeBreakdown.empty();
            List<OpenSearchClientWrapper.FailedItem> failedItems = new ArrayList<>();
            long maxSuccessfulRequestBytes = 0L;
            int offset = 0;
            for (List<PreparedExportDocument> part : splitByByteBudget(fitted)) {
                OpenSearchClientWrapper.BulkResult partResult = pushOne(baseUrl, indexName, part);
                breakdown = breakdown.plus(partResult.breakdown());
                maxSuccessfulRequestBytes =
                        Math.max(maxSuccessfulRequestBytes, partResult.maxSuccessfulRequestBytes());
                for (OpenSearchClientWrapper.FailedItem item : partResult.failedItems) {
                    int local = item.index();
                    if (local < 0 || local >= part.size()) {
                        continue;
                    }
                    failedItems.add(new OpenSearchClientWrapper.FailedItem(
                            offset + local, item.type(), item.reason()));
                }
                offset += part.size();
            }
            return new OpenSearchClientWrapper.BulkResult(
                    breakdown, failedItems, maxSuccessfulRequestBytes);
        }
        if (body.length > maxBytes) {
            String type = body.length > BulkByteBudget.ADAPTIVE_MAX_BYTES
                    ? BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE
                    : "live_bulk_budget_exceeded";
            if (!BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE.equals(type)) {
                Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                        + " Refused over-budget prepared bulk before HTTP:"
                        + " index=" + (indexName == null || indexName.isBlank() ? "unknown" : indexName)
                        + " bytes=" + body.length
                        + " liveBudget=" + maxBytes
                        + " documents=" + fitted.size() + ".");
            }
            return failedBulkResult(
                    fitted.size(),
                    type,
                    fitFailureReason(
                            documents.get(0).resolvedBulkBytes(),
                            body.length,
                            maxBytes));
        }
        ExportStats.BulkInFlightTicket ticket = ExportStats.openBulk();
        try (ticket) {
            OpenSearchClientWrapper.BulkResult result = OpenSearchBulkHttpExecutor.executeBulkPost(
                    baseUrl,
                    indexName,
                    body,
                    (response, requestId) ->
                            handleBulkResponse(response, indexName, fitted.size(), requestId));
            long successfulRequestBytes = result.successCount() > 0 ? body.length : 0L;
            return new OpenSearchClientWrapper.BulkResult(
                    result.breakdown(), result.failedItems, successfulRequestBytes);
        } catch (OpenSearchBulkHttpExecutor.LiveBudgetChangedException e) {
            if (postWaitRefits < MAX_POST_WAIT_REFITS) {
                return pushOne(baseUrl, indexName, documents, postWaitRefits + 1);
            }
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Refused prepared bulk after repeated live-budget changes:"
                    + " index=" + (indexName == null || indexName.isBlank() ? "unknown" : indexName)
                    + " documents=" + fitted.size()
                    + " liveBudget=" + e.liveBudget()
                    + " refits=" + postWaitRefits + ".");
            return failedBulkResult(
                    fitted.size(),
                    "live_bulk_budget_exceeded",
                    "Live bulk budget changed repeatedly while waiting to send"
                            + " fittedBytes=" + body.length
                            + " liveBudget=" + e.liveBudget()
                            + " refits=" + postWaitRefits);
        } catch (IOException | RuntimeException e) {
            logPushFailure(indexName, e);
            String reason = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return failedBulkResult(fitted.size(), "transport_exception", reason);
        }
    }

    private static RefittedPart refitPartToLiveBudget(
            List<PreparedExportDocument> documents) {
        if (documents == null || documents.isEmpty()) {
            return new RefittedPart(List.of(), 0, Math.max(1L, BulkByteBudget.currentMaxBytes()));
        }
        long maxBytes = Math.max(1L, BulkByteBudget.currentMaxBytes());
        List<PreparedExportDocument> fitted = new ArrayList<>(documents.size());
        int truncatedCount = 0;
        for (PreparedExportDocument document : documents) {
            if (document == null) {
                continue;
            }
            if (document.resolvedBulkBytes() > maxBytes) {
                PreparedExportDocument fit = fitForSearch(document, maxBytes);
                if (fit.resolvedBulkBytes() <= maxBytes
                        && SearchBodyPrefixFitter.didTruncate(document, fit)) {
                    truncatedCount++;
                }
                fitted.add(fit);
            } else {
                fitted.add(document);
            }
        }
        return new RefittedPart(fitted, truncatedCount, maxBytes);
    }

    private static OpenSearchClientWrapper.BulkResult handleBulkResponse(
            ClassicHttpResponse response,
            String indexName,
            int attemptedCount,
            long requestId) throws IOException {
        int status = response.getCode();
        String responseBody;
        try {
            responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        } catch (ParseException e) {
            throw new IOException("Failed to parse bulk response body for " + indexName, e);
        }
        if (!ExportRunContext.allowsRunMutation()) {
            return new OpenSearchClientWrapper.BulkResult(BulkOutcomeBreakdown.empty(), List.of());
        }
        if (status >= 200 && status < 300) {
            return parseBulkResponse(responseBody, attemptedCount, indexName, requestId);
        }
        Logger.logDebug(RuntimeConfig.searchDestinationLogPrefix()
                + " PreparedBulkSender bulk request failed: "
                + OpenSearchLogFormat.formatStatusAndIndentedBody(status, responseBody));
        String detail = responseBody != null && responseBody.contains("request body is required")
                ? " Search database reported an empty bulk request body."
                : "";
        if (status == 401 || status == 403) {
            detail += " Authentication rejected - verify credentials"
                    + " (bearer/API key/session token may have expired).";
        }
        if (BulkRateLimitBackoff.isRateLimited(status)) {
            BulkRateLimitBackoff.noteRateLimited(status, response, indexName, "Prepared bulk");
        } else {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Prepared bulk request failed for "
                    + indexName + ": HTTP " + status + "." + detail);
            AmazonOpenSearchPressureLog.maybeNoteHttpPressure(status, indexName, "Prepared bulk");
        }
        return failedBulkResult(
                attemptedCount,
                "http_failure",
                "Bulk HTTP request failed with status " + status);
    }

    /**
     * Parses a prepared-bulk response for isolated callers and tests.
     *
     * <p>Malformed, blank, or incomplete responses become explicit failed-item outcomes; the
     * method does not throw parse failures.</p>
     *
     * @param responseBody raw response body
     * @param attemptedCount number of request items expected
     * @param indexName target index used in diagnostics
     * @return normalized bulk result with request-order failure indexes
     */
    static OpenSearchClientWrapper.BulkResult parseBulkResponse(
            String responseBody,
            int attemptedCount,
            String indexName) {
        return parseBulkResponse(responseBody, attemptedCount, indexName, -1L);
    }

    private static OpenSearchClientWrapper.BulkResult parseBulkResponse(
            String responseBody,
            int attemptedCount,
            String indexName,
            long requestId) {
        if (responseBody == null || responseBody.isBlank()) {
            return failedBulkResult(
                    attemptedCount, "bulk_response_parse_exception", "Bulk response body was blank");
        }
        BulkNdjsonResponseParser.ParsedBulk parsed = BulkNdjsonResponseParser.parse(responseBody, indexName);
        if (requestId > 0L) {
            BulkNdjsonResponseParser.warnIfOutcomeFlagMismatch(parsed, indexName, requestId);
        }
        if (parsed.successCount() == 0 && parsed.failedItems().isEmpty() && attemptedCount > 0) {
            Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                    + " Prepared bulk response parsing failed for "
                    + (indexName == null || indexName.isBlank() ? "unknown" : indexName) + ".");
            return failedBulkResult(
                    attemptedCount,
                    "bulk_response_parse_exception",
                    "Bulk response could not be parsed into item outcomes");
        }
        int observed = parsed.breakdown().successTotal() + parsed.breakdown().failed();
        if (observed >= attemptedCount) {
            return new OpenSearchClientWrapper.BulkResult(parsed.breakdown(), parsed.failedItems());
        }
        List<OpenSearchClientWrapper.FailedItem> completedFailures =
                new ArrayList<>(parsed.failedItems());
        for (int index = observed; index < attemptedCount; index++) {
            completedFailures.add(new OpenSearchClientWrapper.FailedItem(
                    index,
                    "bulk_response_incomplete",
                    "Bulk response omitted this attempted item"));
        }
        BulkOutcomeBreakdown completedBreakdown = parsed.breakdown().plus(
                BulkOutcomeBreakdown.classified(0, attemptedCount - observed));
        return new OpenSearchClientWrapper.BulkResult(completedBreakdown, completedFailures);
    }

    private static OpenSearchClientWrapper.BulkResult failedBulkResult(
            int attemptedCount, String type, String reason) {
        List<OpenSearchClientWrapper.FailedItem> failedItems =
                new ArrayList<>(Math.max(0, attemptedCount));
        for (int index = 0; index < attemptedCount; index++) {
            failedItems.add(new OpenSearchClientWrapper.FailedItem(index, type, reason));
        }
        return new OpenSearchClientWrapper.BulkResult(
                BulkOutcomeBreakdown.classified(0, attemptedCount), failedItems);
    }

    private static PreparedExportDocument fitForSearch(PreparedExportDocument document) {
        long liveBudget = Math.max(1L, BulkByteBudget.currentMaxBytes());
        return fitForSearch(document, liveBudget);
    }

    private static PreparedExportDocument fitForSearch(
            PreparedExportDocument document, long liveBudget) {
        PreparedExportDocument fitted =
                SearchBodyPrefixFitter.fitToBudget(document, Math.max(1L, liveBudget));
        if (SearchBodyPrefixFitter.didTruncate(document, fitted)
                && fitted.resolvedBulkBytes() <= liveBudget
                && ExportRunContext.allowsRunMutation()) {
            recordSearchTruncation(document);
        }
        return fitted;
    }

    private static void recordSearchTruncation(PreparedExportDocument document) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        String indexKey = document.indexKey() == null || document.indexKey().isBlank()
                ? "unknown"
                : document.indexKey();
        ExportStats.recordSearchBodyPrefixTruncationOnce(document.operationId(), indexKey);
    }

    private static String fitFailureReason(
            long originalBytes, long fittedBytes, long liveBudget) {
        return "Prepared NDJSON remained over budget after structural fitting"
                + " originalBytes=" + originalBytes
                + " fittedBytes=" + fittedBytes
                + " liveBudget=" + liveBudget
                + " absoluteMax=" + BulkByteBudget.ADAPTIVE_MAX_BYTES;
    }

    private static void logPushFailure(String indexName, Exception e) {
        if (!ExportRunContext.allowsRunMutation()) {
            return;
        }
        if (OpenSearchPushCancellation.shouldSuppressPushFailure(e)) {
            Logger.logTrace(RuntimeConfig.searchDestinationLogPrefix() + " Prepared bulk cancelled for " + indexName + " ("
                    + OpenSearchPushCancellation.cancelledPushLogSuffix(e) + ")");
            return;
        }
        // Transport messages are not secret-redacted; request bodies and credentials must never be
        // included when transport exceptions are constructed.
        String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        Logger.logWarnPanelOnly(RuntimeConfig.searchDestinationLogPrefix()
                + " Prepared bulk failed for " + indexName + ": " + msg);
        AmazonOpenSearchPressureLog.maybeNoteTransportPressure(msg, indexName, "Prepared bulk");
        BulkRateLimitBackoff.noteTransportPressure(msg, indexName, "Prepared bulk");
    }

    private static String formatMib(long bytes) {
        double mib = bytes / (1024.0 * 1024.0);
        return String.format(java.util.Locale.ROOT, "%.2fMiB", mib);
    }

    private record RefittedPart(
            List<PreparedExportDocument> documents, int truncatedCount, long liveBudget) {
    }
}
