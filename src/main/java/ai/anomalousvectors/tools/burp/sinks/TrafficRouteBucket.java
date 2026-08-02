package ai.anomalousvectors.tools.burp.sinks;

import java.util.Locale;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Centralized traffic "route bucket" mapping shared by all traffic sinks and stats views.
 *
 * <p>Traffic exports can be attributed to either:
 * <ul>
 *   <li>a {@link Kind#TOOL_TYPE} bucket (for example {@code REPEATER_TABS}, {@code PROXY}),
 *       which aligns with the Burp tool/source that emitted HTTP exchanges; or</li>
 *   <li>a {@link Kind#SOURCE} bucket (for example {@code proxy_history_snapshot},
 *       {@code proxy_websocket}), which aligns with the reporter or source that produced the
 *       document rather than the requesting Burp tool.</li>
 * </ul>
 *
 * <p>Keeping the decision in one place ensures database bulk accounting, file-sink accounting,
 * and {@code StatsPanel} display all agree about which bucket a given document belongs to.
 * Sinks should build a {@link Route} once and use the record/resolve helpers here instead of
 * re-implementing the tool label -> bucket mapping locally.</p>
 */
public final class TrafficRouteBucket {

    /** Bucket kind used to group traffic counters in stats. */
    public enum Kind {
        /** Grouped by originating reporter/source (for example {@code proxy_history_snapshot}). */
        SOURCE,
        /** Grouped by Burp tool type (for example {@code REPEATER_TABS}). */
        TOOL_TYPE
    }

    /**
     * Route record carrying the resolved bucket kind and key.
     *
     * @param kind bucket kind; must not be {@code null}
     * @param key bucket key (tool-type name or source label); must not be {@code null} or blank
     */
    public record Route(Kind kind, String key) {
        /**
         * Creates a route for one traffic bucket.
         *
         * @throws IllegalArgumentException if {@code kind} is {@code null} or {@code key} is
         *         {@code null} or blank
         */
        public Route {
            if (kind == null) {
                throw new IllegalArgumentException("kind must not be null");
            }
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("key must not be blank");
            }
        }
    }

    /** Source key for snapshot-pushed Proxy History items. */
    public static final String SOURCE_PROXY_HISTORY_SNAPSHOT = "proxy_history_snapshot";
    /** Source key for Proxy WebSocket items. */
    public static final String SOURCE_PROXY_WEBSOCKET = "proxy_websocket";
    /** Fallback tool-type key when a document does not declare a tool. */
    public static final String TOOL_TYPE_UNKNOWN = "UNKNOWN";
    /** Logical index key used by the traffic sink in {@link ExportStats} and {@link FileExportStats}. */
    public static final String INDEX_KEY = "traffic";

    private TrafficRouteBucket() {}

    /**
     * Resolves the configured traffic index name.
     *
     * <p>Shared by all traffic reporters so the index-name lookup lives in one place instead of
     * being re-implemented with private copy-paste helpers.</p>
     */
    public static String trafficIndexName() {
        return RuntimeConfig.indexNameForKey(INDEX_KEY);
    }

    /**
     * Resolves the route for a traffic document by inspecting its {@code burp.reporting_tool} field.
     *
     * @param document a prepared traffic document; {@code null} resolves to {@link #TOOL_TYPE_UNKNOWN}
     * @return resolved route; never {@code null}
     */
    public static Route fromDocument(Map<String, Object> document) {
        if (document == null) {
            return new Route(Kind.TOOL_TYPE, TOOL_TYPE_UNKNOWN);
        }
        Object raw = null;
        Object burpObj = document.get("burp");
        if (burpObj instanceof Map<?, ?> burp) {
            raw = burp.get("reporting_tool");
        }
        return fromToolLabel(raw == null ? null : String.valueOf(raw));
    }

    /**
     * Resolves the route for an exported display tool label.
     *
     * @param toolLabel exported {@code burp.reporting_tool} value; {@code null} or blank resolves to
     *                  {@link #TOOL_TYPE_UNKNOWN}
     * @return resolved route; never {@code null}
     */
    public static Route fromToolLabel(String toolLabel) {
        if (toolLabel == null || toolLabel.isBlank()) {
            return new Route(Kind.TOOL_TYPE, TOOL_TYPE_UNKNOWN);
        }
        return fromToolType(switch (toolLabel.trim()) {
            case "Proxy History" -> "PROXY_HISTORY";
            case "Proxy WebSocket" -> "PROXY_WEBSOCKET";
            case "Repeater Tabs" -> "REPEATER_TABS";
            case "Burp AI" -> "BURP_AI";
            default -> toolLabel.trim()
                    .replace('-', '_')
                    .replace(' ', '_')
                    .toUpperCase(Locale.ROOT);
        });
    }

    /**
     * Resolves the route for a tool-type string (for example the name of a
     * {@link burp.api.montoya.core.ToolType} constant or a reporter-assigned value).
     *
     * @param toolType tool-type label; {@code null} or blank resolves to {@link #TOOL_TYPE_UNKNOWN}
     * @return resolved route; never {@code null}
     */
    public static Route fromToolType(String toolType) {
        if (toolType == null || toolType.isBlank()) {
            return new Route(Kind.TOOL_TYPE, TOOL_TYPE_UNKNOWN);
        }
        String normalized = toolType.trim();
        if ("PROXY_HISTORY".equals(normalized)) {
            return new Route(Kind.SOURCE, SOURCE_PROXY_HISTORY_SNAPSHOT);
        }
        if ("PROXY_WEBSOCKET".equals(normalized)) {
            return new Route(Kind.SOURCE, SOURCE_PROXY_WEBSOCKET);
        }
        return new Route(Kind.TOOL_TYPE, normalized);
    }

    /** Convenience route for Proxy History snapshot pushes. */
    public static Route proxyHistorySnapshot() {
        return new Route(Kind.SOURCE, SOURCE_PROXY_HISTORY_SNAPSHOT);
    }

    /** Convenience route for Proxy WebSocket messages. */
    public static Route proxyWebSocket() {
        return new Route(Kind.SOURCE, SOURCE_PROXY_WEBSOCKET);
    }

    /**
     * Returns whether a queued traffic document route is still enabled by the live traffic gate.
     *
     * <p>Source buckets map back to the user-facing traffic selections that produce them:
     * Proxy History snapshot documents require {@code proxy_history}; proxy WebSocket documents
     * require live {@code proxy}.</p>
     */
    public static boolean isRouteEnabled(Route route, RuntimeConfig.TrafficExportGate gate) {
        if (route == null || gate == null || !gate.anyTrafficExportEnabled()) {
            return false;
        }
        if (route.kind() == Kind.SOURCE) {
            return switch (route.key()) {
                case SOURCE_PROXY_HISTORY_SNAPSHOT -> gate.includesToolType("proxy_history");
                case SOURCE_PROXY_WEBSOCKET -> gate.includesToolType("proxy");
                default -> false;
            };
        }
        return gate.includesToolType(route.key().toLowerCase(Locale.ROOT));
    }

    /** Records {@code count} successful OpenSearch pushes for {@code route}. */
    public static void recordOpenSearchSuccess(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            ExportStats.recordTrafficSourceSuccess(route.key(), count);
        } else {
            ExportStats.recordTrafficToolTypeSuccess(route.key(), count);
        }
    }

    /** Records {@code count} failed OpenSearch pushes for {@code route}. */
    public static void recordOpenSearchFailure(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            ExportStats.recordTrafficSourceFailure(route.key(), count);
        } else {
            ExportStats.recordTrafficToolTypeFailure(route.key(), count);
        }
    }

    /**
     * Records recovered search-destination retries for a traffic route.
     *
     * @param route traffic attribution route; {@code null} is ignored
     * @param count recovered document count; non-positive values are ignored
     */
    public static void recordOpenSearchRecovery(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            ExportStats.recordTrafficSourceRecovery(route.key(), count);
        } else {
            ExportStats.recordTrafficToolTypeRecovery(route.key(), count);
        }
    }

    /**
     * Records retry-queue capacity drops for a traffic route.
     *
     * @param route traffic attribution route; {@code null} is ignored
     * @param count dropped document count; non-positive values are ignored
     */
    public static void recordOpenSearchRetryQueueDrop(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            ExportStats.recordTrafficSourceRetryQueueDrop(route.key(), count);
        } else {
            ExportStats.recordTrafficToolTypeRetryQueueDrop(route.key(), count);
        }
    }

    /**
     * Records permanent search-destination drops for a traffic route.
     *
     * @param route traffic attribution route; {@code null} is ignored
     * @param count dropped document count; non-positive values are ignored
     */
    public static void recordOpenSearchPermanentDrop(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            ExportStats.recordTrafficSourcePermanentDrop(route.key(), count);
        } else {
            ExportStats.recordTrafficToolTypePermanentDrop(route.key(), count);
        }
    }

    /**
     * Records a traffic search-destination bulk outcome.
     *
     * <p>Delegates the index-key totals and panel/error reporting to
     * {@link BulkOutcomeRecorder#record(String, String, String, int, int, boolean)} so traffic
     * and non-traffic reporters share the same log and error shape, then adds the
     * per-route counter updates on top via {@link #recordOpenSearchSuccess(Route, long)} /
     * {@link #recordOpenSearchFailure(Route, long)}.</p>
     *
     * <p>Counts are clamped so {@code sent} is bounded to {@code [0, max(0, attempted)]} by
     * {@link BulkOutcomeRecorder#record}; per-route counters derived here inherit that clamping
     * and stay consistent with the index totals when callers mis-report.</p>
     *
     * <p>When {@code openSearchActive} is {@code false}, this call is a no-op and no counters
     * are updated (the file sink records its own outcomes separately).</p>
     *
     * @param route route for the bulk; {@code null} resolves to a no-op
     * @param attempted number of documents attempted in the bulk; negative values are clamped to 0
     * @param sent number of documents acknowledged by the search destination; clamped to
     *             {@code [0, max(0, attempted)]}
     * @param openSearchActive whether the search destination was active for this bulk
     * @param logLabel short label for log messages (for example {@code "Proxy history chunk"})
     */
    public static void recordBulkOutcome(
            Route route,
            int attempted,
            int sent,
            boolean openSearchActive,
            String logLabel) {
        recordBulkOutcome(route, attempted, sent, openSearchActive, logLabel, null);
    }

    /**
     * Records a prepared traffic bulk outcome and its item-level breakdown.
     *
     * <p>Safe to call from any thread. Updates index and route counters and may emit a failure
     * warning. Expected cancellation suppresses failure accounting.</p>
     *
     * @param route route for the bulk; {@code null} is ignored
     * @param outcome bulk result; {@code null} is ignored
     * @param openSearchActive whether the search destination was active for this bulk
     * @param logLabel short operation label used in failure details
     */
    public static void recordBulkOutcome(
            Route route,
            BulkPushOutcome outcome,
            boolean openSearchActive,
            String logLabel) {
        if (route == null || outcome == null) {
            return;
        }
        recordBulkOutcome(
                route,
                outcome.attempted(),
                outcome.successCount(),
                openSearchActive,
                logLabel,
                outcome.breakdown());
    }

    /**
     * Records aggregate traffic bulk counts with an optional item-level breakdown.
     *
     * <p>Attempted and sent counts are clamped by {@link BulkOutcomeRecorder}. When the search
     * destination is inactive, route and index counters are unchanged.</p>
     *
     * @param route route for the bulk; {@code null} is ignored
     * @param attempted attempted document count; negative values are treated as zero
     * @param sent acknowledged document count; clamped to {@code [0, attempted]}
     * @param openSearchActive whether the search destination was active for this bulk
     * @param logLabel short operation label used in failure details
     * @param breakdown item-level outcome counts; {@code null} uses aggregate counts
     */
    public static void recordBulkOutcome(
            Route route,
            int attempted,
            int sent,
            boolean openSearchActive,
            String logLabel,
            BulkOutcomeBreakdown breakdown) {
        if (route == null) {
            return;
        }
        BulkOutcomeRecorder.RecordResult recorded = BulkOutcomeRecorder.recordDetailed(
                INDEX_KEY, logSource(route), logLabel, attempted, sent, openSearchActive, breakdown);
        if (!openSearchActive) {
            return;
        }
        if (recorded.sent() > 0) {
            recordOpenSearchSuccess(route, recorded.sent());
        }
        int failure = Math.max(0, attempted) - recorded.sent();
        if (!recorded.failuresSuppressed() && failure > 0) {
            recordOpenSearchFailure(route, failure);
        }
    }

    private static String logSource(Route route) {
        if (route == null || route.kind() == Kind.TOOL_TYPE) {
            return "Traffic";
        }
        return switch (route.key()) {
            case SOURCE_PROXY_HISTORY_SNAPSHOT -> "ProxyHistory";
            case SOURCE_PROXY_WEBSOCKET -> "ProxyWebSocket";
            default -> "Traffic";
        };
    }

    /** Records {@code count} successful file writes for {@code route}. */
    public static void recordFileSuccess(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            FileExportStats.recordTrafficSourceSuccess(route.key(), count);
        } else {
            FileExportStats.recordTrafficToolTypeSuccess(route.key(), count);
        }
    }

    /** Records {@code count} failed file writes for {@code route}. */
    public static void recordFileFailure(Route route, long count) {
        if (route == null || count <= 0) {
            return;
        }
        if (route.kind() == Kind.SOURCE) {
            FileExportStats.recordTrafficSourceFailure(route.key(), count);
        } else {
            FileExportStats.recordTrafficToolTypeFailure(route.key(), count);
        }
    }

    /** Returns the current successful OpenSearch push count for {@code route}. */
    public static long openSearchSuccessCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? ExportStats.getTrafficSourceSuccessCount(route.key())
                : ExportStats.getTrafficToolTypeSuccessCount(route.key());
    }

    /** Returns the current failed OpenSearch push count for {@code route}. */
    public static long openSearchFailureCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? ExportStats.getTrafficSourceFailureCount(route.key())
                : ExportStats.getTrafficToolTypeFailureCount(route.key());
    }

    /** Returns the current successful file write count for {@code route}. */
    public static long fileSuccessCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? FileExportStats.getTrafficSourceSuccessCount(route.key())
                : FileExportStats.getTrafficToolTypeSuccessCount(route.key());
    }

    /** Returns the current failed file write count for {@code route}. */
    public static long fileFailureCount(Route route) {
        if (route == null) {
            return 0L;
        }
        return route.kind() == Kind.SOURCE
                ? FileExportStats.getTrafficSourceFailureCount(route.key())
                : FileExportStats.getTrafficToolTypeFailureCount(route.key());
    }

    /**
     * Resolves the displayed success count for a "Traffic by source" row in OpenSearch stats.
     *
     * <p>Most rows report the live captured tool-type count. The {@code PROXY_HISTORY} row
     * additionally folds in {@link #SOURCE_PROXY_HISTORY_SNAPSHOT} and {@link #SOURCE_PROXY_WEBSOCKET}
     * so snapshot pushes and proxy WebSocket exports surface under a single Proxy-family row.</p>
     */
    public static long resolveOpenSearchSourceSuccess(String sourceKey) {
        long total = ExportStats.getTrafficToolTypeSuccessCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += ExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += ExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /** Resolves the displayed failure count for a "Traffic by source" row in OpenSearch stats. */
    public static long resolveOpenSearchSourceFailure(String sourceKey) {
        long total = ExportStats.getTrafficToolTypeFailureCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += ExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += ExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /**
     * Resolves the displayed recovered count for a Traffic-by-source database row.
     *
     * @param sourceKey displayed tool/source key
     * @return current recovered count, including folded Proxy-family source buckets
     */
    public static long resolveOpenSearchSourceRecovery(String sourceKey) {
        long total = ExportStats.getTrafficToolTypeRecoveryCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += ExportStats.getTrafficSourceRecoveryCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += ExportStats.getTrafficSourceRecoveryCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /**
     * Resolves the displayed retry-queue drop count for a Traffic-by-source row.
     *
     * @param sourceKey displayed tool/source key
     * @return current retry-queue drop count, including folded Proxy-family source buckets
     */
    public static long resolveOpenSearchSourceRetryQueueDrops(String sourceKey) {
        long total = ExportStats.getTrafficToolTypeRetryQueueDrops(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += ExportStats.getTrafficSourceRetryQueueDrops(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += ExportStats.getTrafficSourceRetryQueueDrops(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /**
     * Resolves the displayed permanent-drop count for a Traffic-by-source row.
     *
     * @param sourceKey displayed tool/source key
     * @return current permanent-drop count, including folded Proxy-family source buckets
     */
    public static long resolveOpenSearchSourcePermanentDrops(String sourceKey) {
        long total = ExportStats.getTrafficToolTypePermanentDrops(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += ExportStats.getTrafficSourcePermanentDrops(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += ExportStats.getTrafficSourcePermanentDrops(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /**
     * Returns whether {@code route} contributes to the Stats Traffic sub-row labeled
     * {@code displaySourceKey}.
     *
     * <p>Proxy History snapshot and Proxy WebSocket source buckets fold into the
     * {@code PROXY_HISTORY} display row, matching {@link #resolveOpenSearchSourceSuccess(String)}.</p>
     *
     * @param displaySourceKey Stats sub-row key (for example {@code PROXY_HISTORY})
     * @param route traffic route from a queued or dropped document
     * @return {@code true} when the route should increment that display row
     */
    public static boolean contributesToDisplaySource(String displaySourceKey, Route route) {
        if (displaySourceKey == null || displaySourceKey.isBlank() || route == null) {
            return false;
        }
        if ("PROXY_HISTORY".equals(displaySourceKey)) {
            if (route.kind() == Kind.SOURCE) {
                return SOURCE_PROXY_HISTORY_SNAPSHOT.equals(route.key())
                        || SOURCE_PROXY_WEBSOCKET.equals(route.key());
            }
            return "PROXY_HISTORY".equals(route.key());
        }
        return route.kind() == Kind.TOOL_TYPE && displaySourceKey.equals(route.key());
    }

    /**
     * Counts prepared documents in {@code documents} that attribute to {@code displaySourceKey}.
     *
     * @param displaySourceKey Stats traffic sub-row key
     * @param documents prepared documents to inspect; {@code null} treated as empty
     * @return non-negative count
     */
    public static int countQueuedForDisplaySource(
            String displaySourceKey, Iterable<PreparedExportDocument> documents) {
        if (displaySourceKey == null || displaySourceKey.isBlank() || documents == null) {
            return 0;
        }
        int count = 0;
        for (PreparedExportDocument prepared : documents) {
            if (prepared == null) {
                continue;
            }
            if (contributesToDisplaySource(displaySourceKey, fromDocument(prepared.document()))) {
                count++;
            }
        }
        return count;
    }

    /** Resolves the displayed success count for a "Traffic by source" row in file stats. */
    public static long resolveFileSourceSuccess(String sourceKey) {
        long total = FileExportStats.getTrafficToolTypeSuccessCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += FileExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += FileExportStats.getTrafficSourceSuccessCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }

    /** Resolves the displayed failure count for a "Traffic by source" row in file stats. */
    public static long resolveFileSourceFailure(String sourceKey) {
        long total = FileExportStats.getTrafficToolTypeFailureCount(sourceKey);
        if ("PROXY_HISTORY".equals(sourceKey)) {
            total += FileExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_HISTORY_SNAPSHOT);
            total += FileExportStats.getTrafficSourceFailureCount(SOURCE_PROXY_WEBSOCKET);
        }
        return total;
    }
}
