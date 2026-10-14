package ai.anomalousvectors.tools.burp.sinks;

import java.util.Map;
import java.util.StringJoiner;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.TrafficToolCatalog;

/**
 * Logs sparse live traffic attribution totals when an export run stops.
 *
 * <p>The startup backlog summary accounts for snapshot sources such as Proxy History and Proxy
 * WebSocket. This summary reports the live tool-type deltas that accumulated during the run so
 * Scanner or other active tools can be reconciled from the Log panel.</p>
 */
public final class TrafficLiveAttributionSummary {

    private static final Object LOCK = new Object();
    private static Map<String, Long> openSearchToolBaseline = Map.of();
    private static Map<String, Long> fileToolBaseline = Map.of();
    private static long queueDropBaseline;
    private static long spillDropBaseline;
    private static long retryDropBaseline;
    private static boolean baselineCaptured;

    private TrafficLiveAttributionSummary() {}

    /** Captures current live-traffic counters for the next stop-time summary. */
    public static void startForCurrentRun() {
        synchronized (LOCK) {
            baselineCaptured = true;
            openSearchToolBaseline = openSearchToolCounts();
            fileToolBaseline = fileToolCounts();
            queueDropBaseline = ExportStats.getTrafficQueueDrops();
            spillDropBaseline = ExportStats.getTrafficSpillDrops();
            retryDropBaseline = ExportStats.getTotalRetryQueueDrops();
        }
    }

    /**
     * Logs live tool attribution deltas for the current run, if any non-zero counters exist.
     *
     * <p>No-op when {@link #startForCurrentRun()} did not run for this export session.</p>
     */
    public static void logAndClearForCurrentRun() {
        String line;
        synchronized (LOCK) {
            if (!baselineCaptured) {
                clearLocked();
                return;
            }
            line = formatSummaryLine(
                    delta(openSearchToolBaseline, openSearchToolCounts()),
                    delta(fileToolBaseline, fileToolCounts()),
                    Math.max(0L, ExportStats.getTrafficQueueDrops() - queueDropBaseline),
                    Math.max(0L, ExportStats.getTrafficSpillDrops() - spillDropBaseline),
                    Math.max(0L, ExportStats.getTotalRetryQueueDrops() - retryDropBaseline));
            clearLocked();
        }
        if (line != null) {
            Logger.logInfoPanelOnly(line);
        }
    }

    /** Clears captured baselines without logging. */
    public static void clearRunState() {
        synchronized (LOCK) {
            clearLocked();
        }
    }

    static String formatSummaryLine(
            Map<String, Long> openSearchDeltas,
            Map<String, Long> fileDeltas,
            long queueDrops,
            long spillDrops,
            long retryDrops) {
        StringJoiner sections = new StringJoiner("; ");
        String openSearch = formatCounts(openSearchDeltas);
        if (!openSearch.isEmpty()) {
            sections.add("openSearch={" + openSearch + "}");
        }
        String file = formatCounts(fileDeltas);
        if (!file.isEmpty()) {
            sections.add("file={" + file + "}");
        }
        if (queueDrops > 0L || spillDrops > 0L || retryDrops > 0L) {
            sections.add("drops={queue=" + queueDrops + ", spill=" + spillDrops + ", retry=" + retryDrops + "}");
        }
        String body = sections.toString();
        return body.isEmpty() ? null : "[LiveTraffic] Traffic: attribution summary: " + body + ".";
    }

    static Map<String, Long> liveDeltasForTests(Map<String, Long> before, Map<String, Long> after) {
        return delta(before, after);
    }

    private static Map<String, Long> openSearchToolCounts() {
        java.util.LinkedHashMap<String, Long> counts = new java.util.LinkedHashMap<>();
        for (String key : ExportStats.getTrafficToolTypeKeys()) {
            counts.put(key, ExportStats.getTrafficToolTypeSuccessCount(key));
        }
        return counts;
    }

    private static Map<String, Long> fileToolCounts() {
        java.util.LinkedHashMap<String, Long> counts = new java.util.LinkedHashMap<>();
        for (String key : FileExportStats.getTrafficToolTypeKeys()) {
            counts.put(key, FileExportStats.getTrafficToolTypeSuccessCount(key));
        }
        return counts;
    }

    private static Map<String, Long> delta(Map<String, Long> before, Map<String, Long> after) {
        java.util.LinkedHashMap<String, Long> deltas = new java.util.LinkedHashMap<>();
        for (String key : orderedKeys(after)) {
            if (TrafficToolCatalog.Tool.REPEATER_TABS.statisticsKey().equals(key)) {
                continue;
            }
            long value = Math.max(0L, after.getOrDefault(key, 0L) - before.getOrDefault(key, 0L));
            if (value > 0L) {
                deltas.put(displayToolName(key), value);
            }
        }
        return deltas;
    }

    private static java.util.Set<String> orderedKeys(Map<String, Long> after) {
        java.util.LinkedHashSet<String> keys =
                new java.util.LinkedHashSet<>(TrafficToolCatalog.statisticsKeys());
        keys.add(TrafficRouteBucket.TOOL_TYPE_UNKNOWN);
        keys.addAll(after.keySet());
        return keys;
    }

    private static String displayToolName(String key) {
        if (key == null || key.isBlank()) {
            return "Unknown";
        }
        if (TrafficRouteBucket.TOOL_TYPE_UNKNOWN.equals(key)) {
            return "Unknown";
        }
        return TrafficToolCatalog.findByStatisticsKey(key)
                .map(tool -> tool.displayLabel())
                .orElseGet(() -> key.charAt(0) + key.substring(1).toLowerCase(java.util.Locale.ROOT));
    }

    private static String formatCounts(Map<String, Long> counts) {
        StringJoiner joiner = new StringJoiner(", ");
        counts.forEach((key, value) -> joiner.add(key + "=" + value));
        return joiner.toString();
    }

    private static void clearLocked() {
        baselineCaptured = false;
        openSearchToolBaseline = Map.of();
        fileToolBaseline = Map.of();
        queueDropBaseline = 0L;
        spillDropBaseline = 0L;
        retryDropBaseline = 0L;
    }
}
