package ai.anomalousvectors.tools.burp.sinks;

import java.util.function.LongSupplier;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;

/**
 * Shared helper for logging completion summaries of one-shot export waves.
 *
 * <p>Reporters such as {@code ProxyHistoryIndexReporter} and {@code SitemapIndexReporter} run
 * bounded, single-pass exports at Start. This helper captures counter deltas across the run
 * and emits a single {@code INFO}-level panel line with attempted, file, and OpenSearch
 * outcomes. The {@code file={...}; openSearch={...}} body shares the substructure with the
 * Repeater Tabs startup completion summary so operators can visually align per-source
 * totals across reporters; the surrounding prefix and suffix differ per reporter.</p>
 *
 * <p>Two counter sources are supported via {@link #forRoute(TrafficRouteBucket.Route)} and
 * {@link #forIndexKey(String)}: traffic reporters use the per-route bucket counters, while
 * non-traffic reporters (Sitemap, Findings, etc.) use the index-key totals exposed by
 * {@link ExportStats} / {@link FileExportStats}. Both flavors share identical body output.</p>
 */
public final class SnapshotSummary {

    private SnapshotSummary() {}

    /**
     * Snapshots the current file and OpenSearch counters for a traffic route. Use before starting
     * a run and pair with {@link #logInfo} after the run to compute deltas.
     *
     * @param route route whose counters should be tracked; {@code null} returns an empty snapshot
     * @return baseline snapshot; never {@code null}
     */
    public static Baseline forRoute(TrafficRouteBucket.Route route) {
        if (route == null) {
            return Baseline.empty();
        }
        return new Baseline(
                () -> TrafficRouteBucket.fileSuccessCount(route),
                () -> TrafficRouteBucket.fileFailureCount(route),
                () -> TrafficRouteBucket.databaseSuccessCount(route),
                () -> TrafficRouteBucket.databaseFailureCount(route),
                TrafficRouteBucket.fileSuccessCount(route),
                TrafficRouteBucket.fileFailureCount(route),
                TrafficRouteBucket.databaseSuccessCount(route),
                TrafficRouteBucket.databaseFailureCount(route));
    }

    /**
     * Snapshots the current file and OpenSearch counters for a non-traffic {@code indexKey}.
     *
     * @param indexKey logical index key (for example {@code "sitemap"}, {@code "findings"});
     *                 {@code null} or blank returns an empty snapshot
     * @return baseline snapshot; never {@code null}
     */
    public static Baseline forIndexKey(String indexKey) {
        if (indexKey == null || indexKey.isBlank()) {
            return Baseline.empty();
        }
        String key = indexKey.trim();
        return new Baseline(
                () -> FileExportStats.getSuccessCount(key),
                () -> FileExportStats.getFailureCount(key),
                () -> ExportStats.getSuccessCount(key),
                () -> ExportStats.getFailureCount(key),
                FileExportStats.getSuccessCount(key),
                FileExportStats.getFailureCount(key),
                ExportStats.getSuccessCount(key),
                ExportStats.getFailureCount(key));
    }

    /**
     * Logs a completion summary comparing current counters to {@code baseline}.
     *
     * @param prefix source label appended after the {@code [SnapshotExport]} function prefix
     * @param baseline snapshot captured before the run started
     * @param attempted total documents attempted in the run (including those that produced no doc)
     * @param durationMs wall-clock run duration in milliseconds
     * @param openSearchActive whether the OpenSearch sink was active for the run
     * @param fileActive whether any file sink was active for the run
     */
    public static void logInfo(
            String prefix,
            Baseline baseline,
            int attempted,
            long durationMs,
            boolean openSearchActive,
            boolean fileActive) {
        logInfo(prefix, baseline, attempted, durationMs, -1L, -1L, openSearchActive, fileActive);
    }

    /**
     * Logs a completion summary with optional build/flush timing split for snapshot attribution.
     *
     * @param buildWallMs wall-clock build span ({@code -1} to omit timing suffix)
     */
    public static void logInfo(
            String prefix,
            Baseline baseline,
            int attempted,
            long durationMs,
            long buildWallMs,
            long flushMs,
            boolean openSearchActive,
            boolean fileActive) {
        Logger.logInfoPanelOnly(formatSummary(
                prefix, baseline, attempted, durationMs, buildWallMs, flushMs, openSearchActive, fileActive));
    }

    /**
     * Builds the completion-summary line that {@link #logInfo} emits.
     *
     * <p>Package-private so tests can assert the exact format without intercepting the logger.</p>
     */
    static String formatSummary(
            String prefix,
            Baseline baseline,
            int attempted,
            long durationMs,
            boolean openSearchActive,
            boolean fileActive) {
        return formatSummary(prefix, baseline, attempted, durationMs, -1L, -1L, openSearchActive, fileActive);
    }

    static String formatSummary(
            String prefix,
            Baseline baseline,
            int attempted,
            long durationMs,
            long buildWallMs,
            long flushMs,
            boolean openSearchActive,
            boolean fileActive) {
        String label = (prefix == null || prefix.isBlank()) ? "Export" : prefix.trim();
        StringBuilder sb = new StringBuilder(128);
        sb.append("[SnapshotExport] ").append(label).append(": snapshot complete: captured=")
                .append(Math.max(0, attempted));
        String body = formatCompletionBody(baseline, openSearchActive, fileActive);
        if (!body.isEmpty()) {
            sb.append("; ").append(body);
        }
        sb.append(" in ").append(Math.max(0L, durationMs)).append("ms");
        if (buildWallMs >= 0L && flushMs >= 0L) {
            sb.append(" (build_wall_ms=").append(Math.max(0L, buildWallMs))
                    .append(" flush_ms=").append(Math.max(0L, flushMs)).append(')');
        }
        sb.append('.');
        return sb.toString();
    }

    /**
     * Builds the {@code file={...}; openSearch={...}} body fragment that reporters can compose
     * into their own completion log lines.
     *
     * <p>Each section is included only when the corresponding sink was active for the run. When
     * both are inactive the method returns an empty string. Reporters are responsible for
     * prepending/appending any surrounding prefix, suffix, or separators.</p>
     *
     * @param baseline snapshot captured before the run; {@code null} yields zeroed deltas
     * @param openSearchActive whether the OpenSearch sink was active for the run
     * @param fileActive whether any file sink was active for the run
     * @return fragment such as {@code "file={success=2, failure=0}; openSearch={success=2, failure=0}"};
     *         never {@code null}
     */
    public static String formatCompletionBody(
            Baseline baseline,
            boolean openSearchActive,
            boolean fileActive) {
        CompletionDeltas deltas = completionDeltas(baseline);
        StringBuilder sb = new StringBuilder(64);
        if (fileActive) {
            sb.append("file={written=").append(deltas.fileSuccess())
                    .append(", failure=").append(deltas.fileFailure()).append('}');
        }
        if (openSearchActive) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append("openSearch={exported=").append(deltas.openSearchSuccess())
                    .append(", failure=").append(deltas.openSearchFailure()).append('}');
        }
        return sb.toString();
    }

    /**
     * Returns current completion deltas relative to the supplied baseline.
     *
     * @param baseline snapshot captured before the run; {@code null} yields zeroed deltas
     * @return non-negative file/OpenSearch success and failure deltas
     */
    public static CompletionDeltas completionDeltas(Baseline baseline) {
        if (baseline == null || !baseline.hasSource()) {
            return CompletionDeltas.empty();
        }
        return new CompletionDeltas(
                Math.max(0, baseline.fileSuccessNow.getAsLong() - baseline.fileSuccessBefore),
                Math.max(0, baseline.fileFailureNow.getAsLong() - baseline.fileFailureBefore),
                Math.max(0, baseline.openSearchSuccessNow.getAsLong() - baseline.openSearchSuccessBefore),
                Math.max(0, baseline.openSearchFailureNow.getAsLong() - baseline.openSearchFailureBefore));
    }

    /**
     * Non-negative file and OpenSearch deltas for a one-shot export wave.
     *
     * @param fileSuccess file writes completed since the baseline
     * @param fileFailure file write failures since the baseline
     * @param openSearchSuccess OpenSearch writes completed since the baseline
     * @param openSearchFailure OpenSearch write failures since the baseline
     */
    public record CompletionDeltas(
            long fileSuccess,
            long fileFailure,
            long openSearchSuccess,
            long openSearchFailure) {

        /** Returns a zero-valued delta set. */
        public static CompletionDeltas empty() {
            return new CompletionDeltas(0L, 0L, 0L, 0L);
        }
    }

    /** Baseline counters for a counter source captured before a one-shot run. */
    public static final class Baseline {

        private final LongSupplier fileSuccessNow;
        private final LongSupplier fileFailureNow;
        private final LongSupplier openSearchSuccessNow;
        private final LongSupplier openSearchFailureNow;
        private final long fileSuccessBefore;
        private final long fileFailureBefore;
        private final long openSearchSuccessBefore;
        private final long openSearchFailureBefore;

        private Baseline(
                LongSupplier fileSuccessNow,
                LongSupplier fileFailureNow,
                LongSupplier openSearchSuccessNow,
                LongSupplier openSearchFailureNow,
                long fileSuccessBefore,
                long fileFailureBefore,
                long openSearchSuccessBefore,
                long openSearchFailureBefore) {
            this.fileSuccessNow = fileSuccessNow;
            this.fileFailureNow = fileFailureNow;
            this.openSearchSuccessNow = openSearchSuccessNow;
            this.openSearchFailureNow = openSearchFailureNow;
            this.fileSuccessBefore = fileSuccessBefore;
            this.fileFailureBefore = fileFailureBefore;
            this.openSearchSuccessBefore = openSearchSuccessBefore;
            this.openSearchFailureBefore = openSearchFailureBefore;
        }

        private static Baseline empty() {
            return new Baseline(null, null, null, null, 0, 0, 0, 0);
        }

        private boolean hasSource() {
            return fileSuccessNow != null
                    && fileFailureNow != null
                    && openSearchSuccessNow != null
                    && openSearchFailureNow != null;
        }
    }
}
