package ai.anomalousvectors.tools.burp.ui;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.FieldPosition;
import java.text.NumberFormat;
import java.text.ParsePosition;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.LongFunction;
import java.util.function.ToLongFunction;

import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

/**
 * Pure string formatters for the Misc Stats rows that surface OpenSearch health, retry-queue
 * age, and silent-skip counters. Extracted from {@link StatsPanel} so the logic is
 * unit-testable without a Swing harness.
 *
 * <p>All methods read from {@link ExportStats} (no Swing state) and return plain strings.
 * Returned values are ready to drop into a {@code JLabel}; callers do not need to format
 * further.</p>
 *
 * <p>This class is not thread-safe because its shared decimal formatter is mutable. Stats-panel
 * refresh and Stop/clipboard snapshot formatting must not invoke it concurrently.</p>
 */
final class StatsPanelFormatters {

    private static final DecimalFormat DECIMAL_ONE =
            new DecimalFormat("0.0", DecimalFormatSymbols.getInstance(Locale.ROOT));

    /** Y-axis tick labels stay at or below this value by rolling KiB → MiB → GiB (or MiB → GiB). */
    static final double AXIS_TICK_LABEL_MAX = 999.0;

    /** Smallest nice axis ceiling ≥ normalized value (1, 1.2, … 10), used for values &gt; 10. */
    private static final double[] NICE_AXIS_NORMALIZED =
            {1.0, 1.2, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0};

    private StatsPanelFormatters() {}

    /**
     * Y-axis label and tick scaling for throughput byte-rate charts (dataset values are KiB/s).
     *
     * @param maxKiBPerSec largest series sample in KiB/s (before headroom)
     * @param headroomMultiplier applied to max when picking the display unit (matches chart range)
     */
    static ChartAxisScale chooseByteRateAxisScale(double maxKiBPerSec, double headroomMultiplier) {
        return chooseAxisScale(
                maxKiBPerSec * headroomMultiplier,
                new String[] { "KiB per second", "MiB per second", "GiB per second" },
                new double[] { 1.0, 1024.0, 1024.0 * 1024.0 });
    }

    /**
     * Y-axis label and tick scaling for the JVM heap chart (dataset values are MiB).
     */
    static ChartAxisScale chooseMemoryAxisScale(double maxMiB, double headroomMultiplier) {
        return chooseAxisScale(
                maxMiB * headroomMultiplier,
                new String[] { "MiB", "GiB" },
                new double[] { 1.0, 1024.0 });
    }

    private static ChartAxisScale chooseAxisScale(
            double rangeUpperInBaseUnits,
            String[] labels,
            double[] divisorsFromBase) {
        for (int unitIndex = 0; unitIndex < labels.length; unitIndex++) {
            double displayUpper = rangeUpperInBaseUnits / divisorsFromBase[unitIndex];
            boolean lastUnit = unitIndex == labels.length - 1;
            if (displayUpper <= AXIS_TICK_LABEL_MAX || lastUnit) {
                return new ChartAxisScale(labels[unitIndex], divisorsFromBase[unitIndex]);
            }
        }
        throw new AssertionError("unreachable");
    }

    /**
     * Range maximum in stored units after headroom and a readable tick ceiling in display units
     * (e.g. raw 3.9 GiB → 4 GiB → {@code 4 * 1024} MiB).
     */
    static double rangeUpperInBaseUnits(double maxInBaseUnits, double headroomMultiplier, ChartAxisScale scale) {
        double niceDisplayUpper = rangeCeiling(
                maxInBaseUnits / scale.displayDivisor(),
                headroomMultiplier);
        return niceDisplayUpper * scale.displayDivisor();
    }

    /**
     * Y-axis ceiling in the same units as {@code maxValue}: headroom, then a nice tick that stays
     * strictly above the padded peak so spline overshoot cannot paint through the plot top.
     *
     * @param maxValue largest visible sample (docs/s, KiB/s, MiB, …)
     * @param headroomMultiplier multiplier applied before choosing a nice tick
     * @return positive axis upper bound
     */
    static double rangeCeiling(double maxValue, double headroomMultiplier) {
        if (maxValue <= 0.0) {
            return 1.0;
        }
        double headroom = headroomMultiplier > 0.0 ? headroomMultiplier : 1.0;
        double rawUpper = maxValue * headroom;
        double bound = nicePositiveUpperBound(rawUpper);
        // When max*headroom lands on (or within 0.5% of) a nice tick, step to the next tick.
        if (bound <= rawUpper * 1.005) {
            bound = nicePositiveUpperBound(bound + Math.max(bound * 0.05, 0.05));
        }
        return bound;
    }

    /**
     * Smallest readable axis ceiling ≥ {@code value} ({@code 7.5 → 8}, {@code 750 → 800}, not {@code 1000}).
     */
    static double nicePositiveUpperBound(double value) {
        if (value <= 0.0) {
            return 1.0;
        }
        if (value <= 10.0) {
            return Math.ceil(value);
        }
        double magnitude = Math.pow(10.0, Math.floor(Math.log10(value)));
        double normalized = value / magnitude;
        for (double candidate : NICE_AXIS_NORMALIZED) {
            if (candidate + 1e-9 >= normalized) {
                return candidate * magnitude;
            }
        }
        return 10.0 * magnitude;
    }

    /**
     * Largest sample in {@code dataset} whose timestamp falls in {@code [minMs, maxMs]} (inclusive).
     * Used so the Y-axis tracks the visible chart window, not older points still held in the series.
     */
    static double maxTimeSeriesValueInDomain(TimeSeriesCollection dataset, long minMs, long maxMs) {
        if (maxMs < minMs) {
            maxMs = minMs;
        }
        double max = 0.0;
        for (int seriesIndex = 0; seriesIndex < dataset.getSeriesCount(); seriesIndex++) {
            TimeSeries series = dataset.getSeries(seriesIndex);
            int items = series.getItemCount();
            for (int itemIndex = 0; itemIndex < items; itemIndex++) {
                long t = series.getTimePeriod(itemIndex).getMiddleMillisecond();
                if (t < minMs || t > maxMs) {
                    continue;
                }
                Number value = series.getValue(itemIndex);
                if (value != null) {
                    max = Math.max(max, value.doubleValue());
                }
            }
        }
        return max;
    }

    /**
     * Tick step in display units (whole numbers only) targeting about four labels on the axis.
     */
    static int integerDisplayTickStep(double niceDisplayUpper) {
        if (niceDisplayUpper <= 0.0) {
            return 1;
        }
        double step = nicePositiveUpperBound(niceDisplayUpper / 4.0);
        return (int) Math.max(1L, Math.round(step));
    }

    /**
     * Formats range-axis ticks as whole display units ({@code divisor} converts stored values).
     */
    static NumberFormat axisTickNumberFormat(double divisor) {
        DecimalFormat pattern = new DecimalFormat("#,##0", DecimalFormatSymbols.getInstance(Locale.ROOT));
        return new NumberFormat() {
            @Override
            public StringBuffer format(double number, StringBuffer toAppendTo, FieldPosition pos) {
                return pattern.format(Math.round(number / divisor), toAppendTo, pos);
            }

            @Override
            public StringBuffer format(long number, StringBuffer toAppendTo, FieldPosition pos) {
                return format((double) number, toAppendTo, pos);
            }

            @Override
            public Number parse(String source, ParsePosition parsePosition) {
                return null;
            }
        };
    }

    /** Label and divisor from stored units to display units. */
    record ChartAxisScale(String label, double displayDivisor) {}

    /**
     * Formats an epoch-ms timestamp as a compact "Xs ago" label.
     *
     * <p>Returns {@code "never"} when the timestamp is non-positive (no success recorded yet),
     * and scales to seconds, minutes, hours, or days as age grows. Used for the OpenSearch
     * connection-health Last Success row.</p>
     */
    static String formatRelativeTime(long epochMs) {
        return formatRelativeTime(epochMs, System.currentTimeMillis());
    }

    /**
     * Testable variant that accepts a caller-supplied "now" so unit tests can exercise each
     * unit boundary (seconds, minutes, hours, days) without relying on real wall-clock time.
     */
    static String formatRelativeTime(long epochMs, long nowMs) {
        if (epochMs <= 0) {
            return "never";
        }
        long delta = nowMs - epochMs;
        if (delta < 0) {
            delta = 0;
        }
        long seconds = delta / 1000L;
        if (seconds < 60) {
            return seconds + "s ago";
        }
        long minutes = seconds / 60L;
        if (minutes < 60) {
            return minutes + "m ago";
        }
        long hours = minutes / 60L;
        if (hours < 24) {
            return hours + "h ago";
        }
        long days = hours / 24L;
        return days + "d ago";
    }

    /**
     * Formats spill backlog as {@code "N docs (X.X MiB)"}.
     */
    static String formatSpillQueue(long docs, long bytes) {
        double mib = bytes / (1024.0 * 1024.0);
        return formatWhole(docs) + " docs (" + DECIMAL_ONE.format(mib) + " MiB)";
    }

    /**
     * Summarizes database export totals on one line: docs, size, and failure count.
     */
    static String formatExportedSummary(long docs, String sizeHuman, long failures) {
        return formatWhole(docs) + " docs · " + sizeHuman + " · " + formatWhole(failures) + " failures";
    }

    /**
     * Lists per-index retry-queue depths, omitting indexes at zero. Returns {@code "—"} when
     * every queue is empty.
     */
    static String formatRetryQueueDepthSummary() {
        return formatPerIndexNonZero(
                indexKey -> (long) IndexingRetryCoordinator.getInstance()
                        .getQueueSize(RuntimeConfig.indexNameForKey(indexKey)),
                value -> formatWhole(value) + " queued");
    }

    /** Lists unique search-document prefix truncations by index, omitting indexes at zero. */
    static String formatBodyTruncationsByIndex() {
        return formatPerIndexNonZero(ExportStats::getSearchBodyPrefixTruncations, StatsPanelFormatters::formatWhole);
    }

    /** Formats current reserved snapshot build-ahead capacity and its fixed envelope. */
    static String formatSnapshotBuildAhead() {
        return formatBytesHuman(ExportStats.getSnapshotBuildAheadReservedBytes())
                + " / " + formatBytesHuman(SnapshotExportEngine.maxBuildAheadBytes())
                + " (" + formatWhole(ExportStats.getSnapshotBuildAheadReservedPermits())
                + " / " + formatWhole(SnapshotExportEngine.maxBuildAheadPermits()) + " permits)";
    }

    /** Formats the run peak of reserved snapshot build-ahead capacity. */
    static String formatPeakSnapshotBuildAhead() {
        long bytes = ExportStats.getPeakSnapshotBuildAheadReservedBytes();
        int permits = ExportStats.getPeakSnapshotBuildAheadReservedPermits();
        if (bytes <= 0L && permits <= 0) {
            return "—";
        }
        return formatBytesHuman(bytes) + " (" + formatWhole(permits) + " permits)";
    }

    /**
     * Returns the total retry-queue doc count across all exporter indexes.
     */
    static int totalRetryQueueDocs() {
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        int total = 0;
        for (String indexKey : ExportStats.getIndexKeys()) {
            total += coordinator.getQueueSize(RuntimeConfig.indexNameForKey(indexKey));
        }
        return total;
    }

    /**
     * Returns the total estimated retry-queue bytes across all exporter indexes.
     */
    static long totalRetryQueueBytes() {
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        long total = 0L;
        for (String indexKey : ExportStats.getIndexKeys()) {
            total += coordinator.getQueueBytesEstimate(RuntimeConfig.indexNameForKey(indexKey));
        }
        return total;
    }

    /**
     * Formats a run peak queue depth as {@code "N docs (X.X MiB)"}, or {@code "—"} when zero.
     */
    static String formatPeakQueueDepth(int docs, long bytes) {
        if (docs <= 0 && bytes <= 0) {
            return "—";
        }
        return formatSpillQueue(Math.max(0, docs), Math.max(0L, bytes));
    }

    /**
     * Lists per-index oldest queued ages, omitting empty queues. Returns {@code "—"} when none
     * are queued.
     */
    static String formatOldestQueuedAgeSummary() {
        return formatPerIndexNonZero(
                ExportStats::getOldestQueuedAgeMs,
                ageMs -> DECIMAL_ONE.format(ageMs / 1000.0) + "s");
    }

    private static String formatPerIndexNonZero(
            ToLongFunction<String> valueForKey,
            LongFunction<String> formatValue) {
        List<String> sortedKeys = new ArrayList<>(ExportStats.getIndexKeys());
        sortedKeys.sort((left, right) -> left.compareToIgnoreCase(right));
        List<String> parts = new ArrayList<>();
        for (String indexKey : sortedKeys) {
            long value = valueForKey.applyAsLong(indexKey);
            if (value > 0) {
                parts.add(indexKey + ": " + formatValue.apply(value));
            }
        }
        if (parts.isEmpty()) {
            return "—";
        }
        return String.join(", ", parts);
    }

    /**
     * Builds a compact "reason=N" summary from the skip-reason counters, showing {@code "-"}
     * when nothing has been skipped yet. Stable key order is guaranteed by
     * {@link ExportStats#getSkipReasonCounts()}.
     */
    static String formatSkipReasons() {
        return formatReasons(ExportStats.getSkipReasonCounts());
    }

    /**
     * Builds a compact stable summary of permanent-drop reason totals.
     *
     * @return space-separated {@code reason=count} values, or {@code "-"} when empty
     */
    static String formatPermanentDropReasons() {
        return formatReasons(ExportStats.getPermanentDropReasonCounts());
    }

    private static String formatReasons(Map<String, Long> reasons) {
        if (reasons.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, Long> entry : reasons.entrySet()) {
            if (!first) {
                sb.append(' ');
            }
            sb.append(entry.getKey()).append('=').append(formatWhole(entry.getValue()));
            first = false;
        }
        return sb.toString();
    }

    private static String formatWhole(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    /**
     * Formats a byte count for a Misc Stats row, choosing KiB / MiB / GiB scale automatically.
     * Returns {@code "-"} for negative inputs so callers can feed "missing" sentinels through
     * without guarding each call site.
     */
    static String formatBytesHuman(long bytes) {
        if (bytes < 0) {
            return "-";
        }
        if (bytes < 1024L) {
            return bytes + " B";
        }
        double kib = bytes / 1024.0;
        if (kib < 1024.0) {
            return DECIMAL_ONE.format(kib) + " KiB";
        }
        double mib = kib / 1024.0;
        if (mib < 1024.0) {
            return DECIMAL_ONE.format(mib) + " MiB";
        }
        double gib = mib / 1024.0;
        return DECIMAL_ONE.format(gib) + " GiB";
    }

    /**
     * Formats remaining shared capacity cooldown for Misc Stats.
     *
     * @param remainingMs milliseconds remaining; {@code <= 0} renders as an em dash
     * @return human-readable cooldown remainder
     */
    static String formatCooldownRemaining(long remainingMs) {
        if (remainingMs <= 0L) {
            return "—";
        }
        if (remainingMs < 1_000L) {
            return remainingMs + " ms";
        }
        return DECIMAL_ONE.format(remainingMs / 1_000.0) + " s";
    }

    /**
     * Returns the live bulk byte budget, or the last active value after Stop reset the controller.
     */
    static long displayedBulkByteBudget() {
        long lastActive = ExportStats.getLastActiveBulkByteBudget();
        return !RuntimeConfig.isExportRunning() && lastActive > 0L
                ? lastActive
                : BulkByteBudget.currentMaxBytes();
    }

    /**
     * Returns the live snapshot flush cap, or the last active value after Stop reset the controller.
     */
    static int displayedSnapshotFlushCap() {
        int lastActive = ExportStats.getLastActiveSnapshotFlushCap();
        return !RuntimeConfig.isExportRunning() && lastActive > 0
                ? lastActive
                : BulkByteBudget.maxInFlightFlushes();
    }

    /**
     * Formats the Yes/No Soft Outage gauge.
     *
     * @param active whether soft capacity outage mode is active
     * @return {@code Yes} or {@code No}
     */
    static String formatSoftOutage(boolean active) {
        return active ? "Yes" : "No";
    }

    /**
     * Formats the recoverable database-authorization pause.
     *
     * @return {@code No} when inactive, otherwise pause duration, retained backlog, and next probe
     */
    static String formatAuthorizationRecovery() {
        IndexingRetryCoordinator coordinator = IndexingRetryCoordinator.getInstance();
        if (!coordinator.isAuthorizationRecoveryPaused()) {
            return "No";
        }
        long now = System.currentTimeMillis();
        long pausedSeconds = Math.max(0L, (now - coordinator.getAuthorizationPausedAtMs()) / 1_000L);
        long nextProbeSeconds = Math.max(
                0L,
                (coordinator.getNextAuthorizationProbeAtMs() - now + 999L) / 1_000L);
        int retained = coordinator.getTotalQueueSize()
                + ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentSize()
                + ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentSpillSize();
        return "Paused " + formatDurationSeconds(pausedSeconds)
                + " · " + formatWhole(retained) + " retained"
                + " · probe " + nextProbeSeconds + "s";
    }

    private static String formatDurationSeconds(long seconds) {
        if (seconds < 60L) {
            return seconds + "s";
        }
        long minutes = seconds / 60L;
        if (minutes < 60L) {
            return minutes + "m";
        }
        return (minutes / 60L) + "h " + (minutes % 60L) + "m";
    }

    /**
     * Formats Overview Traffic Spill status.
     *
     * @param status spill status; {@code null} treated as Ready
     * @return {@code Ready}, {@code In use}, or {@code Full}
     */
    static String formatSpillStatus(ai.anomalousvectors.tools.burp.utils.ExportAdmissionController.SpillStatus status) {
        if (status == null) {
            return "Ready";
        }
        return switch (status) {
            case READY -> "Ready";
            case IN_USE -> "In use";
            case FULL -> "Full";
        };
    }

}
