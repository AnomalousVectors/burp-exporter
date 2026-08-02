package ai.anomalousvectors.tools.burp.ui;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link StatsPanelFormatters}. Covers each output branch (empty state,
 * unit scaling) without needing a Swing harness.
 */
class StatsPanelFormattersTest {

    @BeforeEach
    public void resetStats() {
        ExportStats.resetForTests();
    }

    @Test
    void formatBytesHuman_handlesEachUnitBoundaryAndNegative() {
        assertThat(StatsPanelFormatters.formatBytesHuman(-1L)).isEqualTo("-");
        assertThat(StatsPanelFormatters.formatBytesHuman(0L)).isEqualTo("0 B");
        assertThat(StatsPanelFormatters.formatBytesHuman(1023L)).isEqualTo("1023 B");
        assertThat(StatsPanelFormatters.formatBytesHuman(1024L)).isEqualTo("1.0 KiB");
        assertThat(StatsPanelFormatters.formatBytesHuman(1024L * 1024L)).isEqualTo("1.0 MiB");
        assertThat(StatsPanelFormatters.formatBytesHuman(1024L * 1024L * 1024L)).isEqualTo("1.0 GiB");
    }

    @Test
    void formatCooldownRemaining_andSoftOutage_coverEmptyAndActiveStates() {
        assertThat(StatsPanelFormatters.formatCooldownRemaining(0L)).isEqualTo("—");
        assertThat(StatsPanelFormatters.formatCooldownRemaining(-1L)).isEqualTo("—");
        assertThat(StatsPanelFormatters.formatCooldownRemaining(250L)).isEqualTo("250 ms");
        assertThat(StatsPanelFormatters.formatCooldownRemaining(12_500L)).isEqualTo("12.5 s");
        assertThat(StatsPanelFormatters.formatSoftOutage(false)).isEqualTo("No");
        assertThat(StatsPanelFormatters.formatSoftOutage(true)).isEqualTo("Yes");
    }

    @Test
    void formatSpillQueue_combinesDocsAndMiB() {
        assertThat(StatsPanelFormatters.formatSpillQueue(0, 0)).isEqualTo("0 docs (0.0 MiB)");
        assertThat(StatsPanelFormatters.formatSpillQueue(12, 1024L * 1024L)).isEqualTo("12 docs (1.0 MiB)");
    }

    @Test
    void formatExportedSummary_joinsDocsSizeAndFailures() {
        assertThat(StatsPanelFormatters.formatExportedSummary(100, "2.4 GB", 0))
                .isEqualTo("100 docs · 2.4 GB · 0 failures");
    }

    @Test
    void formatRetryQueueDepthSummary_allZero_returnsEmDash() {
        assertThat(StatsPanelFormatters.formatRetryQueueDepthSummary()).isEqualTo("—");
    }

    @Test
    void formatBodyTruncationsByIndex_omitsZeroIndexesAndUsesStableOrder() {
        ExportStats.recordSearchBodyPrefixTruncation("traffic");
        ExportStats.recordSearchBodyPrefixTruncation("findings");
        ExportStats.recordSearchBodyPrefixTruncation("findings");

        assertThat(StatsPanelFormatters.formatBodyTruncationsByIndex())
                .isEqualTo("findings: 2, traffic: 1");
    }

    @Test
    void formatSnapshotBuildAhead_showsCurrentCapacityAndPeak() {
        assertThat(StatsPanelFormatters.formatSnapshotBuildAhead())
                .isEqualTo("0 B / 64.0 MiB (0 / 1,024 permits)");
        assertThat(StatsPanelFormatters.formatPeakSnapshotBuildAhead()).isEqualTo("—");

        ExportStats.reserveSnapshotBuildAhead(4, 256L * 1024L);

        assertThat(StatsPanelFormatters.formatSnapshotBuildAhead())
                .isEqualTo("256.0 KiB / 64.0 MiB (4 / 1,024 permits)");
        assertThat(StatsPanelFormatters.formatPeakSnapshotBuildAhead())
                .isEqualTo("256.0 KiB (4 permits)");
    }

    @Test
    void formatOldestQueuedAgeSummary_allEmpty_returnsEmDash() {
        assertThat(StatsPanelFormatters.formatOldestQueuedAgeSummary()).isEqualTo("—");
    }

    @Test
    void formatRelativeTime_nonPositiveEpoch_returnsNever() {
        assertThat(StatsPanelFormatters.formatRelativeTime(0L, 1_000_000L)).isEqualTo("never");
        assertThat(StatsPanelFormatters.formatRelativeTime(-1L, 1_000_000L)).isEqualTo("never");
    }

    @Test
    void formatRelativeTime_subSecond_returnsZeroSecondsAgo() {
        long now = 10_000L;
        assertThat(StatsPanelFormatters.formatRelativeTime(now - 250L, now)).isEqualTo("0s ago");
    }

    @Test
    void formatRelativeTime_secondsBranch() {
        long now = 1_000_000L;
        assertThat(StatsPanelFormatters.formatRelativeTime(now - 45_000L, now)).isEqualTo("45s ago");
    }

    @Test
    void formatRelativeTime_minutesBranch() {
        long now = 10_000_000L;
        long fiveMinutesAgo = now - (5 * 60 * 1000L);
        assertThat(StatsPanelFormatters.formatRelativeTime(fiveMinutesAgo, now)).isEqualTo("5m ago");
    }

    @Test
    void formatRelativeTime_hoursBranch() {
        long now = 100_000_000L;
        long twoHoursAgo = now - (2 * 60 * 60 * 1000L);
        assertThat(StatsPanelFormatters.formatRelativeTime(twoHoursAgo, now)).isEqualTo("2h ago");
    }

    @Test
    void formatRelativeTime_daysBranch() {
        long now = 10_000_000_000L;
        long threeDaysAgo = now - (3L * 24 * 60 * 60 * 1000L);
        assertThat(StatsPanelFormatters.formatRelativeTime(threeDaysAgo, now)).isEqualTo("3d ago");
    }

    @Test
    void formatRelativeTime_futureTimestamp_clampsToZero() {
        long now = 1_000_000L;
        assertThat(StatsPanelFormatters.formatRelativeTime(now + 5_000L, now)).isEqualTo("0s ago");
    }

    @Test
    void formatSkipReasons_none_returnsDash() {
        assertThat(StatsPanelFormatters.formatSkipReasons()).isEqualTo("-");
    }

    @Test
    void chooseByteRateAxisScale_staysKiBUntilDisplayUpperExceeds999() {
        assertThat(StatsPanelFormatters.chooseByteRateAxisScale(500.0, 1.5).label()).isEqualTo("KiB per second");
        assertThat(StatsPanelFormatters.chooseByteRateAxisScale(500.0, 1.5).displayDivisor()).isEqualTo(1.0);

        assertThat(StatsPanelFormatters.chooseByteRateAxisScale(800.0, 1.5).label()).isEqualTo("MiB per second");
        assertThat(StatsPanelFormatters.chooseByteRateAxisScale(800.0, 1.5).displayDivisor()).isEqualTo(1024.0);
    }

    @Test
    void maxTimeSeriesValueInDomain_usesOnlySamplesInsideWindow() {
        TimeSeriesCollection dataset = new TimeSeriesCollection();
        TimeSeries traffic = new TimeSeries("Traffic");
        long baseMs = 1_700_000_000_000L;
        traffic.addOrUpdate(new Millisecond(new Date(baseMs)), 400.0);
        traffic.addOrUpdate(new Millisecond(new Date(baseMs + 30_000L)), 55.0);
        dataset.addSeries(traffic);

        assertThat(StatsPanelFormatters.maxTimeSeriesValueInDomain(dataset, baseMs, baseMs + 40_000L))
                .isEqualTo(400.0);
        assertThat(StatsPanelFormatters.maxTimeSeriesValueInDomain(dataset, baseMs + 20_000L, baseMs + 40_000L))
                .isEqualTo(55.0);
    }

    @Test
    void maxTimeSeriesValueInDomain_emptyWindow_returnsZero() {
        TimeSeriesCollection dataset = new TimeSeriesCollection();
        TimeSeries traffic = new TimeSeries("Traffic");
        long baseMs = 1_700_000_000_000L;
        traffic.addOrUpdate(new Millisecond(new Date(baseMs)), 100.0);
        dataset.addSeries(traffic);

        assertThat(StatsPanelFormatters.maxTimeSeriesValueInDomain(dataset, baseMs + 60_000L, baseMs + 120_000L))
                .isEqualTo(0.0);
    }

    @Test
    void nicePositiveUpperBound_roundsSmallCeilingsToWholeNumbers() {
        assertThat(StatsPanelFormatters.nicePositiveUpperBound(3.9)).isEqualTo(4.0);
        assertThat(StatsPanelFormatters.nicePositiveUpperBound(2.01)).isEqualTo(3.0);
        assertThat(StatsPanelFormatters.nicePositiveUpperBound(87.0)).isEqualTo(90.0);
        assertThat(StatsPanelFormatters.nicePositiveUpperBound(750.0)).isEqualTo(800.0);
    }

    @Test
    void integerDisplayTickStep_isAlwaysAtLeastOneWholeUnit() {
        assertThat(StatsPanelFormatters.integerDisplayTickStep(4.0)).isEqualTo(1);
        assertThat(StatsPanelFormatters.integerDisplayTickStep(100.0)).isEqualTo(25);
    }

    @Test
    void rangeUpperInBaseUnits_usesNiceDisplayCeiling() {
        double headroom = 1.12;
        StatsPanelFormatters.ChartAxisScale gib = StatsPanelFormatters.chooseMemoryAxisScale(2500.0, headroom);
        double upper = StatsPanelFormatters.rangeUpperInBaseUnits(2500.0, headroom, gib);
        assertThat(upper / gib.displayDivisor()).isEqualTo(3.0);
        assertThat(upper).isEqualTo(3.0 * 1024.0);
    }

    @Test
    void rangeCeiling_stepsPastTightNiceTickSoSplineHasHeadroom() {
        // 800 * 1.0 lands exactly on a nice tick; ceiling must move above it.
        assertThat(StatsPanelFormatters.rangeCeiling(800.0, 1.0)).isGreaterThan(800.0);
        // Spiky rate peak with Smooth headroom still keeps spare above the padded max.
        double max = 50.0;
        double headroom = 1.22;
        double ceiling = StatsPanelFormatters.rangeCeiling(max, headroom);
        assertThat(ceiling).isGreaterThan(max * headroom);
    }

    @Test
    void chooseMemoryAxisScale_rollsToGiBWhenHeapExceeds999MiBDisplay() {
        assertThat(StatsPanelFormatters.chooseMemoryAxisScale(500.0, 1.5).label()).isEqualTo("MiB");
        assertThat(StatsPanelFormatters.chooseMemoryAxisScale(2500.0, 1.5).label()).isEqualTo("GiB");
        assertThat(StatsPanelFormatters.chooseMemoryAxisScale(2500.0, 1.5).displayDivisor()).isEqualTo(1024.0);
    }

    @Test
    void formatSkipReasons_multipleReasons_joinsWithSpacesAndThousandsSeparators() {
        ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1_234);
        ExportStats.recordSkipReason(ExportStats.SKIP_REASON_TOOL_DISABLED, 5);

        String rendered = StatsPanelFormatters.formatSkipReasons();

        assertThat(rendered)
                .contains("scope=1,234")
                .contains("tool_disabled=5")
                .doesNotContain("-");
    }

    @Test
    void formatPermanentDropReasons_isStableAndCompact() {
        ExportStats.recordPermanentDropReason(ExportStats.PERMANENT_DROP_REASON_STOP, 5);
        ExportStats.recordPermanentDropReason(ExportStats.PERMANENT_DROP_REASON_MAX_FIT, 1_234);

        assertThat(StatsPanelFormatters.formatPermanentDropReasons())
                .isEqualTo("max_fit_exceeded=1,234 stop_discard=5");
    }
}
