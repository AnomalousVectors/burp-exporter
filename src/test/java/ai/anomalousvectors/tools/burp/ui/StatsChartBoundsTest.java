package ai.anomalousvectors.tools.burp.ui;

import java.util.Date;

import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class StatsChartBoundsTest {

    private static final long BASE_MS = 1_700_000_000_000L;

    @Test
    void linearBounds_includeCrossingSegmentsButExcludeInvisibleOldPeaks() {
        TimeSeriesCollection dataset = dataset(new long[] { 0, 30, 60 }, new double[] { 400, 55, 0 });
        assertThat(maximum(dataset, 0, 40, false)).isEqualTo(400.0);
        assertThat(maximum(dataset, 20, 40, false)).isCloseTo(170.0, within(1e-8));
        assertThat(maximum(dataset, 35, 40, false)).isCloseTo(55.0 * 25.0 / 30.0, within(1e-8));
        assertThat(maximum(dataset, 90, 120, false)).isZero();
    }

    @Test
    void smoothBounds_coverIrregularGapOvershootAndClipToTheVisibleWindow() {
        TimeSeriesCollection dataset = dataset(new long[] { 0, 3, 300, 303 }, new double[] { 0, 10, 0, 0 });
        assertThat(maximum(dataset, 0, 303, false)).isEqualTo(10.0);
        assertThat(maximum(dataset, 0, 303, true)).isBetween(152.0, 153.0);
        assertThat(maximum(dataset, 0, 1, true)).isBetween(3.0, 4.0);
        // At the right edge, a sampled chord sits above the underlying cubic.
        assertThat(maximum(dataset, 290, 303, true)).isCloseTo(2.7808041395, within(1e-6));
    }

    @Test
    void smoothBounds_includeAnInteriorPeakEvenWithNoSampleInsideTheWindow() {
        TimeSeriesCollection dataset = dataset(new long[] { 0, 3, 300, 303 }, new double[] { 0, 10, 0, 0 });
        assertThat(maximum(dataset, 80, 120, true)).isCloseTo(maximum(dataset, 0, 303, true), within(1e-8));
    }

    @Test
    void smoothBounds_handleZeroOneTwoAndConstantSamples() {
        assertThat(maximum(new TimeSeriesCollection(), 0, 30, true)).isZero();
        TimeSeriesCollection single = dataset(new long[] { 0 }, new double[] { 7 });
        assertThat(maximum(single, 0, 30, true)).isEqualTo(7.0);
        assertThat(maximum(single, 1, 30, true)).isZero();
        assertThat(maximum(dataset(new long[] { 0, 30 }, new double[] { 5, 10 }), 10, 20, true))
                .isCloseTo(25.0 / 3.0, within(1e-8));
        assertThat(maximum(dataset(new long[] { 0, 3, 300, 303 }, new double[] { 7, 7, 7, 7 }), 1, 302, true))
                .isEqualTo(7.0);
    }

    @Test
    void bounds_useTheLargestSeriesAndSkipMissingNonFiniteValues() {
        TimeSeriesCollection dataset = dataset(new long[] { 0, 30 }, new double[] { 2, 2 });
        TimeSeries larger = new TimeSeries("Other");
        larger.add(new Millisecond(new Date(BASE_MS)), 8.0);
        larger.add(new Millisecond(new Date(BASE_MS + 10_000L)), (Number) null);
        larger.add(new Millisecond(new Date(BASE_MS + 20_000L)), Double.NaN);
        larger.add(new Millisecond(new Date(BASE_MS + 25_000L)), Double.POSITIVE_INFINITY);
        larger.add(new Millisecond(new Date(BASE_MS + 30_000L)), 8.0);
        dataset.addSeries(larger);
        assertThat(maximum(dataset, 0, 30, true)).isEqualTo(8.0);
        assertThat(maximum(dataset, 0, 30, false)).isEqualTo(8.0);
    }

    private static double maximum(TimeSeriesCollection dataset, long fromSeconds, long toSeconds, boolean smooth) {
        return StatsChartBounds.maximum(
                dataset, BASE_MS + fromSeconds * 1000L, BASE_MS + toSeconds * 1000L, smooth ? 12 : 1);
    }

    private static TimeSeriesCollection dataset(long[] seconds, double[] values) {
        TimeSeries series = new TimeSeries("Traffic");
        for (int item = 0; item < seconds.length; item++) {
            series.add(new Millisecond(new Date(BASE_MS + seconds[item] * 1000L)), values[item]);
        }
        return new TimeSeriesCollection(series);
    }
}
