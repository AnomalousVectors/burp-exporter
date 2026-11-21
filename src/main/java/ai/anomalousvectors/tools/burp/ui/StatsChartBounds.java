package ai.anomalousvectors.tools.burp.ui;

import org.jfree.data.time.TimeSeriesCollection;

/**
 * Computes visible line or sampled natural-spline maxima for the Stats charts.
 *
 * <p>Caller must keep the dataset stable; StatsPanel invokes this on the EDT. All retained finite points
 * participate in the spline, matching the renderer; only the visible curve contributes to
 * the result. Work is linear in retained samples times renderer precision; temporary storage
 * is linear in retained samples.</p>
 */
final class StatsChartBounds {

    private StatsChartBounds() {}

    /** Returns a non-negative maximum, including curve segments crossing either window edge. */
    static double maximum(TimeSeriesCollection dataset, long minMs, long maxMs, int splinePrecision) {
        double maximum = 0.0;
        double windowEnd = Math.max(minMs, maxMs);
        int segments = Math.max(1, splinePrecision);
        for (int series = 0; series < dataset.getSeriesCount(); series++) {
            int capacity = dataset.getItemCount(series);
            double[] x = new double[capacity];
            double[] y = new double[capacity];
            int count = 0;
            for (int item = 0; item < capacity; item++) {
                double timestamp = dataset.getXValue(series, item);
                double value = dataset.getYValue(series, item);
                if (Double.isFinite(timestamp) && Double.isFinite(value)) {
                    x[count] = timestamp;
                    y[count++] = value;
                    if (timestamp >= minMs && timestamp <= windowEnd) {
                        maximum = Math.max(maximum, value);
                    }
                }
            }
            double[] second = segments > 1 ? secondDerivatives(x, y, count) : new double[count];
            for (int item = 1; item < count; item++) {
                double width = x[item] - x[item - 1];
                if (x[item] < minMs || x[item - 1] > windowEnd) {
                    continue;
                }
                double from = Math.max(0.0, (minMs - x[item - 1]) / width);
                double to = Math.min(1.0, (windowEnd - x[item - 1]) / width);
                maximum = Math.max(maximum, segmentMaximum(
                        y[item - 1], y[item], second[item - 1], second[item], width, from, to, segments));
            }
        }
        return maximum;
    }

    /** Solves the natural cubic's tridiagonal system with zero endpoint second derivatives. */
    private static double[] secondDerivatives(double[] x, double[] y, int count) {
        double[] second = new double[count];
        double[] diagonal = new double[count];
        for (int item = 1; item < count - 1; item++) {
            double left = x[item] - x[item - 1];
            double right = x[item + 1] - x[item];
            diagonal[item] = 2.0 * (left + right);
            second[item] = 6.0 * ((y[item + 1] - y[item]) / right
                    - (y[item] - y[item - 1]) / left);
            if (item > 1) {
                double factor = left / diagonal[item - 1];
                diagonal[item] -= factor * left;
                second[item] -= factor * second[item - 1];
            }
        }
        for (int item = count - 2; item > 0; item--) {
            second[item] = (second[item] - (x[item + 1] - x[item]) * second[item + 1])
                    / diagonal[item];
        }
        return second;
    }

    /** Clips the renderer's sampled line segments, not the ideal cubic, to the visible domain. */
    private static double segmentMaximum(
            double start, double end, double startSecond, double endSecond,
            double width, double from, double to, int segments) {
        double squaredWidth = width * width;
        double cubic = (endSecond - startSecond) * squaredWidth / 6.0;
        double quadratic = startSecond * squaredWidth / 2.0;
        double linear = end - start - squaredWidth * (2.0 * startSecond + endSecond) / 6.0;
        double maximum = 0.0;
        for (int segment = 0; segment < segments; segment++) {
            double segmentFrom = segment / (double) segments;
            double segmentTo = (segment + 1.0) / segments;
            double visibleFrom = Math.max(from, segmentFrom);
            double visibleTo = Math.min(to, segmentTo);
            if (visibleFrom > visibleTo) {
                continue;
            }
            double left = valueAt(start, linear, quadratic, cubic, segmentFrom);
            double right = valueAt(start, linear, quadratic, cubic, segmentTo);
            double span = segmentTo - segmentFrom;
            maximum = Math.max(maximum, Math.max(
                    left + (right - left) * ((visibleFrom - segmentFrom) / span),
                    left + (right - left) * ((visibleTo - segmentFrom) / span)));
        }
        return maximum;
    }

    private static double valueAt(double start, double linear, double quadratic, double cubic, double position) {
        return ((cubic * position + quadratic) * position + linear) * position + start;
    }
}
