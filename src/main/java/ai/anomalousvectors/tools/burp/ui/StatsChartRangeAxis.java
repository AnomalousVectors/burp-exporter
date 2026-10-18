package ai.anomalousvectors.tools.burp.ui;

import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.Serial;
import java.util.List;

import org.jfree.chart.axis.AxisState;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.text.TextUtils;
import org.jfree.chart.ui.RectangleEdge;
import org.jfree.chart.ui.RectangleInsets;
import org.jfree.chart.ui.TextAnchor;

/**
 * Range axis for Stats throughput and memory charts. Reserves a fixed label column, gap, and
 * tick column so unit labels left-align across stacked charts and spacing sits between labels
 * and numbers (not outside the labels on the chart edge).
 */
final class StatsChartRangeAxis extends NumberAxis {

    @Serial private static final long serialVersionUID = 1L;

    /** Horizontal space for the rotated unit label (Docs/sec, GiB, …). */
    static final double LABEL_COLUMN_WIDTH = 16.0;
    /** Horizontal space for numeric tick labels (e.g. {@code 200}). */
    static final double TICK_COLUMN_WIDTH = 34.0;
    /** Gap between the label column and tick numbers. */
    static final double LABEL_TICK_GAP = 12.0;
    static final double TOTAL_WIDTH = LABEL_COLUMN_WIDTH + LABEL_TICK_GAP + TICK_COLUMN_WIDTH;

    StatsChartRangeAxis(String label) {
        super(label);
        setFixedDimension(TOTAL_WIDTH);
        setLabelInsets(RectangleInsets.ZERO_INSETS);
        setTickLabelInsets(RectangleInsets.ZERO_INSETS);
    }

    /**
     * {@link org.jfree.chart.axis.ValueAxis} declares this override hook with a raw {@link List}.
     *
     * <p>{@code List<?>} was tested and fails with a same-erasure name clash instead of
     * overriding the superclass method. Approved suppression.</p>
     */
    @Override
    protected double findMaximumTickLabelWidth(
            @SuppressWarnings("rawtypes") List ticks,
            Graphics2D g2,
            Rectangle2D drawArea,
            boolean vertical) {
        if (!vertical) {
            return TICK_COLUMN_WIDTH;
        }
        return super.findMaximumTickLabelWidth(ticks, g2, drawArea, vertical);
    }

    @Override
    protected Rectangle2D getLabelEnclosure(Graphics2D g2, RectangleEdge edge) {
        if (RectangleEdge.isLeftOrRight(edge)) {
            Rectangle2D natural = super.getLabelEnclosure(g2, edge);
            return new Rectangle2D.Double(0, 0, LABEL_COLUMN_WIDTH, natural.getHeight());
        }
        return super.getLabelEnclosure(g2, edge);
    }

    @Override
    protected AxisState drawLabel(
            String label,
            Graphics2D g2,
            Rectangle2D plotArea,
            Rectangle2D dataArea,
            RectangleEdge edge,
            AxisState state) {
        if (edge != RectangleEdge.LEFT || label == null || label.isEmpty()) {
            return super.drawLabel(label, g2, plotArea, dataArea, edge, state);
        }
        g2.setFont(getLabelFont());
        g2.setPaint(getLabelPaint());
        FontMetrics fm = g2.getFontMetrics();
        Rectangle2D labelBounds = TextUtils.getTextBounds(label, g2, fm);
        AffineTransform rotation = AffineTransform.getRotateInstance(
                getLabelAngle() - Math.PI / 2.0,
                labelBounds.getCenterX(),
                labelBounds.getCenterY());
        labelBounds = rotation.createTransformedShape(labelBounds).getBounds2D();

        double labelColumnRight = state.getCursor() - LABEL_TICK_GAP;
        double labelColumnLeft = labelColumnRight - LABEL_COLUMN_WIDTH;
        double labelx = labelColumnLeft + labelBounds.getWidth() / 2.0;
        double labely = labelLocationY(getLabelLocation(), dataArea);
        TextAnchor anchor = labelAnchorV(getLabelLocation());
        TextUtils.drawRotatedString(
                label,
                g2,
                (float) labelx,
                (float) labely,
                anchor,
                getLabelAngle() - Math.PI / 2.0,
                anchor);
        state.cursorLeft(LABEL_COLUMN_WIDTH);
        return state;
    }
}
