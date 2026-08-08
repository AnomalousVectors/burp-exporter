package ai.anomalousvectors.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.font.FontRenderContext;
import java.awt.font.GlyphVector;
import java.awt.geom.AffineTransform;
import java.awt.geom.Area;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.PathIterator;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.io.Serial;

import javax.swing.JLabel;
import javax.swing.UIManager;

import ai.anomalousvectors.tools.burp.utils.ProductInfo;

/**
 * Brand name label that keeps the current Look-and-Feel font/colors and paints only the
 * Anomalous Vectors red/blue vector wedges on {@code A} and {@code V}.
 *
 * <p>Caller must create and mutate this component on the EDT.</p>
 *
 * <p>Letter shapes stay theme-driven via {@link #getForeground()}. The wedges use fixed brand
 * colors. Glyph segments covered by each wedge are subtracted so the strokes replace that part of
 * the letter rather than stacking on top of it. Wedges intentionally overhang above/below the
 * word.</p>
 */
public final class AnomalousVectorsBrandLabel extends JLabel {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final String BRAND_TEXT = ProductInfo.ORGANIZATION_NAME;
    private static final int INDEX_A = 0;
    private static final int INDEX_V = 10;

    /** Design units: letter box height on the website wordmark; design baseline is {@code y = 84}. */
    private static final double DESIGN_EM = 84.0;
    /**
     * Wedge letter-box height vs live cap height. Values above {@code 1} overhang the word; both
     * wedges share one scale so they stay lined up. {@code 1.054} is 85% of the prior {@code 1.24}
     * length.
     */
    private static final double WEDGE_SIZE_FACTOR = 1.24 * 0.85;
    /** Sharp tip of the red wedge in design space (meets the apex of {@code A}). */
    private static final double RED_TIP_X = 30.0;
    private static final double RED_TIP_Y = 1.5;
    /** Sharp tip of the blue wedge in design space (meets the vertex of {@code V}). */
    private static final double BLUE_TIP_X = 34.0;
    private static final double BLUE_TIP_Y = 84.0;
    /**
     * Clockwise degrees around the red tip (Java2D Y-down). Negative swings the red base to the right
     * (closes the A apex / crossbar gap) while the tip stays on the A apex.
     */
    private static final double RED_CLOSE_ANGLE_DEG = -8.0;
    /**
     * Clockwise degrees around the blue tip. Negative swings the blue top left so the stroke sits more
     * upright while the tip stays on the V vertex. Leave alone when V already looks right.
     */
    private static final double BLUE_CLOSE_ANGLE_DEG = -6.0;
    /** Grow the wedge subtraction so antialiased glyph fringe does not leave a white ghost. */
    private static final float STEM_CLEAR_STROKE_PX = 4.5f;

    private static final Color WEDGE_RED = new Color(0xf0, 0x00, 0x00);
    private static final Color WEDGE_BLUE = new Color(0x00, 0x00, 0xf0);

    private static final double[] RED_WEDGE_POINTS = {
        -37.77, 107.58,
        -36.59, 104.57,
        -34.4, 101.29,
        -32.3, 97.91,
        -30.2, 94.54,
        -28.01, 91.25,
        -25.91, 87.88,
        -23.82, 84.5,
        -21.63, 81.22,
        -19.53, 77.84,
        -17.34, 74.56,
        -15.24, 71.19,
        -13.05, 67.9,
        -10.95, 64.53,
        -8.77, 61.24,
        -6.67, 57.87,
        -4.48, 54.59,
        -2.38, 51.21,
        -0.28, 47.84,
        1.91, 44.55,
        4.1, 41.27,
        6.19, 37.89,
        8.29, 34.52,
        10.48, 31.24,
        12.67, 27.95,
        14.77, 24.58,
        16.96, 21.29,
        19.15, 18.01,
        21.24, 14.63,
        23.43, 11.35,
        25.62, 8.07,
        27.81, 4.78,
        30, 1.5,
        29.54, 3.42,
        27.72, 7.06,
        25.9, 10.71,
        24.16, 14.45,
        22.34, 18.1,
        20.51, 21.75,
        18.69, 25.4,
        16.96, 29.14,
        15.13, 32.79,
        13.4, 36.53,
        11.58, 40.17,
        9.75, 43.82,
        7.93, 47.47,
        6.19, 51.21,
        4.37, 54.86,
        2.55, 58.51,
        0.81, 62.25,
        -1.01, 65.9,
        -2.84, 69.54,
        -4.66, 73.19,
        -6.39, 76.93,
        -8.22, 80.58,
        -9.95, 84.32,
        -11.78, 87.97,
        -13.6, 91.62,
        -15.33, 95.36,
        -17.16, 99.01,
        -19.53, 102.11,
        -23.72, 103.38,
        -27.92, 104.66,
        -32.21, 105.85,
        -36.4, 107.12,
        -37.77, 107.58
    };


    private static final double[] BLUE_WEDGE_POINTS = {
        34, 84,
        35.32, 80.24,
        36.84, 76.49,
        38.37, 72.73,
        39.79, 68.87,
        41.41, 65.22,
        42.93, 61.46,
        44.46, 57.71,
        46.08, 54.05,
        47.5, 50.19,
        49.13, 46.54,
        50.65, 42.78,
        52.17, 39.03,
        53.8, 35.37,
        55.32, 31.62,
        56.84, 27.86,
        58.47, 24.21,
        59.99, 20.45,
        61.51, 16.69,
        63.14, 13.04,
        64.76, 9.38,
        66.28, 5.63,
        67.91, 1.97,
        69.43, -1.78,
        71.05, -5.44,
        72.68, -9.09,
        74.91, -12.14,
        78.36, -13.96,
        81.81, -15.79,
        85.27, -17.62,
        88.82, -19.35,
        92.27, -21.17,
        95.72, -23,
        94.61, -20.26,
        92.68, -16.91,
        90.75, -13.56,
        88.82, -10.21,
        86.89, -6.86,
        84.96, -3.51,
        83.03, -0.16,
        81.1, 3.19,
        79.18, 6.54,
        77.15, 9.79,
        75.32, 13.24,
        73.29, 16.49,
        71.36, 19.84,
        69.43, 23.19,
        67.5, 26.54,
        65.57, 29.89,
        63.64, 33.24,
        61.71, 36.59,
        59.68, 39.84,
        57.86, 43.29,
        55.83, 46.54,
        53.9, 49.89,
        51.97, 53.24,
        50.04, 56.59,
        48.11, 59.94,
        46.18, 63.29,
        44.25, 66.64,
        42.32, 69.99,
        40.4, 73.34,
        38.37, 76.59,
        36.44, 79.94,
        34.51, 83.29,
        34, 84
    };

    private static final Path2D RED_WEDGE = pathFromPoints(RED_WEDGE_POINTS);
    private static final Path2D BLUE_WEDGE = pathFromPoints(BLUE_WEDGE_POINTS);

    /**
     * Creates the brand label using {@code font} for metrics and glyph outlines.
     *
     * @param font LAF-derived brand font; caller must invoke on the EDT
     */
    public AnomalousVectorsBrandLabel(Font font) {
        super(BRAND_TEXT);
        if (BRAND_TEXT.charAt(INDEX_A) != 'A' || BRAND_TEXT.charAt(INDEX_V) != 'V') {
            throw new IllegalStateException("Brand text layout no longer matches A/V glyph indexes");
        }
        setFont(font);
        setOpaque(false);
        Color foreground = UIManager.getColor("Label.foreground");
        if (foreground != null) {
            setForeground(foreground);
        }
    }

    @Override
    public Dimension getPreferredSize() {
        return paddedSize();
    }

    @Override
    public Dimension getMinimumSize() {
        return paddedSize();
    }

    /**
     * Returns the painted text baseline so sibling tagline labels can share one writing line.
     */
    @Override
    public int getBaseline(int width, int height) {
        Font font = getFont();
        FontMetrics metrics = getFontMetrics(font);
        int padY = verticalPad(font);
        int contentHeight = metrics.getHeight() + padY * 2;
        int originOffsetY = Math.max(0, (height - contentHeight) / 2);
        return originOffsetY + padY + metrics.getAscent();
    }

    @Override
    public Component.BaselineResizeBehavior getBaselineResizeBehavior() {
        return Component.BaselineResizeBehavior.CONSTANT_ASCENT;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);

            Font font = getFont();
            FontMetrics metrics = getFontMetrics(font);
            int padX = horizontalPad(font);
            int padY = verticalPad(font);
            int contentHeight = metrics.getHeight() + padY * 2;
            int originOffsetY = Math.max(0, (getHeight() - contentHeight) / 2);
            float originX = padX;
            float baseline = originOffsetY + padY + metrics.getAscent();

            FontRenderContext frc = g2.getFontRenderContext();
            GlyphVector glyphs = font.createGlyphVector(frc, BRAND_TEXT);
            double sharedScale = sharedWedgeScale(glyphs);

            Shape aOutline = glyphs.getGlyphOutline(INDEX_A);
            Shape vOutline = glyphs.getGlyphOutline(INDEX_V);
            Point2D.Double aApex = extremePoint(aOutline, true);
            Point2D.Double vVertex = extremePoint(vOutline, false);

            // Red tip -> A apex; blue tip -> V vertex; small tip-pivots close the stroke angles.
            Shape red = transformWedgeByTip(
                    RED_WEDGE,
                    RED_TIP_X,
                    RED_TIP_Y,
                    originX + aApex.x,
                    baseline + aApex.y,
                    sharedScale,
                    RED_CLOSE_ANGLE_DEG);
            Shape blue = transformWedgeByTip(
                    BLUE_WEDGE,
                    BLUE_TIP_X,
                    BLUE_TIP_Y,
                    originX + vVertex.x,
                    baseline + vVertex.y,
                    sharedScale,
                    BLUE_CLOSE_ANGLE_DEG);

            Color textColor = getForeground();
            if (textColor == null) {
                textColor = UIManager.getColor("Label.foreground");
            }
            if (textColor == null) {
                textColor = Color.BLACK;
            }
            g2.setColor(textColor);
            int glyphCount = glyphs.getNumGlyphs();
            for (int i = 0; i < glyphCount; i++) {
                Shape outline = glyphs.getGlyphOutline(i, originX, baseline);
                if (i == INDEX_A) {
                    g2.fill(snipGlyphStem(outline, red, true));
                } else if (i == INDEX_V) {
                    g2.fill(snipGlyphStem(outline, blue, false));
                } else {
                    g2.fill(outline);
                }
            }

            g2.setColor(WEDGE_RED);
            g2.fill(red);
            fillTipCap(g2, originX + aApex.x, baseline + aApex.y, sharedScale);
            g2.setColor(WEDGE_BLUE);
            g2.fill(blue);
            fillTipCap(g2, originX + vVertex.x, baseline + vVertex.y, sharedScale);
        } finally {
            g2.dispose();
        }
    }

    /** Tiny tip disc so the sharp wedge end stays visible on the letter point after antialias. */
    private static void fillTipCap(Graphics2D g2, double tipX, double tipY, double scale) {
        double radius = Math.max(0.7, scale * 1.1);
        g2.fill(new Ellipse2D.Double(tipX - radius, tipY - radius, radius * 2, radius * 2));
    }

    private Dimension paddedSize() {
        Font font = getFont();
        FontMetrics metrics = getFontMetrics(font);
        int padX = horizontalPad(font);
        int padY = verticalPad(font);
        return new Dimension(metrics.stringWidth(BRAND_TEXT) + padX * 2, metrics.getHeight() + padY * 2);
    }

    private static int horizontalPad(Font font) {
        return Math.max(10, Math.round(font.getSize2D() * 0.55f));
    }

    private static int verticalPad(Font font) {
        // Room for wedges overhanging the cap/baseline at WEDGE_SIZE_FACTOR.
        return Math.max(12, Math.round(font.getSize2D() * 0.55f));
    }

    /** One scale for both wedges, from the taller of {@code A}/{@code V}, so they stay matched. */
    private static double sharedWedgeScale(GlyphVector glyphs) {
        double letterHeight = Math.max(
                glyphs.getGlyphOutline(INDEX_A).getBounds2D().getHeight(),
                glyphs.getGlyphOutline(INDEX_V).getBounds2D().getHeight());
        if (letterHeight <= 0) {
            return 1.0;
        }
        return (letterHeight * WEDGE_SIZE_FACTOR) / DESIGN_EM;
    }

    /**
     * Places {@code designTip} exactly on {@code targetTip} with uniform scale so the wedge tip
     * meets the letter point (A apex or V vertex), then rotates about that tip to close the stroke
     * angle without moving the tip.
     *
     * @param closeAngleDeg clockwise degrees in Java2D space (Y down)
     */
    private static Shape transformWedgeByTip(
            Path2D wedge,
            double designTipX,
            double designTipY,
            double targetTipX,
            double targetTipY,
            double scale,
            double closeAngleDeg) {
        AffineTransform tx = new AffineTransform();
        tx.translate(targetTipX, targetTipY);
        tx.rotate(Math.toRadians(closeAngleDeg));
        tx.scale(scale, scale);
        tx.translate(-designTipX, -designTipY);
        return tx.createTransformedShape(wedge);
    }

    /**
     * Top-most or bottom-most outline point of a glyph, used as the A apex / V vertex target.
     *
     * <p>When several flattened path samples share the extreme Y, picks the sample closest to the
     * glyph's horizontal center so a V's two feet do not pull the tip off the vertex.</p>
     *
     * @param topmost {@code true} for apex, {@code false} for vertex
     */
    private static Point2D.Double extremePoint(Shape outline, boolean topmost) {
        Rectangle2D bounds = outline.getBounds2D();
        PathIterator iterator = outline.getPathIterator(null, 0.05);
        double[] coords = new double[6];
        double extremeY = topmost ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY;
        boolean found = false;
        while (!iterator.isDone()) {
            int type = iterator.currentSegment(coords);
            int pointCount = switch (type) {
                case PathIterator.SEG_MOVETO, PathIterator.SEG_LINETO -> 1;
                case PathIterator.SEG_QUADTO -> 2;
                case PathIterator.SEG_CUBICTO -> 3;
                default -> 0;
            };
            for (int i = 0; i < pointCount; i++) {
                double y = coords[i * 2 + 1];
                if (!found || (topmost && y < extremeY) || (!topmost && y > extremeY)) {
                    extremeY = y;
                    found = true;
                }
            }
            iterator.next();
        }
        if (!found) {
            return new Point2D.Double(bounds.getCenterX(), topmost ? bounds.getMinY() : bounds.getMaxY());
        }

        double band = 0.5;
        double centerX = bounds.getCenterX();
        iterator = outline.getPathIterator(null, 0.05);
        double bestX = centerX;
        double bestDist = Double.POSITIVE_INFINITY;
        boolean bandFound = false;
        while (!iterator.isDone()) {
            int type = iterator.currentSegment(coords);
            int pointCount = switch (type) {
                case PathIterator.SEG_MOVETO, PathIterator.SEG_LINETO -> 1;
                case PathIterator.SEG_QUADTO -> 2;
                case PathIterator.SEG_CUBICTO -> 3;
                default -> 0;
            };
            for (int i = 0; i < pointCount; i++) {
                double x = coords[i * 2];
                double y = coords[i * 2 + 1];
                if (Math.abs(y - extremeY) <= band) {
                    double dist = Math.abs(x - centerX);
                    if (!bandFound || dist < bestDist) {
                        bestX = x;
                        bestDist = dist;
                        bandFound = true;
                    }
                }
            }
            iterator.next();
        }
        return new Point2D.Double(bandFound ? bestX : centerX, extremeY);
    }

    /**
     * Prepares a glyph for wedge overlay.
     *
     * <p>For {@code A}, the entire white left stem is removed (red is thinner/pointed and cannot cover
     * it). Crossbar and right stem stay. For {@code V}, the right stem is snipped and cleared under
     * the blue wedge so no white ghost remains.</p>
     */
    private static Area snipGlyphStem(Shape outline, Shape wedge, boolean leftStem) {
        Rectangle2D bounds = outline.getBounds2D();
        Area snip = leftStem ? stemSnipA(bounds) : stemSnipV(bounds);
        Area kept = new Area(outline);
        kept.subtract(snip);
        if (leftStem) {
            // Also clear any leftover left-stem white that still sits under/beside the red.
            Area underRed = new Area(wedge);
            underRed.intersect(expand(snip, STEM_CLEAR_STROKE_PX));
            kept.subtract(underRed);
            kept.subtract(expand(snip, STEM_CLEAR_STROKE_PX));
            return kept;
        }
        kept.subtract(new Area(wedge));
        Area fringe = expand(new Area(wedge), STEM_CLEAR_STROKE_PX);
        fringe.intersect(snip);
        kept.subtract(fringe);
        Area wideFringe = expand(new Area(wedge), STEM_CLEAR_STROKE_PX * 1.75f);
        wideFringe.intersect(snip);
        kept.subtract(wideFringe);
        return kept;
    }

    /** Stroke-expands {@code area} so antialiased fringe is included in a subtract. */
    private static Area expand(Area area, float strokePx) {
        Shape stroked = new BasicStroke(strokePx, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
                .createStrokedShape(area);
        Area expanded = new Area(area);
        expanded.add(new Area(stroked));
        return expanded;
    }

    /**
     * Full left-stem snip for {@code A}. The red wedge is pointed and narrower than the LAF stem, so
     * white on that stroke must be deleted rather than covered. The cut narrows at mid-height so the
     * crossbar is preserved.
     */
    private static Area stemSnipA(Rectangle2D bounds) {
        Path2D snip = new Path2D.Double();
        double minX = bounds.getMinX() - 3;
        double minY = bounds.getMinY() - 2;
        double maxY = bounds.getMaxY() + 2;
        double midY = bounds.getMinY() + bounds.getHeight() * 0.55;
        double topCut = bounds.getMinX() + bounds.getWidth() * 0.52;
        double midCut = bounds.getMinX() + bounds.getWidth() * 0.34;
        double botCut = bounds.getMinX() + bounds.getWidth() * 0.44;
        snip.moveTo(minX, minY);
        snip.lineTo(topCut, minY);
        snip.lineTo(midCut, midY);
        snip.lineTo(botCut, maxY);
        snip.lineTo(minX, maxY);
        snip.closePath();
        return new Area(snip);
    }

    /** Right-stem snip for {@code V}: diagonal cut from upper mid to the vertex. */
    private static Area stemSnipV(Rectangle2D bounds) {
        Path2D snip = new Path2D.Double();
        double maxX = bounds.getMaxX() + 2;
        double minY = bounds.getMinY() - 2;
        double maxY = bounds.getMaxY() + 2;
        double topCut = bounds.getMinX() + bounds.getWidth() * 0.50;
        double vertexX = bounds.getCenterX();
        snip.moveTo(topCut, minY);
        snip.lineTo(maxX, minY);
        snip.lineTo(maxX, maxY);
        snip.lineTo(vertexX, maxY);
        snip.closePath();
        return new Area(snip);
    }

    private static Path2D pathFromPoints(double[] points) {
        Path2D.Double path = new Path2D.Double(Path2D.WIND_NON_ZERO, points.length / 2);
        path.moveTo(points[0], points[1]);
        for (int i = 2; i < points.length; i += 2) {
            path.lineTo(points[i], points[i + 1]);
        }
        path.closePath();
        return path;
    }
}
