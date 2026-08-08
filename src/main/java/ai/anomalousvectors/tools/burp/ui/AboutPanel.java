package ai.anomalousvectors.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.io.Serial;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;

import ai.anomalousvectors.tools.burp.ui.primitives.ScrollPanes;
import ai.anomalousvectors.tools.burp.utils.ProductInfo;
import ai.anomalousvectors.tools.burp.utils.Version;
import net.miginfocom.swing.MigLayout;

/**
 * Renders the About tab content for the extension UI.
 *
 * <p>Caller must construct this panel on the EDT because it creates and wires Swing components.</p>
 */
public class AboutPanel extends JPanel {

    private static final int SECTION_GAP_BOTTOM = 12;
    /** Extra space under the brand block so it stands apart from the extension title. */
    private static final int BRAND_GAP_BOTTOM = 28;
    /** Brand name is twice the body font size so it reads as the hero. */
    private static final float BRAND_FONT_SIZE_FACTOR = 2f;
    /** Tagline size sits between brand and body copy (before the point adjustment). */
    private static final float TAGLINE_FONT_SIZE_FACTOR = 1.4f;
    /** Points subtracted from the scaled tagline size. */
    private static final float TAGLINE_FONT_SIZE_DELTA_PT = 3f;
    /**
     * Leading indent for rows under the brand. Pixel gap is more reliable than leading spaces, which
     * can look flush against the brand letters after wedge padding.
     */
    private static final int CONTENT_INDENT_PX = 36;
    /** Separator thickness: thin, but tall enough for the red→blue gradient to read. */
    private static final int BRAND_RULE_HEIGHT_PX = 3;
    /** Extra width beyond the longer of brand/tagline so the centered rule reads a touch wider. */
    private static final int BRAND_RULE_EXTRA_WIDTH_PX = 16;
    /** Vertical gap between the tagline and the gradient rule. */
    private static final int BRAND_RULE_GAP_TOP_PX = 12;
    /** Brand wedge red used by the About rule gradient. */
    private static final Color BRAND_RULE_RED = new Color(0xf0, 0x00, 0x00);
    /** Brand wedge blue used by the About rule gradient. */
    private static final Color BRAND_RULE_BLUE = new Color(0x00, 0x00, 0xf0);

    /** Creates the About panel UI on the EDT. */
    public AboutPanel() {
        setLayout(new BorderLayout());

        String version = Version.get();
        JPanel content = buildContent(version);

        add(ScrollPanes.wrapNoHorizontalScroll(content), BorderLayout.CENTER);
    }

    private static JPanel buildContent(String version) {
        JPanel panel = new JPanel(new MigLayout("insets 12, wrap 1, fillx", "[grow,left]"));
        panel.setOpaque(true);
        panel.setBackground(UIManager.getColor("Panel.background"));

        Font bodyFont = UIManager.getFont("Label.font").deriveFont(Font.PLAIN);
        String bodyIndent = "gapleft " + CONTENT_INDENT_PX;

        panel.add(buildBrandBlock(bodyFont), "gapbottom " + BRAND_GAP_BOTTOM);
        panel.add(buildPlainRow(ProductInfo.EXTENSION_NAME, bodyFont), bodyIndent + ", gapbottom 2");
        panel.add(buildPlainRow("Version " + version, bodyFont), bodyIndent + ", gapbottom " + SECTION_GAP_BOTTOM);
        panel.add(buildDescriptionRow(bodyFont), bodyIndent + ", growx, gapbottom " + SECTION_GAP_BOTTOM);
        panel.add(buildLinkRow(ProductInfo.REPOSITORY_LABEL, ProductInfo.REPOSITORY_URL, bodyFont),
                bodyIndent + ", growx");
        return panel;
    }

    private static JPanel buildBrandBlock(Font bodyFont) {
        // One centered column sized to the widest child so tagline and rule sit under the brand.
        JPanel block = new JPanel(new MigLayout("insets 0, wrap 1, gapy 4", "[center]"));
        block.setOpaque(false);

        AnomalousVectorsBrandLabel brand = new AnomalousVectorsBrandLabel(
                bodyFont.deriveFont(bodyFont.getSize2D() * BRAND_FONT_SIZE_FACTOR));
        float taglineSize = Math.max(11f, bodyFont.getSize2D() * TAGLINE_FONT_SIZE_FACTOR - TAGLINE_FONT_SIZE_DELTA_PT);
        JLabel tagline = new JLabel(ProductInfo.ORGANIZATION_TAGLINE);
        tagline.setFont(bodyFont.deriveFont(Font.ITALIC, taglineSize));
        tagline.setForeground(UIManager.getColor("Label.foreground"));

        int ruleWidth = Math.max(brand.getPreferredSize().width, tagline.getPreferredSize().width)
                + BRAND_RULE_EXTRA_WIDTH_PX;
        BrandGradientRule rule = new BrandGradientRule(ruleWidth, BRAND_RULE_HEIGHT_PX);

        block.add(brand, "alignx center");
        block.add(tagline, "alignx center, gapbottom " + BRAND_RULE_GAP_TOP_PX);
        block.add(rule, "alignx center");
        return block;
    }

    private static JLabel buildPlainRow(String text, Font bodyFont) {
        JLabel label = new JLabel(text);
        label.setFont(bodyFont);
        label.setForeground(UIManager.getColor("Label.foreground"));
        return label;
    }

    private static JLabel buildDescriptionRow(Font bodyFont) {
        JLabel description = new JLabel(
                "Continuously exports settings, sitemap data, issues, and traffic to indexed databases for agentic penetration testing and research.");
        description.setFont(bodyFont);
        description.setForeground(UIManager.getColor("Label.foreground"));
        return description;
    }

    private static JPanel buildLinkRow(String labelText, String url, Font bodyFont) {
        JPanel row = new JPanel(new MigLayout("insets 0, gapx 6", "[][grow,left]", "[]"));
        row.setOpaque(false);

        JLabel label = new JLabel(labelText);
        label.setFont(bodyFont);
        label.setForeground(UIManager.getColor("Label.foreground"));

        JLabel urlLabel = new JLabel(url);
        urlLabel.setFont(bodyFont);
        urlLabel.setForeground(readableLinkColor(defaultColor(UIManager.getColor("Panel.background"), Color.WHITE)));
        urlLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        urlLabel.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                openLink(url);
            }
        });

        row.add(label);
        row.add(urlLabel, "growx");
        return row;
    }

    private static Color defaultColor(Color color, Color fallback) {
        return color != null ? color : fallback;
    }

    private static Color readableLinkColor(Color background) {
        Color configured = UIManager.getColor("Component.linkColor");
        if (configured == null) {
            configured = UIManager.getColor("Link.foreground");
        }
        if (configured != null && contrastRatio(configured, background) >= 3.0) {
            return configured;
        }
        return isDark(background) ? new Color(120, 170, 255) : new Color(0, 102, 204);
    }

    private static boolean isDark(Color color) {
        return luminance(color) < 0.5;
    }

    private static double contrastRatio(Color left, Color right) {
        double lighter = Math.max(luminance(left), luminance(right));
        double darker = Math.min(luminance(left), luminance(right));
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double luminance(Color color) {
        double red = channel(color.getRed());
        double green = channel(color.getGreen());
        double blue = channel(color.getBlue());
        return (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
    }

    private static double channel(int value) {
        double normalized = value / 255.0;
        return normalized <= 0.03928 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
    }

    private static void openLink(String url) {
        if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            return;
        }
        try {
            Desktop.getDesktop().browse(java.net.URI.create(url));
        } catch (IOException | IllegalArgumentException ignored) {
        }
    }

    /**
     * Thin horizontal rule under the brand/tagline, painted red→blue to echo the A/V wedges.
     *
     * <p>Caller must create and display this on the EDT. Width is fixed to the longer of the brand
     * name or tagline preferred widths, plus a small extra so the centered rule reads slightly
     * wider than the text block.</p>
     */
    private static final class BrandGradientRule extends JComponent {

        @Serial
        private static final long serialVersionUID = 1L;

        private final int ruleWidth;
        private final int ruleHeight;

        private BrandGradientRule(int ruleWidth, int ruleHeight) {
            this.ruleWidth = Math.max(1, ruleWidth);
            this.ruleHeight = Math.max(1, ruleHeight);
            setOpaque(false);
        }

        @Override
        public Dimension getPreferredSize() {
            return new Dimension(ruleWidth, ruleHeight);
        }

        @Override
        public Dimension getMinimumSize() {
            return getPreferredSize();
        }

        @Override
        public Dimension getMaximumSize() {
            return getPreferredSize();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int width = Math.max(1, getWidth());
                int height = Math.max(1, getHeight());
                g2.setPaint(new GradientPaint(0, 0, BRAND_RULE_RED, width, 0, BRAND_RULE_BLUE));
                g2.fillRect(0, 0, width, height);
            } finally {
                g2.dispose();
            }
        }
    }
}
