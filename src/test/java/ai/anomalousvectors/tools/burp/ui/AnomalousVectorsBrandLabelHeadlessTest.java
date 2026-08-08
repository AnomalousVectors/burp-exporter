package ai.anomalousvectors.tools.burp.ui;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

import javax.swing.UIManager;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.utils.ProductInfo;

class AnomalousVectorsBrandLabelHeadlessTest {

    @Test
    void paints_theme_text_and_brand_wedges() {
        Font font = UIManager.getFont("Label.font");
        if (font == null) {
            font = new Font(Font.SANS_SERIF, Font.PLAIN, 16);
        }
        AnomalousVectorsBrandLabel label = new AnomalousVectorsBrandLabel(font.deriveFont(Font.PLAIN, 18f));
        label.setForeground(new Color(0xe8, 0xea, 0xed));
        label.setSize(label.getPreferredSize());

        assertThat(label.getText()).isEqualTo(ProductInfo.ORGANIZATION_NAME);

        BufferedImage image = new BufferedImage(
                Math.max(1, label.getWidth()),
                Math.max(1, label.getHeight()),
                BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        try {
            label.paint(g);
        } finally {
            g.dispose();
        }

        int redWedgePixels = 0;
        int blueWedgePixels = 0;
        int lightTextPixels = 0;
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int argb = image.getRGB(x, y);
                int alpha = (argb >>> 24) & 0xff;
                if (alpha < 32) {
                    continue;
                }
                int red = (argb >>> 16) & 0xff;
                int green = (argb >>> 8) & 0xff;
                int blue = argb & 0xff;
                if (red > 180 && green < 60 && blue < 60) {
                    redWedgePixels++;
                } else if (blue > 180 && red < 60 && green < 60) {
                    blueWedgePixels++;
                } else if (red > 160 && green > 160 && blue > 160) {
                    lightTextPixels++;
                }
            }
        }

        assertThat(redWedgePixels).as("red A wedge").isGreaterThan(20);
        assertThat(blueWedgePixels).as("blue V wedge").isGreaterThan(20);
        assertThat(lightTextPixels).as("theme-colored brand letters").isGreaterThan(50);
    }
}
