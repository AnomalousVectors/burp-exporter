package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.accessibility.AccessibleRole;
import javax.imageio.ImageIO;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.ProductInfo;

/** Exercises the release hyperlink on the EDT without launching a browser. */
class AboutPanelReleaseLinkTest {

    @AfterEach
    void clearLogDeliveries() {
        Logger.resetState();
    }

    @Test
    void link_preservesExactUrlAndAccessibleName_withoutActingUntilClicked() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            List<URI> opened = new ArrayList<>();
            List<String> logs = new ArrayList<>();
            Logger.registerListener((level, message) -> logs.add(level + ": " + message));
            var panel = new AboutPanel(opened::add);
            JButton open = find(panel, "about.release.open", JButton.class);
            assertThat(opened).isEmpty();
            assertThat(find(panel, "about.release.status", JLabel.class)).isNull();
            assertThat(open.getText()).isEqualTo(ProductInfo.REPOSITORY_URL);
            assertThat(open.isFocusable()).isTrue();
            assertThat(open.isFocusPainted()).isTrue();
            assertThat(open.isBorderPainted()).isFalse();
            assertThat(open.isContentAreaFilled()).isFalse();
            assertThat(open.getHorizontalAlignment()).isEqualTo(SwingConstants.LEADING);
            assertThat(open.getAccessibleContext().getAccessibleRole()).isEqualTo(AccessibleRole.PUSH_BUTTON);
            assertThat(open.getAccessibleContext().getAccessibleName()).isEqualTo("Open latest release in browser");
            assertThat(open.getAccessibleContext().getAccessibleDescription()).isEqualTo(ProductInfo.REPOSITORY_URL);
            assertThat(find(panel, "about.release.copy", JButton.class)).isNull();
            open.doClick(0);
            assertThat(opened).containsExactly(URI.create(ProductInfo.REPOSITORY_URL));
            assertThat(find(panel, "about.release.status", JLabel.class)).isNull();
            assertThat(open.getParent().getComponents()).hasSize(2);
            assertThat(logs).isEmpty();
        });
    }

    @Test
    void enterAndSpace_activateTheHyperlink() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var opens = new AtomicInteger();
            var panel = new AboutPanel(uri -> opens.incrementAndGet());
            JButton button = find(panel, "about.release.open", JButton.class);
            invokeKey(button, "ENTER");
            invokeKey(button, "pressed SPACE");
            invokeKey(button, "released SPACE");
            assertThat(opens.get()).isEqualTo(2);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"io", "unsupported", "security"})
    void browserFailure_doesNotAddAboutContentOrLogEvents(String kind) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            List<String> logs = new ArrayList<>();
            Logger.registerListener((level, message) -> logs.add(level + ": " + message));
            var panel = new AboutPanel(uri -> {
                switch (kind) {
                    case "io" -> throw new IOException("private OS detail");
                    case "unsupported" -> throw new UnsupportedOperationException("private OS detail");
                    default -> throw new SecurityException("private OS detail");
                }
            });
            JButton open = find(panel, "about.release.open", JButton.class);
            open.doClick(0);
            assertThat(find(panel, "about.release.status", JLabel.class)).isNull();
            assertThat(open.getParent().getComponents()).hasSize(2);
            assertThat(logs).isEmpty();
        });
    }

    @Test
    void releaseAction_doesNotSwallowErrors() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var error = new AssertionError("unexpected platform failure");
            var panel = new AboutPanel(uri -> { throw error; });
            assertThatThrownBy(() -> find(panel, "about.release.open", JButton.class).doClick(0)).isSameAs(error);
        });
    }

    @ParameterizedTest
    @CsvSource({"900, false", "2048, false", "900, true", "2048, true"})
    void layout_keepsHyperlinkBesideLabelAtBothWidthsAndPalettes(int width, boolean dark) throws Exception {
        var rendered = new AtomicReference<BufferedImage>();
        SwingUtilities.invokeAndWait(() -> {
            Object previousBackground = UIManager.get("Panel.background");
            Object previousForeground = UIManager.get("Label.foreground");
            try {
                UIManager.put("Panel.background", dark ? new Color(48, 48, 48) : Color.WHITE);
                UIManager.put("Label.foreground", dark ? Color.LIGHT_GRAY : Color.BLACK);
                var panel = new AboutPanel(uri -> { });
                panel.setSize(width, 550);
                layoutTree(panel);
                JButton open = find(panel, "about.release.open", JButton.class);
                Container row = open.getParent();
                JLabel label = (JLabel) row.getComponent(0);
                assertThat(label.getText()).isEqualTo(ProductInfo.REPOSITORY_LABEL);
                int gap = open.getX() - (label.getX() + label.getWidth());
                assertThat(gap).isBetween(0, 12);
                assertThat(open.getWidth()).isEqualTo(open.getPreferredSize().width);
                assertThat(open.getX()).isLessThan(200);
                assertThat(open.getY() + open.getHeight() / 2)
                        .isBetween(label.getY(), label.getY() + label.getHeight());
                assertThat(row.getComponents()).hasSize(2); // Original label and hyperlink only.

                var image = new BufferedImage(width, panel.getHeight(), BufferedImage.TYPE_INT_RGB);
                var graphics = image.createGraphics();
                try {
                    panel.printAll(graphics);
                } finally {
                    graphics.dispose();
                }
                rendered.set(image);
                var bounds = open.getBounds();
                open.doClick(0);
                layoutTree(panel);
                assertThat(open.getBounds()).as("Clicking must not change the hyperlink layout").isEqualTo(bounds);
                assertThat(row.getComponents()).hasSize(2);
            } finally {
                UIManager.put("Panel.background", previousBackground);
                UIManager.put("Label.foreground", previousForeground);
            }
        });
        // Retain a render of the actual Swing component tree for review, not a separate mock-up.
        Path preview = Path.of("build/reports/about-layout", (dark ? "dark-" : "light-") + width + ".png");
        Files.createDirectories(preview.getParent());
        assertThat(ImageIO.write(rendered.get(), "png", preview.toFile())).isTrue();
    }

    private static void layoutTree(Container container) {
        container.doLayout();
        for (Component component : container.getComponents()) {
            if (component instanceof Container child) {
                layoutTree(child);
            }
        }
    }

    private static void invokeKey(JButton button, String stroke) {
        Object key = button.getInputMap(JComponent.WHEN_FOCUSED).get(KeyStroke.getKeyStroke(stroke));
        assertThat(key).as(stroke).isNotNull();
        var action = button.getActionMap().get(key);
        assertThat(action).as(stroke).isNotNull();
        action.actionPerformed(new ActionEvent(button, ActionEvent.ACTION_PERFORMED, stroke));
    }

    private static <T extends Component> T find(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            if (name.equals(component.getName())) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T found = find(child, name, type);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
