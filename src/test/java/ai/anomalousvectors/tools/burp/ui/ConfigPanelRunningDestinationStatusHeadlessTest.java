package ai.anomalousvectors.tools.burp.ui;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.call;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/**
 * Verifies Config Control status reflects live destination changes during an export run.
 */
class ConfigPanelRunningDestinationStatusHeadlessTest {

    private final ConfigPanel panel = createPanel();

    @AfterEach
    public void tearDown() {
        ExportReporterLifecycle.resetForTests();
    }

    @Test
    void toggling_destination_controls_updates_control_status_while_export_running() throws Exception {
        JCheckBox filesEnable = JCheckBox.class.cast(get(panel, "fileSinkCheckbox"));
        javax.swing.AbstractButton openSearch = javax.swing.AbstractButton.class.cast(get(panel, "openSearchSinkCheckbox"));
        javax.swing.AbstractButton aws = javax.swing.AbstractButton.class.cast(get(panel, "openSearchAmazonDestinationRadio"));
        JTextArea controlStatus = findByName(panel, "control.status", JTextArea.class);

        SwingUtilities.invokeAndWait(() -> {
            if (!filesEnable.isSelected()) {
                filesEnable.doClick();
            }
            if (!openSearch.isSelected()) {
                openSearch.doClick();
            }
            RuntimeConfig.setExportRunning(true);
            call(panel, "updateRuntimeConfig");
        });

        assertThat(controlStatus.getText())
                .contains("Files: Running")
                .contains("OpenSearch: Running");

        SwingUtilities.invokeAndWait(aws::doClick);

        assertThat(controlStatus.getText())
                .contains("Files: Running")
                .doesNotContain("OpenSearch:");

        SwingUtilities.invokeAndWait(filesEnable::doClick);

        assertThat(controlStatus.getText())
                .doesNotContain("Files:")
                .doesNotContain("OpenSearch:");

        SwingUtilities.invokeAndWait(() -> {
            filesEnable.doClick();
            openSearch.doClick();
        });

        assertThat(controlStatus.getText())
                .contains("Files: Running")
                .contains("OpenSearch: Running");
    }

    private static ConfigPanel createPanel() {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                ConfigPanel p = new ConfigPanel(new ConfigController(new NoopUi()));
                if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                    p.setSize(1000, 700);
                }
                p.doLayout();
                ref.set(p);
            });
            return ref.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Failed to create ConfigPanel test fixture", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw new RuntimeException(
                    "Failed to create ConfigPanel test fixture", cause != null ? cause : e);
        }
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        if (name.equals(root.getName()) && type.isInstance(root)) {
            return type.cast(root);
        }
        for (Component child : root.getComponents()) {
            if (child instanceof Container container) {
                T nested = findByName(container, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {
            // not used
        }

        @Override public void onDatabaseStatus(String message) {
            // not used
        }

        @Override public void onControlStatus(String message) {
            // not used
        }
    }
}
