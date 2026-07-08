package ai.anomalousvectors.tools.burp.ui;

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;

/**
 * Pressing Enter in the OS URL field should invoke testConnection.
 * Ensures OpenSearch is enabled before firing the action.
 */
class ConfigPanelEnterBindingsHeadlessTest {

    private static final class TestUi implements ConfigController.Ui {
        final AtomicReference<String> os = new AtomicReference<>();
        @Override public void onFileStatus(String m) {
            // File status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onDatabaseStatus(String m) { os.set(m); }
        @Override public void onControlStatus(String m) {
            // Control status is not observed in this test; required by ConfigController.Ui
        }
    }

    private TestUi ui;
    private ConfigPanel panel;

    @BeforeEach
    public void setup() throws Exception {
        ui = new TestUi();
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(ui));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();

            javax.swing.AbstractButton osEnable = javax.swing.AbstractButton.class.cast(get(p, "openSearchSinkCheckbox"));
            if (!osEnable.isSelected()) osEnable.doClick();

            ref.set(p);
        });
        panel = ref.get();
    }

    @Test
    void pressEnterOnOpenSearchUrlField_triggersTestConnection_andUpdatesStatus() throws Exception {
        JTextField field = JTextField.class.cast(get(panel, "openSearchUrlField"));

        onEdtAndWait(() -> {
            field.setText("http://127.0.0.1:1");
            field.postActionEvent(); // Enter -> bound action triggers testConnection
        });

        await(() -> ui.os.get() != null);
        assertThat(ui.os.get()).isNotBlank();
    }

    // ---- helpers ----
    private static void onEdtAndWait(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    private static void await(java.util.concurrent.Callable<Boolean> cond) {
        long deadline = System.currentTimeMillis() + 2500;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (Boolean.TRUE.equals(cond.call())) {
                    return;
                }
            } catch (Exception ignored) {
                // Condition evaluation failed; continue until deadline or success.
            }
            LockSupport.parkNanos(15_000_000L); // ~15ms without using Thread.sleep
        }
        throw new AssertionError("Timed out waiting for Database status");
    }
}
