package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportControlBridge;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import net.miginfocom.swing.MigLayout;

/**
 * Headless tests for {@link ConfigControlPanel}: layout, stable component names,
 * and Start/Stop button and indicator behaviour.
 */
class ConfigControlPanelHeadlessTest {

    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";

    private static void resetExportRunning() {
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStopping(false);
    }

    @Test
    void control_panel_has_header_and_named_components() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(noOpStartAction(), noOpStopAction());

            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            JLabel header = findLabelByText(root, "Config Control");
            assertThat(header).isNotNull();
            assertThat(header.getToolTipText())
                    .isEqualTo("<html>Import or export the configuration.<br>Start or stop Burp Exporter.</html>");

            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            assertThat(startStop).isNotNull();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(startStop.getToolTipText()).contains("Start exporting to the configured destination(s).");
            assertThat(startStop.getToolTipText()).contains("During export");
            assertThat(startStop.getToolTipText()).contains("spill");
            assertThat(startStop.getToolTipLocation(null))
                    .isEqualTo(new java.awt.Point(startStop.getWidth() + 8, 0));
            assertThat(indicator).isNotNull();
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void control_tooltip_owners_create_html_enabled_tooltips() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(noOpStartAction(), noOpStopAction());

            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(() -> {
                JToolTip startStopToolTip = startStop.createToolTip();
                JToolTip indicatorToolTip = indicator.createToolTip();

                assertThat(startStopToolTip.getComponent()).isSameAs(startStop);
                assertThat(indicatorToolTip.getComponent()).isSameAs(indicator);
                assertThat(startStopToolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
                assertThat(indicatorToolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
            });
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void control_panel_buttons_have_expected_labels() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(noOpStartAction(), noOpStopAction());
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            List<JButton> buttons = collect(root, JButton.class);
            List<String> texts = buttons.stream().map(button -> button.getText()).toList();
            assertThat(texts).contains("Import Config", "Export Config", "Start");
            assertThat(texts).doesNotContain("Save");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void start_stop_click_invokes_actions_and_updates_button_indicator_and_status() throws Exception {
        resetExportRunning();
        try {
            AtomicInteger startCount = new AtomicInteger(0);
            AtomicInteger stopCount = new AtomicInteger(0);
            AtomicReference<JTextArea> controlStatusRef = new AtomicReference<>();
            JPanel root = buildPanel(
                    callbacks -> {
                        startCount.incrementAndGet();
                        RuntimeConfig.setExportRunning(true);
                    },
                    callbacks -> {
                        stopCount.incrementAndGet();
                        RuntimeConfig.setExportRunning(false);
                        callbacks.onStopComplete().run();
                    },
                    controlStatusRef
            );

            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");

            runEdt(startStop::doClick);
            runEdt(() -> { });
            assertThat(startCount.get()).isEqualTo(1);
            assertThat(stopCount.get()).isEqualTo(0);
            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(indicator.getToolTipText())
                    .isEqualTo("<html>Export is starting (preparing destinations)</html>");
            assertThat(controlStatusRef.get().getText()).startsWith("Starting:");

            runEdt(startStop::doClick);
            runEdt(() -> { });
            assertThat(startCount.get()).isEqualTo(1);
            assertThat(stopCount.get()).isEqualTo(1);
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
            assertThat(controlStatusRef.get().getText()).isEqualTo(ExportShutdownStatus.stoppedMessage());
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void stop_click_keepsExportReadyUntilStopActionDrainsAcceptedWork() throws Exception {
        resetExportRunning();
        AtomicBoolean exportReadyWhenStopClickLogged = new AtomicBoolean(true);
        Logger.LogListener listener = (level, message) -> {
            if (message.startsWith("[Control] Stop clicked; intake closed")) {
                exportReadyWhenStopClickLogged.set(RuntimeConfig.isExportReady());
            }
        };
        Logger.registerListener(listener);
        try {
            AtomicReference<Boolean> runningWhenStopActionRuns = new AtomicReference<>();
            AtomicReference<Boolean> runTokenValidWhenStopActionRuns = new AtomicReference<>();
            JPanel root = buildPanel(
                    callbacks -> callbacks.onStartSuccess().run(),
                    callbacks -> {
                        runningWhenStopActionRuns.set(RuntimeConfig.isExportRunning());
                        runTokenValidWhenStopActionRuns.set(
                                RuntimeConfig.currentExportRunToken().isValid());
                    });
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);

            runEdt(startStop::doClick);
            runEdt(() -> { });
            runEdt(startStop::doClick);
            runEdt(() -> { });

            assertThat(runningWhenStopActionRuns).hasValue(true);
            assertThat(runTokenValidWhenStopActionRuns).hasValue(true);
            assertThat(exportReadyWhenStopClickLogged).isTrue();
        } finally {
            Logger.unregisterListener(listener);
            Logger.resetState();
            resetExportRunning();
        }
    }

    @Test
    void stop_click_keeps_stop_label_until_onStopComplete() throws Exception {
        resetExportRunning();
        try {
            AtomicReference<Runnable> stopCompleteRef = new AtomicReference<>();
            JPanel root = buildPanel(
                    callbacks -> callbacks.onStartSuccess().run(),
                    callbacks -> stopCompleteRef.set(callbacks.onStopComplete())
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);

            runEdt(startStop::doClick);
            runEdt(() -> { });
            runEdt(startStop::doClick);

            assertThat(RuntimeConfig.isExportStopping()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");

            runEdt(() -> stopCompleteRef.get().run());
            assertThat(startStop.getText()).isEqualTo("Start");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void second_stop_click_while_stopping_requests_force_abort() throws Exception {
        resetExportRunning();
        try {
            AtomicReference<Runnable> stopCompleteRef = new AtomicReference<>();
            AtomicReference<JTextArea> controlStatusRef = new AtomicReference<>();
            JPanel root = buildPanel(
                    callbacks -> callbacks.onStartSuccess().run(),
                    callbacks -> stopCompleteRef.set(callbacks.onStopComplete()),
                    controlStatusRef
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);

            runEdt(startStop::doClick);
            runEdt(() -> { });
            runEdt(startStop::doClick);
            assertThat(RuntimeConfig.isExportStopping()).isTrue();
            assertThat(RuntimeConfig.isExportStopForceAbortRequested()).isFalse();

            runEdt(startStop::doClick);
            assertThat(RuntimeConfig.isExportStopForceAbortRequested()).isTrue();
            assertThat(controlStatusRef.get().getText())
                    .isEqualTo(ExportShutdownStatus.forceStoppingMessage());

            runEdt(() -> stopCompleteRef.get().run());
            assertThat(RuntimeConfig.isExportStopping()).isFalse();
            assertThat(RuntimeConfig.isExportStopForceAbortRequested()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(controlStatusRef.get().getText())
                    .isEqualTo(ExportShutdownStatus.forceStoppedMessage());
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void forced_stop_bridge_syncs_button_and_indicator_to_stopped() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(
                    callbacks -> callbacks.onStartSuccess().run(),
                    noOpStopAction()
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(startStop::doClick);
            runEdt(() -> { });
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is running</html>");

            runEdt(() -> {
                RuntimeConfig.setExportRunning(false);
                ExportControlBridge.notifyForcedStopped();
            });
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
        } finally {
            ExportControlBridge.clear();
            resetExportRunning();
        }
    }

    @Test
    void stop_click_shows_stopping_before_onStopComplete() throws Exception {
        resetExportRunning();
        try {
            AtomicReference<Runnable> stopCompleteRef = new AtomicReference<>();
            AtomicReference<JTextArea> controlStatusRef = new AtomicReference<>();
            JPanel root = buildPanel(
                    callbacks -> callbacks.onStartSuccess().run(),
                    callbacks -> stopCompleteRef.set(callbacks.onStopComplete()),
                    controlStatusRef
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(startStop::doClick);
            runEdt(() -> { });
            runEdt(startStop::doClick);

            assertThat(RuntimeConfig.isExportStopping()).isTrue();
            assertThat(indicator.getToolTipText())
                    .isEqualTo("<html>Export is stopping (finishing in-flight work)</html>");
            assertThat(controlStatusRef.get().getText()).startsWith("Stopping:");

            runEdt(() -> { });
            runEdt(() -> stopCompleteRef.get().run());
            assertThat(RuntimeConfig.isExportStopping()).isFalse();
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
            assertThat(controlStatusRef.get().getText()).isEqualTo(ExportShutdownStatus.stoppedMessage());
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void start_action_calling_onStartFailure_reverts_button_and_indicator_to_stopped() throws Exception {
        resetExportRunning();
        try {
            JPanel root = buildPanel(callbacks -> callbacks.onStartFailure().run(), noOpStopAction());
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(startStop::doClick);
            runEdt(() -> { });
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void start_action_calling_onStartSuccess_marks_indicator_running_and_sets_running_status() throws Exception {
        resetExportRunning();
        try {
            AtomicReference<JTextArea> controlStatusRef = new AtomicReference<>();
            JPanel root = buildPanel(callbacks -> callbacks.onStartSuccess().run(), noOpStopAction(), controlStatusRef);
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(startStop::doClick);
            runEdt(() -> { });

            assertThat(RuntimeConfig.isExportRunning()).isTrue();
            assertThat(startStop.getText()).isEqualTo("Stop");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is running</html>");
            assertThat(controlStatusRef.get().getText()).startsWith("Starting:");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void stop_clicked_before_deferred_start_runs_keeps_control_stopped() throws Exception {
        resetExportRunning();
        try {
            AtomicInteger startAcceptedCount = new AtomicInteger(0);
            AtomicInteger stopCount = new AtomicInteger(0);
            JPanel root = buildPanel(
                    callbacks -> {
                        if (!RuntimeConfig.isExportRunning() || RuntimeConfig.isExportStopping()) {
                            return;
                        }
                        startAcceptedCount.incrementAndGet();
                    },
                    callbacks -> {
                        stopCount.incrementAndGet();
                        RuntimeConfig.setExportRunning(false);
                        callbacks.onStopComplete().run();
                    }
            );
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });
            JButton startStop = findByName(root, "control.startStop", JButton.class);
            JComponent indicator = findByName(root, "control.exportIndicator", JComponent.class);

            runEdt(() -> {
                startStop.doClick();
                assertThat(RuntimeConfig.isExportRunning()).isTrue();
                assertThat(startStop.getText()).isEqualTo("Stop");
                assertThat(indicator.getToolTipText())
                        .isEqualTo("<html>Export is starting (preparing destinations)</html>");
                startStop.doClick();
                assertThat(RuntimeConfig.isExportRunning()).isTrue();
                assertThat(indicator.getToolTipText())
                        .isEqualTo("<html>Export is stopping (finishing in-flight work)</html>");
            });
            runEdt(() -> { });
            assertThat(stopCount.get()).isEqualTo(1);
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");

            runEdt(() -> { });
            assertThat(startAcceptedCount.get()).isEqualTo(0);
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(startStop.getText()).isEqualTo("Start");
            assertThat(indicator.getToolTipText()).isEqualTo("<html>Export is stopped</html>");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void when_export_running_panel_builds_with_stop_label() throws Exception {
        resetExportRunning();
        try {
            RuntimeConfig.setExportRunning(true);
            JPanel root = buildPanel(noOpStartAction(), noOpStopAction());
            runEdt(() -> {
                root.setSize(600, 400);
                root.doLayout();
            });

            JButton startStop = findByName(root, "control.startStop", JButton.class);
            assertThat(startStop.getText()).isEqualTo("Stop");
        } finally {
            resetExportRunning();
        }
    }

    @Test
    void control_components_findable_inside_config_panel() throws Exception {
        resetExportRunning();
        try {
            ConfigPanel configPanel = new ConfigPanel();
            runEdt(() -> {
                configPanel.setSize(1000, 700);
                configPanel.doLayout();
            });

            JButton startStop = findByName(configPanel, "control.startStop", JButton.class);
            JComponent indicator = findByName(configPanel, "control.exportIndicator", JComponent.class);
            JLabel header = findLabelByText(configPanel, "Config Control");

            assertThat(header).isNotNull();
            assertThat(startStop.getText()).isIn("Start", "Stop");
            assertThat(indicator).isNotNull();
        } finally {
            resetExportRunning();
        }
    }

    private static JPanel buildPanel(
            Consumer<ConfigControlPanel.StartUiCallbacks> startAction,
            Consumer<ConfigControlPanel.StopUiCallbacks> stopAction
    ) {
        return buildPanel(startAction, stopAction, new AtomicReference<>());
    }

    private static JPanel buildPanel(
            Consumer<ConfigControlPanel.StartUiCallbacks> startAction,
            Consumer<ConfigControlPanel.StopUiCallbacks> stopAction,
            AtomicReference<JTextArea> controlStatusRef
    ) {
        JTextArea importExportStatus = new JTextArea();
        JPanel importExportStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
        JTextArea controlStatus = new JTextArea();
        controlStatusRef.set(controlStatus);
        JPanel controlStatusWrapper = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

        ConfigControlPanel panel = new ConfigControlPanel(
                importExportStatus,
                importExportStatusWrapper,
                controlStatus,
                controlStatusWrapper,
                30,
                15,
                ta -> { },
                () -> { },
                () -> { },
                startAction,
                stopAction
        );
        return panel.build();
    }

    private static Consumer<ConfigControlPanel.StartUiCallbacks> noOpStartAction() {
        return callbacks -> { };
    }

    private static Consumer<ConfigControlPanel.StopUiCallbacks> noOpStopAction() {
        return callbacks -> callbacks.onStopComplete().run();
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        List<T> all = new ArrayList<>();
        collectByType(root, type, all);
        for (T c : all) {
            if (name.equals(c.getName())) return c;
        }
        throw new AssertionError("Component not found: name=" + name + " type=" + type.getSimpleName());
    }

    private static JLabel findLabelByText(Container root, String text) {
        List<JLabel> all = new ArrayList<>();
        collectByType(root, JLabel.class, all);
        for (JLabel lbl : all) {
            if (text.equals(lbl.getText())) return lbl;
        }
        throw new AssertionError("JLabel with text not found: " + text);
    }

    private static <T extends Component> void collectByType(Container root, Class<T> type, List<T> out) {
        if (type.isInstance(root)) out.add(type.cast(root));
        for (Component comp : root.getComponents()) {
            if (comp instanceof Container cont) collectByType(cont, type, out);
            else if (type.isInstance(comp)) out.add(type.cast(comp));
        }
    }

    private static List<JButton> collect(Container root, Class<JButton> type) {
        List<JButton> out = new ArrayList<>();
        collectByType(root, type, out);
        return out;
    }

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeAndWait(r);
    }
}
