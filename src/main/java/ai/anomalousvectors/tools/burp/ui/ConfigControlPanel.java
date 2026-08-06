package ai.anomalousvectors.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.MultipleGradientPaint.CycleMethod;
import java.awt.RadialGradientPaint;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.io.Serial;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import ai.anomalousvectors.tools.burp.ui.primitives.ButtonStyles;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.ExportControlBridge;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.sinks.ProxyLiveMetadataCorrelator;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator;
import net.miginfocom.swing.MigLayout;

/**
 * Config Control section: Import / Export actions, Start/Stop export, and their status rows.
 *
 * <p><strong>Responsibilities:</strong> render control panel and expose the assembled panel.
 * Callers supply actions and a status configurator for consistent text-area setup. A single
 * Start/Stop button toggles {@link RuntimeConfig#setExportRunning(boolean)}; its label and
 * tooltip show "Start" when stopped and "Stop" when running or stopping. While stopping, a second
 * Stop click requests force-abort of long remote waits. The indicator shows starting
 * (yellow), running (green), stopping (yellow), or stopped (red), and the control status
 * reflects those states. Forced stops outside the click path sync via
 * {@link ExportControlBridge}.</p>
 *
 * <p><strong>Threading:</strong> created/used on the EDT. {@link #build()} mounts status text areas
 * into their wrapper panels so callers can update them via
 * {@link ai.anomalousvectors.tools.burp.ui.primitives.StatusViews#setStatus(javax.swing.JTextArea,
 * javax.swing.JPanel, String, int, int)}.</p>
 */
public final class ConfigControlPanel {

    private static final Color INDICATOR_GREEN = new Color(0x00_88_00);
    private static final Color INDICATOR_YELLOW = new Color(0xCC_AA_00);
    private static final Color INDICATOR_RED   = new Color(0x99_00_00);
    private static final Color INDICATOR_BORDER = Color.BLACK;
    /** Inset so the border is not clipped by the component bounds. */
    private static final int INDICATOR_INSET   = 2;
    private static final int BUTTON_ROWS_EXTRA_GAP = 8;

    /** Paints a 3D-style circle: red/green fill with top-left gloss and a thin black border; transparent background. */
    private static final class IndicatorDot extends JComponent {
        @Serial private static final long serialVersionUID = 1L;

        private final int size;
        private State state = State.STOPPED;

        private enum State {
            STOPPED,
            STARTING,
            RUNNING,
            STOPPING
        }

        IndicatorDot(int sizePx) {
            this.size = sizePx;
            setPreferredSize(new Dimension(sizePx, sizePx));
            setMinimumSize(new Dimension(sizePx, sizePx));
            setMaximumSize(new Dimension(sizePx, sizePx));
            setName("control.exportIndicator");
            setOpaque(false);
            putClientProperty("html.disable", Boolean.FALSE);
        }

        /**
         * Creates an HTML-enabled tooltip owned by this indicator.
         *
         * @return tooltip configured for shared exporter HTML rendering
         */
        @Override
        public javax.swing.JToolTip createToolTip() {
            return Tooltips.createHtmlToolTip(this);
        }

        void setState(State state) {
            if (this.state != state) {
                Logger.logTrace("[Control] indicator state=" + state.name().toLowerCase());
                this.state = state;
                repaint();
            }
            Tooltips.apply(this, Tooltips.html(switch (state) {
                case STOPPED -> "Export is stopped";
                case STARTING -> "Export is starting (preparing destinations)";
                case RUNNING -> "Export is running";
                case STOPPING -> "Export is stopping (finishing in-flight work)";
            }));
        }

        /**
         * Paints the current lifecycle state indicator.
         *
         * @param g Swing paint context
         */
        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int inset = INDICATOR_INSET;
            double d = size - 2.0 * inset;
            Ellipse2D.Double circle = new Ellipse2D.Double(inset, inset, d, d);

            Color base = switch (state) {
                case STOPPED -> INDICATOR_RED;
                case STARTING, STOPPING -> INDICATOR_YELLOW;
                case RUNNING -> INDICATOR_GREEN;
            };
            g2.setColor(base);
            g2.fill(circle);

            double cx = inset + d * 0.28;
            double cy = inset + d * 0.28;
            float radius = (float) (d * 0.65);
            float[] fractions = { 0f, 1f };
            Color[] colors = { new Color(255, 255, 255, 180), new Color(255, 255, 255, 0) };
            RadialGradientPaint gloss = new RadialGradientPaint(
                    (float) cx, (float) cy, radius, fractions, colors, CycleMethod.NO_CYCLE);
            g2.setPaint(gloss);
            g2.fill(circle);

            g2.setPaint(INDICATOR_BORDER);
            g2.setStroke(new BasicStroke(1f));
            g2.draw(circle);
            g2.dispose();
        }
    }

    private final JTextArea importExportStatus;
    private final JPanel importExportStatusWrapper;
    private final JTextArea controlStatus;
    private final JPanel controlStatusWrapper;
    private final int indent;
    private final int rowGap;
    private final Consumer<JTextArea> statusConfigurator;
    private final Runnable importAction;
    private final Runnable exportAction;
    /** Receives start UI callbacks; caller posts phased status and completes or reverts on the EDT. */
    private final Consumer<StartUiCallbacks> startAction;
    /** Invoked on Stop; caller runs phased shutdown and invokes callbacks on the EDT. */
    private final Consumer<StopUiCallbacks> stopAction;

    /**
     * Start lifecycle UI hooks. {@link #snapshot()} is captured on the EDT when Start is clicked;
     * {@link #onStartProgress()} receives status lines during bootstrap; {@link #onStartSuccess()}
     * runs when startup finishes (final running status is posted separately). All callbacks are
     * invoked on the EDT.
     *
     * @param onStartFailure restores stopped controls after startup failure
     * @param onStartSuccess applies running controls after successful startup
     * @param onStartProgress displays one startup phase message
     * @param snapshot destination selection captured at Start time
     */
    public record StartUiCallbacks(
            Runnable onStartFailure,
            Runnable onStartSuccess,
            Consumer<String> onStartProgress,
            ExportStartupStatus.Snapshot snapshot
    ) {}

    /**
     * Stop lifecycle UI hooks. {@link #snapshot()} is captured on the EDT when Stop is clicked;
     * {@link #onStopProgress()} receives status lines during wind-down; {@link #onStopComplete()}
     * runs when shutdown is fully finished. All callbacks are invoked on the EDT.
     *
     * @param onStopComplete applies stopped controls after shutdown
     * @param onStopProgress displays one shutdown phase message
     * @param snapshot queue depths captured at Stop time
     */
    public record StopUiCallbacks(
            Runnable onStopComplete,
            Consumer<String> onStopProgress,
            ExportShutdownStatus.Snapshot snapshot
    ) {}

    /**
     * Creates the Config Control section from caller-owned components and actions.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param importExportStatus import/export status text area
     * @param importExportStatusWrapper wrapper that controls import/export status visibility
     * @param controlStatus Start/Stop status text area
     * @param controlStatusWrapper wrapper that controls Start/Stop status visibility
     * @param indent left indentation for nested rows
     * @param rowGap MigLayout row-gap expression
     * @param statusConfigurator shared text-area configuration callback
     * @param importAction configuration import action
     * @param exportAction configuration export action
     * @param startAction asynchronous Start action
     * @param stopAction asynchronous Stop action
     * @throws NullPointerException if a component or callback is {@code null}
     */
    public ConfigControlPanel(
            JTextArea importExportStatus,
            JPanel importExportStatusWrapper,
            JTextArea controlStatus,
            JPanel controlStatusWrapper,
            int indent,
            int rowGap,
            Consumer<JTextArea> statusConfigurator,
            Runnable importAction,
            Runnable exportAction,
            Consumer<StartUiCallbacks> startAction,
            Consumer<StopUiCallbacks> stopAction
    ) {
        this.importExportStatus = Objects.requireNonNull(importExportStatus, "importExportStatus");
        this.importExportStatusWrapper = Objects.requireNonNull(importExportStatusWrapper, "importExportStatusWrapper");
        this.controlStatus = Objects.requireNonNull(controlStatus, "controlStatus");
        this.controlStatusWrapper = Objects.requireNonNull(controlStatusWrapper, "controlStatusWrapper");
        this.indent = indent;
        this.rowGap = rowGap;
        this.statusConfigurator = Objects.requireNonNull(statusConfigurator, "statusConfigurator");
        this.importAction = Objects.requireNonNull(importAction, "importAction");
        this.exportAction = Objects.requireNonNull(exportAction, "exportAction");
        this.startAction = Objects.requireNonNull(startAction, "startAction");
        this.stopAction = Objects.requireNonNull(stopAction, "stopAction");
    }

    /**
     * Builds the Config Control panel.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @return assembled control panel
     */
    public JPanel build() {
        JPanel root = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        root.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Config Control",
                Tooltips.html("Import or export the configuration.", "Start or stop Burp Exporter."));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        root.add(header, "gapbottom 6");

        JButton importBtn = new Tooltips.HtmlButton("Import Config");
        JButton exportBtn = new Tooltips.HtmlButton("Export Config");

        JButton startStopBtn = new Tooltips.HtmlButton(runningButtonLabel(RuntimeConfig.isExportRunning()));
        startStopBtn.setName("control.startStop");
        ButtonStyles.normalize(importBtn);
        ButtonStyles.normalize(exportBtn);
        ButtonStyles.normalize(startStopBtn);
        Tooltips.preferTipToRight(startStopBtn);
        updateStartStopButton(startStopBtn, RuntimeConfig.isExportRunning());

        int btnHeight = startStopBtn.getPreferredSize().height;
        IndicatorDot indicator = new IndicatorDot(btnHeight);
        indicator.setState(RuntimeConfig.isExportRunning() ? IndicatorDot.State.RUNNING : IndicatorDot.State.STOPPED);

        assignToolTips(importBtn, exportBtn);

        importBtn.addActionListener(e -> importAction.run());
        exportBtn.addActionListener(e -> exportAction.run());
        startStopBtn.addActionListener(e -> {
            if (RuntimeConfig.isExportStopping()) {
                if (RuntimeConfig.requestExportStopForceAbort()) {
                    Logger.logWarnPanelOnly(
                            "[Export] Force-stop requested; skipping remaining shutdown waits.");
                    updateControlStatus(ExportShutdownStatus.forceStoppingMessage());
                }
                return;
            }
            boolean wasRunning = RuntimeConfig.isExportRunning();
            if (wasRunning) {
                RuntimeConfig.ExportRunToken stoppedRun = RuntimeConfig.currentExportRunToken();
                ProxyLiveMetadataCorrelator.closeIntake();
                RuntimeConfig.beginExportStop();
                RuntimeConfig.setExportStopping(true);
                StartupSnapshotCoordinator.cancelRun(stoppedRun);
                Logger.logDebug(
                        "[Control] Stop clicked; intake closed and accepted work is draining "
                                + "(running=true, stopping=true).");
                // Keep Stop label so a second click can force-abort a hung graceful shutdown.
                updateStartStopButton(startStopBtn, true);
                Tooltips.apply(startStopBtn, forceStopExportTooltip());
                indicator.setState(IndicatorDot.State.STOPPING);
                ExportShutdownStatus.Snapshot snapshot = ExportShutdownStatus.capture();
                updateControlStatus(ExportShutdownStatus.initialStoppingMessage(snapshot));
                Runnable markStoppedUi = () -> {
                    boolean forced = RuntimeConfig.isExportStopForceAbortRequested();
                    RuntimeConfig.setExportStopping(false);
                    RuntimeConfig.clearExportStopForceAbort();
                    updateStartStopButton(startStopBtn, false);
                    indicator.setState(IndicatorDot.State.STOPPED);
                    updateControlStatus(forced
                            ? ExportShutdownStatus.forceStoppedMessage()
                            : ExportShutdownStatus.stoppedMessage());
                };
                StopUiCallbacks callbacks = new StopUiCallbacks(
                        markStoppedUi,
                        this::updateControlStatus,
                        snapshot);
                // Post stop work after this listener returns so Stopping paints before shutdown.
                SwingUtilities.invokeLater(() -> stopAction.accept(callbacks));
            } else {
                Logger.logDebug("[Control] Start clicked; running=false -> true");
                RuntimeConfig.setExportRunning(true);
                RuntimeConfig.setExportStarting(true);
                updateStartStopButton(startStopBtn, true);
                indicator.setState(IndicatorDot.State.STARTING);
                ExportStartupStatus.Snapshot snapshot = ExportStartupStatus.capture();
                updateControlStatus(ExportStartupStatus.initialStartingMessage(snapshot));
                Runnable revertUi = () -> {
                    RuntimeConfig.setExportRunning(false);
                    updateStartStopButton(startStopBtn, false);
                    indicator.setState(IndicatorDot.State.STOPPED);
                };
                Runnable markStartedUi = () -> {
                    RuntimeConfig.setExportStarting(false);
                    updateStartStopButton(startStopBtn, true);
                    indicator.setState(IndicatorDot.State.RUNNING);
                };
                StartUiCallbacks callbacks = new StartUiCallbacks(
                        revertUi,
                        markStartedUi,
                        this::updateControlStatus,
                        snapshot);
                SwingUtilities.invokeLater(() -> startAction.accept(callbacks));
            }
        });

        ExportControlBridge.registerForcedStopped(() -> {
            Runnable sync = () -> {
                RuntimeConfig.setExportStopping(false);
                RuntimeConfig.clearExportStopForceAbort();
                updateStartStopButton(startStopBtn, false);
                indicator.setState(IndicatorDot.State.STOPPED);
                Logger.logDebug("[Control] Forced-stop UI sync: indicator=stopped button=Start");
            };
            if (SwingUtilities.isEventDispatchThread()) {
                sync.run();
            } else {
                SwingUtilities.invokeLater(sync);
            }
        });

        JPanel row1 = new JPanel(new MigLayout("insets 0, gapx 10", "[left][left]", "[]"));
        row1.setAlignmentX(Component.LEFT_ALIGNMENT);
        row1.add(importBtn, "gapleft " + indent);
        row1.add(exportBtn);

        JPanel row2 = new JPanel(new MigLayout("insets 0, gapx 10", "[left][left]", "[]"));
        row2.setAlignmentX(Component.LEFT_ALIGNMENT);
        row2.add(startStopBtn, "gapleft " + indent + ", aligny center");
        row2.add(indicator, "aligny center");

        JPanel buttons = new JPanel(new MigLayout("insets 0, gapy " + rowGap, "[left]", "[]" + rowGap + " []"));
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttons.add(row1, "wrap");
        buttons.add(row2, "gaptop " + BUTTON_ROWS_EXTRA_GAP);

        root.add(buttons);

        statusConfigurator.accept(importExportStatus);
        statusConfigurator.accept(controlStatus);

        importExportStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        importExportStatusWrapper.removeAll();
        importExportStatusWrapper.add(importExportStatus, "w pref!");
        importExportStatusWrapper.setVisible(false);

        controlStatusWrapper.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        controlStatusWrapper.removeAll();
        controlStatusWrapper.add(controlStatus, "w pref!");
        controlStatusWrapper.setVisible(false);

        final int gapPx = 8;
        JPanel statuses = new JPanel(new MigLayout(
                "insets " + rowGap + " " + indent + " 0 0, gapy " + gapPx,
                "[left]",
                "[] " + gapPx + " []"
        ));
        statuses.add(importExportStatusWrapper, "hidemode 3, w pref!, wrap");
        statuses.add(controlStatusWrapper, "hidemode 3, w pref!");

        root.add(statuses);
        return root;
    }

    private void updateControlStatus(String message) {
        ai.anomalousvectors.tools.burp.ui.primitives.StatusViews.setStatus(
                controlStatus, controlStatusWrapper, message, 20, 120);
    }

    private static String runningButtonLabel(boolean running) {
        return running ? "Stop" : "Start";
    }

    private static void updateStartStopButton(JButton btn, boolean running) {
        btn.setText(runningButtonLabel(running));
        Tooltips.apply(btn, running ? stopExportTooltip() : startExportTooltip());
    }

    private static String startExportTooltip() {
        String spillPath = Tooltips.escapeHtml(
                ai.anomalousvectors.tools.burp.utils.ManagedDiskPaths.spillDirectory().toString());
        String correlationPath = Tooltips.escapeHtml(
                ai.anomalousvectors.tools.burp.utils.ManagedDiskPaths.proxyCorrelationDirectory().toString());
        return Tooltips.htmlRaw(
                "<b>Start</b>",
                "Start exporting to the configured destination(s).",
                "",
                "<b>During export</b>",
                "Repeated push failures trigger a health check. Authentication failures (HTTP 401/403) or connectivity failures can disable the database destination for the current run.",
                "If Files remains enabled, file export continues; otherwise export stops.",
                "Live traffic overflow can spill under <code>" + spillPath + "</code> when the in-memory queue is full.",
                "Live Proxy documents awaiting exact History fields persist under <code>"
                        + correlationPath + "</code>.");
    }

    private static String stopExportTooltip() {
        return Tooltips.htmlRaw(
                "<b>Stop</b>",
                "Stop exporting.",
                "Drains in-flight work where possible, pushes final exporter stats, validates Files,",
                "and closes database connections without reading database counts back.",
                "The current in-memory configuration remains active until changed.",
                "",
                "<b>If Stop hangs</b>",
                "Click Stop again to force-abort remaining remote waits",
                "(retry drain, final stats, file validation, connection close).",
                "",
                "<b>If the database destination was disabled mid-run</b>",
                "Authentication or connectivity failures can leave Files-only export running until Stop.",
                "Update credentials or connectivity, then Start again to resume database export.");
    }

    private static String forceStopExportTooltip() {
        return Tooltips.htmlRaw(
                "<b>Stop (in progress)</b>",
                "Graceful shutdown is finishing in-flight work.",
                "Click Stop again to force-abort remaining remote waits.");
    }

    /**
     * Assigns tooltips for control buttons in a single place.
     *
     * @param importBtn import action button
     * @param exportBtn export action button
     */
    private static void assignToolTips(JButton importBtn, JButton exportBtn) {
        Tooltips.apply(importBtn, Tooltips.html("Import configuration from file."));
        Tooltips.apply(exportBtn, Tooltips.html("Export configuration to file."));
    }
}
