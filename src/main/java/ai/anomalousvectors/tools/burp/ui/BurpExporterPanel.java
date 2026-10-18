package ai.anomalousvectors.tools.burp.ui;

import java.awt.BorderLayout;
import java.io.Serial;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import ai.anomalousvectors.tools.burp.ui.primitives.ScrollPanes;

/**
 * Top-level tabbed UI for the Burp Exporter extension.
 * <p>
 * Hosts the Config, Log, Stats, and About panels in a single {@link JTabbedPane}.</p>
 */
public final class BurpExporterPanel extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private final ConfigPanel configPanel;

    /**
     * Constructs the top-level tab container for the extension.
     * <p>
     * Caller must invoke on the EDT. Tooltip hover timing is configured once in
     * {@link ai.anomalousvectors.tools.burp.Exporter#initialize}. Mounts all major panels inside a
     * {@link JTabbedPane} wrapped with scroll panes.</p>
     */
    public BurpExporterPanel() {
        super(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        configPanel = new ConfigPanel();

        tabbedPane.addTab("Config", ScrollPanes.wrap(configPanel));
        tabbedPane.addTab("Log",    ScrollPanes.wrap(new LogPanel()));
        tabbedPane.addTab("Stats",  ScrollPanes.wrap(new StatsPanel()));
        tabbedPane.addTab("About",  ScrollPanes.wrap(new AboutPanel()));

        add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Closes extension-owned UI callbacks before Burp removes the suite tab.
     *
     * <p>Safe to invoke from Burp's unload thread. Swing components are not mutated here; the
     * Config panel only closes its background controller and fences later callbacks.</p>
     */
    public void closeForUnload() {
        configPanel.closeForUnload();
    }

}
