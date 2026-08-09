package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.awt.Image;
import java.net.URL;
import java.util.Objects;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Burp Suite Sources" section used by {@link ConfigPanel}.
 *
 * <p>{@link ConfigPanel} owns the checkbox instances, names, and listeners. This builder receives
 * those components so the UI layout stays centralized without duplicating state.</p>
 *
 * <p>Settings, Findings, Traffic, and Exporter expose collapsible sub-options. Sitemap remains a
 * single row.</p>
 */
public final class ConfigSourcesPanel {
    /** Display size for Sources notice icons (CE + Repeater Tabs). */
    private static final int NOTICE_ICON_SIZE = 16;

    private static final String COMMUNITY_ICON_TOOLTIP = Tooltips.html("Unsupported in Community Edition.");

    /**
     * Shared notice glyph for Sources info indicators.
     *
     * <p>Asset is Material Icons {@code error} (Apache 2.0), recolored to a blue circle with a white
     * bang and loaded from {@code /ui/notice-info.png}.</p>
     */
    private static final Icon NOTICE_INFO_ICON = loadNoticeInfoIcon();

    private final JCheckBox settingsCheckbox;
    private final JCheckBox sitemapCheckbox;
    private final JCheckBox issuesCheckbox;
    private final JCheckBox trafficCheckbox;
    private final JCheckBox exporterCheckbox;
    private final JButton settingsExpandButton;
    private final JPanel settingsSubPanel;
    private final JButton issuesExpandButton;
    private final JPanel issuesSubPanel;
    private final JButton trafficExpandButton;
    private final JPanel trafficSubPanel;
    private final JButton exporterExpandButton;
    private final JPanel exporterSubPanel;
    private final JComponent issuesCommunityIndicator;
    private final int indentPx;
    private static final String GAPLEFT = "gapleft ";

    public ConfigSourcesPanel(JCheckBox settingsCheckbox,
                              JCheckBox sitemapCheckbox,
                              JCheckBox issuesCheckbox,
                              JCheckBox trafficCheckbox,
                              JCheckBox exporterCheckbox,
                              JButton settingsExpandButton,
                              JPanel settingsSubPanel,
                              JButton issuesExpandButton,
                              JPanel issuesSubPanel,
                              JButton trafficExpandButton,
                              JPanel trafficSubPanel,
                              JButton exporterExpandButton,
                              JPanel exporterSubPanel,
                              JComponent issuesCommunityIndicator,
                              int indentPx) {
        this.settingsCheckbox = Objects.requireNonNull(settingsCheckbox, "settingsCheckbox");
        this.sitemapCheckbox = Objects.requireNonNull(sitemapCheckbox, "sitemapCheckbox");
        this.issuesCheckbox = Objects.requireNonNull(issuesCheckbox, "issuesCheckbox");
        this.trafficCheckbox = Objects.requireNonNull(trafficCheckbox, "trafficCheckbox");
        this.exporterCheckbox = Objects.requireNonNull(exporterCheckbox, "exporterCheckbox");
        this.settingsExpandButton = Objects.requireNonNull(settingsExpandButton, "settingsExpandButton");
        this.settingsSubPanel = Objects.requireNonNull(settingsSubPanel, "settingsSubPanel");
        this.issuesExpandButton = Objects.requireNonNull(issuesExpandButton, "issuesExpandButton");
        this.issuesSubPanel = Objects.requireNonNull(issuesSubPanel, "issuesSubPanel");
        this.trafficExpandButton = Objects.requireNonNull(trafficExpandButton, "trafficExpandButton");
        this.trafficSubPanel = Objects.requireNonNull(trafficSubPanel, "trafficSubPanel");
        this.exporterExpandButton = Objects.requireNonNull(exporterExpandButton, "exporterExpandButton");
        this.exporterSubPanel = Objects.requireNonNull(exporterSubPanel, "exporterSubPanel");
        this.issuesCommunityIndicator = issuesCommunityIndicator;
        this.indentPx = indentPx;
    }

    static JPanel buildCommunityEditionIndicator(String panelName, String iconName) {
        return buildInfoNoticeIndicator(panelName, iconName, COMMUNITY_ICON_TOOLTIP, false);
    }

    /**
     * Builds an always-visible Sources info-notice icon with a caller-supplied HTML tooltip.
     *
     * <p>Uses the same blue notice icon as Community Edition indicators. Caller must invoke on the
     * EDT. The returned panel starts visible.</p>
     *
     * @param panelName component name for the indicator panel
     * @param iconName component name for the icon label
     * @param tooltipHtml HTML tooltip text (typically from {@link Tooltips#htmlRaw(String...)})
     * @return visible indicator panel containing the icon
     */
    static JPanel buildInfoNoticeIndicator(String panelName, String iconName, String tooltipHtml) {
        return buildInfoNoticeIndicator(panelName, iconName, tooltipHtml, true);
    }

    private static JPanel buildInfoNoticeIndicator(
            String panelName, String iconName, String tooltipHtml, boolean visible) {
        JPanel indicator = new JPanel(new MigLayout("insets 0, aligny center, hidemode 3", "[pref!]"));
        indicator.setOpaque(false);
        indicator.setName(panelName);
        indicator.setVisible(visible);

        JLabel iconLabel = new Tooltips.HtmlLabel("");
        iconLabel.setName(iconName);
        iconLabel.setIcon(NOTICE_INFO_ICON);
        iconLabel.setOpaque(false);
        iconLabel.setToolTipText(tooltipHtml);

        indicator.add(iconLabel);
        return indicator;
    }

    private static Icon loadNoticeInfoIcon() {
        URL resource = ConfigSourcesPanel.class.getResource("/ui/notice-info.png");
        if (resource == null) {
            throw new IllegalStateException("Missing classpath resource /ui/notice-info.png");
        }
        ImageIcon source = new ImageIcon(resource);
        Image scaled = source.getImage()
                .getScaledInstance(NOTICE_ICON_SIZE, NOTICE_ICON_SIZE, Image.SCALE_SMOOTH);
        return new ImageIcon(scaled);
    }

    /**
     * Builds the Burp Suite Sources panel.
     *
     * <p>Caller must invoke on the EDT. The assembled panel includes rows for Settings, Sitemap,
     * Findings, Traffic, and Exporter. Collapsible sub-panels start hidden.</p>
     *
     * @return assembled panel containing the section header and source controls
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Burp Suite Sources",
                Tooltips.html("Configure the Burp Suite sources of data for export."));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6");

        int childIndent = indentPx * 2;
        int subIndent = indentPx + childIndent;

        // Settings: main checkbox + inline +/-; then sub-panel (collapsed)
        panel.add(parentRow(settingsCheckbox, settingsExpandButton, null, indentPx), "wrap");
        panel.add(settingsSubPanel, GAPLEFT + subIndent + ", wrap");

        panel.add(sitemapCheckbox, GAPLEFT + indentPx);

        // Findings: main checkbox + inline +/-; then sub-panel
        panel.add(parentRow(issuesCheckbox, issuesExpandButton, issuesCommunityIndicator, indentPx), "wrap");
        panel.add(issuesSubPanel, GAPLEFT + subIndent + ", wrap");

        // Traffic: main checkbox + inline +/-; then sub-panel
        panel.add(parentRow(trafficCheckbox, trafficExpandButton, null, indentPx), "wrap");
        panel.add(trafficSubPanel, GAPLEFT + subIndent + ", wrap");

        // Exporter: main checkbox + inline +/-; then sub-panel
        panel.add(parentRow(exporterCheckbox, exporterExpandButton, null, indentPx), "wrap");
        panel.add(exporterSubPanel, GAPLEFT + subIndent + ", wrap");

        return panel;
    }

    private JPanel parentRow(JCheckBox parent, JButton expandButton, JComponent communityNotice, int indentPx) {
        JPanel row = new JPanel(new MigLayout("insets 0, aligny center, hidemode 3", "[left]6[pref!]12[pref]"));
        row.setOpaque(false);
        row.add(parent, GAPLEFT + indentPx + ", aligny center");
        row.add(expandButton, "aligny center");
        if (communityNotice != null) {
            row.add(communityNotice, "aligny center, hidemode 3");
        }
        return row;
    }
}
