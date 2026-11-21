package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.util.Map;
import java.util.Objects;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ai.anomalousvectors.tools.burp.ui.primitives.ButtonStyles;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.config.ExportFieldRegistry;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Index Fields" section used by {@link ConfigPanel}.
 *
 * <p>Each index is rendered as an expandable group of toggleable export-field checkboxes. The
 * layout wraps so all controls remain visible when a section expands.</p>
 */
public final class ConfigFieldsPanel {

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private static final String GAPLEFT = "gapleft ";

    private final Map<String, JButton> expandButtonsByIndex;
    private final Map<String, JPanel> subPanelsByIndex;
    private final JPanel namingDefaultsPanel;
    private final int indentPx;

    /**
     * Stores the field controls used when assembling the section on the EDT.
     *
     * @param expandButtonsByIndex non-null map of index names to existing expand buttons
     * @param subPanelsByIndex non-null map of index names to existing field panels
     * @param namingDefaultsPanel optional index-naming controls; {@code null} omits that row
     * @param indentPx horizontal indentation in pixels
     * @throws NullPointerException if either control map is {@code null}
     */
    public ConfigFieldsPanel(
            Map<String, JButton> expandButtonsByIndex,
            Map<String, JPanel> subPanelsByIndex,
            JPanel namingDefaultsPanel,
            int indentPx) {
        this.expandButtonsByIndex = Objects.requireNonNull(expandButtonsByIndex);
        this.subPanelsByIndex = Objects.requireNonNull(subPanelsByIndex);
        this.namingDefaultsPanel = namingDefaultsPanel;
        this.indentPx = indentPx;
    }

    /**
     * Builds the Index Fields panel.
     *
     * <p>Caller must invoke on the EDT. Sub-panels start collapsed. When
     * {@code sectionHeaderRowsOut} is non-null, this method fills it with the header row for each
     * index so callers can enable or disable entire sections.</p>
     *
     * @param sectionHeaderRowsOut optional destination for index-name to header-row mappings
     * @return assembled panel containing the section header and per-index groups
     */
    public JPanel build(java.util.Map<String, JPanel> sectionHeaderRowsOut) {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1, hidemode 3", "[grow,left]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Index Fields",
                Tooltips.html(
                        "Configure index naming and which mapped fields each exported document includes.",
                        "Naming controls affect index creation and file basenames.",
                        "Field toggles affect document contents."
                ));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");
        if (namingDefaultsPanel != null) {
            panel.add(namingDefaultsPanel, GAPLEFT + indentPx + ", growx, wrap");
        }

        int subIndent = indentPx * 2;

        for (String indexName : ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            JButton expandBtn = expandButtonsByIndex.get(indexName);
            JPanel subPanel = subPanelsByIndex.get(indexName);
            if (expandBtn == null || subPanel == null) continue;

            String displayName = indexDisplayName(indexName);
            JLabel indexLabel = Tooltips.label(displayName, indexTooltip(indexName));
            Tooltips.apply(expandBtn, indexExpandTooltip(indexName));

            JPanel parentRow = new JPanel(new MigLayout("insets 0, aligny center", "[left]6[pref!]"));
            parentRow.setOpaque(false);
            parentRow.add(indexLabel, GAPLEFT + indentPx + ", aligny center");
            parentRow.add(expandBtn, "aligny center");

            if (sectionHeaderRowsOut != null) {
                sectionHeaderRowsOut.put(indexName, parentRow);
            }

            panel.add(parentRow, "growx, wrap");
            panel.add(subPanel, GAPLEFT + subIndent + ", growx, wrap");
        }

        return panel;
    }

    private static String indexDisplayName(String indexShortName) {
        return switch (indexShortName) {
            case "settings" -> "Settings";
            case "sitemap" -> "Sitemap";
            case "findings" -> "Findings";
            case "traffic" -> "Traffic";
            case "exporter" -> "Exporter";
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    private static String indexTooltip(String indexShortName) {
        return switch (indexShortName) {
            case "settings" -> Tooltips.htmlRaw(
                    "<b>Settings fields</b>",
                    "Configure fields exported to the Settings index.",
                    "The index name can be customized from the Index Base Name field.",
                    "Use these toggles to trim the settings document payload."
            );
            case "sitemap" -> Tooltips.htmlRaw(
                    "<b>Sitemap fields</b>",
                    "Configure fields exported to the Sitemap index.",
                    "The index name can be customized from the Index Base Name field.",
                    "Field names follow the request/response document shape."
            );
            case "findings" -> findingsTooltip();
            case "traffic" -> Tooltips.htmlRaw(
                    "<b>Traffic fields</b>",
                    "Configure fields exported to the Traffic index.",
                    "The index name can be customized from the Index Base Name field.",
                    "Traffic field labels are shown hierarchically to match the mapped document shape."
            );
            case "exporter" -> Tooltips.htmlRaw(
                    "<b>Exporter fields</b>",
                    "Configure fields exported to the Exporter index.",
                    "The index name can be customized from the Index Base Name field.",
                    "These fields cover Burp Exporter logs, runtime stats snapshots, and config snapshots."
            );
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    private static String indexExpandTooltip(String indexShortName) {
        return switch (indexShortName) {
            case "settings" -> Tooltips.html("Show or hide Settings field options.");
            case "sitemap" -> Tooltips.html("Show or hide Sitemap field options.");
            case "findings" -> findingsExpandTooltip();
            case "traffic" -> Tooltips.html("Show or hide Traffic field options.");
            case "exporter" -> Tooltips.html("Show or hide Exporter field options.");
            default -> throw new IllegalArgumentException("Unknown index for Fields panel: " + indexShortName);
        };
    }

    private static String findingsTooltip() {
        if (RuntimeConfig.isCommunityEdition()) {
            return Tooltips.html("Unsupported in Community Edition.");
        }
        return Tooltips.htmlRaw(
                "<b>Findings fields</b>",
                "Configure fields exported to the Findings index.",
                "The index name can be customized from the Index Base Name field.",
                "These fields cover Burp findings (aka issues) documents."
        );
    }

    private static String findingsExpandTooltip() {
        if (RuntimeConfig.isCommunityEdition()) {
            return Tooltips.html("Unsupported in Community Edition.");
        }
        return Tooltips.html("Show or hide Findings field options.");
    }

    /** Configures the shared expand-button style used in the sources and fields sections. */
    public static void configureExpandButton(JButton b) {
        ButtonStyles.configureExpandButton(b);
    }

    /** Updates the expand button label and the matching sub-panel visibility. */
    public static void setExpanded(JButton expandButton, JPanel subPanel, boolean expanded) {
        expandButton.setText(expanded ? EXPAND_EXPANDED : EXPAND_COLLAPSED);
        subPanel.setVisible(expanded);
    }
}
