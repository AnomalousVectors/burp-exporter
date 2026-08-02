package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Font;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import ai.anomalousvectors.tools.burp.ui.primitives.StatusViews;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Destinations" section panel used by ConfigPanel.
 *
 * <p>Components are owned by {@link ConfigPanel} and injected to keep a single source of state.
 * Layout is a vertical stack: Files details under Files, then Database radios (OpenSearch first)
 * with collapsed per-destination details, then one shared Test Connection control and status.</p>
 */
public final class ConfigDestinationPanel {

    /**
     * Shared MigLayout columns for destination label/value rows.
     *
     * <p>The label column width is the preferred width of the longest destination label so nested
     * Base URL / auth / TLS panels keep the same input left edge without an oversized fixed gap.
     * The value column is {@code pref} so auto-sizing text fields and prototype-sized combos stay
     * content-wide instead of stretching across the window.</p>
     */
    static final String FIELD_COLS = "[" + sharedDestinationLabelColumnWidth() + "!, left]6[pref]";

    /**
     * Returns the preferred width used for every destination label column.
     *
     * <p>Nested auth/TLS panels each run their own MigLayout, so a per-panel {@code pref!} column
     * would size to that panel's longest label only and misalign inputs. Measuring the global
     * longest label once keeps all destination blocks on one shared width.</p>
     *
     * @return label-column width in pixels
     */
    private static int sharedDestinationLabelColumnWidth() {
        String[] samples = {
            "Disk Usage Limits:",
            "Secret Access Key:",
            "Credentials file:",
            "Amazon Username:",
            "Deployment type:",
            "Bearer Token:",
            "Session Token:",
            "Access Key ID:",
            "Base URL:",
            "Auth type:",
            "TLS mode:"
        };
        JLabel probe = new JLabel();
        int width = 0;
        for (String sample : samples) {
            probe.setText(sample);
            width = Math.max(width, probe.getPreferredSize().width);
        }
        return width;
    }

    // Files destination
    private final JCheckBox fileSinkCheckbox;
    private final JTextField filePathField;
    private final AbstractButton fileJsonlCheckbox;
    private final AbstractButton fileBulkNdjsonCheckbox;
    private final JPanel fileLimitsPanel;
    // Search destination
    private final JCheckBox databaseSinkCheckbox;
    private final AbstractButton openSearchSinkCheckbox;
    private final JTextField openSearchUrlField;
    private final AbstractButton openSearchAmazonDestinationRadio;
    private final JTextField openSearchAmazonUrlField;
    private final JPanel openSearchAmazonOptionsPanel;
    private final JPanel openSearchAmazonTlsPanel;
    private final AbstractButton elasticSearchDestinationRadio;
    private final JTextField elasticSearchUrlField;
    private final JPanel elasticSearchOptionsPanel;
    private final JPanel elasticSearchTlsPanel;
    private final JPanel openSearchTlsPanel;
    private final JButton testConnectionButton;
    private final JPanel openSearchAuthFormPanel;
    private final JTextArea databaseStatus;
    private final JPanel statusWrapper;

    // Layout
    private final int indentPx;
    private final int rowGap;

    // Delegate from ConfigPanel for consistent status styling
    private final Consumer<JTextArea> statusConfigurer;

    private static final String GAPLEFT = "gapleft ";
    private static final String ALIGN_LEFT_TOP = "alignx left, top";
    /** Extra indent that preserves the visual hierarchy under Files and Database checkboxes. */
    private static final int NESTED_INDENT_PX = 42;

    /**
     * Creates a destination section backed by controls owned by {@link ConfigPanel}.
     *
     * <p>Caller supplies already-configured Swing controls so selection state, tooltips, names, and
     * runtime synchronization remain centralized in the parent panel. The returned section is not
     * thread-safe; build and mutate it on the EDT.</p>
     *
     * @param fileSinkCheckbox enables file export
     * @param filePathField file root directory field
     * @param fileJsonlCheckbox selects JSONL file output
     * @param fileBulkNdjsonCheckbox selects search database bulk NDJSON file output
     * @param fileLimitsPanel file export safety-limit controls
     * @param databaseSinkCheckbox enables database export
     * @param openSearchSinkCheckbox selects the OpenSearch destination
     * @param openSearchUrlField OpenSearch base URL
     * @param openSearchAmazonDestinationRadio selects the Amazon OpenSearch destination
     * @param openSearchAmazonUrlField Amazon OpenSearch base URL
     * @param openSearchAmazonOptionsPanel Amazon OpenSearch non-secret options
     * @param openSearchAmazonTlsPanel Amazon OpenSearch TLS controls
     * @param elasticSearchDestinationRadio selects the Elasticsearch destination
     * @param elasticSearchUrlField Elasticsearch base URL
     * @param elasticSearchOptionsPanel Elasticsearch non-secret options
     * @param elasticSearchTlsPanel Elasticsearch TLS controls
     * @param openSearchTlsPanel TLS controls for the selected search destination
     * @param testConnectionButton runs a connection test for wired destinations
     * @param openSearchAuthFormPanel authentication controls for the selected search destination
     * @param databaseStatus connection/status output area
     * @param statusWrapper wrapper for showing and hiding {@code databaseStatus}
     * @param indentPx left indent used for rows under the section header
     * @param rowGap MigLayout row gap expression
     * @param statusConfigurer configures the shared status text area
     */
    public ConfigDestinationPanel(
            JCheckBox fileSinkCheckbox,
            JTextField filePathField,
            AbstractButton fileJsonlCheckbox,
            AbstractButton fileBulkNdjsonCheckbox,
            JPanel fileLimitsPanel,
            JCheckBox databaseSinkCheckbox,
            AbstractButton openSearchSinkCheckbox,
            JTextField openSearchUrlField,
            AbstractButton openSearchAmazonDestinationRadio,
            JTextField openSearchAmazonUrlField,
            JPanel openSearchAmazonOptionsPanel,
            JPanel openSearchAmazonTlsPanel,
            AbstractButton elasticSearchDestinationRadio,
            JTextField elasticSearchUrlField,
            JPanel elasticSearchOptionsPanel,
            JPanel elasticSearchTlsPanel,
            JPanel openSearchTlsPanel,
            JButton testConnectionButton,
            JPanel openSearchAuthFormPanel,
            JTextArea databaseStatus,
            JPanel statusWrapper,
            int indentPx,
            int rowGap,
            Consumer<JTextArea> statusConfigurer
    ) {
        this.fileSinkCheckbox = Objects.requireNonNull(fileSinkCheckbox, "fileSinkCheckbox");
        this.filePathField = Objects.requireNonNull(filePathField, "filePathField");
        this.fileJsonlCheckbox = Objects.requireNonNull(fileJsonlCheckbox, "fileJsonlCheckbox");
        this.fileBulkNdjsonCheckbox = Objects.requireNonNull(fileBulkNdjsonCheckbox, "fileBulkNdjsonCheckbox");
        this.fileLimitsPanel = Objects.requireNonNull(fileLimitsPanel, "fileLimitsPanel");

        this.databaseSinkCheckbox = Objects.requireNonNull(databaseSinkCheckbox, "databaseSinkCheckbox");
        this.openSearchSinkCheckbox = Objects.requireNonNull(openSearchSinkCheckbox, "openSearchSinkCheckbox");
        this.openSearchUrlField = Objects.requireNonNull(openSearchUrlField, "openSearchUrlField");
        this.openSearchAmazonDestinationRadio = Objects.requireNonNull(
                openSearchAmazonDestinationRadio, "openSearchAmazonDestinationRadio");
        this.openSearchAmazonUrlField = Objects.requireNonNull(openSearchAmazonUrlField, "openSearchAmazonUrlField");
        this.openSearchAmazonOptionsPanel = Objects.requireNonNull(
                openSearchAmazonOptionsPanel, "openSearchAmazonOptionsPanel");
        this.openSearchAmazonTlsPanel = Objects.requireNonNull(openSearchAmazonTlsPanel, "openSearchAmazonTlsPanel");
        this.elasticSearchDestinationRadio = Objects.requireNonNull(
                elasticSearchDestinationRadio, "elasticSearchDestinationRadio");
        this.elasticSearchUrlField = Objects.requireNonNull(elasticSearchUrlField, "elasticSearchUrlField");
        this.elasticSearchOptionsPanel = Objects.requireNonNull(elasticSearchOptionsPanel, "elasticSearchOptionsPanel");
        this.elasticSearchTlsPanel = Objects.requireNonNull(elasticSearchTlsPanel, "elasticSearchTlsPanel");
        this.openSearchTlsPanel = Objects.requireNonNull(openSearchTlsPanel, "openSearchTlsPanel");
        this.testConnectionButton = Objects.requireNonNull(testConnectionButton, "testConnectionButton");
        this.openSearchAuthFormPanel = Objects.requireNonNull(openSearchAuthFormPanel, "openSearchAuthFormPanel");
        this.databaseStatus = Objects.requireNonNull(databaseStatus, "databaseStatus");
        this.statusWrapper = Objects.requireNonNull(statusWrapper, "statusWrapper");

        this.indentPx = indentPx;
        this.rowGap = rowGap;
        this.statusConfigurer = Objects.requireNonNull(statusConfigurer, "statusConfigurer");
    }

    /**
     * Builds the Destination section containing Files and search-destination controls.
     *
     * <p>Caller must invoke on the EDT. Files and Database nest their details vertically. Database
     * radios are ordered OpenSearch, Amazon OpenSearch, then Elasticsearch; inactive radios collapse
     * URL/auth/TLS. Test Connection and status sit once under the Database block.</p>
     *
     * @return assembled panel with destination controls and the shared status area
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout(
                "insets 0, wrap 1, hidemode 3, gapy " + rowGap, "[grow]", "[]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Destinations",
                Tooltips.htmlRaw(
                        "<b>Destinations</b>",
                        "Choose where Burp Exporter writes selected sources.",
                        "Enable <b>Files</b>, one <b>Database</b> destination, or both.",
                        "Database choices are OpenSearch (recommended), Amazon OpenSearch, or Elasticsearch."));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");

        int nestedIndent = indentPx + NESTED_INDENT_PX;
        int detailIndent = nestedIndent + NESTED_INDENT_PX;

        panel.add(fileSinkCheckbox, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);

        JPanel filesDetails = buildFilesDetailsPanel();
        filesDetails.setName("files.details");
        panel.add(filesDetails, GAPLEFT + nestedIndent + ", " + ALIGN_LEFT_TOP);

        Runnable syncFileRowDecorations = () -> {
            boolean enabled = fileSinkCheckbox.isSelected();
            filesDetails.setVisible(enabled);
            setEnabledRecursively(filesDetails, enabled);
            panel.revalidate();
            panel.repaint();
        };
        fileSinkCheckbox.getModel().addChangeListener(e -> syncFileRowDecorations.run());
        syncFileRowDecorations.run();

        panel.add(databaseSinkCheckbox, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);

        JPanel openSearchDetails = buildDestinationDetails(
                "os.destination.openSearch.details",
                openSearchUrlField,
                "os.url.baseLabel",
                openSearchAuthFormPanel,
                openSearchTlsPanel);
        JPanel amazonDetails = buildDestinationDetails(
                "os.destination.amazon.details",
                openSearchAmazonUrlField,
                "os.amazon.url.baseLabel",
                openSearchAmazonOptionsPanel,
                openSearchAmazonTlsPanel);
        JPanel elasticDetails = buildDestinationDetails(
                "os.destination.elasticsearch.details",
                elasticSearchUrlField,
                "os.elasticsearch.url.baseLabel",
                elasticSearchOptionsPanel,
                elasticSearchTlsPanel);

        panel.add(openSearchSinkCheckbox, GAPLEFT + nestedIndent + ", " + ALIGN_LEFT_TOP);
        panel.add(openSearchDetails, GAPLEFT + detailIndent + ", " + ALIGN_LEFT_TOP);

        panel.add(openSearchAmazonDestinationRadio, GAPLEFT + nestedIndent + ", " + ALIGN_LEFT_TOP);
        panel.add(amazonDetails, GAPLEFT + detailIndent + ", " + ALIGN_LEFT_TOP);

        panel.add(elasticSearchDestinationRadio, GAPLEFT + nestedIndent + ", " + ALIGN_LEFT_TOP);
        panel.add(elasticDetails, GAPLEFT + detailIndent + ", " + ALIGN_LEFT_TOP);

        JPanel testConnectionSlot = buildTestConnectionSlot("os.destination.testSlot");
        testConnectionSlot.add(testConnectionButton, ALIGN_LEFT_TOP);
        panel.add(testConnectionSlot, GAPLEFT + nestedIndent + ", " + ALIGN_LEFT_TOP);

        statusConfigurer.accept(databaseStatus);
        StatusViews.configureWrapper(statusWrapper, databaseStatus);
        panel.add(statusWrapper, GAPLEFT + nestedIndent + ", hidemode 3, alignx left, w pref!, wrap");

        boolean[] openSearchHttpsDetected = { isHttpsEndpoint(openSearchUrlField) };
        boolean[] amazonHttpsDetected = { isHttpsEndpoint(openSearchAmazonUrlField) };
        boolean[] elasticHttpsDetected = { isHttpsEndpoint(elasticSearchUrlField) };

        Runnable syncDatabaseRowDetails = () -> {
            boolean databaseSelected = databaseSinkCheckbox.isSelected();
            boolean openSearchSelected = databaseSelected && openSearchSinkCheckbox.isSelected();
            boolean amazonSelected = databaseSelected && openSearchAmazonDestinationRadio.isSelected();
            boolean elasticSearchSelected = databaseSelected && elasticSearchDestinationRadio.isSelected();
            boolean openSearchTlsVisible = openSearchSelected && openSearchHttpsDetected[0];
            boolean amazonTlsVisible = amazonSelected && amazonHttpsDetected[0];
            boolean elasticSearchTlsVisible = elasticSearchSelected && elasticHttpsDetected[0];
            boolean anyDestination = openSearchSelected || amazonSelected || elasticSearchSelected;

            openSearchDetails.setVisible(openSearchSelected);
            openSearchUrlField.setVisible(openSearchSelected);
            openSearchAuthFormPanel.setVisible(openSearchSelected);
            openSearchTlsPanel.setVisible(openSearchTlsVisible);

            amazonDetails.setVisible(amazonSelected);
            openSearchAmazonUrlField.setVisible(amazonSelected);
            openSearchAmazonOptionsPanel.setVisible(amazonSelected);
            openSearchAmazonTlsPanel.setVisible(amazonTlsVisible);

            elasticDetails.setVisible(elasticSearchSelected);
            elasticSearchUrlField.setVisible(elasticSearchSelected);
            elasticSearchOptionsPanel.setVisible(elasticSearchSelected);
            elasticSearchTlsPanel.setVisible(elasticSearchTlsVisible);

            testConnectionSlot.setVisible(databaseSelected && anyDestination);
            testConnectionButton.setVisible(databaseSelected && anyDestination);

            panel.revalidate();
            panel.repaint();
        };
        databaseSinkCheckbox.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        openSearchSinkCheckbox.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        openSearchAmazonDestinationRadio.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        elasticSearchDestinationRadio.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        installHttpsDetector(openSearchUrlField, openSearchHttpsDetected, syncDatabaseRowDetails);
        installHttpsDetector(openSearchAmazonUrlField, amazonHttpsDetected, syncDatabaseRowDetails);
        installHttpsDetector(elasticSearchUrlField, elasticHttpsDetected, syncDatabaseRowDetails);
        syncDatabaseRowDetails.run();

        return panel;
    }

    private JPanel buildFilesDetailsPanel() {
        JPanel details = new JPanel(new MigLayout(
                "insets 0, wrap 2, hidemode 3, gapy " + rowGap, FIELD_COLS, "[]"));
        details.setOpaque(false);

        String pathTip = Tooltips.htmlRaw(
                "<b>Path</b>",
                "Root directory for file export when Files is enabled.");
        JLabel pathLabel = Tooltips.label("Path:", pathTip);
        pathLabel.setName("files.path.label");
        Tooltips.apply(filePathField, pathTip);

        JLabel formatsLabel = Tooltips.label("Format:",
                Tooltips.htmlRaw(
                        "<b>Format</b>",
                        "Select the on-disk export format used when Files is enabled.",
                        "Only <b>NDJSON</b> can be imported directly into OpenSearch later.",
                        "<b>JSONL</b> writes one document per line for local analysis.",
                        "<b>NDJSON</b> writes bulk action + document pairs for later <code>_bulk</code> re-import."));
        formatsLabel.setName("files.format.label");
        JPanel formatChoices = new JPanel(new MigLayout("insets 0", "[pref][pref]", "[]"));
        formatChoices.setOpaque(false);
        formatChoices.setName("files.format.choices");
        formatChoices.add(fileJsonlCheckbox, ALIGN_LEFT_TOP);
        formatChoices.add(fileBulkNdjsonCheckbox, ALIGN_LEFT_TOP);

        JLabel safetyLabel = Tooltips.label("Disk Usage Limits:",
                Tooltips.htmlRaw(
                        "<b>Disk Usage Limits</b>",
                        "Optional safety stops for file export under the selected root.",
                        "Use a combined GiB cap and/or a volume used-percent threshold to stop file writes before the destination grows too large.",
                        "These limits do not replace the built-in low-disk free-space reserve.",
                        "When Database remains enabled, database export can continue after file export stops."));
        safetyLabel.setName("files.limits.label");

        details.add(pathLabel, ALIGN_LEFT_TOP);
        details.add(filePathField, ALIGN_LEFT_TOP);
        details.add(formatsLabel, ALIGN_LEFT_TOP);
        details.add(formatChoices, ALIGN_LEFT_TOP);
        details.add(safetyLabel, ALIGN_LEFT_TOP);
        details.add(fileLimitsPanel, ALIGN_LEFT_TOP);
        return details;
    }

    private static JPanel buildDestinationDetails(
            String name,
            JTextField urlField,
            String baseUrlLabelName,
            JPanel authPanel,
            JPanel tlsPanel) {
        JPanel details = new JPanel(new MigLayout(
                "insets 0, wrap 2, hidemode 3, gapy 6", FIELD_COLS, "[]"));
        details.setName(name);
        details.setOpaque(false);

        String baseUrlTip = Tooltips.htmlRaw(
                "<b>Base URL</b>",
                "HTTPS or HTTP base URL for the selected database destination.");
        JLabel baseUrlLabel = Tooltips.label("Base URL:", baseUrlTip);
        baseUrlLabel.setName(baseUrlLabelName);
        Tooltips.apply(urlField, baseUrlTip);

        details.add(baseUrlLabel, ALIGN_LEFT_TOP);
        details.add(urlField, ALIGN_LEFT_TOP);
        details.add(authPanel, "span 2, " + ALIGN_LEFT_TOP);
        details.add(tlsPanel, "span 2, " + ALIGN_LEFT_TOP);
        return details;
    }

    private static JPanel buildTestConnectionSlot(String name) {
        JPanel panel = new JPanel(new MigLayout("insets 0", "[pref]", "[]"));
        panel.setName(name);
        panel.setOpaque(false);
        return panel;
    }

    private static void installHttpsDetector(JTextField field, boolean[] detected, Runnable onDetectionChanged) {
        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                boolean https = isHttpsEndpoint(field);
                if (detected[0] != https) {
                    detected[0] = https;
                    onDetectionChanged.run();
                }
            }
        });
    }

    private static boolean isHttpsEndpoint(JTextField field) {
        String text = field == null ? "" : field.getText();
        return text != null && text.trim().regionMatches(true, 0, "https://", 0, "https://".length());
    }

    private static void setEnabledRecursively(Component component, boolean enabled) {
        component.setEnabled(enabled);
        if (component instanceof java.awt.Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursively(child, enabled);
            }
        }
    }
}
