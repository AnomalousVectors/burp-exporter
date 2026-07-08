package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Dimension;
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
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import ai.anomalousvectors.tools.burp.ui.primitives.StatusViews;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import net.miginfocom.swing.MigLayout;

/**
 * Builds the "Destinations" section panel used by ConfigPanel.
 *
 * <p>Components are owned by {@link ConfigPanel} and injected to keep a single source of state.
 * The section has one shared status box, used for OpenSearch test-connection results.</p>
 */
public final class ConfigDestinationPanel {

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
    private static final int DESTINATION_LABEL_COLUMN_WIDTH = 250;

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
     * @param fileBulkNdjsonCheckbox selects OpenSearch bulk NDJSON file output
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
        this.openSearchAmazonDestinationRadio = Objects.requireNonNull(openSearchAmazonDestinationRadio, "openSearchAmazonDestinationRadio");
        this.openSearchAmazonUrlField = Objects.requireNonNull(openSearchAmazonUrlField, "openSearchAmazonUrlField");
        this.openSearchAmazonOptionsPanel = Objects.requireNonNull(openSearchAmazonOptionsPanel, "openSearchAmazonOptionsPanel");
        this.openSearchAmazonTlsPanel = Objects.requireNonNull(openSearchAmazonTlsPanel, "openSearchAmazonTlsPanel");
        this.elasticSearchDestinationRadio = Objects.requireNonNull(elasticSearchDestinationRadio, "elasticSearchDestinationRadio");
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
     * <p>Caller must invoke on the EDT. Layout keeps all Files controls on one row and places the
     * shared destination status box beneath the search row.</p>
     *
     * @return assembled panel with destination controls and the shared status area
     */
    public JPanel build() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 1", "[grow]", "[]"+rowGap+"[]"+rowGap+"[]"+rowGap+"[]"+rowGap+"[]"));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel header = Tooltips.label("Destinations",
                Tooltips.html("Configure export destination(s)."));
        header.setFont(header.getFont().deriveFont(Font.BOLD, 18f));
        panel.add(header, "gapbottom 6, wrap");

        JPanel destinationRows = new JPanel(new MigLayout(
                "insets 0, wrap 8, hidemode 2, gapy " + rowGap,
                "[" + DESTINATION_LABEL_COLUMN_WIDTH + "!, left]20[pref]18[pref]8[pref]8[pref]22[pref]12[pref]12[pref]"));
        destinationRows.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel formatsLabel = Tooltips.label("Format:",
                Tooltips.html("Select the on-disk export format."));
        formatsLabel.setName("files.format.label");
        JLabel safetyLabel = Tooltips.label("Disk Usage Limits:",
                Tooltips.html("Configure file-export safety limits.", "These controls stop file export before the destination grows too large."));
        safetyLabel.setName("files.limits.label");
        JSeparator formatsSafetySeparator = buildInlineVerticalSeparator();
        formatsSafetySeparator.setName("files.format.separator");

        destinationRows.add(fileSinkCheckbox, GAPLEFT + indentPx + ", " + ALIGN_LEFT_TOP);
        destinationRows.add(filePathField,    ALIGN_LEFT_TOP);
        destinationRows.add(formatsLabel, ALIGN_LEFT_TOP);
        destinationRows.add(fileJsonlCheckbox, ALIGN_LEFT_TOP);
        destinationRows.add(fileBulkNdjsonCheckbox, "gapright 6, " + ALIGN_LEFT_TOP);
        destinationRows.add(formatsSafetySeparator, "growy, h 18!, " + ALIGN_LEFT_TOP);
        destinationRows.add(safetyLabel, ALIGN_LEFT_TOP);
        destinationRows.add(fileLimitsPanel, ALIGN_LEFT_TOP);

        Runnable syncFileRowDecorations = () -> {
            boolean enabled = fileSinkCheckbox.isSelected();
            formatsLabel.setEnabled(enabled);
            formatsSafetySeparator.setEnabled(enabled);
            safetyLabel.setEnabled(enabled);
            setEnabledRecursively(fileLimitsPanel, enabled);
        };
        fileSinkCheckbox.getModel().addChangeListener(e -> syncFileRowDecorations.run());
        syncFileRowDecorations.run();

        int databaseOptionIndentPx = 72;

        // Database rows share the destination grid so every URL starts in the same column.
        destinationRows.add(databaseSinkCheckbox, GAPLEFT + indentPx + ", span 8, " + ALIGN_LEFT_TOP);

        JSeparator amazonTlsSeparator = buildInlineVerticalSeparator();
        JPanel amazonTestConnectionSlot = buildTestConnectionSlot("os.destination.amazon.testSlot");
        destinationRows.add(openSearchAmazonDestinationRadio, GAPLEFT + databaseOptionIndentPx + ", " + ALIGN_LEFT_TOP);
        destinationRows.add(openSearchAmazonUrlField, ALIGN_LEFT_TOP);
        destinationRows.add(openSearchAmazonOptionsPanel, "span 3, " + ALIGN_LEFT_TOP);
        destinationRows.add(amazonTlsSeparator, "growy, h 18!, " + ALIGN_LEFT_TOP);
        destinationRows.add(openSearchAmazonTlsPanel, ALIGN_LEFT_TOP);
        destinationRows.add(amazonTestConnectionSlot, ALIGN_LEFT_TOP);

        JSeparator elasticTlsSeparator = buildInlineVerticalSeparator();
        JPanel elasticTestConnectionSlot = buildTestConnectionSlot("os.destination.elasticsearch.testSlot");
        destinationRows.add(elasticSearchDestinationRadio, GAPLEFT + databaseOptionIndentPx + ", " + ALIGN_LEFT_TOP);
        destinationRows.add(elasticSearchUrlField, ALIGN_LEFT_TOP);
        destinationRows.add(elasticSearchOptionsPanel, "span 3, " + ALIGN_LEFT_TOP);
        destinationRows.add(elasticTlsSeparator, "growy, h 18!, " + ALIGN_LEFT_TOP);
        destinationRows.add(elasticSearchTlsPanel, ALIGN_LEFT_TOP);
        destinationRows.add(elasticTestConnectionSlot, ALIGN_LEFT_TOP);

        JSeparator tlsSeparator = buildInlineVerticalSeparator();
        JPanel openSearchTestConnectionSlot = buildTestConnectionSlot("os.destination.openSearch.testSlot");
        destinationRows.add(openSearchSinkCheckbox, GAPLEFT + databaseOptionIndentPx + ", " + ALIGN_LEFT_TOP);
        destinationRows.add(openSearchUrlField, ALIGN_LEFT_TOP);
        destinationRows.add(openSearchAuthFormPanel, "span 3, " + ALIGN_LEFT_TOP);
        destinationRows.add(tlsSeparator, "growy, h 18!, " + ALIGN_LEFT_TOP);
        destinationRows.add(openSearchTlsPanel, ALIGN_LEFT_TOP);
        destinationRows.add(openSearchTestConnectionSlot, ALIGN_LEFT_TOP);

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

            openSearchUrlField.setVisible(openSearchSelected);
            openSearchAuthFormPanel.setVisible(openSearchSelected);
            tlsSeparator.setVisible(openSearchTlsVisible);
            openSearchTlsPanel.setVisible(openSearchTlsVisible);
            openSearchTestConnectionSlot.setVisible(openSearchSelected);

            openSearchAmazonUrlField.setVisible(amazonSelected);
            openSearchAmazonOptionsPanel.setVisible(amazonSelected);
            amazonTlsSeparator.setVisible(amazonTlsVisible);
            openSearchAmazonTlsPanel.setVisible(amazonTlsVisible);
            amazonTestConnectionSlot.setVisible(amazonSelected);

            elasticSearchUrlField.setVisible(elasticSearchSelected);
            elasticSearchOptionsPanel.setVisible(elasticSearchSelected);
            elasticTlsSeparator.setVisible(elasticSearchTlsVisible);
            elasticSearchTlsPanel.setVisible(elasticSearchTlsVisible);
            elasticTestConnectionSlot.setVisible(elasticSearchSelected);

            if (openSearchSelected) {
                moveTestConnectionButton(openSearchTestConnectionSlot);
            } else if (amazonSelected) {
                moveTestConnectionButton(amazonTestConnectionSlot);
            } else if (elasticSearchSelected) {
                moveTestConnectionButton(elasticTestConnectionSlot);
            }
            testConnectionButton.setVisible(openSearchSelected || amazonSelected || elasticSearchSelected);

            destinationRows.revalidate();
            destinationRows.repaint();
        };
        databaseSinkCheckbox.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        openSearchSinkCheckbox.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        openSearchAmazonDestinationRadio.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        elasticSearchDestinationRadio.getModel().addChangeListener(e -> syncDatabaseRowDetails.run());
        installHttpsDetector(openSearchUrlField, openSearchHttpsDetected, syncDatabaseRowDetails);
        installHttpsDetector(openSearchAmazonUrlField, amazonHttpsDetected, syncDatabaseRowDetails);
        installHttpsDetector(elasticSearchUrlField, elasticHttpsDetected, syncDatabaseRowDetails);
        syncDatabaseRowDetails.run();

        panel.add(destinationRows, "growx, wrap");

        // Search status (below the row), left-aligned with checkboxes
        statusConfigurer.accept(databaseStatus);
        StatusViews.configureWrapper(statusWrapper, databaseStatus);
        panel.add(statusWrapper, "gapleft " + indentPx + ", hidemode 3, alignx left, w pref!, wrap");

        return panel;
    }

    private static JSeparator buildInlineVerticalSeparator() {
        JSeparator separator = new JSeparator(SwingConstants.VERTICAL);
        separator.setPreferredSize(new Dimension(8, 18));
        separator.setMinimumSize(new Dimension(8, 18));
        return separator;
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

    private void moveTestConnectionButton(JPanel target) {
        if (testConnectionButton.getParent() == target) {
            return;
        }
        if (testConnectionButton.getParent() != null) {
            testConnectionButton.getParent().remove(testConnectionButton);
        }
        target.add(testConnectionButton, ALIGN_LEFT_TOP);
        target.revalidate();
        target.repaint();
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
