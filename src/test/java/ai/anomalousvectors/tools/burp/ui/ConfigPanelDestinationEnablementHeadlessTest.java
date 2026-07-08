package ai.anomalousvectors.tools.burp.ui;

import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JComponent;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.call;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getComboBox;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStatic;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

/**
 * Verifies that toggling destination checkboxes enables/disables the corresponding
 * text fields and action buttons.
 */
class ConfigPanelDestinationEnablementHeadlessTest {

    private final ConfigPanel panel = createPanel();

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

    @Test
    void deselecting_destinations_disables_textfields_and_action_buttons() {
        // Files row (access private fields directly via shared Reflect helper).
        JCheckBox filesEnable = JCheckBox.class.cast(get(panel, "fileSinkCheckbox"));
        JRadioButton jsonlEnable = JRadioButton.class.cast(get(panel, "fileJsonlCheckbox"));
        JRadioButton bulkNdjsonEnable = JRadioButton.class.cast(get(panel, "fileBulkNdjsonCheckbox"));
        JTextField filesPath = JTextField.class.cast(get(panel, "filePathField"));
        JCheckBox totalEnable = JCheckBox.class.cast(get(panel, "fileTotalCapCheckbox"));
        JTextField totalField = JTextField.class.cast(get(panel, "fileTotalCapField"));
        JCheckBox diskPercentEnable = JCheckBox.class.cast(get(panel, "fileDiskUsagePercentCheckbox"));
        JTextField diskPercentField = JTextField.class.cast(get(panel, "fileDiskUsagePercentField"));
        JComponent formatsLabel = findByName(panel, "files.format.label");
        JComponent limitsLabel = findByName(panel, "files.limits.label");
        JComponent formatsSeparator = findByName(panel, "files.format.separator");

        // OpenSearch row
        JCheckBox databaseEnable = JCheckBox.class.cast(get(panel, "databaseSinkCheckbox"));
        JRadioButton osDestination = JRadioButton.class.cast(get(panel, "openSearchSinkCheckbox"));
        JRadioButton awsDestination = JRadioButton.class.cast(get(panel, "openSearchAmazonDestinationRadio"));
        JRadioButton elasticDestination = JRadioButton.class.cast(get(panel, "elasticSearchDestinationRadio"));
        JTextField osUrl = JTextField.class.cast(get(panel, "openSearchUrlField"));
        JTextField awsUrl = JTextField.class.cast(get(panel, "openSearchAmazonUrlField"));
        JTextField elasticUrl = JTextField.class.cast(get(panel, "elasticSearchUrlField"));
        JComboBox<?> osAuthType = getComboBox(panel, "openSearchAuthTypeCombo");
        JComboBox<?> awsAuthType = getComboBox(panel, "openSearchAmazonAuthTypeCombo");
        JComboBox<?> elasticAuthType = getComboBox(panel, "elasticSearchAuthTypeCombo");
        JComboBox<?> osTlsMode = getComboBox(panel, "openSearchTlsModeCombo");
        JComboBox<?> awsTlsMode = getComboBox(panel, "openSearchAmazonTlsModeCombo");
        JComboBox<?> elasticTlsMode = getComboBox(panel, "elasticSearchTlsModeCombo");
        JButton osTest = JButton.class.cast(get(panel, "testConnectionButton"));

        // Ensure both destinations are enabled
        if (!filesEnable.isSelected()) filesEnable.doClick();
        if (!bulkNdjsonEnable.isSelected()) bulkNdjsonEnable.doClick();
        if (!databaseEnable.isSelected()) databaseEnable.doClick();
        if (!osDestination.isSelected()) osDestination.doClick();

        // Enabled assertions
        assertThat(filesPath.isEnabled()).isTrue();
        assertThat(jsonlEnable.isEnabled()).isTrue();
        assertThat(bulkNdjsonEnable.isEnabled()).isTrue();
        assertThat(totalEnable.isEnabled()).isTrue();
        assertThat(totalField.isEnabled()).isTrue();
        assertThat(diskPercentEnable.isEnabled()).isTrue();
        assertThat(diskPercentField.isEnabled()).isTrue();
        assertThat(formatsLabel.isEnabled()).isTrue();
        assertThat(limitsLabel.isEnabled()).isTrue();
        assertThat(formatsSeparator.isEnabled()).isTrue();
        assertThat(databaseEnable.isEnabled()).isTrue();
        assertThat(osDestination.isEnabled()).isTrue();
        assertThat(awsDestination.isEnabled()).isTrue();
        assertThat(elasticDestination.isEnabled()).isTrue();
        assertThat(osUrl.isEnabled()).isTrue();
        assertThat(awsUrl.isEnabled()).isFalse();
        assertThat(elasticUrl.isEnabled()).isFalse();
        assertThat(osAuthType.isEnabled()).isTrue();
        assertThat(awsAuthType.isEnabled()).isFalse();
        assertThat(elasticAuthType.isEnabled()).isFalse();
        assertThat(osTlsMode.isEnabled()).isTrue();
        assertThat(awsTlsMode.isEnabled()).isFalse();
        assertThat(elasticTlsMode.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isTrue();

        // Disable Files; search destinations remain mutually exclusive radios.
        if (filesEnable.isSelected()) filesEnable.doClick();

        // Disabled assertions
        assertThat(filesPath.isEnabled()).isFalse();
        assertThat(jsonlEnable.isEnabled()).isFalse();
        assertThat(bulkNdjsonEnable.isEnabled()).isFalse();
        assertThat(totalEnable.isEnabled()).isFalse();
        assertThat(totalField.isEnabled()).isFalse();
        assertThat(diskPercentEnable.isEnabled()).isFalse();
        assertThat(diskPercentField.isEnabled()).isFalse();
        assertThat(formatsLabel.isEnabled()).isFalse();
        assertThat(limitsLabel.isEnabled()).isFalse();
        assertThat(formatsSeparator.isEnabled()).isFalse();
        assertThat(databaseEnable.isEnabled()).isTrue();
        assertThat(osDestination.isEnabled()).isTrue();
        assertThat(awsDestination.isEnabled()).isTrue();
        assertThat(elasticDestination.isEnabled()).isTrue();
        assertThat(osUrl.isEnabled()).isTrue();
        assertThat(awsUrl.isEnabled()).isFalse();
        assertThat(elasticUrl.isEnabled()).isFalse();
        assertThat(osAuthType.isEnabled()).isTrue();
        assertThat(awsAuthType.isEnabled()).isFalse();
        assertThat(elasticAuthType.isEnabled()).isFalse();
        assertThat(osTlsMode.isEnabled()).isTrue();
        assertThat(awsTlsMode.isEnabled()).isFalse();
        assertThat(elasticTlsMode.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isTrue();

        if (databaseEnable.isSelected()) databaseEnable.doClick();
        assertThat(osDestination.isEnabled()).isFalse();
        assertThat(awsDestination.isEnabled()).isFalse();
        assertThat(elasticDestination.isEnabled()).isFalse();
        assertThat(osUrl.isEnabled()).isFalse();
        assertThat(osAuthType.isEnabled()).isFalse();
        assertThat(osTlsMode.isEnabled()).isFalse();
        assertThat(awsTlsMode.isEnabled()).isFalse();
        assertThat(elasticTlsMode.isEnabled()).isFalse();
        assertThat(osTest.isEnabled()).isFalse();
    }

    @Test
    void search_destination_radios_default_to_opensearch_and_enable_one_row_at_a_time() {
        JRadioButton openSearch = JRadioButton.class.cast(get(panel, "openSearchSinkCheckbox"));
        JCheckBox database = JCheckBox.class.cast(get(panel, "databaseSinkCheckbox"));
        JRadioButton aws = JRadioButton.class.cast(get(panel, "openSearchAmazonDestinationRadio"));
        JRadioButton elastic = JRadioButton.class.cast(get(panel, "elasticSearchDestinationRadio"));
        JTextField url = JTextField.class.cast(get(panel, "openSearchUrlField"));
        JTextField awsUrl = JTextField.class.cast(get(panel, "openSearchAmazonUrlField"));
        JTextField elasticUrl = JTextField.class.cast(get(panel, "elasticSearchUrlField"));
        JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
        JComboBox<?> awsAuthType = getComboBox(panel, "openSearchAmazonAuthTypeCombo");
        JComboBox<?> elasticAuthType = getComboBox(panel, "elasticSearchAuthTypeCombo");
        JComboBox<?> awsTlsMode = getComboBox(panel, "openSearchAmazonTlsModeCombo");
        JComboBox<?> elasticTlsMode = getComboBox(panel, "elasticSearchTlsModeCombo");
        JButton testConnection = JButton.class.cast(get(panel, "testConnectionButton"));

        assertThat(database.isSelected()).isTrue();
        assertThat(openSearch.isSelected()).isTrue();
        assertThat(testConnection.getParent().getName()).isEqualTo("os.destination.openSearch.testSlot");
        assertThat(url.getText()).isEqualTo("https://opensearch.url:9200");
        assertThat(awsUrl.getText()).isEqualTo("https://opensearch.url:9200");
        assertThat(elasticUrl.getText()).isEqualTo("https://elasticsearch.url:443");
        assertThat(comboItems(authType)).containsExactly("API key", "Bearer token", "Certificate", "Basic", "None");
        assertThat(testConnection.isEnabled()).isTrue();

        elastic.doClick();
        assertThat(openSearch.isSelected()).isFalse();
        assertThat(aws.isSelected()).isFalse();
        assertThat(elastic.isSelected()).isTrue();
        assertThat(url.isEnabled()).isFalse();
        assertThat(elasticUrl.isEnabled()).isTrue();
        assertThat(comboItems(elasticAuthType)).containsExactly("API key", "Bearer token", "Certificate", "Basic", "None");
        assertThat(elasticTlsMode.isEnabled()).isTrue();
        assertThat(awsTlsMode.isEnabled()).isFalse();
        assertThat(testConnection.getParent().getName()).isEqualTo("os.destination.elasticsearch.testSlot");
        assertThat(testConnection.isEnabled()).isTrue();

        aws.doClick();
        assertThat(openSearch.isSelected()).isFalse();
        assertThat(aws.isSelected()).isTrue();
        assertThat(elastic.isSelected()).isFalse();
        assertThat(awsUrl.isEnabled()).isTrue();
        assertThat(elasticUrl.isEnabled()).isFalse();
        assertThat(comboItems(awsAuthType)).containsExactly("IAM (sigV4)", "Basic", "None");
        assertThat(awsTlsMode.isEnabled()).isTrue();
        assertThat(elasticTlsMode.isEnabled()).isFalse();
        assertThat(testConnection.getParent().getName()).isEqualTo("os.destination.amazon.testSlot");
        assertThat(testConnection.isEnabled()).isTrue();

        openSearch.doClick();
        assertThat(openSearch.isSelected()).isTrue();
        assertThat(url.getText()).isEqualTo("https://opensearch.url:9200");
        assertThat(testConnection.getParent().getName()).isEqualTo("os.destination.openSearch.testSlot");
        assertThat(testConnection.isEnabled()).isTrue();

        database.doClick();
        assertThat(openSearch.isSelected()).isTrue();
        assertThat(openSearch.isEnabled()).isFalse();
        assertThat(url.isEnabled()).isFalse();
        assertThat(testConnection.isEnabled()).isFalse();
    }

    @Test
    void file_format_tooltips_expand_jsonl_and_ndjson_terms() {
        JRadioButton jsonlEnable = JRadioButton.class.cast(get(panel, "fileJsonlCheckbox"));
        JRadioButton bulkNdjsonEnable = JRadioButton.class.cast(get(panel, "fileBulkNdjsonCheckbox"));

        assertThat(jsonlEnable.getText()).isEqualTo("JSONL");
        assertThat(bulkNdjsonEnable.getText()).isEqualTo("NDJSON");
        assertThat(jsonlEnable.getToolTipText()).contains("JSON Lines");
        assertThat(jsonlEnable.getToolTipText()).contains("standalone JSON object");
        assertThat(bulkNdjsonEnable.getToolTipText()).contains("Newline-Delimited JSON");
        assertThat(bulkNdjsonEnable.getToolTipText()).contains("_bulk");
        assertThat(bulkNdjsonEnable.getToolTipText()).contains("two lines");
    }

    @Test
    void file_format_radios_default_to_bulk_ndjson_and_allow_only_one_selection() {
        JCheckBox filesEnable = JCheckBox.class.cast(get(panel, "fileSinkCheckbox"));
        JRadioButton jsonlEnable = JRadioButton.class.cast(get(panel, "fileJsonlCheckbox"));
        JRadioButton bulkNdjsonEnable = JRadioButton.class.cast(get(panel, "fileBulkNdjsonCheckbox"));

        if (!filesEnable.isSelected()) {
            filesEnable.doClick();
        }

        assertThat(jsonlEnable.isSelected()).isFalse();
        assertThat(bulkNdjsonEnable.isSelected()).isTrue();

        jsonlEnable.doClick();
        assertThat(jsonlEnable.isSelected()).isTrue();
        assertThat(bulkNdjsonEnable.isSelected()).isFalse();

        bulkNdjsonEnable.doClick();
        assertThat(jsonlEnable.isSelected()).isFalse();
        assertThat(bulkNdjsonEnable.isSelected()).isTrue();
    }

    @Test
    void file_total_cap_field_accepts_decimal_gib_and_round_trips_cleanly() throws Exception {
        JTextField totalField = JTextField.class.cast(get(panel, "fileTotalCapField"));

        SwingUtilities.invokeAndWait(() -> {
            totalField.setText("1.25");
        });

        ConfigState.State current = (ConfigState.State) call(panel, "buildCurrentState");
        assertThat(current.sinks().fileTotalCapBytes()).isEqualTo(1_342_177_280L);

        ConfigState.State imported = new ConfigState.State(
                java.util.List.of(),
                ConfigKeys.SCOPE_ALL,
                java.util.List.of(),
                new ConfigState.Sinks(true, "/path/to/directory", false, true,
                        true, ConfigState.bytesToGb(1_342_177_280L),
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false, "", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );

        SwingUtilities.invokeAndWait(() -> panel.onImportResult(imported));

        assertThat(totalField.getText()).isEqualTo("1.25");
    }

    @Test
    void per_index_cap_controls_are_not_present() {
        assertThat(findByName(panel, "files.limit.perIndex.enable")).isNull();
        assertThat(findByName(panel, "files.limit.perIndex.gib")).isNull();
    }

    @Test
    void tls_mode_combo_binds_enter_to_test_connection_action() throws Exception {
        String actionKey = String.class.cast(getStatic(ConfigPanel.class, "TLS_MODE_ENTER_TEST_CONNECTION"));
        SwingUtilities.invokeAndWait(() -> {
            JComboBox<?> tlsMode = getComboBox(panel, "openSearchTlsModeCombo");
            Object mapped = tlsMode.getInputMap(JComponent.WHEN_FOCUSED)
                    .get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0));
            assertThat(mapped).isEqualTo(actionKey);
            assertThat(tlsMode.getActionMap().get(actionKey)).isNotNull();
        });
    }

    @Test
    void pinned_tls_mode_shows_import_button_only_when_selected() {
        JComboBox<?> tlsMode = getComboBox(panel, "openSearchTlsModeCombo");
        JButton importButton = JButton.class.cast(get(panel, "importPinnedCertificateButton"));

        assertThat(importButton.isVisible()).isFalse();

        tlsMode.setSelectedItem("Trust pinned certificate");
        assertThat(importButton.isVisible()).isTrue();

        tlsMode.setSelectedItem("Verify");
        assertThat(importButton.isVisible()).isFalse();
    }

    @Test
    void destination_pinned_tls_modes_show_destination_import_buttons() {
        JComboBox<?> amazonTlsMode = getComboBox(panel, "openSearchAmazonTlsModeCombo");
        JComboBox<?> elasticTlsMode = getComboBox(panel, "elasticSearchTlsModeCombo");
        JComponent amazonImportButton = findByName(panel, "os.amazon.tls.import");
        JComponent elasticImportButton = findByName(panel, "os.elasticsearch.tls.import");

        assertThat(amazonImportButton).isNotNull();
        assertThat(elasticImportButton).isNotNull();
        assertThat(amazonImportButton.isVisible()).isFalse();
        assertThat(elasticImportButton.isVisible()).isFalse();

        amazonTlsMode.setSelectedItem("Trust pinned certificate");
        elasticTlsMode.setSelectedItem("Trust pinned certificate");
        assertThat(amazonImportButton.isVisible()).isTrue();
        assertThat(elasticImportButton.isVisible()).isTrue();

        amazonTlsMode.setSelectedItem("Verify");
        elasticTlsMode.setSelectedItem("Verify");
        assertThat(amazonImportButton.isVisible()).isFalse();
        assertThat(elasticImportButton.isVisible()).isFalse();
    }

    @Test
    void amazon_and_elasticsearch_auth_panels_show_only_selected_auth_card() {
        JComboBox<?> amazonAuthType = getComboBox(panel, "openSearchAmazonAuthTypeCombo");
        JComboBox<?> elasticAuthType = getComboBox(panel, "elasticSearchAuthTypeCombo");
        JComponent amazonIam = findByName(panel, "os.amazon.authCard.iam");
        JComponent amazonBasic = findByName(panel, "os.amazon.authCard.basic");
        JComponent amazonNone = findByName(panel, "os.amazon.authCard.none");
        JComponent elasticApiKey = findByName(panel, "os.elasticsearch.authCard.apikey");
        JComponent elasticBearer = findByName(panel, "os.elasticsearch.authCard.bearer");
        JComponent elasticCertificate = findByName(panel, "os.elasticsearch.authCard.certificate");
        JComponent elasticBasic = findByName(panel, "os.elasticsearch.authCard.basic");
        JComponent elasticNone = findByName(panel, "os.elasticsearch.authCard.none");

        amazonAuthType.setSelectedItem("IAM (sigV4)");
        assertThat(amazonIam.isVisible()).isTrue();
        assertThat(amazonBasic.isVisible()).isFalse();
        assertThat(amazonNone.isVisible()).isFalse();

        amazonAuthType.setSelectedItem("Basic");
        assertThat(amazonIam.isVisible()).isFalse();
        assertThat(amazonBasic.isVisible()).isTrue();
        assertThat(amazonNone.isVisible()).isFalse();

        amazonAuthType.setSelectedItem("None");
        assertThat(amazonIam.isVisible()).isFalse();
        assertThat(amazonBasic.isVisible()).isFalse();
        assertThat(amazonNone.isVisible()).isTrue();

        elasticAuthType.setSelectedItem("API key");
        assertThat(elasticApiKey.isVisible()).isTrue();
        assertThat(elasticBearer.isVisible()).isFalse();
        assertThat(elasticCertificate.isVisible()).isFalse();
        assertThat(elasticBasic.isVisible()).isFalse();
        assertThat(elasticNone.isVisible()).isFalse();

        elasticAuthType.setSelectedItem("Bearer token");
        assertThat(elasticApiKey.isVisible()).isFalse();
        assertThat(elasticBearer.isVisible()).isTrue();
        assertThat(elasticCertificate.isVisible()).isFalse();
        assertThat(elasticBasic.isVisible()).isFalse();
        assertThat(elasticNone.isVisible()).isFalse();

        elasticAuthType.setSelectedItem("Certificate");
        assertThat(elasticApiKey.isVisible()).isFalse();
        assertThat(elasticBearer.isVisible()).isFalse();
        assertThat(elasticCertificate.isVisible()).isTrue();
        assertThat(elasticBasic.isVisible()).isFalse();
        assertThat(elasticNone.isVisible()).isFalse();

        elasticAuthType.setSelectedItem("Basic");
        assertThat(elasticApiKey.isVisible()).isFalse();
        assertThat(elasticBearer.isVisible()).isFalse();
        assertThat(elasticCertificate.isVisible()).isFalse();
        assertThat(elasticBasic.isVisible()).isTrue();
        assertThat(elasticNone.isVisible()).isFalse();

        elasticAuthType.setSelectedItem("None");
        assertThat(elasticApiKey.isVisible()).isFalse();
        assertThat(elasticBearer.isVisible()).isFalse();
        assertThat(elasticCertificate.isVisible()).isFalse();
        assertThat(elasticBasic.isVisible()).isFalse();
        assertThat(elasticNone.isVisible()).isTrue();
    }

    private static JComponent findByName(JComponent root, String name) {
        String componentName = root.getName();
        if (componentName != null && componentName.equals(name)) {
            return root;
        }
        for (java.awt.Component component : root.getComponents()) {
            if (component instanceof JComponent child) {
                JComponent nested = findByName(child, name);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static List<String> comboItems(JComboBox<?> comboBox) {
        java.util.ArrayList<String> items = new java.util.ArrayList<>();
        for (int i = 0; i < comboBox.getItemCount(); i++) {
            items.add(String.valueOf(comboBox.getItemAt(i)));
        }
        return items;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {
            // File status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onDatabaseStatus(String message) {
            // Database status is not observed in this test; required by ConfigController.Ui
        }
        @Override public void onControlStatus(String message) {
            // Control status is not observed in this test; required by ConfigController.Ui
        }
    }
}
