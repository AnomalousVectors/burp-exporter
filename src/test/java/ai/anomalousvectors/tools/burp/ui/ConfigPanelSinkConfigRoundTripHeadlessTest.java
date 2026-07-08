package ai.anomalousvectors.tools.burp.ui;

import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.call;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getComboBox;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.config.ConfigJsonMapper;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

class ConfigPanelSinkConfigRoundTripHeadlessTest {

    @Test
    void export_and_import_roundTrip_preserves_nested_sink_shape_from_ui_state() throws Exception {
        withCleanSession(() -> {
            ConfigPanel original = newPanelOnEdt();

            JCheckBox fileSinkCheckbox = JCheckBox.class.cast(get(original, "fileSinkCheckbox"));
            JTextField filePathField = JTextField.class.cast(get(original, "filePathField"));
            JRadioButton fileJsonlCheckbox = JRadioButton.class.cast(get(original, "fileJsonlCheckbox"));
            JCheckBox fileTotalCapCheckbox = JCheckBox.class.cast(get(original, "fileTotalCapCheckbox"));
            JTextField fileTotalCapField = JTextField.class.cast(get(original, "fileTotalCapField"));
            JCheckBox fileDiskUsagePercentCheckbox = JCheckBox.class.cast(get(original, "fileDiskUsagePercentCheckbox"));
            JTextField fileDiskUsagePercentField = JTextField.class.cast(get(original, "fileDiskUsagePercentField"));
            javax.swing.AbstractButton openSearchSinkCheckbox = javax.swing.AbstractButton.class.cast(get(original, "openSearchSinkCheckbox"));
            JTextField openSearchUrlField = JTextField.class.cast(get(original, "openSearchUrlField"));
            JComboBox<?> openSearchAuthTypeCombo = getComboBox(original, "openSearchAuthTypeCombo");
            JTextField openSearchUserField = JTextField.class.cast(get(original, "openSearchUserField"));
            JTextField openSearchCertPathField = JTextField.class.cast(get(original, "openSearchCertPathField"));
            JTextField openSearchCertKeyPathField = JTextField.class.cast(get(original, "openSearchCertKeyPathField"));
            JComboBox<?> openSearchTlsModeCombo = getComboBox(original, "openSearchTlsModeCombo");
            JTextField openSearchAmazonUrlField = JTextField.class.cast(get(original, "openSearchAmazonUrlField"));
            JComboBox<?> openSearchAmazonAuthTypeCombo = getComboBox(original, "openSearchAmazonAuthTypeCombo");
            JComboBox<?> openSearchAmazonTlsModeCombo = getComboBox(original, "openSearchAmazonTlsModeCombo");
            JTextField openSearchAmazonUserField = JTextField.class.cast(get(original, "openSearchAmazonUserField"));
            JTextField openSearchAmazonRegionField = JTextField.class.cast(get(original, "openSearchAmazonRegionField"));
            JTextField openSearchAmazonProfileField = JTextField.class.cast(get(original, "openSearchAmazonProfileField"));
            JTextField elasticSearchUrlField = JTextField.class.cast(get(original, "elasticSearchUrlField"));
            JComboBox<?> elasticSearchAuthTypeCombo = getComboBox(original, "elasticSearchAuthTypeCombo");
            JComboBox<?> elasticSearchTlsModeCombo = getComboBox(original, "elasticSearchTlsModeCombo");
            JTextField elasticSearchUserField = JTextField.class.cast(get(original, "elasticSearchUserField"));
            JTextField elasticSearchCertPathField = JTextField.class.cast(get(original, "elasticSearchCertPathField"));
            JTextField elasticSearchCertKeyPathField = JTextField.class.cast(get(original, "elasticSearchCertKeyPathField"));

            runEdt(() -> {
                if (!fileSinkCheckbox.isSelected()) {
                    fileSinkCheckbox.doClick();
                }
                filePathField.setText("C:/Burp/ui-roundtrip");
                if (!fileJsonlCheckbox.isSelected()) {
                    fileJsonlCheckbox.doClick();
                }
                if (fileTotalCapCheckbox.isSelected()) {
                    fileTotalCapCheckbox.doClick();
                }
                fileTotalCapField.setText("12.5");
                if (!fileDiskUsagePercentCheckbox.isSelected()) {
                    fileDiskUsagePercentCheckbox.doClick();
                }
                fileDiskUsagePercentField.setText("88");

                if (!openSearchSinkCheckbox.isSelected()) {
                    openSearchSinkCheckbox.doClick();
                }
                openSearchUrlField.setText("https://opensearch.example:9200");
                openSearchUserField.setText("stale-user");
                openSearchAuthTypeCombo.setSelectedItem("Certificate");
                openSearchCertPathField.setText("certs/client.pem");
                openSearchCertKeyPathField.setText("certs/client-key.pem");
                openSearchTlsModeCombo.setSelectedItem("Trust all certificates");
                openSearchAmazonUrlField.setText("https://aws-domain.example:443");
                openSearchAmazonAuthTypeCombo.setSelectedItem("Basic");
                openSearchAmazonTlsModeCombo.setSelectedItem("Trust all certificates");
                openSearchAmazonUserField.setText("aws-user");
                openSearchAmazonRegionField.setText("us-east-1");
                openSearchAmazonProfileField.setText("burp-exporter");
                elasticSearchUrlField.setText("https://elasticsearch.example:9200");
                elasticSearchAuthTypeCombo.setSelectedItem("Certificate");
                elasticSearchTlsModeCombo.setSelectedItem("Trust all certificates");
                elasticSearchUserField.setText("elastic-user");
                elasticSearchCertPathField.setText("certs/elastic-client.pem");
                elasticSearchCertKeyPathField.setText("certs/elastic-client-key.pem");
                SecureCredentialStore.savePinnedTlsCertificate(
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                        "certs/aws-ca.pem",
                        "AA:BB:CC",
                        new byte[] { 1, 2, 3 });
                SecureCredentialStore.savePinnedTlsCertificate(
                        ConfigState.SearchDestination.ELASTICSEARCH.configKey(),
                        "certs/elastic-ca.pem",
                        "DD:EE:FF",
                        new byte[] { 4, 5, 6 });
            });

            ConfigState.State originalState = (ConfigState.State) call(original, "buildCurrentState");
            String json = ConfigJsonMapper.build(originalState);

            assertThat(json).contains("\"sinks\" : {");
            assertThat(json).contains("\"files\" : {");
            assertThat(json).contains("\"openSearch\" : {");
            assertThat(json).contains("\"formats\" : [ \"jsonl\" ]");
            assertThat(json).contains("\"tlsMode\" : \"insecure\"");
            assertThat(json).contains("\"type\" : \"Certificate\"");
            assertThat(json).contains("\"certPath\" : \"certs/client.pem\"");
            assertThat(json).contains("\"certKeyPath\" : \"certs/client-key.pem\"");
            assertThat(json).contains("\"openSearchAmazon\" : {");
            assertThat(json).contains("\"url\" : \"https://aws-domain.example:443\"");
            assertThat(json).contains("\"region\" : \"us-east-1\"");
            assertThat(json).contains("\"profile\" : \"burp-exporter\"");
            assertThat(json).contains("\"username\" : \"aws-user\"");
            assertThat(json).contains("\"sourcePath\" : \"certs/aws-ca.pem\"");
            assertThat(json).contains("\"fingerprintSha256\" : \"AA:BB:CC\"");
            assertThat(json).contains("\"elasticsearch\" : {");
            assertThat(json).contains("\"url\" : \"https://elasticsearch.example:9200\"");
            assertThat(json).contains("\"certPath\" : \"certs/elastic-client.pem\"");
            assertThat(json).contains("\"certKeyPath\" : \"certs/elastic-client-key.pem\"");
            assertThat(json).contains("\"sourcePath\" : \"certs/elastic-ca.pem\"");
            assertThat(json).contains("\"fingerprintSha256\" : \"DD:EE:FF\"");
            assertThat(json).doesNotContain("\"filesEnabled\"");
            assertThat(json).doesNotContain("\"openSearchEnabled\"");
            assertThat(json).doesNotContain("\"username\" : \"stale-user\"");

            ConfigState.State imported = ConfigJsonMapper.parseState(json);

            SecureCredentialStore.clearAll();
            RuntimeConfig.updateState(null);

            ConfigPanel restored = newPanelOnEdt();
            runEdt(() -> restored.onImportResult(imported));
            SecureCredentialStore.PinnedTlsCertificate restoredAmazonPin =
                    SecureCredentialStore.loadPinnedTlsCertificate(
                            ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
            SecureCredentialStore.PinnedTlsCertificate restoredElasticPin =
                    SecureCredentialStore.loadPinnedTlsCertificate(
                            ConfigState.SearchDestination.ELASTICSEARCH.configKey());

            JTextField restoredFilePathField = JTextField.class.cast(get(restored, "filePathField"));
            JComboBox<?> restoredAuthTypeCombo = getComboBox(restored, "openSearchAuthTypeCombo");
            JTextField restoredOpenSearchUserField = JTextField.class.cast(get(restored, "openSearchUserField"));
            JTextField restoredCertPathField = JTextField.class.cast(get(restored, "openSearchCertPathField"));
            JTextField restoredCertKeyPathField = JTextField.class.cast(get(restored, "openSearchCertKeyPathField"));
            JComboBox<?> restoredTlsModeCombo = getComboBox(restored, "openSearchTlsModeCombo");
            JComboBox<?> restoredAmazonTlsModeCombo = getComboBox(restored, "openSearchAmazonTlsModeCombo");
            JComboBox<?> restoredElasticTlsModeCombo = getComboBox(restored, "elasticSearchTlsModeCombo");
            JTextField restoredAwsRegionField = JTextField.class.cast(get(restored, "openSearchAmazonRegionField"));
            JTextField restoredAwsProfileField = JTextField.class.cast(get(restored, "openSearchAmazonProfileField"));
            JTextField restoredElasticCertPathField = JTextField.class.cast(get(restored, "elasticSearchCertPathField"));
            JTextField restoredElasticCertKeyPathField = JTextField.class.cast(get(restored, "elasticSearchCertKeyPathField"));

            runEdt(() -> {
                assertThat(restoredFilePathField.getText()).isEqualTo("C:/Burp/ui-roundtrip");
                assertThat(String.valueOf(restoredAuthTypeCombo.getSelectedItem())).isEqualTo("Certificate");
                assertThat(restoredOpenSearchUserField.getText()).isEmpty();
                assertThat(restoredCertPathField.getText()).isEqualTo("certs/client.pem");
                assertThat(restoredCertKeyPathField.getText()).isEqualTo("certs/client-key.pem");
                assertThat(String.valueOf(restoredTlsModeCombo.getSelectedItem())).isEqualTo("Trust all certificates");
                assertThat(String.valueOf(restoredAmazonTlsModeCombo.getSelectedItem())).isEqualTo("Trust all certificates");
                assertThat(String.valueOf(restoredElasticTlsModeCombo.getSelectedItem())).isEqualTo("Trust all certificates");
                assertThat(restoredAwsRegionField.getText()).isEqualTo("us-east-1");
                assertThat(restoredAwsProfileField.getText()).isEqualTo("burp-exporter");
                assertThat(restoredAmazonPin.sourcePath()).isEqualTo("certs/aws-ca.pem");
                assertThat(restoredAmazonPin.fingerprintSha256()).isEqualTo("AA:BB:CC");
                assertThat(restoredElasticCertPathField.getText()).isEqualTo("certs/elastic-client.pem");
                assertThat(restoredElasticCertKeyPathField.getText()).isEqualTo("certs/elastic-client-key.pem");
                assertThat(restoredElasticPin.sourcePath()).isEqualTo("certs/elastic-ca.pem");
                assertThat(restoredElasticPin.fingerprintSha256()).isEqualTo("DD:EE:FF");
            });

            ConfigState.State restoredState = (ConfigState.State) call(restored, "buildCurrentState");
            assertThat(restoredState.sinks().filesEnabled()).isTrue();
            assertThat(restoredState.sinks().filesPath()).isEqualTo("C:/Burp/ui-roundtrip");
            assertThat(restoredState.sinks().fileJsonlEnabled()).isTrue();
            assertThat(restoredState.sinks().fileBulkNdjsonEnabled()).isFalse();
            assertThat(restoredState.sinks().fileTotalCapEnabled()).isFalse();
            assertThat(restoredState.sinks().fileTotalCapGb()).isEqualTo(12.5d);
            assertThat(restoredState.sinks().fileDiskUsagePercentEnabled()).isTrue();
            assertThat(restoredState.sinks().fileDiskUsagePercent()).isEqualTo(88);
            assertThat(restoredState.sinks().osEnabled()).isTrue();
            assertThat(restoredState.sinks().openSearchUrl()).isEqualTo("https://opensearch.example:9200");
            assertThat(restoredState.sinks().openSearchUser()).isBlank();
            assertThat(restoredState.sinks().openSearchTlsMode()).isEqualTo(ConfigState.OPEN_SEARCH_TLS_INSECURE);
            assertThat(restoredState.sinks().openSearchOptions().authType()).isEqualTo("Certificate");
            assertThat(restoredState.sinks().openSearchOptions().certPath()).isEqualTo("certs/client.pem");
            assertThat(restoredState.sinks().openSearchOptions().certKeyPath()).isEqualTo("certs/client-key.pem");
            assertThat(restoredState.sinks().openSearchAmazonOptions().username()).isEqualTo("aws-user");
            assertThat(restoredState.sinks().openSearchAmazonOptions().region()).isEqualTo("us-east-1");
            assertThat(restoredState.sinks().openSearchAmazonOptions().profile()).isEqualTo("burp-exporter");
            assertThat(restoredState.sinks().openSearchAmazonOptions().tlsMode()).isEqualTo(ConfigState.OPEN_SEARCH_TLS_INSECURE);
            assertThat(restoredState.sinks().openSearchAmazonOptions().pinnedTlsCertificateSourcePath())
                    .isEqualTo("certs/aws-ca.pem");
            assertThat(restoredState.sinks().elasticSearchOptions().certPath()).isEqualTo("certs/elastic-client.pem");
            assertThat(restoredState.sinks().elasticSearchOptions().certKeyPath()).isEqualTo("certs/elastic-client-key.pem");
            assertThat(restoredState.sinks().elasticSearchOptions().tlsMode()).isEqualTo(ConfigState.OPEN_SEARCH_TLS_INSECURE);
            assertThat(restoredState.sinks().elasticSearchOptions().pinnedTlsCertificateSourcePath())
                    .isEqualTo("certs/elastic-ca.pem");
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel(new ConfigController(new NoopUi()));
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static void runEdt(Runnable r) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }

    private static void withCleanSession(CheckedRunnable action) throws Exception {
        SecureCredentialStore.clearAll();
        RuntimeConfig.updateState(null);
        try {
            action.run();
        } finally {
            SecureCredentialStore.clearAll();
            RuntimeConfig.updateState(null);
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) { }
        @Override public void onDatabaseStatus(String message) { }
        @Override public void onControlStatus(String message) { }
    }
}
