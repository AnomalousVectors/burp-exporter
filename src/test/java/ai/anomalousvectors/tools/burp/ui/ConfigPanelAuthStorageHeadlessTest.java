package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.FontMetrics;
import java.awt.Insets;
import java.awt.event.MouseEvent;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.call;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getComboBox;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

class ConfigPanelAuthStorageHeadlessTest {

    @Test
    void authDefaultsToBasic_andLoadsSessionBasicValues() throws Exception {
        withCleanSession(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("alice", "secret");
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));

            runEdt(() -> assertThat(authType.getSelectedItem()).isEqualTo("Basic"));
            runEdt(() -> {
                assertThat(user.getText()).isEqualTo("alice");
                assertThat(new String(pass.getPassword())).isEqualTo("secret");
            });
        });
    }

    @Test
    void defaultBasicAuth_appliesLoadedSessionCredentialsWithoutAdditionalAction() throws Exception {
        withCleanSession(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("carol", "pw123");
            newPanelOnEdt();
            assertThat(RuntimeConfig.openSearchUser()).isEqualTo("carol");
            assertThat(RuntimeConfig.openSearchPassword()).isEqualTo("pw123");
        });
    }

    @Test
    void defaultBasicAuth_showsBasicCredentialFormOnInitialLoad() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JPanel authForm = JPanel.class.cast(get(panel, "openSearchAuthFormPanel"));
            Component basicCard = findByName(authForm, "os.authCard.basic");
            Component noneCard = findByName(authForm, "os.authCard.none");
            runEdt(() -> {
                assertThat(isEffectivelyVisible(basicCard)).isTrue();
                assertThat(isEffectivelyVisible(noneCard)).isFalse();
            });
        });
    }

    @Test
    void selectingApiKeyJwtAndCertificate_showsCorrectFormAndLoadsSessionValues() throws Exception {
        withCleanSession(() -> {
            SecureCredentialStore.saveApiKeyCredentials("os_api_token_1");
            SecureCredentialStore.saveJwtCredentials("jwt-token-1");
            SecureCredentialStore.saveCertificateCredentials("cert.pem", "cert.key", "passphrase-1");

            ConfigPanel panel = newPanelOnEdt();
            JPanel authForm = JPanel.class.cast(get(panel, "openSearchAuthFormPanel"));
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");

            JPasswordField apiKeyToken = JPasswordField.class.cast(get(panel, "openSearchApiKeyTokenField"));
            JTextField jwtToken = JTextField.class.cast(get(panel, "openSearchJwtTokenField"));
            JTextField certPath = JTextField.class.cast(get(panel, "openSearchCertPathField"));
            JTextField certKeyPath = JTextField.class.cast(get(panel, "openSearchCertKeyPathField"));
            JPasswordField certPassphrase = JPasswordField.class.cast(get(panel, "openSearchCertPassphraseField"));

            Component apiKeyCard = findByName(authForm, "os.authCard.apikey");
            Component jwtCard = findByName(authForm, "os.authCard.jwt");
            Component certCard = findByName(authForm, "os.authCard.certificate");

            runEdt(() -> authType.setSelectedItem("API key"));
            runEdt(() -> {
                assertThat(isEffectivelyVisible(apiKeyCard)).isTrue();
                assertThat(new String(apiKeyToken.getPassword())).isEqualTo("os_api_token_1");
            });

            runEdt(() -> authType.setSelectedItem("Bearer token"));
            runEdt(() -> {
                assertThat(isEffectivelyVisible(jwtCard)).isTrue();
                assertThat(jwtToken.getText()).isEqualTo("jwt-token-1");
            });

            runEdt(() -> authType.setSelectedItem("Certificate"));
            runEdt(() -> {
                assertThat(isEffectivelyVisible(certCard)).isTrue();
                assertThat(certPath.getText()).isEqualTo("cert.pem");
                assertThat(certKeyPath.getText()).isEqualTo("cert.key");
                assertThat(new String(certPassphrase.getPassword())).isEqualTo("passphrase-1");
            });
        });
   }

    @Test
    void defaultBasicAuth_withEmptySessionStore_keepsVisibleFormAndClearsRuntimeCredentials() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JPanel authForm = JPanel.class.cast(get(panel, "openSearchAuthFormPanel"));
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));
            Component basicCard = findByName(authForm, "os.authCard.basic");

            runEdt(() -> {
                assertThat(isEffectivelyVisible(basicCard)).isTrue();
                assertThat(user.getText()).isEmpty();
                assertThat(new String(pass.getPassword())).isEmpty();
            });
            assertThat(RuntimeConfig.openSearchUser()).isEmpty();
            assertThat(RuntimeConfig.openSearchPassword()).isEmpty();
        });
    }

    @Test
    void tlsMode_defaultsToVerify() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> tlsMode = getComboBox(panel, "openSearchTlsModeCombo");
            runEdt(() -> assertThat(String.valueOf(tlsMode.getSelectedItem())).isEqualTo("Verify"));
        });
    }

    @Test
    void tlsMode_arrowButton_usesSameHtmlTooltipSetupAsCombo() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> tlsMode = getComboBox(panel, "openSearchTlsModeCombo");
            JButton arrowButton = findComboArrowButton(tlsMode);

            runEdt(() -> {
                assertThat(arrowButton).isNotNull();
                assertThat(arrowButton.getToolTipText()).isNull();
                assertThat(arrowButton.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
                assertThat(arrowButton.getClientProperty("ai.anomalousvectors.tools.burp.ui.text.Tooltips.tooltipForwarder"))
                        .isNotNull();
            });
        });
    }

    @Test
    void changingTlsMode_emitsLogPanelEvents() throws Exception {
        withCleanSession(() -> {
            Logger.resetState();
            List<String> events = new CopyOnWriteArrayList<>();
            Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
            Logger.registerListener(listener);
            try {
                ConfigPanel panel = newPanelOnEdt();
                JComboBox<?> tlsMode = getComboBox(panel, "openSearchTlsModeCombo");

                runEdt(() -> tlsMode.setSelectedItem("Trust pinned certificate"));
                runEdt(() -> tlsMode.setSelectedItem("Trust all certificates"));

                assertThat(events).anyMatch(message -> message.contains("OpenSearch TLS mode set to Trust pinned certificate."));
                assertThat(events).anyMatch(message -> message.contains("requires an imported pinned certificate before test/start"));
                assertThat(events).anyMatch(message -> message.contains("OpenSearch TLS mode set to Trust all certificates."));
                assertThat(events).anyMatch(message -> message.contains("trusting all certificates insecurely"));
            } finally {
                Logger.unregisterListener(listener);
                Logger.resetState();
            }
        });
    }

    @Test
    void applyPinnedCertificateImport_logsSuccessAndStoresPinnedCertificate() throws Exception {
        withCleanSession(() -> {
            Logger.resetState();
            List<String> events = new CopyOnWriteArrayList<>();
            Logger.LogListener listener = (level, message) -> events.add(level + "|" + message);
            Logger.registerListener(listener);
            Path certFile = exportAnyDefaultTrustStoreCertificate();
            try {
                ConfigPanel panel = newPanelOnEdt();
                runEdt(() -> call(panel, "applyPinnedCertificateImport",
                        ConfigState.SearchDestination.OPEN_SEARCH, certFile));

                SecureCredentialStore.PinnedTlsCertificate pinned = SecureCredentialStore.loadPinnedTlsCertificate();
                assertThat(pinned.sourcePath()).isEqualTo(certFile.toAbsolutePath().normalize().toString());
                assertThat(pinned.fingerprintSha256()).isNotBlank();
                assertThat(events).anyMatch(message -> message.contains("Importing OpenSearch pinned TLS certificate from"));
                assertThat(events).anyMatch(message -> message.contains("Imported OpenSearch pinned TLS certificate: fingerprint=")
                        && message.contains(pinned.fingerprintSha256()));
            } finally {
                Files.deleteIfExists(certFile);
                Logger.unregisterListener(listener);
                Logger.resetState();
            }
        });
    }

    @Test
    void onImportResult_applies_nonSecret_auth_settings_and_pinned_certificate_from_config() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            ConfigState.State imported = new ConfigState.State(
                    List.of(),
                    "all",
                    List.of(),
                    new ConfigState.Sinks(
                            false,
                            "",
                            false,
                            false,
                            true,
                            ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                            true,
                            ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            true,
                            "https://opensearch.url:9200",
                            "alice",
                            "",
                            ConfigState.OPEN_SEARCH_TLS_PINNED,
                            new ConfigState.OpenSearchOptions(
                                    "Certificate",
                                    "kid-1",
                                    "client-cert.pem",
                                    "client-key.pem",
                                    "c:/tls/opensearch.pem",
                                    "fingerprint-123",
                                    "ZmFrZWNlcnQ=")),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null);

            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JTextField certPath = JTextField.class.cast(get(panel, "openSearchCertPathField"));
            JTextField certKeyPath = JTextField.class.cast(get(panel, "openSearchCertKeyPathField"));
            JComboBox<?> tlsMode = getComboBox(panel, "openSearchTlsModeCombo");

            runEdt(() -> panel.onImportResult(imported));

            runEdt(() -> {
                assertThat(String.valueOf(authType.getSelectedItem())).isEqualTo("Certificate");
                assertThat(user.getText()).isEqualTo("alice");
                assertThat(certPath.getText()).isEqualTo("client-cert.pem");
                assertThat(certKeyPath.getText()).isEqualTo("client-key.pem");
                assertThat(String.valueOf(tlsMode.getSelectedItem())).isEqualTo("Trust pinned certificate");
            });

            SecureCredentialStore.PinnedTlsCertificate pinned = SecureCredentialStore.loadPinnedTlsCertificate();
            assertThat(pinned.sourcePath()).isEqualTo("c:/tls/opensearch.pem");
            assertThat(pinned.fingerprintSha256()).isEqualTo("fingerprint-123");
            assertThat(pinned.encodedBytes()).containsExactly("fakecert".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        });
    }

    @Test
    void testConnectionTooltip_explainsSessionOnlyHandling() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JButton testButton = JButton.class.cast(get(panel, "testConnectionButton"));
            JPanel authForm = JPanel.class.cast(get(panel, "openSearchAuthFormPanel"));
            runEdt(() -> {
                assertThat(testButton.getToolTipText())
                        .isEqualTo("<html>Test connectivity and authentication against the selected database destination.<br>Status output includes connection, authentication, trust, and reported version.<br>Secrets are only stored within in-process memory.</html>");
                assertThat(findByNameOrNull(authForm, "os.authenticate")).isNull();
            });
        });
    }

    @Test
    void configControl_noLongerShowsSaveButton() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            runEdt(() -> assertThat(findByNameOrNull(panel, "control.save")).isNull());
        });
    }

    @Test
    void startTooltip_describesStartingExportToConfiguredDestinations() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JButton start = (JButton) findByName(panel, "control.startStop");
            runEdt(() -> assertThat(start.getToolTipText()).isEqualTo("<html>Start exporting to the configured destination(s).</html>"));
        });
    }

    @Test
    void sourceAndDestinationTooltips_matchSpreadsheetDecisions() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JCheckBox settings = JCheckBox.class.cast(get(panel, "settingsCheckbox"));
            JCheckBox issues = JCheckBox.class.cast(get(panel, "issuesCheckbox"));
            JCheckBox traffic = JCheckBox.class.cast(get(panel, "trafficCheckbox"));
            JTextField filePathField = JTextField.class.cast(get(panel, "filePathField"));
            JTextField openSearchUrlField = JTextField.class.cast(get(panel, "openSearchUrlField"));
            JRadioButton openSearchDestination = JRadioButton.class.cast(get(panel, "openSearchSinkCheckbox"));
            JRadioButton awsDestination = JRadioButton.class.cast(get(panel, "openSearchAmazonDestinationRadio"));
            JRadioButton elasticDestination = JRadioButton.class.cast(get(panel, "elasticSearchDestinationRadio"));
            Component destinationsHeader = findLabelByText(panel, "Destinations");

            runEdt(() -> {
                assertThat(settings.getToolTipText()).isEqualTo("<html>All settings.</html>");
                assertThat(issues.getToolTipText()).isEqualTo("<html>All findings (aka issues).</html>");
                assertThat(traffic.getToolTipText()).isEqualTo("<html>All in-scope traffic.</html>");
                assertThat(Arrays.stream(traffic.getMouseListeners()).anyMatch(ToolTipManager.class::isInstance)).isTrue();
                assertThat(filePathField.getToolTipText()).isEqualTo(
                        "<html>Root directory for generated files. Examples:<br>&nbsp;&nbsp;/path/to/directory<br>&nbsp;&nbsp;c:\\path\\to\\directory</html>");
                assertThat(openSearchDestination.getToolTipText()).isEqualTo("<html>OpenSearch destination. Wired in this build.</html>");
                assertThat(awsDestination.getToolTipText()).contains("Amazon OpenSearch destination");
                assertThat(elasticDestination.getToolTipText()).contains("Elasticsearch destination");
                assertThat(openSearchUrlField.getToolTipText()).isEqualTo(
                        "<html>Base URL of the OpenSearch destination. Examples:<br>&nbsp;&nbsp;https://opensearch.url:9200<br>&nbsp;&nbsp;http://10.0.0.1:9200</html>");
                assertThat(((javax.swing.JLabel) destinationsHeader).getToolTipText())
                        .isEqualTo("<html>Configure export destination(s).</html>");
            });
        });
    }

    @Test
    void authControls_have_expected_tooltips() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));
            JPasswordField apiKeyToken = JPasswordField.class.cast(get(panel, "openSearchApiKeyTokenField"));
            JTextField jwtToken = JTextField.class.cast(get(panel, "openSearchJwtTokenField"));
            JTextField certPath = JTextField.class.cast(get(panel, "openSearchCertPathField"));
            JTextField certKeyPath = JTextField.class.cast(get(panel, "openSearchCertKeyPathField"));
            JPasswordField certPassphrase = JPasswordField.class.cast(get(panel, "openSearchCertPassphraseField"));
            JPanel authPanel = JPanel.class.cast(get(panel, "openSearchAuthFormPanel"));

            runEdt(() -> {
                assertThat(authType.getToolTipText()).isNull();
                assertThat(user.getToolTipText()).isEqualTo("<html>OpenSearch Basic auth username.<br>Stored only within in-process memory.</html>");
                assertThat(pass.getToolTipText()).isEqualTo("<html>OpenSearch Basic auth password.<br>Stored only within in-process memory.</html>");
                assertThat(apiKeyToken.getToolTipText()).isEqualTo(
                        "<html>OpenSearch API key.<br>Use the token returned by upstream OpenSearch API key creation.<br>Stored only within in-process memory.</html>");
                assertThat(jwtToken.getToolTipText()).isEqualTo("<html>OpenSearch bearer token.<br>Stored only within in-process memory.</html>");
                assertThat(certPath.getToolTipText()).isEqualTo("<html>Path to the client certificate file used for OpenSearch authentication.</html>");
                assertThat(certKeyPath.getToolTipText()).isEqualTo("<html>Path to the client private key file used for OpenSearch authentication.</html>");
                assertThat(certPassphrase.getToolTipText()).isEqualTo("<html>Client key passphrase.<br>Stored only within in-process memory.</html>");

                assertThat(openSearchAuthLabel(authPanel, "Auth type:").getToolTipText())
                        .isEqualTo("<html>Select how requests to OpenSearch authenticate.</html>");
                assertThat(openSearchAuthLabel(authPanel, "Username:").getToolTipText())
                        .isEqualTo("<html>OpenSearch Basic auth username.<br>Stored only within in-process memory.</html>");
                assertThat(openSearchAuthLabel(authPanel, "Password:").getToolTipText())
                        .isEqualTo("<html>OpenSearch Basic auth password.<br>Stored only within in-process memory.</html>");
                assertThat(openSearchAuthLabel(authPanel, "API Key:").getToolTipText())
                        .isEqualTo("<html>OpenSearch API key.<br>Use the token returned by upstream OpenSearch API key creation.<br>Stored only within in-process memory.</html>");
                assertThat(openSearchAuthLabel(authPanel, "Bearer Token:").getToolTipText())
                        .isEqualTo("<html>OpenSearch bearer token.<br>Stored only within in-process memory.</html>");
                assertThat(openSearchAuthLabel(authPanel, "Cert Path:").getToolTipText())
                        .isEqualTo("<html>Path to the client certificate file used for OpenSearch authentication.</html>");
                assertThat(openSearchAuthLabel(authPanel, "Key Path:").getToolTipText())
                        .isEqualTo("<html>Path to the client private key file used for OpenSearch authentication.</html>");
                assertThat(openSearchAuthLabel(authPanel, "Passphrase:").getToolTipText())
                        .isEqualTo("<html>Client key passphrase.<br>Stored only within in-process memory.</html>");
            });
        });
    }

    @Test
    void authCredentialFields_stackInRows_andUseCompactInitialWidths() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));
            JPasswordField apiKeyToken = JPasswordField.class.cast(get(panel, "openSearchApiKeyTokenField"));
            JTextField jwtToken = JTextField.class.cast(get(panel, "openSearchJwtTokenField"));
            JTextField certPath = JTextField.class.cast(get(panel, "openSearchCertPathField"));
            JTextField certKeyPath = JTextField.class.cast(get(panel, "openSearchCertKeyPathField"));
            JPasswordField certPassphrase = JPasswordField.class.cast(get(panel, "openSearchCertPassphraseField"));

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                layoutTree(panel);
                assertThat(user.getParent()).isSameAs(pass.getParent());
                assertThat(user.getX()).isEqualTo(pass.getX());
                assertThat(user.getY()).isLessThan(pass.getY());

                assertThat(apiKeyToken.getPreferredSize().width).isLessThan(160);
                assertThat(jwtToken.getPreferredSize().width).isLessThan(160);
                assertThat(certPath.getPreferredSize().width).isLessThan(160);
                assertThat(certKeyPath.getPreferredSize().width).isLessThan(160);
                assertThat(certPassphrase.getPreferredSize().width).isLessThan(160);

                String longPassword = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
                pass.setText(longPassword);
                int hiddenWidth = pass.getPreferredSize().width;
                char hiddenEcho = pass.getEchoChar();
                assertThat(hiddenWidth).isLessThan(160);

                clickPasswordEye(pass);
                assertThat(pass.getEchoChar()).isEqualTo((char) 0);
                assertThat(pass.getPreferredSize().width).isGreaterThan(hiddenWidth);
                assertThat(pass.getPreferredSize().width).isEqualTo(expectedPasswordVisibleWidth(pass, longPassword));

                clickPasswordEye(pass);
                assertThat(pass.getEchoChar()).isEqualTo(hiddenEcho);
                assertThat(pass.getPreferredSize().width).isEqualTo(hiddenWidth);
            });
        });
    }

    @Test
    void selectingNone_doesNotEmitAuthenticationClearedStatus() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            javax.swing.JTextArea status = javax.swing.JTextArea.class.cast(get(panel, "databaseStatus"));

            runEdt(() -> authType.setSelectedItem("None"));

            assertThat(status.getText()).isEmpty();
        });
    }

    @Test
    void persistSelectedAuthSecrets_cachesBasicCredentialsForCurrentSession() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                user.setText("bob");
                pass.setText("s3cret");
                ai.anomalousvectors.tools.burp.testutils.Reflect.call(panel, "persistSelectedAuthSecrets");
            });

            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("bob");
            assertThat(creds.password()).isEqualTo("s3cret");
        });
    }

    @Test
    void persistSelectedAuthSecrets_cachesAwsAndElasticsearchCredentialsForCurrentSession() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> awsAuthType = getComboBox(panel, "openSearchAmazonAuthTypeCombo");
            JTextField awsUser = JTextField.class.cast(get(panel, "openSearchAmazonUserField"));
            JPasswordField awsPassword = JPasswordField.class.cast(get(panel, "openSearchAmazonPasswordField"));
            JComboBox<?> elasticAuthType = getComboBox(panel, "elasticSearchAuthTypeCombo");
            JTextField elasticUser = JTextField.class.cast(get(panel, "elasticSearchUserField"));
            JPasswordField elasticPassword = JPasswordField.class.cast(get(panel, "elasticSearchPasswordField"));

            runEdt(() -> {
                awsAuthType.setSelectedItem("Basic");
                awsUser.setText("aws-user");
                awsPassword.setText("aws-pass");
                elasticAuthType.setSelectedItem("Basic");
                elasticUser.setText("elastic-user");
                elasticPassword.setText("elastic-pass");
                ai.anomalousvectors.tools.burp.testutils.Reflect.call(panel, "persistSelectedAuthSecrets");
            });

            SecureCredentialStore.BasicCredentials awsCreds = SecureCredentialStore.loadBasicCredentials(
                    ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
            SecureCredentialStore.BasicCredentials elasticCreds = SecureCredentialStore.loadBasicCredentials(
                    ConfigState.SearchDestination.ELASTICSEARCH.configKey());
            assertThat(SecureCredentialStore.loadSelectedAuthType(
                    ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey())).isEqualTo("Basic");
            assertThat(SecureCredentialStore.loadSelectedAuthType(
                    ConfigState.SearchDestination.ELASTICSEARCH.configKey())).isEqualTo("Basic");
            assertThat(awsCreds.username()).isEqualTo("aws-user");
            assertThat(awsCreds.password()).isEqualTo("aws-pass");
            assertThat(elasticCreds.username()).isEqualTo("elastic-user");
            assertThat(elasticCreds.password()).isEqualTo("elastic-pass");
        });
    }

    @Test
    void testConnection_appliesAndCachesSelectedBasicAuthForCurrentSession() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));
            JButton testConnection = JButton.class.cast(get(panel, "testConnectionButton"));

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                user.setText("dana");
                pass.setText("pw-conn");
                testConnection.doClick();
            });

            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("dana");
            assertThat(creds.password()).isEqualTo("pw-conn");
            assertThat(RuntimeConfig.openSearchUser()).isEqualTo("dana");
            assertThat(RuntimeConfig.openSearchPassword()).isEqualTo("pw-conn");
        });
    }

    @Test
    void editingBasicAuthFields_updatesSessionStoreAndRuntimeImmediately() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                user.setText("frank");
                pass.setText("pw-live");
            });

            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("frank");
            assertThat(creds.password()).isEqualTo("pw-live");
            assertThat(RuntimeConfig.openSearchUser()).isEqualTo("frank");
            assertThat(RuntimeConfig.openSearchPassword()).isEqualTo("pw-live");
        });
    }

    @Test
    void enterOnBasicPasswordField_triggersTestConnectionBehavior() throws Exception {
        withCleanSession(() -> {
            ConfigPanel panel = newPanelOnEdt();
            JComboBox<?> authType = getComboBox(panel, "openSearchAuthTypeCombo");
            JTextField user = JTextField.class.cast(get(panel, "openSearchUserField"));
            JPasswordField pass = JPasswordField.class.cast(get(panel, "openSearchPasswordField"));

            runEdt(() -> {
                authType.setSelectedItem("Basic");
                user.setText("erin");
                pass.setText("pw-enter");
                pass.postActionEvent();
            });

            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("erin");
            assertThat(creds.password()).isEqualTo("pw-enter");
            assertThat(RuntimeConfig.openSearchUser()).isEqualTo("erin");
            assertThat(RuntimeConfig.openSearchPassword()).isEqualTo("pw-enter");
        });
    }

    private static ConfigPanel newPanelOnEdt() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(new ConfigController.Ui() {
                @Override public void onFileStatus(String message) { }
                @Override public void onDatabaseStatus(String message) { }
                @Override public void onControlStatus(String message) { }
            }));
            p.setSize(1000, 700);
            p.doLayout();
            ref.set(p);
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

    private static void layoutTree(Container container) {
        container.doLayout();
        for (Component component : container.getComponents()) {
            if (component instanceof Container child) {
                layoutTree(child);
            }
        }
    }

    private static void clickPasswordEye(JPasswordField field) {
        if (field.getWidth() <= 0 || field.getHeight() <= 0) {
            field.setSize(field.getPreferredSize());
            field.doLayout();
        }
        MouseEvent click = new MouseEvent(
                field,
                MouseEvent.MOUSE_CLICKED,
                System.currentTimeMillis(),
                0,
                Math.max(0, field.getWidth() - 6),
                field.getHeight() / 2,
                1,
                false,
                MouseEvent.BUTTON1);
        field.dispatchEvent(click);
    }

    private static int expectedPasswordVisibleWidth(JPasswordField field, String value) {
        FontMetrics fm = field.getFontMetrics(field.getFont());
        Insets margin = field.getMargin();
        int textWidth = fm.charsWidth(value.toCharArray(), 0, value.length());
        return Math.clamp(textWidth + margin.left + margin.right + 8, 80, 900);
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

    private static Path exportAnyDefaultTrustStoreCertificate() throws Exception {
        Path trustStore = Path.of(System.getProperty("java.home"), "lib", "security", "cacerts");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream input = Files.newInputStream(trustStore)) {
            keyStore.load(input, "changeit".toCharArray());
        }
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (cert == null) {
                continue;
            }
            Path file = Files.createTempFile("tls-pin-", ".cer");
            Files.write(file, cert.getEncoded());
            return file;
        }
        throw new AssertionError("No certificate found in default trust store");
    }

    private static Component findByName(Container root, String name) {
        Component found = findByNameOrNull(root, name);
        if (found != null) {
            return found;
        }
        throw new AssertionError("Component not found by name: " + name);
    }

    private static Component findByNameOrNull(Container root, String name) {
        for (Component component : root.getComponents()) {
            if (name.equals(component.getName())) {
                return component;
            }
            if (component instanceof Container child) {
                Component nested = findByNameOrNull(child, name);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static Component findLabelByText(Container root, String text) {
        for (Component component : root.getComponents()) {
            if (component instanceof javax.swing.JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (component instanceof Container child) {
                Component nested = findLabelByText(child, text);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static javax.swing.JLabel openSearchAuthLabel(Container authPanel, String text) {
        Component label = findLabelByText(authPanel, text);
        assertThat(label).as("OpenSearch auth label %s", text).isInstanceOf(javax.swing.JLabel.class);
        return javax.swing.JLabel.class.cast(label);
    }

    private static boolean isEffectivelyVisible(Component component) {
        Component current = component;
        while (current != null) {
            if (!current.isVisible()) {
                return false;
            }
            current = current.getParent();
        }
        return true;
    }

    private static JButton findComboArrowButton(JComboBox<?> comboBox) {
        for (Component child : comboBox.getComponents()) {
            if (child instanceof JButton button) {
                return button;
            }
            if (child instanceof Container nested) {
                JButton nestedButton = findFirstButton(nested);
                if (nestedButton != null) {
                    return nestedButton;
                }
            }
        }
        throw new AssertionError("Combo box button child not found");
    }

    private static JButton findFirstButton(Container root) {
        for (Component child : root.getComponents()) {
            if (child instanceof JButton button) {
                return button;
            }
            if (child instanceof Container nested) {
                JButton nestedButton = findFirstButton(nested);
                if (nestedButton != null) {
                    return nestedButton;
                }
            }
        }
        return null;
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
