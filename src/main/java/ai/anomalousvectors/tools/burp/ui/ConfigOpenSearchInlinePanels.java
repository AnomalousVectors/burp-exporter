package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import javax.swing.AbstractButton;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import net.miginfocom.swing.MigLayout;

/**
 * Inline OpenSearch authentication and TLS sub-panels extracted from {@link ConfigPanel}.
 *
 * <p>This helper is not thread-safe. Caller must invoke its builders on the EDT.</p>
 */
final class ConfigOpenSearchInlinePanels {

    private ConfigOpenSearchInlinePanels() { }

    record AuthFormResult(JPanel panel, JComboBox<String> authTypeCombo) { }

    record AuthFormFields(
            JTextField userField,
            JPasswordField passwordField,
            JPasswordField apiKeyTokenField,
            JTextField jwtTokenField,
            JTextField certPathField,
            JTextField certKeyPathField,
            JPasswordField certPassphraseField,
            javax.swing.JLabel bearerTokenWarningLabel) {
    }

    /**
     * Builds the auth-type selector and credential cards shown on the OpenSearch destination row.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param fields non-null caller-owned credential controls
     * @param onAuthTypeChanged callback invoked on the EDT after operator selection changes
     * @param suppressAuthSync reports whether programmatic selection should suppress the callback
     * @return assembled auth form and its auth-type combo box
     */
    static AuthFormResult buildAuthFormPanel(AuthFormFields fields, Runnable onAuthTypeChanged,
            BooleanSupplier suppressAuthSync) {
        String[] authTypes = { "API key", "Bearer token", "Certificate", "Basic", "None" };
        JComboBox<String> authTypeCombo = new Tooltips.ItemTooltipComboBox<>(authTypes,
                java.util.Map.of(
                        "API key", Tooltips.htmlRaw(
                                "<b>API key</b>",
                                "Recommended for programmatic OpenSearch export/indexing when the cluster supports API keys.",
                                "Prefer a scoped key that can outlast the export run.",
                                "Note: OpenSearch API keys are a newer OpenSearch Security feature; older clusters may not support them.",
                                "",
                                "Reference: https://docs.opensearch.org/latest/security/access-control/api-keys/"),
                        "Bearer token", ConfigPanel.withTemporaryCredentialRisk(
                                "<b>Bearer token</b>",
                                "Use when OpenSearch accepts JWT, OIDC, service-account tokens, or another bearer-token workflow.",
                                "Many bearer tokens are short-lived. Prefer <b>API key</b> (when available) or <b>Basic</b> for multi-day or unattended export runs.",
                                "",
                                "References:",
                                "https://docs.opensearch.org/latest/security/authentication-backends/jwt/",
                                "https://docs.opensearch.org/latest/security/access-control/authentication-tokens/"),
                        "Certificate", Tooltips.htmlRaw(
                                "<b>Certificate</b>",
                                "Use client certificate authentication when the cluster requires mutual TLS or certificate-based identity.",
                                "Provide a client certificate, private key, and any required passphrase; the cluster must trust the issuing CA.",
                                "Strong, but usually more setup than API key or Basic.",
                                "",
                                "Reference: https://docs.opensearch.org/latest/security/authentication-backends/client-auth/"),
                        "Basic", Tooltips.htmlRaw(
                                "<b>Basic</b>",
                                "Use a username and password for the OpenSearch internal user database, LDAP/Active Directory-backed users, or another HTTP Basic backend.",
                                "Common and easy to configure. API keys are usually better for service-style integrations when the cluster supports them.",
                                "",
                                "Reference: https://docs.opensearch.org/latest/security/authentication-backends/basic-authc/"),
                        "None", Tooltips.htmlRaw(
                                "<b>None</b>",
                                "Send requests without authentication headers.",
                                "Use only for local testing, isolated lab clusters, or deployments where access is enforced by the network or an upstream proxy.")));
        authTypeCombo.setName("os.authType");
        authTypeCombo.setSelectedItem("Basic");
        String longest = java.util.Arrays.stream(authTypes)
                .max(java.util.Comparator.comparingInt(value -> value.length()))
                .orElse("Certificate");
        authTypeCombo.setPrototypeDisplayValue(longest);

        JPanel contentCards = new JPanel(new MigLayout("insets 0, hidemode 3", "[left]", "[]"));
        contentCards.setName("os.authContent");

        JPanel noneCard = new JPanel(new MigLayout("insets 0", "[left]", "[]"));
        noneCard.setName("os.authCard.none");

        JPanel basicCard = authCardPanel();
        basicCard.setName("os.authCard.basic");

        JPanel apiKeyCard = authCardPanel();
        apiKeyCard.setName("os.authCard.apikey");

        JPanel jwtCard = authCardPanel();
        jwtCard.setName("os.authCard.jwt");

        JPanel clientCertCard = authCardPanel();
        clientCertCard.setName("os.authCard.certificate");

        contentCards.add(noneCard, "hidemode 3");
        contentCards.add(basicCard, "hidemode 3");
        contentCards.add(apiKeyCard, "hidemode 3");
        contentCards.add(jwtCard, "hidemode 3");
        contentCards.add(clientCertCard, "hidemode 3");

        Consumer<String> applyAuthTypeCardVisibility = selectedType -> {
            noneCard.setVisible("None".equals(selectedType));
            basicCard.setVisible("Basic".equals(selectedType));
            apiKeyCard.setVisible("API key".equals(selectedType));
            jwtCard.setVisible("Bearer token".equals(selectedType));
            clientCertCard.setVisible("Certificate".equals(selectedType));
        };

        authTypeCombo.addActionListener(e -> {
            String selectedType = String.valueOf(authTypeCombo.getSelectedItem());
            applyAuthTypeCardVisibility.accept(selectedType);
            if (!suppressAuthSync.getAsBoolean()) {
                onAuthTypeChanged.run();
            }
            contentCards.revalidate();
            contentCards.repaint();
        });
        applyAuthTypeCardVisibility.accept(String.valueOf(authTypeCombo.getSelectedItem()));

        JPanel form = new JPanel(new MigLayout("insets 0, wrap 2", ConfigDestinationPanel.FIELD_COLS, "[top]"));
        form.setAlignmentX(Component.LEFT_ALIGNMENT);

        String authTypeTip = Tooltips.htmlRaw(
                "<b>Auth type</b>",
                "Select how requests to OpenSearch authenticate.",
                "Hover each dropdown item for guidance.",
                "API key is usually best for long or unattended export runs when the cluster supports it.");
        String basicUserTip = Tooltips.htmlRaw(
                "<b>Username</b>",
                "OpenSearch Basic auth username.",
                "Stored only within in-process memory.");
        String basicPasswordTip = Tooltips.htmlRaw(
                "<b>Password</b>",
                "OpenSearch Basic auth password.",
                "Stored only within in-process memory.");
        String apiKeyTokenTip = Tooltips.htmlRaw(
                "<b>API Key</b>",
                "OpenSearch API key token returned by upstream API key creation.",
                "Prefer a scoped key that can outlast the export run.",
                "Stored only within in-process memory.");
        String jwtTip = ConfigPanel.withTemporaryCredentialRisk(
                "<b>Bearer Token</b>",
                "OpenSearch bearer/JWT/OIDC access token.",
                "Many bearer tokens are short-lived. Prefer <b>API key</b> (when available) or <b>Basic</b> for multi-day or unattended export runs.",
                "Stored only within in-process memory.");
        String certPathTip = Tooltips.htmlRaw(
                "<b>Cert Path</b>",
                "Path to the client certificate file used for OpenSearch mutual TLS / certificate auth.");
        String keyPathTip = Tooltips.htmlRaw(
                "<b>Key Path</b>",
                "Path to the client private key file used with the OpenSearch client certificate.");
        String passphraseTip = Tooltips.htmlRaw(
                "<b>Passphrase</b>",
                "Optional passphrase for the OpenSearch client private key.",
                "Stored only within in-process memory.");

        Tooltips.apply(fields.userField(), basicUserTip);
        Tooltips.apply(fields.passwordField(), basicPasswordTip);
        Tooltips.apply(fields.apiKeyTokenField(), apiKeyTokenTip);
        Tooltips.apply(fields.jwtTokenField(), jwtTip);
        Tooltips.apply(fields.certPathField(), certPathTip);
        Tooltips.apply(fields.certKeyPathField(), keyPathTip);
        Tooltips.apply(fields.certPassphraseField(), passphraseTip);

        addAuthFieldRow(basicCard, "Username:", fields.userField(), basicUserTip);
        addAuthFieldRow(basicCard, "Password:", fields.passwordField(), basicPasswordTip);

        addAuthFieldRow(apiKeyCard, "API Key:", fields.apiKeyTokenField(), apiKeyTokenTip);

        addAuthFieldRow(jwtCard, "Bearer Token:", fields.jwtTokenField(), jwtTip);
        if (fields.bearerTokenWarningLabel() != null) {
            fields.bearerTokenWarningLabel().setName("os.bearer.warning");
            jwtCard.add(fields.bearerTokenWarningLabel(), "span 2, growx, wrap");
        }

        addAuthFieldRow(clientCertCard, "Cert Path:", fields.certPathField(), certPathTip);
        addAuthFieldRow(clientCertCard, "Key Path:", fields.certKeyPathField(), keyPathTip);
        addAuthFieldRow(clientCertCard, "Passphrase:", fields.certPassphraseField(), passphraseTip);

        form.add(Tooltips.label("Auth type:", authTypeTip), "top");
        form.add(authTypeCombo, "top, wrap");
        form.add(contentCards, "span 2, top");

        return new AuthFormResult(form, authTypeCombo);
    }

    private static JPanel authCardPanel() {
        JPanel panel = new JPanel(new MigLayout(
                "insets 0, wrap 2", ConfigDestinationPanel.FIELD_COLS, "[]"));
        panel.setOpaque(false);
        return panel;
    }

    private static void addAuthFieldRow(JPanel panel, String label, Component field, String tooltip) {
        panel.add(Tooltips.label(label, tooltip), "alignx left, top");
        panel.add(field, "alignx left, top");
    }

    record TlsFormFields(
            JComboBox<String> tlsModeCombo,
            JButton importPinnedCertificateButton,
            AbstractButton openSearchSinkCheckbox) {
    }

    /**
     * Builds TLS mode and pinned-certificate import controls for the OpenSearch destination row.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param fields non-null caller-owned TLS controls
     * @param onTlsModeSelected callback invoked on the EDT after operator selection changes
     * @return assembled TLS controls
     */
    static JPanel buildTlsPanel(TlsFormFields fields, Consumer<String> onTlsModeSelected) {
        fields.tlsModeCombo().setName("os.tlsMode");
        fields.tlsModeCombo().setSelectedItem("Verify");
        fields.importPinnedCertificateButton().setName("os.tls.import");

        JPanel pinnedPanel = new JPanel(new MigLayout("insets 0", "[pref]", "[]"));
        pinnedPanel.setOpaque(false);
        pinnedPanel.add(fields.importPinnedCertificateButton());

        JPanel controls = new JPanel(new MigLayout("insets 0, hidemode 3", "[pref]", "[]"));
        controls.setOpaque(false);
        controls.add(Box.createHorizontalStrut(0), "hidemode 3");
        controls.add(pinnedPanel, "hidemode 3");

        Consumer<String> applyPinnedVisibility = selectedMode -> {
            boolean pinned = ConfigState.OPEN_SEARCH_TLS_PINNED.equals(normalizeTlsModeLabel(selectedMode));
            pinnedPanel.setVisible(pinned);
            fields.importPinnedCertificateButton().setVisible(pinned);
            fields.importPinnedCertificateButton().setEnabled(fields.openSearchSinkCheckbox().isSelected() && pinned);
        };
        applyPinnedVisibility.accept(String.valueOf(fields.tlsModeCombo().getSelectedItem()));
        fields.tlsModeCombo().addActionListener(e -> {
            String selectedMode = String.valueOf(fields.tlsModeCombo().getSelectedItem());
            onTlsModeSelected.accept(selectedMode);
            applyPinnedVisibility.accept(selectedMode);
            controls.revalidate();
            controls.repaint();
        });

        String tlsModeTip = Tooltips.htmlRaw(
                "<b>TLS mode</b>",
                "Select how OpenSearch HTTPS server certificates are trusted.",
                "",
                "<b>Verify</b>",
                "&nbsp;&nbsp;Use the JVM/system trust store. Recommended for production.",
                "<b>Trust pinned certificate</b>",
                "&nbsp;&nbsp;Trust only an imported X.509 server certificate for this Burp session.",
                "<b>Trust all certificates</b>",
                "&nbsp;&nbsp;Disable verification. Lab/testing only; allows man-in-the-middle interception.");
        String importTip = Tooltips.htmlRaw(
                "<b>Import pinned certificate</b>",
                "Import a pinned X.509 server certificate for OpenSearch TLS trust.",
                "Common file types: <code>.cer</code>, <code>.crt</code>, <code>.der</code>, <code>.pem</code>.",
                "Imported certificate bytes and source path stay in session memory only.");
        Tooltips.apply(fields.importPinnedCertificateButton(), importTip);

        JPanel form = new JPanel(new MigLayout(
                "insets 0, hidemode 3, wrap 2", ConfigDestinationPanel.FIELD_COLS, "[]"));
        form.setOpaque(false);
        form.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(Tooltips.label("TLS mode:", tlsModeTip));
        form.add(fields.tlsModeCombo(), "wrap");
        form.add(controls, "span 2");
        return form;
    }

    /**
     * Normalizes a UI TLS label to a runtime configuration value.
     *
     * @param label selected UI label; null, blank, and unknown labels select verification
     * @return one of the canonical {@link ConfigState} TLS mode values
     */
    static String normalizeTlsModeLabel(String label) {
        if (label == null || label.isBlank()) {
            return ConfigState.OPEN_SEARCH_TLS_VERIFY;
        }
        return switch (label.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "trust pinned certificate" -> ConfigState.OPEN_SEARCH_TLS_PINNED;
            case "trust all certificates" -> ConfigState.OPEN_SEARCH_TLS_INSECURE;
            default -> ConfigState.OPEN_SEARCH_TLS_VERIFY;
        };
    }
}
