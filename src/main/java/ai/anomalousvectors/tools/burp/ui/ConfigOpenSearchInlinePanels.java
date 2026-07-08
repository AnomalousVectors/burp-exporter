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
            JPasswordField certPassphraseField) {
    }

    /**
     * Builds the auth-type selector and credential cards shown on the OpenSearch destination row.
     */
    static AuthFormResult buildAuthFormPanel(AuthFormFields fields, Runnable onAuthTypeChanged,
            BooleanSupplier suppressAuthSync) {
        String[] authTypes = { "API key", "Bearer token", "Certificate", "Basic", "None" };
        JComboBox<String> authTypeCombo = new Tooltips.ItemTooltipComboBox<>(authTypes,
                java.util.Map.of(
                        "API key", Tooltips.htmlRaw(
                                "Recommended for programmatic access when available.",
                                "Use a scoped API key for indexing/export operations.",
                                "Note: OpenSearch API keys are a newer OpenSearch Security feature, so older clusters may not support them.",
                                "Reference: https://docs.opensearch.org/latest/security/access-control/api-keys/"),
                        "Bearer token", Tooltips.htmlRaw(
                                "Use when the OpenSearch cluster is configured for token-based authentication, such as JWT, OIDC, service-account tokens, or another bearer-token workflow.",
                                "This is a good option when your organization already issues short-lived or centrally managed tokens.",
                                "References:",
                                "https://docs.opensearch.org/latest/security/authentication-backends/jwt/",
                                "https://docs.opensearch.org/latest/security/access-control/authentication-tokens/"),
                        "Certificate", Tooltips.htmlRaw(
                                "Use client certificate authentication when the cluster requires mutual TLS or certificate-based identity.",
                                "This is strong, but usually requires more setup because users must provide a client certificate, private key, and the cluster must trust the issuing CA.",
                                "Reference: https://docs.opensearch.org/latest/security/authentication-backends/client-auth/"),
                        "Basic", Tooltips.htmlRaw(
                                "Use a username and password for clusters using the OpenSearch internal user database, LDAP/Active Directory-backed users, or another backend exposed through HTTP Basic authentication.",
                                "This is common and easy to configure, but API keys or short-lived tokens are usually better for service-style integrations.",
                                "Reference: https://docs.opensearch.org/latest/security/authentication-backends/basic-authc/"),
                        "None", Tooltips.htmlRaw(
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

        JPanel form = new JPanel(new MigLayout("insets 0", "[pref][pref][grow]", "[top]"));
        form.setAlignmentX(Component.LEFT_ALIGNMENT);

        String authTypeTip = Tooltips.html("Select how requests to OpenSearch authenticate.");
        String basicUserTip = Tooltips.html("OpenSearch Basic auth username.", "Stored only within in-process memory.");
        String basicPasswordTip = Tooltips.html("OpenSearch Basic auth password.", "Stored only within in-process memory.");
        String apiKeyTokenTip = Tooltips.html(
                "OpenSearch API key.",
                "Use the token returned by upstream OpenSearch API key creation.",
                "Stored only within in-process memory.");
        String jwtTip = Tooltips.html("OpenSearch bearer token.", "Stored only within in-process memory.");
        String certPathTip = Tooltips.html("Path to the client certificate file used for OpenSearch authentication.");
        String keyPathTip = Tooltips.html("Path to the client private key file used for OpenSearch authentication.");
        String passphraseTip = Tooltips.html("Client key passphrase.", "Stored only within in-process memory.");

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

        addAuthFieldRow(clientCertCard, "Cert Path:", fields.certPathField(), certPathTip);
        addAuthFieldRow(clientCertCard, "Key Path:", fields.certKeyPathField(), keyPathTip);
        addAuthFieldRow(clientCertCard, "Passphrase:", fields.certPassphraseField(), passphraseTip);

        form.add(Tooltips.label("Auth type:", authTypeTip), "top");
        form.add(authTypeCombo, "top");
        form.add(contentCards, "gapleft 15, top");

        return new AuthFormResult(form, authTypeCombo);
    }

    private static JPanel authCardPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 2", "[pref][pref]", "[]"));
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

        String tlsModeTip = Tooltips.html(
                "Select how OpenSearch TLS server certificates are trusted.",
                "- Verify: uses the system trust store.",
                "- Trust pinned certificate: requires an imported X.509 server certificate.",
                "- Trust all certificates: disables verification. Use with caution.");
        String importTip = Tooltips.html(
                "Import a pinned X.509 server certificate for OpenSearch TLS trust.",
                "  Common file types: .cer, .crt, .der, .pem.",
                "  The imported certificate bytes and source path are stored only within in-process memory.");
        Tooltips.apply(fields.importPinnedCertificateButton(), importTip);

        JPanel form = new JPanel(new MigLayout("insets 0", "[pref][pref][pref]", "[]"));
        form.setOpaque(false);
        form.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(Tooltips.label("TLS mode:", tlsModeTip));
        form.add(fields.tlsModeCombo());
        form.add(controls, "gapleft 12");
        return form;
    }

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
