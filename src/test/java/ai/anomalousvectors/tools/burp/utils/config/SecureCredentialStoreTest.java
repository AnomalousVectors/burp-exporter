package ai.anomalousvectors.tools.burp.utils.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SecureCredentialStoreTest {

    @Test
    void basic_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("alice", "secret");
            SecureCredentialStore.BasicCredentials creds = SecureCredentialStore.loadOpenSearchCredentials();
            assertThat(creds.username()).isEqualTo("alice");
            assertThat(creds.password()).isEqualTo("secret");
        });
    }

    @Test
    void credentialValues_preserveWhitespaceAndUnicodeExactly() {
        withCleanStore(() -> {
            String amazon = ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey();
            SecureCredentialStore.saveOpenSearchCredentials("  用户  ", "\t密码\n");
            SecureCredentialStore.saveApiKeyCredentials("  api-token  ");
            SecureCredentialStore.saveJwtCredentials("\tbearer-token\n");
            SecureCredentialStore.saveCertificateCredentials(" cert.pem ", " key.pem ", "  passphrase  ");
            SecureCredentialStore.saveAwsStaticCredentials(amazon, "  access-id  ", "\tsecret\n", "   ");

            assertThat(SecureCredentialStore.loadOpenSearchCredentials())
                    .isEqualTo(new SecureCredentialStore.BasicCredentials("  用户  ", "\t密码\n"));
            assertThat(SecureCredentialStore.loadApiKeyCredentials().token()).isEqualTo("  api-token  ");
            assertThat(SecureCredentialStore.loadJwtCredentials().token()).isEqualTo("\tbearer-token\n");
            assertThat(SecureCredentialStore.loadCertificateCredentials())
                    .isEqualTo(new SecureCredentialStore.CertificateCredentials(
                            "cert.pem", "key.pem", "  passphrase  "));
            assertThat(SecureCredentialStore.loadAwsStaticCredentials(amazon))
                    .isEqualTo(new SecureCredentialStore.AwsStaticCredentials(
                            "  access-id  ", "\tsecret\n", "   "));
        });
    }

    @Test
    void whitespaceOnlyRequiredCredentials_remainPresent() {
        withCleanStore(() -> {
            SecureCredentialStore.saveOpenSearchCredentials(" ", "\t");
            SecureCredentialStore.saveApiKeyCredentials(" ");
            SecureCredentialStore.saveJwtCredentials("\n");

            assertThat(SecureCredentialStore.loadOpenSearchCredentials())
                    .isEqualTo(new SecureCredentialStore.BasicCredentials(" ", "\t"));
            assertThat(SecureCredentialStore.loadApiKeyCredentials().token()).isEqualTo(" ");
            assertThat(SecureCredentialStore.loadJwtCredentials().token()).isEqualTo("\n");
        });
    }

    @Test
    void apiKey_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveApiKeyCredentials("os_api_token_1");
            SecureCredentialStore.ApiKeyCredentials creds = SecureCredentialStore.loadApiKeyCredentials();
            assertThat(creds.token()).isEqualTo("os_api_token_1");
        });
    }

    @Test
    void jwt_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveJwtCredentials("jwt-token");
            SecureCredentialStore.JwtCredentials creds = SecureCredentialStore.loadJwtCredentials();
            assertThat(creds.token()).isEqualTo("jwt-token");
        });
    }

    @Test
    void certificate_roundTrip_saveAndLoad() {
        withCleanStore(() -> {
            SecureCredentialStore.saveCertificateCredentials("cert.pem", "key.pem", "passphrase");
            SecureCredentialStore.CertificateCredentials creds = SecureCredentialStore.loadCertificateCredentials();
            assertThat(creds.certPath()).isEqualTo("cert.pem");
            assertThat(creds.keyPath()).isEqualTo("key.pem");
            assertThat(creds.passphrase()).isEqualTo("passphrase");
        });
    }

    @Test
    void pinnedTlsCertificate_roundTrip_saveAndLoad_returnsDefensiveCopy() {
        withCleanStore(() -> {
            byte[] encoded = new byte[] { 1, 2, 3, 4 };
            SecureCredentialStore.savePinnedTlsCertificate("server.pem", "AA:BB", encoded);

            SecureCredentialStore.PinnedTlsCertificate cert = SecureCredentialStore.loadPinnedTlsCertificate();
            cert.encodedBytes()[0] = 9;

            SecureCredentialStore.PinnedTlsCertificate reloaded = SecureCredentialStore.loadPinnedTlsCertificate();
            assertThat(reloaded.sourcePath()).isEqualTo("server.pem");
            assertThat(reloaded.fingerprintSha256()).isEqualTo("AA:BB");
            assertThat(reloaded.encodedBytes()).containsExactly(1, 2, 3, 4);
        });
    }

    @Test
    void emptyInput_clearsOnlyTargetAuthType() {
        withCleanStore(() -> {
            SecureCredentialStore.saveOpenSearchCredentials("u", "p");
            SecureCredentialStore.saveApiKeyCredentials("os_api_token");
            SecureCredentialStore.saveOpenSearchCredentials("", "");

            SecureCredentialStore.BasicCredentials basic = SecureCredentialStore.loadOpenSearchCredentials();
            SecureCredentialStore.ApiKeyCredentials api = SecureCredentialStore.loadApiKeyCredentials();
            assertThat(basic.username()).isBlank();
            assertThat(basic.password()).isBlank();
            assertThat(api.token()).isEqualTo("os_api_token");
        });
    }

    @Test
    void clearAll_resets_session_values() {
        withCleanStore(() -> {
            SecureCredentialStore.saveSelectedAuthType("Bearer token");
            SecureCredentialStore.saveOpenSearchCredentials("u", "p");
            SecureCredentialStore.saveJwtCredentials("jwt-token");

            SecureCredentialStore.clearAll();

            assertThat(SecureCredentialStore.loadSelectedAuthType()).isEqualTo("Basic");
            assertThat(SecureCredentialStore.loadOpenSearchCredentials().username()).isBlank();
            assertThat(SecureCredentialStore.loadJwtCredentials().token()).isBlank();
            assertThat(SecureCredentialStore.loadPinnedTlsCertificate().fingerprintSha256()).isBlank();
        });
    }

    @Test
    void selectedAuthType_preservesDestinationSpecificIamSelection() {
        withCleanStore(() -> {
            String destination = ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey();

            assertThat(SecureCredentialStore.hasSelectedAuthType(destination)).isFalse();

            SecureCredentialStore.saveSelectedAuthType(destination, "IAM (sigV4)");

            assertThat(SecureCredentialStore.hasSelectedAuthType(destination)).isTrue();
            assertThat(SecureCredentialStore.loadSelectedAuthType(destination))
                    .isEqualTo(ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC);
        });
    }

    private static void withCleanStore(CheckedRunnable action) {
        SecureCredentialStore.clearAll();
        try {
            action.run();
        } finally {
            SecureCredentialStore.clearAll();
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run();
    }
}
