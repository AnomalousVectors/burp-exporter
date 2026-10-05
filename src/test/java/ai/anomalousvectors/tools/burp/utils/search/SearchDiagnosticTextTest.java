package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

class SearchDiagnosticTextTest {

    @AfterEach
    void clearCredentials() {
        SecureCredentialStore.clearAll();
    }

    @Test
    void singleLine_redactsEverySessionCredentialKind() {
        String openSearch = ConfigState.SearchDestination.OPEN_SEARCH.configKey();
        String elasticsearch = ConfigState.SearchDestination.ELASTICSEARCH.configKey();
        String amazon = ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey();
        SecureCredentialStore.saveBasicCredentials(
                openSearch, "basic-user-value", "basic-password-value");
        SecureCredentialStore.saveApiKeyCredentials(elasticsearch, "api-key-value");
        SecureCredentialStore.saveJwtCredentials(elasticsearch, "bearer-token-value");
        SecureCredentialStore.saveCertificateCredentials(
                openSearch, "cert.pem", "key.pem", "private-key-passphrase-value");
        SecureCredentialStore.saveAwsStaticCredentials(
                amazon, "AKIA-ACCESS-VALUE", "aws-secret-value", "aws-session-value");

        String input = String.join(" ",
                "basic-user-value",
                "basic-password-value",
                "api-key-value",
                "bearer-token-value",
                "private-key-passphrase-value",
                "AKIA-ACCESS-VALUE",
                "aws-secret-value",
                "aws-session-value");

        String diagnostic = SearchDiagnosticText.singleLine(input, 4_096);

        assertThat(diagnostic).doesNotContain(
                "basic-user-value",
                "basic-password-value",
                "api-key-value",
                "bearer-token-value",
                "private-key-passphrase-value",
                "AKIA-ACCESS-VALUE",
                "aws-secret-value",
                "aws-session-value");
        assertThat(diagnostic).contains("***");
    }

    @Test
    void singleLine_knownCredentialRedactionDoesNotCorruptContainingTokens() {
        SecureCredentialStore.saveBasicCredentials(
                ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
                "admin",
                "secret-value");

        String diagnostic = SearchDiagnosticText.singleLine(
                "administrator admin secret-value-suffix secret-value",
                4_096);

        assertThat(diagnostic)
                .isEqualTo("administrator *** secret-value-suffix ***");
    }

    @Test
    void singleLine_redactsCredentialPatternsAndNormalizesForgedLines() {
        String diagnostic = SearchDiagnosticText.singleLine(
                "failure\r\n[ERROR] forged Authorization: Bearer raw-token"
                        + " https://host/?api_key=query-secret"
                        + "&X-Amz-Credential=aws-credential"
                        + "&X-Amz-Signature=aws-signature"
                        + "\r\nX-Api-Key: header-secret"
                        + "\r\nCookie: session=cookie-secret"
                        + "\r\n{\"password\":\"json-secret\"}",
                4_096);

        assertThat(diagnostic)
                .doesNotContain(
                        "\r",
                        "\n",
                        "raw-token",
                        "query-secret",
                        "aws-credential",
                        "aws-signature",
                        "header-secret",
                        "cookie-secret",
                        "json-secret")
                .contains(
                        "Bearer ***",
                        "api_key=***",
                        "X-Amz-Credential=***",
                        "X-Amz-Signature=***",
                        "X-Api-Key:***",
                        "Cookie:***",
                        "\"password\":\"***\"");
    }

    @Test
    void responseBodyPreview_isUtf8BoundedAndMarksTruncation() {
        String preview = SearchDiagnosticText.responseBodyPreview("é".repeat(10_000));

        assertThat(preview).endsWith("... [truncated]");
        assertThat(preview.getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(SearchDiagnosticText.RESPONSE_BODY_PREVIEW_BYTES);
    }

    @Test
    void responseBodyPreview_removesServerFieldValuePreview() {
        String preview = SearchDiagnosticText.responseBodyPreview(
                "{\n  \"reason\": \"Preview of field's value: 'captured-value'\"\n}");

        assertThat(preview)
                .contains("Preview of field's value: ***")
                .doesNotContain("captured-value");
    }

    @Test
    void multiLine_boundsCompleteResponseEnvelope() {
        String diagnostic = SearchDiagnosticText.multiLine(
                "HTTP/2 502 Bad Gateway\n" + "X-Large: value\n".repeat(2_000),
                SearchDiagnosticText.RESPONSE_DIAGNOSTIC_BYTES);

        assertThat(diagnostic).endsWith("... [truncated]");
        assertThat(diagnostic.getBytes(StandardCharsets.UTF_8).length)
                .isLessThanOrEqualTo(SearchDiagnosticText.RESPONSE_DIAGNOSTIC_BYTES);
    }

    @Test
    void exceptionChain_isBoundedNormalizedAndRedacted() {
        SecureCredentialStore.saveJwtCredentials("exception-secret");
        Exception failure = new IllegalStateException(
                "first\r\nforged exception-secret",
                new IllegalArgumentException("Bearer another-secret"));

        String diagnostic = SearchDiagnosticText.exceptionChain(failure);

        assertThat(diagnostic)
                .contains("IllegalStateException", "IllegalArgumentException")
                .doesNotContain("\r", "\n", "exception-secret", "another-secret")
                .contains("Bearer ***");
        assertThat(diagnostic.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(600);
    }
}
