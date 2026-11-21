package ai.anomalousvectors.tools.burp.utils.search;

import static java.nio.file.StandardOpenOption.WRITE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;

import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;

class SearchAuthTest {

    @Test
    void authorizationHeaders_preserveOpaqueCredentialValuesExactly() {
        String username = "  用户  ";
        String password = "\t密码\n";
        String expectedBasic = "Basic " + Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));

        assertThat(SearchAuth.basic(username, password).authorizationHeaderValue())
                .isEqualTo(expectedBasic);
        assertThat(SearchAuth.apiKey("  api-token  ").authorizationHeaderValue())
                .isEqualTo("ApiKey   api-token  ");
        assertThat(SearchAuth.bearerToken("\tbearer-token\n").authorizationHeaderValue())
                .isEqualTo("Bearer \tbearer-token\n");
    }

    @Test
    void whitespaceOnlyCredentials_arePresentAndComplete() {
        assertThat(SearchAuth.basicOrNone(" ", "\t").mode()).isEqualTo(SearchAuth.Mode.BASIC);
        assertThat(SearchAuth.basic(" ", "\t").isComplete()).isTrue();
        assertThat(SearchAuth.apiKey(" ").isComplete()).isTrue();
        assertThat(SearchAuth.bearerToken("\n").isComplete()).isTrue();
    }

    @Test
    void basicOrNone_treatsOnlyNullOrEmptyValuesAsAbsent() {
        assertThat(SearchAuth.basicOrNone(null, "password").mode()).isEqualTo(SearchAuth.Mode.NONE);
        assertThat(SearchAuth.basicOrNone("username", "").mode()).isEqualTo(SearchAuth.Mode.NONE);
        assertThat(SearchAuth.basicOrNone(" username ", " password ").mode())
                .isEqualTo(SearchAuth.Mode.BASIC);
    }

    @Test
    void readBoundedFile_acceptsTheExactTenMebibyteLimit() throws Exception {
        Path file = fileWithSize("maximum-client-auth-file", ".pem", SearchAuth.MAX_CLIENT_AUTH_FILE_BYTES);
        byte[] bytes = null;
        try {
            bytes = SearchAuth.readBoundedFile(file, "Client authentication file");
            assertThat(bytes).hasSize(SearchAuth.MAX_CLIENT_AUTH_FILE_BYTES);
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
            Files.deleteIfExists(file);
        }
    }

    @Test
    void loadClientKeyMaterial_rejectsOversizedCertificateBeforeParsing() throws Exception {
        Path certificate = oversizedFile("oversized-client-certificate", ".pem");
        Path privateKey = TestPathSupport.createFile("empty-client-key", ".pem");
        try {
            SearchAuth auth = SearchAuth.certificate(
                    certificate.toString(), privateKey.toString(), "");

            assertThatThrownBy(() -> auth.loadClientKeyMaterial(SSLContextBuilder.create()))
                    .isInstanceOf(java.io.IOException.class)
                    .hasMessageContaining("Client certificate exceeds the 10 MiB limit")
                    .hasMessageContaining(certificate.toString());
        } finally {
            Files.deleteIfExists(certificate);
            Files.deleteIfExists(privateKey);
        }
    }

    @Test
    void loadClientKeyMaterial_rejectsOversizedPrivateKeyBeforeCertificateParsing() throws Exception {
        Path certificate = TestPathSupport.createFile("empty-client-certificate", ".pem");
        Path privateKey = oversizedFile("oversized-client-key", ".pem");
        try {
            SearchAuth auth = SearchAuth.certificate(
                    certificate.toString(), privateKey.toString(), "");

            assertThatThrownBy(() -> auth.loadClientKeyMaterial(SSLContextBuilder.create()))
                    .isInstanceOf(java.io.IOException.class)
                    .hasMessageContaining("Client private key exceeds the 10 MiB limit")
                    .hasMessageContaining(privateKey.toString());
        } finally {
            Files.deleteIfExists(certificate);
            Files.deleteIfExists(privateKey);
        }
    }

    private static Path oversizedFile(String prefix, String suffix) throws Exception {
        return fileWithSize(prefix, suffix, SearchAuth.MAX_CLIENT_AUTH_FILE_BYTES + 1L);
    }

    private static Path fileWithSize(String prefix, String suffix, long size) throws Exception {
        Path path = TestPathSupport.createFile(prefix, suffix);
        try (var channel = Files.newByteChannel(path, WRITE)) {
            channel.position(size - 1L);
            channel.write(ByteBuffer.wrap(new byte[] { 1 }));
        }
        return path;
    }
}
