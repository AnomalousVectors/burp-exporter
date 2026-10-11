package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutionException;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.core5.http.HttpHost;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opensearch.client.opensearch.OpenSearchClient;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

class OpenSearchTlsSupportTest {

    private ConfigState.State previousState;
    private String previousInsecureOverride;

    @TempDir
    private Path temporaryDirectory;

    @BeforeEach
    void prepareTlsState() {
        previousState = RuntimeConfig.getState();
        previousInsecureOverride = System.getProperty("OPENSEARCH_INSECURE");
        System.clearProperty("OPENSEARCH_INSECURE");
        SecureCredentialStore.clearAll();
        OpenSearchConnector.closeAll();
    }

    @AfterEach
    void restoreTlsState() {
        OpenSearchConnector.closeAll();
        SecureCredentialStore.clearAll();
        RuntimeConfig.updateState(previousState);
        if (previousInsecureOverride == null) {
            System.clearProperty("OPENSEARCH_INSECURE");
        } else {
            System.setProperty("OPENSEARCH_INSECURE", previousInsecureOverride);
        }
    }

    @Test
    void destinationModesAndPins_areResolvedIndependently() {
        RuntimeConfig.updateState(stateWithTlsModes(
                ConfigState.OPEN_SEARCH_TLS_VERIFY,
                ConfigState.OPEN_SEARCH_TLS_INSECURE,
                ConfigState.OPEN_SEARCH_TLS_PINNED));
        savePin(ConfigState.SearchDestination.OPEN_SEARCH, "OPEN", new byte[] {1});
        savePin(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON, "AMAZON", new byte[] {2});
        savePin(ConfigState.SearchDestination.ELASTICSEARCH, "ELASTIC", new byte[] {3});

        assertThat(OpenSearchTlsSupport.currentTlsMode(ConfigState.SearchDestination.OPEN_SEARCH))
                .isEqualTo(ConfigState.OPEN_SEARCH_TLS_VERIFY);
        assertThat(OpenSearchTlsSupport.currentTlsMode(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON))
                .isEqualTo(ConfigState.OPEN_SEARCH_TLS_INSECURE);
        assertThat(OpenSearchTlsSupport.currentTlsMode(ConfigState.SearchDestination.ELASTICSEARCH))
                .isEqualTo(ConfigState.OPEN_SEARCH_TLS_PINNED);
        assertThat(OpenSearchTlsSupport.pinnedCertificateFingerprint(ConfigState.SearchDestination.OPEN_SEARCH))
                .isEqualTo("OPEN");
        assertThat(OpenSearchTlsSupport.pinnedCertificateFingerprint(
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON))
                .isEqualTo("AMAZON");
        assertThat(OpenSearchTlsSupport.pinnedCertificateFingerprint(ConfigState.SearchDestination.ELASTICSEARCH))
                .isEqualTo("ELASTIC");

        System.setProperty("OPENSEARCH_INSECURE", "true");
        for (ConfigState.SearchDestination destination : ConfigState.SearchDestination.values()) {
            assertThat(OpenSearchTlsSupport.currentTlsMode(destination))
                    .isEqualTo(ConfigState.OPEN_SEARCH_TLS_INSECURE);
        }
    }

    @Test
    void pinnedMode_acceptsExactLeafCertificate() throws Exception {
        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_PINNED);
            savePin(ConfigState.SearchDestination.OPEN_SEARCH, "fixture", server.certificateBytes());

            assertThat(executeGet("localhost", server.port(), OpenSearchAuth.none())).isEqualTo(200);
        }
    }

    @Test
    void pinnedMode_rejectsWrongLeafCertificate() throws Exception {
        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_PINNED);
            savePin(ConfigState.SearchDestination.OPEN_SEARCH, "wrong", new byte[] {1, 2, 3});

            assertThatThrownBy(() -> executeGet("localhost", server.port(), OpenSearchAuth.none()))
                    .isInstanceOf(IOException.class);
        }
    }

    @Test
    void pinnedMode_preservesHostnameVerification() throws Exception {
        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_PINNED);
            savePin(ConfigState.SearchDestination.OPEN_SEARCH, "fixture", server.certificateBytes());

            assertThatThrownBy(() -> executeGet("127.0.0.1", server.port(), OpenSearchAuth.none()))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("127.0.0.1");
        }
    }

    @Test
    void asyncPinnedMode_preservesHostnameVerification() throws Exception {
        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_PINNED);
            savePin(ConfigState.SearchDestination.OPEN_SEARCH, "fixture", server.certificateBytes());

            assertThatThrownBy(() -> executeAsyncGet("127.0.0.1", server.port(), OpenSearchAuth.none()))
                    .isInstanceOf(IOException.class)
                    .rootCause()
                    .hasMessageContaining("127.0.0.1");
        }
    }

    @Test
    void insecureMode_isOnlyModeThatTrustsSelfSignedCertificateAndDisablesHostnameVerification()
            throws Exception {
        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_VERIFY);
            assertThatThrownBy(() -> executeGet("localhost", server.port(), OpenSearchAuth.none()))
                    .isInstanceOf(IOException.class);
        }

        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_INSECURE);
            assertThat(executeGet("127.0.0.1", server.port(), OpenSearchAuth.none())).isEqualTo(200);
        }
    }

    @Test
    void asyncInsecureMode_disablesTrustAndHostnameVerification() throws Exception {
        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_INSECURE);

            assertThat(executeAsyncGet("127.0.0.1", server.port(), OpenSearchAuth.none())).isEqualTo(200);
        }
    }

    @Test
    void pinnedMode_composesClientCertificateWithPinnedServerTrust() throws Exception {
        try (TlsTestServer server = TlsTestServer.start(true)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_PINNED);
            savePin(ConfigState.SearchDestination.OPEN_SEARCH, "fixture", server.certificateBytes());

            assertThatThrownBy(() -> executeGet("localhost", server.port(), OpenSearchAuth.none()))
                    .isInstanceOf(IOException.class);

            TlsTestServer.ClientPem clientPem = server.writeClientPem(temporaryDirectory);
            OpenSearchAuth certificateAuth = OpenSearchAuth.certificate(
                    clientPem.certificatePath().toString(),
                    clientPem.privateKeyPath().toString(),
                    "");
            assertThat(executeGet("localhost", server.port(), certificateAuth)).isEqualTo(200);
            assertThat(executeAsyncGet("localhost", server.port(), certificateAuth)).isEqualTo(200);
        }
    }

    @Test
    void connectorCache_separatesPinFingerprintsAndReusesIdenticalInputs() throws Exception {
        try (TlsTestServer server = TlsTestServer.start(false)) {
            configureOpenSearchTls(ConfigState.OPEN_SEARCH_TLS_PINNED);
            byte[] certificate = server.certificateBytes();
            savePin(ConfigState.SearchDestination.OPEN_SEARCH, "first", certificate);
            OpenSearchClient first = OpenSearchConnector.getClient(
                    "https://localhost:" + server.port(), OpenSearchAuth.none());
            OpenSearchClient firstAgain = OpenSearchConnector.getClient(
                    "https://localhost:" + server.port(), OpenSearchAuth.none());

            savePin(ConfigState.SearchDestination.OPEN_SEARCH, "second", certificate);
            OpenSearchClient second = OpenSearchConnector.getClient(
                    "https://localhost:" + server.port(), OpenSearchAuth.none());

            assertThat(firstAgain).isSameAs(first);
            assertThat(second).isNotSameAs(first);
        }
    }

    private static int executeGet(String host, int port, OpenSearchAuth auth) throws IOException {
        String baseUrl = "https://" + host + ":" + port;
        HttpHost httpHost = new HttpHost("https", host, port);
        HttpGet request = new HttpGet("/");
        return OpenSearchConnector.getClassicHttpClient(baseUrl, auth)
                .execute(httpHost, request, response -> response.getCode());
    }

    private static int executeAsyncGet(String host, int port, OpenSearchAuth auth) throws IOException {
        String baseUrl = "https://" + host + ":" + port;
        SimpleHttpRequest request = SimpleRequestBuilder.get(baseUrl + "/").build();
        try {
            SimpleHttpResponse response = OpenSearchConnector.getAsyncHttpClient(baseUrl, auth)
                    .execute(request, null)
                    .get();
            return response.getCode();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while awaiting TLS test response.", e);
        } catch (ExecutionException e) {
            throw new IOException("Async TLS request failed.", e.getCause() == null ? e : e.getCause());
        }
    }

    private static void configureOpenSearchTls(String tlsMode) {
        RuntimeConfig.updateState(stateWithTlsModes(
                tlsMode,
                ConfigState.OPEN_SEARCH_TLS_VERIFY,
                ConfigState.OPEN_SEARCH_TLS_VERIFY));
        OpenSearchConnector.closeAll();
    }

    private static void savePin(
            ConfigState.SearchDestination destination, String fingerprint, byte[] encodedCertificate) {
        SecureCredentialStore.savePinnedTlsCertificate(
                destination.configKey(), "fixture.pem", fingerprint, encodedCertificate);
    }

    private static ConfigState.State stateWithTlsModes(
            String openSearchMode, String amazonMode, String elasticsearchMode) {
        ConfigState.OpenSearchAmazonOptions amazonOptions = new ConfigState.OpenSearchAmazonOptions(
                ConfigState.DEFAULT_OPEN_SEARCH_AMAZON_AUTH_TYPE,
                "",
                "",
                "",
                "",
                "",
                ConfigState.DEPLOYMENT_AUTO,
                amazonMode,
                "",
                "",
                "");
        ConfigState.ElasticsearchOptions elasticsearchOptions = new ConfigState.ElasticsearchOptions(
                ConfigState.DEFAULT_OPEN_SEARCH_AUTH_TYPE,
                "",
                "",
                "",
                ConfigState.DEPLOYMENT_AUTO,
                elasticsearchMode,
                "",
                "",
                "");
        ConfigState.Sinks sinks = new ConfigState.Sinks(
                false,
                "",
                false,
                false,
                true,
                ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                true,
                ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                true,
                "https://localhost:9200",
                "",
                "",
                openSearchMode,
                ConfigState.defaultOpenSearchOptions(),
                ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
                "https://amazon.example",
                amazonOptions,
                "https://elastic.example",
                elasticsearchOptions);
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
