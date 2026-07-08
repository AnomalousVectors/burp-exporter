package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.anomalousvectors.tools.burp.sinks.OpenSearchSink;
import ai.anomalousvectors.tools.burp.sinks.TrafficQueueEntry;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Verifies certificate-authenticated bulk export paths that bypass the classic HTTP client for mTLS.
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class OpenSearchCertificateBulkIT {

    private static final String DEFAULT_CERT =
            "d:\\opensearch-data\\certs\\burp-exporter-client.pem";
    private static final String DEFAULT_KEY =
            "d:\\opensearch-data\\certs\\burp-exporter-client-key.pem";

    @Test
    void preparedBulkSender_indexesDocumentWithClientCertificate() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        try {
            assumeCertificateAuthReady();
            String baseUrl = OpenSearchTestConfig.get().baseUrl();
            String indexName = RuntimeConfig.indexNameForKey("traffic");
            OpenSearchAuth auth = OpenSearchAuth.fromRuntime();

            List<OpenSearchSink.IndexResult> indexResults =
                    OpenSearchSink.createSelectedIndexes(baseUrl, List.of(ConfigKeys.SRC_TRAFFIC), auth, () -> true);
            assertThat(indexResults).isNotEmpty();

            Map<String, Object> document = new LinkedHashMap<>();
            document.put("meta", Map.of("schema_version", "1"));
            document.put("burp", Map.of("reporting_tool", "CertificateBulkIT"));
            PreparedExportDocument prepared =
                    ExportDocumentIdentity.prepare(indexName, "traffic", document);

            OpenSearchClientWrapper.BulkResult result =
                    PreparedBulkSender.push(baseUrl, indexName, List.of(prepared));

            assertThat(result.successCount()).isEqualTo(1);
            assertThat(result.failedItems).isEmpty();
        } finally {
            RuntimeConfig.updateState(previousState);
            SecureCredentialStore.clearAll();
            OpenSearchConnector.closeAll();
        }
    }

    @Test
    void chunkedBulkSender_indexesDocumentWithClientCertificate() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        try {
            assumeCertificateAuthReady();
            String baseUrl = OpenSearchTestConfig.get().baseUrl();
            String indexName = RuntimeConfig.indexNameForKey("traffic");
            OpenSearchAuth auth = OpenSearchAuth.fromRuntime();

            List<OpenSearchSink.IndexResult> indexResults =
                    OpenSearchSink.createSelectedIndexes(baseUrl, List.of(ConfigKeys.SRC_TRAFFIC), auth, () -> true);
            assertThat(indexResults).isNotEmpty();

            LinkedBlockingQueue<TrafficQueueEntry> queue = new LinkedBlockingQueue<>();
            assertThat(queue.offer(TrafficQueueEntry.from(certificateTrafficDocument()))).isTrue();

            ChunkedBulkSender.Result result =
                    ChunkedBulkSender.push(baseUrl, indexName, "traffic", queue, 10, 5L * 1024 * 1024, 10);

            assertThat(result.successCount).isEqualTo(1);
            assertThat(result.failedItems).isEmpty();
        } finally {
            RuntimeConfig.updateState(previousState);
            SecureCredentialStore.clearAll();
            OpenSearchConnector.closeAll();
        }
    }

    private static void assumeCertificateAuthReady() {
        OpenSearchConnector.closeAll();
        String certPath = certPath();
        String keyPath = keyPath();
        Assumptions.assumeTrue(Files.isRegularFile(Path.of(certPath)), "client certificate file missing");
        Assumptions.assumeTrue(Files.isRegularFile(Path.of(keyPath)), "client private key file missing");

        SecureCredentialStore.clearAll();
        SecureCredentialStore.saveCertificateCredentials(certPath, keyPath, "");
        RuntimeConfig.updateState(certificateState(OpenSearchTestConfig.get().baseUrl()));
        OpenSearchConnector.closeAll();

        OpenSearchRawGet.RawGetResult probe = OpenSearchRawGet.performRawGet(
                OpenSearchTestConfig.get().baseUrl(), OpenSearchAuth.fromRuntime());
        Assumptions.assumeTrue(
                probe.statusCode() == 200,
                () -> "certificate auth not active on cluster: " + probe.reasonPhrase());
    }

    private static Map<String, Object> certificateTrafficDocument() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("meta", Map.of("schema_version", "1"));
        document.put("burp", Map.of("reporting_tool", "CertificateBulkIT"));
        return document;
    }

    private static String certPath() {
        return firstNonBlank(
                System.getProperty("OPENSEARCH_CERT_PATH"),
                System.getenv("OPENSEARCH_CERT_PATH"),
                DEFAULT_CERT);
    }

    private static String keyPath() {
        return firstNonBlank(
                System.getProperty("OPENSEARCH_CERT_KEY_PATH"),
                System.getenv("OPENSEARCH_CERT_KEY_PATH"),
                DEFAULT_KEY);
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private static ConfigState.State certificateState(String baseUrl) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
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
                        baseUrl,
                        "",
                        "",
                        ConfigState.OPEN_SEARCH_TLS_INSECURE,
                        new ConfigState.OpenSearchOptions("Certificate", "", "", "", "", "", "")),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
