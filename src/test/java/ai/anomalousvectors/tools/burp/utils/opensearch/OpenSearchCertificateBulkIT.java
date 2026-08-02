package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

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
import ai.anomalousvectors.tools.burp.testutils.OpenSearchClientCertificateSupport;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Verifies certificate-authenticated bulk export paths that bypass the classic HTTP client for mTLS.
 *
 * <p>Client PEMs are provisioned from the local multi/opensearch data volume
 * ({@code ${DATA_VOLUME_ROOT}/certs}) via {@link OpenSearchClientCertificateSupport}: signed by the
 * current root CA and recreated when that CA fingerprint changes. Tests skip when no OpenSearch or
 * certificate-stack option is configured, as in credential-free CI. Once any relevant option is
 * explicit, missing files and other broken prerequisites fail the test.</p>
 */
@Tag("integration")
@ResourceLock("traffic-opensearch-index")
@ResourceLock("opensearch-client-cert")
class OpenSearchCertificateBulkIT {

    @Test
    void preparedBulkSender_indexesDocumentWithClientCertificate() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        try {
            OpenSearchClientCertificateSupport.Paths certPaths = prepareCertificateAuth();
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

            assertThat(result.successCount())
                    .as("prepared bulk with client cert %s", certPaths.certificatePath())
                    .isEqualTo(1);
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
            OpenSearchClientCertificateSupport.Paths certPaths = prepareCertificateAuth();
            String baseUrl = OpenSearchTestConfig.get().baseUrl();
            String indexName = RuntimeConfig.indexNameForKey("traffic");
            OpenSearchAuth auth = OpenSearchAuth.fromRuntime();

            List<OpenSearchSink.IndexResult> indexResults =
                    OpenSearchSink.createSelectedIndexes(baseUrl, List.of(ConfigKeys.SRC_TRAFFIC), auth, () -> true);
            assertThat(indexResults).isNotEmpty();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
            RuntimeConfig.setExportRunning(true);

            LinkedBlockingQueue<TrafficQueueEntry> queue = new LinkedBlockingQueue<>();
            assertThat(queue.offer(TrafficQueueEntry.from(certificateTrafficDocument()))).isTrue();

            ChunkedBulkSender.Result result =
                    ChunkedBulkSender.push(baseUrl, indexName, "traffic", queue, 10, 5L * 1024 * 1024, 10);

            assertThat(result.successCount)
                    .as("chunked bulk with client cert %s", certPaths.certificatePath())
                    .isEqualTo(1);
            assertThat(result.failedItems).isEmpty();
        } finally {
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
            RuntimeConfig.setExportStopping(false);
            IndexingRetryCoordinator.getInstance().stopDrainThread();
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            RuntimeConfig.updateState(previousState);
            SecureCredentialStore.clearAll();
            OpenSearchConnector.closeAll();
        }
    }

    private static OpenSearchClientCertificateSupport.Paths prepareCertificateAuth() {
        Assumptions.assumeTrue(
                OpenSearchClientCertificateSupport.hasExplicitTestEnvironment(),
                "OpenSearch certificate test environment is not configured");
        OpenSearchConnector.closeAll();
        OpenSearchClientCertificateSupport.Paths paths = OpenSearchClientCertificateSupport.ensureReady();
        SecureCredentialStore.clearAll();
        SecureCredentialStore.saveCertificateCredentials(
                paths.certificatePath().toString(),
                paths.privateKeyPath().toString(),
                "");
        RuntimeConfig.updateState(certificateState(
                OpenSearchTestConfig.get().baseUrl(),
                paths.certificatePath().toString(),
                paths.privateKeyPath().toString()));
        OpenSearchConnector.closeAll();
        return paths;
    }

    private static Map<String, Object> certificateTrafficDocument() {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("meta", Map.of("schema_version", "1"));
        document.put("burp", Map.of("reporting_tool", "Proxy"));
        return document;
    }

    private static ConfigState.State certificateState(String baseUrl, String certPath, String keyPath) {
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
                        new ConfigState.OpenSearchOptions("Certificate", "", certPath, keyPath, "", "", "")),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
