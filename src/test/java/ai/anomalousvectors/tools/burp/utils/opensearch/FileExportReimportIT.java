package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.sinks.FileExportService;
import ai.anomalousvectors.tools.burp.sinks.OpenSearchCleanupIT;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
/**
 * Verifies that exported NDJSON files can be re-imported idempotently into OpenSearch.
 *
 * <p>The same exported file is imported twice into the same target index. Because the file uses
 * the shared stable export ID in its bulk action metadata, the second import should update in
 * place rather than increasing document count.</p>
 */
@Tag("integration")
class FileExportReimportIT {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ConfigState.State previous = RuntimeConfig.getState();

    private void restoreRuntimeState() {
        RuntimeConfig.updateState(previous);
        FileExportService.resetForTests();
        OpenSearchCleanupIT.deleteExporterIndexesNow();
    }

    @Test
    void exportedNdjson_canBeImportedTwice_withoutIncreasingCount() throws Exception {
        try {
            Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

            Path root = TestPathSupport.createDirectory("file-export-reimport");
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            RuntimeConfig.updateState(fileOnlyNdjsonState(root));
            OpenSearchCleanupIT.deleteExporterIndexesNow();
            OpenSearchReachable.createSelectedIndexes(List.of("traffic"));

            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, sampleDocument());
            FileExportService.emit(prepared);

            Path ndjsonPath = root.resolve(indexName + ".ndjson");
            assertThat(ndjsonPath).exists();
            String payload = Files.readString(ndjsonPath);
            assertThat(payload).contains(
                    "{\"index\":{\"_id\":\"" + prepared.operationId() + "\"}}");
            assertThat(prepared.document().toString()).doesNotContain(prepared.operationId());

            bulkImport(indexName, payload);
            long countAfterFirst = countDocuments(indexName);

            bulkImport(indexName, payload);
            long countAfterSecond = countDocuments(indexName);

            assertThat(countAfterFirst).isEqualTo(1L);
            assertThat(countAfterSecond).isEqualTo(1L);
        } finally {
            restoreRuntimeState();
        }
    }

    private static ConfigState.State fileOnlyNdjsonState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(true, root.toString(), false, true,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false, "", "", "", false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null
        );
    }

    private static Map<String, Object> sampleDocument() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", "1");
        meta.put("indexed_at", "2026-03-28T00:00:00Z");
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("method", "GET");

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("url", "https://acme.com/reimport");
        document.put("method", "GET");
        document.put("tool", "Proxy");
        document.put("request", request);
        document.put("meta", meta);
        return document;
    }

    private static void bulkImport(String indexName, String payload) throws IOException {
        String baseUrl = OpenSearchReachable.getBaseUrl();
        String bulkUrl = (baseUrl.endsWith("/") ? baseUrl + indexName + "/_bulk" : baseUrl + "/" + indexName + "/_bulk")
                + "?refresh=wait_for";
        HttpPost post = new HttpPost(bulkUrl);
        post.setEntity(new StringEntity(payload, ContentType.create("application/x-ndjson")));
        addBasicAuthIfConfigured(post);

        CloseableHttpClient client = OpenSearchConnector.getClassicHttpClient(
                baseUrl, OpenSearchReachable.getUsername(), OpenSearchReachable.getPassword());
        client.execute(post, response -> {
            String body;
            try {
                body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse bulk response body", e);
            }
            assertThat(response.getCode()).isBetween(200, 299);
            JsonNode root = JSON.readTree(body);
            assertThat(root.path("errors").asBoolean(true)).isFalse();
            return null;
        });
    }

    private static long countDocuments(String indexName) throws IOException {
        return OpenSearchReachable.getClient().count(b -> b.index(indexName)).count();
    }

    private static void addBasicAuthIfConfigured(HttpPost post) {
        String username = OpenSearchReachable.getUsername();
        String password = OpenSearchReachable.getPassword();
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            return;
        }
        String token = Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        post.setHeader("Authorization", "Basic " + token);
    }
}
