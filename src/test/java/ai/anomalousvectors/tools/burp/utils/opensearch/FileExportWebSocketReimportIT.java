package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.sinks.FileExportService;
import ai.anomalousvectors.tools.burp.sinks.OpenSearchCleanupIT;
import ai.anomalousvectors.tools.burp.sinks.ProxyWebSocketIndexReporter;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.websocket.Direction;

/**
 * File-export NDJSON round-trip for nested proxy WebSocket traffic documents.
 */
@Tag("integration")
class FileExportWebSocketReimportIT {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ConfigState.State previous = RuntimeConfig.getState();

    private void restoreRuntimeState() {
        RuntimeConfig.updateState(previous);
        FileExportService.resetForTests();
        OpenSearchCleanupIT.deleteExporterIndexesNow();
    }

    @Test
    void exportedProxyWebSocketNdjson_canBeImportedTwice_withoutIncreasingCount() throws Exception {
        try {
            Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

            Path root = TestPathSupport.createDirectory("file-export-reimport-ws");
            String indexKey = "traffic";
            String indexName = IndexNaming.indexNameForShortName("traffic");
            RuntimeConfig.updateState(fileOnlyNdjsonState(root));
            OpenSearchCleanupIT.deleteExporterIndexesNow();
            OpenSearchReachable.createSelectedIndexes(List.of("traffic"));

            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            MontoyaApiProvider.set(api);

            Map<String, Object> document = proxyWebSocketSampleDocument(api);
            PreparedExportDocument prepared = ExportDocumentIdentity.prepare(indexName, indexKey, document);
            FileExportService.emit(prepared);

            Path ndjsonPath = root.resolve(indexName + ".ndjson");
            assertThat(ndjsonPath).exists();
            String payload = Files.readString(ndjsonPath);
            assertThat(payload).contains(
                    "{\"index\":{\"_id\":\"" + prepared.operationId() + "\"}}");
            assertThat(prepared.document().toString()).doesNotContain(prepared.operationId());
            assertThat(payload).contains("\"is_websocket\":true");

            bulkImport(indexName, payload);
            long countAfterFirst = countDocuments(indexName);

            bulkImport(indexName, payload);
            long countAfterSecond = countDocuments(indexName);

            assertThat(countAfterFirst).isEqualTo(1L);
            assertThat(countAfterSecond).isEqualTo(1L);
        } finally {
            MontoyaApiProvider.set(null);
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

    private static Map<String, Object> proxyWebSocketSampleDocument(MontoyaApi api) {
        ProxyWebSocketMessage ws = mock(ProxyWebSocketMessage.class);
        HttpRequest upgrade = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        ByteArray payload = mock(ByteArray.class);
        when(service.host()).thenReturn("example.com");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        when(upgrade.httpService()).thenReturn(service);
        when(upgrade.url()).thenReturn("https://example.com/ws");
        when(upgrade.httpVersion()).thenReturn("HTTP/1.1");
        when(upgrade.path()).thenReturn("/ws");
        when(upgrade.method()).thenReturn("GET");
        when(upgrade.pathWithoutQuery()).thenReturn("/ws");
        when(upgrade.query()).thenReturn("");
        when(upgrade.fileExtension()).thenReturn("");
        when(upgrade.headers()).thenReturn(List.of());
        when(upgrade.parameters()).thenReturn(List.of());
        when(upgrade.body()).thenReturn(null);
        when(upgrade.markers()).thenReturn(List.of());
        when(upgrade.contentType()).thenReturn(null);
        when(payload.getBytes()).thenReturn("ping".getBytes(StandardCharsets.UTF_8));
        when(ws.upgradeRequest()).thenReturn(upgrade);
        when(ws.id()).thenReturn(42);
        when(ws.webSocketId()).thenReturn(9);
        when(ws.listenerPort()).thenReturn(8080);
        when(ws.payload()).thenReturn(payload);
        when(ws.editedPayload()).thenReturn(null);
        when(ws.direction()).thenReturn(Direction.SERVER_TO_CLIENT);
        when(ws.time()).thenReturn(ZonedDateTime.parse("2026-03-28T12:00:00Z"));
        when(ws.annotations()).thenReturn(null);
        Object built = Objects.requireNonNull(Reflect.callStatic(
                ProxyWebSocketIndexReporter.class, "buildDocument", api, ws));
        assertThat(built).isInstanceOf(Map.class);
        Map<?, ?> raw = (Map<?, ?>) built;
        Map<String, Object> doc = new LinkedHashMap<>();
        raw.forEach((key, value) -> doc.put(String.valueOf(key), value));
        return doc;
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
        String token = java.util.Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        post.setHeader("Authorization", "Basic " + token);
    }
}
