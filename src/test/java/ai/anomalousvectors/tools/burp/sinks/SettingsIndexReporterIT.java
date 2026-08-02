package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.Version;
import burp.api.montoya.project.Project;

/**
 * Integration test: {@link SettingsIndexReporter} pushes a document to the
 * settings index when export is running and Burp API is available. Uses the
 * real OpenSearch instance at {@value #BASE_URL}; mocks Burp's MontoyaApi to
 * supply project/user JSON and project id. Verifies document shape and content
 * after round-trip. Uses real OpenSearch at {@value #BASE_URL}; run with full
 * test task or exclude with {@code -PexcludeIntegration} to skip.
 */
@Tag("integration")
class SettingsIndexReporterIT {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;

    private static final String PROJECT_JSON = "{\"project_options\":{\"test_key\":\"project_value\"}}";
    private static final String USER_JSON = "{\"user_options\":{\"test_key\":\"user_value\"}}";
    private static final String PROJECT_ID = "it-settings-project-id";

    private static String settingsIndexName() {
        return IndexNaming.indexNameForShortName("settings");
    }

    private void cleanup() {
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
        OpenSearchClient client = OpenSearchReachable.getClient();
        try {
            client.indices().delete(new DeleteIndexRequest.Builder().index(settingsIndexName()).build());
        } catch (IOException e) {
            Logger.logError("[SettingsIndexReporterIT] Failed to delete index during cleanup: " + settingsIndexName(), e);
        }
    }

    @Test
    void pushSnapshotNow_indexesDocument_withExpectedShapeAndContent() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        try {
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            createSettingsIndex();
            setRuntimeConfigForSettingsExport();
            setMockMontoyaApi();

            SettingsIndexReporter.pushSnapshotNow();

            Map<String, Object> doc = awaitFirstDocument();
            assertThat(doc).isNotNull();
            assertThat(doc).containsKey("burp");
            assertThat(doc).containsKey("project");
            assertThat(doc).containsKey("user");
            assertThat(doc).containsKey("meta");

            Map<?, ?> burp = nestedMap(doc, "burp");
            assertThat(burp.get("project_id")).isEqualTo(PROJECT_ID);
            assertThat(burp.containsKey("version")).isTrue();

            Map<?, ?> settingsProject = nestedMap(doc, "project");
            assertThat(settingsProject.get("project_options")).isEqualTo(Map.of("test_key", "project_value"));

            Map<?, ?> settingsUser = nestedMap(doc, "user");
            assertThat(settingsUser.get("user_options")).isEqualTo(Map.of("test_key", "user_value"));

            Map<?, ?> meta = nestedMap(doc, "meta");
            assertContainsKeys(meta, "schema_version", "extension_version", "indexed_at");
        } finally {
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            cleanup();
        }
    }

    private void createSettingsIndex() {
        List<OpenSearchSink.IndexResult> results = OpenSearchReachable.createSelectedIndexes(List.of("settings"));
        assertThat(results).isNotEmpty();
        boolean settingsCreated = results.stream()
                .anyMatch(r -> r.shortName().equals("settings") && (r.status() == OpenSearchSink.IndexResult.Status.CREATED || r.status() == OpenSearchSink.IndexResult.Status.EXISTS));
        assertThat(settingsCreated).as("settings index created or exists").isTrue();
    }

    private void setRuntimeConfigForSettingsExport() {
        ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig config = ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig.get();
        ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, BASE_URL, config.username(), config.password(), false);
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                sinks,
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
        RuntimeConfig.updateState(state);
        RuntimeConfig.setExportRunning(true);
    }

    private void setMockMontoyaApi() {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Version version = mock(Version.class);
        Project project = mock(Project.class);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(api.project()).thenReturn(project);
        when(burpSuite.version()).thenReturn(version);
        when(version.toString()).thenReturn("2026.4");
        when(burpSuite.exportProjectOptionsAsJson()).thenReturn(PROJECT_JSON);
        when(burpSuite.exportUserOptionsAsJson()).thenReturn(USER_JSON);
        when(project.id()).thenReturn(PROJECT_ID);
        MontoyaApiProvider.set(api);
    }

    /**
     * Refreshes the settings index and searches until at least one document is
     * found or the retry limit is reached (handles refresh latency when cluster
     * is under load, e.g. in the integration suite).
     */
    private Map<String, Object> awaitFirstDocument() {
        OpenSearchClient client = OpenSearchReachable.getClient();
        SearchRequest req = new SearchRequest.Builder()
                .index(settingsIndexName())
                .size(1)
                .build();
        int maxAttempts = 5;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(settingsIndexName()).build());
            } catch (IOException ignored) {
                // best-effort refresh
            }
            try {
                SearchResponse<JsonNode> resp = client.search(req, JsonNode.class);
                List<?> hits = resp.hits().hits();
                if (!hits.isEmpty()) {
                    JsonNode source = resp.hits().hits().get(0).source();
                    if (source != null) {
                        return JSON.convertValue(source, new TypeReference<Map<String, Object>>() { });
                    }
                }
            } catch (IOException e) {
                throw new AssertionError("Search failed: " + e.getMessage(), e);
            }
            if (i < maxAttempts - 1) {
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(300));
            }
        }
        throw new AssertionError("at least one document indexed (after " + maxAttempts + " attempts)");
    }

    private static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        Object value = parent.get(key);
        assertThat(value).isInstanceOf(Map.class);
        return (Map<?, ?>) value;
    }

    private static void assertContainsKeys(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            assertThat(map.containsKey(key)).isTrue();
        }
    }
}
