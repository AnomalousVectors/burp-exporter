package ai.anomalousvectors.tools.burp.testutils;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.query_dsl.Query;
import org.opensearch.client.opensearch.core.CountRequest;
import org.opensearch.client.opensearch.core.CountResponse;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import ai.anomalousvectors.tools.burp.sinks.SearchSink;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.search.SearchClientWrapper;

/**
 * Shared helpers for integration tests that index partially field-filtered documents
 * against the configured OpenSearch test cluster.
 */
public final class PartialFieldOpenSearchTestSupport {

    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();
    private static final Object TRAFFIC_INDEX_IT_LOCK = new Object();
    private static final int AWAIT_INDEX_ATTEMPTS = 120;
    private static final long AWAIT_INDEX_SLEEP_MS = 250L;

    private PartialFieldOpenSearchTestSupport() {}

    private static Object lockFor(String indexShortName) {
        return "traffic".equals(indexShortName) ? TRAFFIC_INDEX_IT_LOCK : indexShortName.intern();
    }

    /** Configured cluster base URL ({@link OpenSearchTestConfig#get()}). */
    public static String baseUrl() {
        return OpenSearchTestConfig.get().baseUrl();
    }

    /** Builds {@link ConfigState.Sinks} aimed at {@link #baseUrl()} with test-cluster credentials. */
    public static ConfigState.Sinks openSearchSinks() {
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        return new ConfigState.Sinks(false, "", true, config.baseUrl(), config.username(), config.password(), false);
    }

    /**
     * Creates the OpenSearch index for {@code indexShortName} using mapping resources.
     */
    public static void createIndex(String indexShortName) {
        synchronized (lockFor(indexShortName)) {
            createIndexLocked(indexShortName);
        }
    }

    private static void createIndexLocked(String indexShortName) {
        List<SearchSink.IndexResult> results =
                OpenSearchReachable.createSelectedIndexes(List.of(indexShortName));
        assertThat(results).isNotEmpty();
        boolean created = results.stream()
                .anyMatch(r -> r.shortName().equals(indexShortName)
                        && (r.status() == SearchSink.IndexResult.Status.CREATED
                                || r.status() == SearchSink.IndexResult.Status.EXISTS));
        assertThat(created).as(indexShortName + " index created or exists").isTrue();
    }

    /** Deletes the test index for {@code indexShortName}; ignores missing-index errors. */
    public static void deleteIndex(String indexShortName) {
        synchronized (lockFor(indexShortName)) {
            deleteIndexLocked(indexShortName);
        }
    }

    private static void deleteIndexLocked(String indexShortName) {
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        try {
            OpenSearchReachable.getClient().indices().delete(
                    new DeleteIndexRequest.Builder().index(indexName).build());
        } catch (IOException | RuntimeException ignored) {
            // Cleanup is best-effort between integration tests.
        }
    }

    /**
     * Applies {@code runtimeState}, pushes one filtered document, and returns the prepared export.
     */
    public static PreparedExportDocument pushOneDocument(
            String indexShortName,
            Map<String, Object> built,
            ConfigState.State runtimeState) {
        synchronized (lockFor(indexShortName)) {
            return pushOneDocumentLocked(indexShortName, built, runtimeState);
        }
    }

    /**
     * Pushes one document and polls until the matching indexed document is visible, atomically
     * for {@code indexShortName} so parallel integration tests cannot delete the index mid-flight.
     *
     * @param indexShortName index short name (for example {@code "traffic"})
     * @param built full document before field filtering
     * @param runtimeState config applied before push
     * @param matchField OpenSearch term field (for example {@code issue.name.raw}); use keyword subfields
     *     for analyzed text paths
     * @param matchValue term value to await
     * @return indexed document source map
     */
    public static Map<String, Object> pushAndAwaitIndexedDocument(
            String indexShortName,
            Map<String, Object> built,
            ConfigState.State runtimeState,
            String matchField,
            Object matchValue) {
        synchronized (lockFor(indexShortName)) {
            deleteIndexLocked(indexShortName);
            createIndexLocked(indexShortName);
            pushOneDocumentLocked(indexShortName, built, runtimeState);
            return awaitIndexedDocumentLocked(indexShortName, matchField, matchValue);
        }
    }

    private static PreparedExportDocument pushOneDocumentLocked(
            String indexShortName,
            Map<String, Object> built,
            ConfigState.State runtimeState) {
        RuntimeConfig.updateState(runtimeState);
        RuntimeConfig.setExportRunning(true);
        RuntimeConfig.setExportStarting(false);
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        PreparedExportDocument prepared =
                ExportDocumentIdentity.prepare(indexName, indexShortName, built);
        BulkPushOutcome outcome = SearchClientWrapper.pushPreparedBulk(
                baseUrl(), indexName, indexShortName, List.of(prepared));
        assertThat(outcome.exportedCount())
                .as("OpenSearch exported docs for " + indexShortName)
                .isEqualTo(1);
        refreshIndexForSearch(indexShortName);
        return prepared;
    }

    private static void refreshIndexForSearch(String indexShortName) {
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        try {
            OpenSearchReachable.getClient().indices().refresh(
                    new RefreshRequest.Builder().index(indexName).build());
        } catch (IOException | RuntimeException ignored) {
            // Best-effort; polling loop retries refresh.
        }
    }

    /**
     * Polls OpenSearch until at least one document is visible in {@code indexShortName}.
     *
     * <p>Prefer {@link #awaitIndexedDocument(String, String, Object)} when parallel integration
     * tests share an index.</p>
     */
    public static Map<String, Object> awaitSingleIndexedDocument(String indexShortName) {
        return awaitIndexedDocument(indexShortName, null, null);
    }

    /** Polls OpenSearch until a document matching {@code matchField}={@code matchValue} is visible.
     */
    public static Map<String, Object> awaitIndexedDocument(
            String indexShortName, String matchField, Object matchValue) {
        synchronized (lockFor(indexShortName)) {
            return awaitIndexedDocumentLocked(indexShortName, matchField, matchValue);
        }
    }

    /**
     * Returns the document count for {@code indexShortName}, refreshing the index first.
     *
     * @param indexShortName index short name
     * @return number of documents in the index
     */
    public static long documentCount(String indexShortName) {
        synchronized (lockFor(indexShortName)) {
            return documentCountLocked(indexShortName);
        }
    }

    private static long documentCountLocked(String indexShortName) {
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        refreshIndexForSearch(indexShortName);
        try {
            CountResponse response = OpenSearchReachable.getClient().count(
                    CountRequest.of(c -> c.index(indexName)));
            return response.count();
        } catch (IOException e) {
            throw new AssertionError("Count failed for " + indexShortName + ": " + e.getMessage(), e);
        }
    }

    /**
     * Polls OpenSearch until a document matching {@code matchField}={@code matchValue} is visible.
     */
    private static Map<String, Object> awaitIndexedDocumentLocked(
            String indexShortName, String matchField, Object matchValue) {
        String indexName = IndexNaming.indexNameForShortName(indexShortName);
        OpenSearchClient client = OpenSearchReachable.getClient();
        SearchRequest.Builder requestBuilder = new SearchRequest.Builder()
                .index(indexName)
                .size(1);
        if (matchField != null && matchValue != null) {
            Query termQuery = Query.of(q -> q.term(t -> t
                    .field(matchField)
                    .value(toFieldValue(matchValue))));
            requestBuilder.query(termQuery);
        }
        SearchRequest request = requestBuilder.build();
        for (int attempt = 0; attempt < AWAIT_INDEX_ATTEMPTS; attempt++) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(indexName).build());
            } catch (IOException | RuntimeException ignored) {
                // Refresh before search is best-effort; polling retries on the next attempt.
            }
            try {
                SearchResponse<JsonNode> response = client.search(request, JsonNode.class);
                if (!response.hits().hits().isEmpty()) {
                    JsonNode sourceNode = response.hits().hits().getFirst().source();
                    if (sourceNode != null) {
                        return JSON.convertValue(sourceNode, new TypeReference<Map<String, Object>>() { });
                    }
                }
            } catch (IOException | RuntimeException e) {
                throw new AssertionError("Search failed: " + e.getMessage(), e);
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(AWAIT_INDEX_SLEEP_MS));
        }
        String detail = matchField == null
                ? indexShortName
                : indexShortName + " where " + matchField + "=" + matchValue;
        throw new AssertionError("No document indexed in " + detail);
    }

    private static FieldValue toFieldValue(Object value) {
        if (value instanceof String s) {
            return FieldValue.of(s);
        }
        if (value instanceof Boolean b) {
            return FieldValue.of(b);
        }
        if (value instanceof Integer i) {
            return FieldValue.of(i.longValue());
        }
        if (value instanceof Long l) {
            return FieldValue.of(l);
        }
        if (value instanceof Double d) {
            return FieldValue.of(d);
        }
        return FieldValue.of(String.valueOf(value));
    }

    /** Asserts {@code key} is a nested map and returns it. */
    public static Map<?, ?> nestedMap(Map<?, ?> parent, String key) {
        assertThat(parent.get(key)).isInstanceOf(Map.class);
        return (Map<?, ?>) parent.get(key);
    }

    /** Asserts {@code value} is a list of string-keyed maps and returns defensive copies. */
    public static List<Map<String, Object>> stringObjectMapList(Object value) {
        assertThat(value).isInstanceOf(List.class);
        return ((List<?>) value).stream()
                .map(PartialFieldOpenSearchTestSupport::stringObjectMap)
                .toList();
    }

    private static Map<String, Object> stringObjectMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        Map<String, Object> copy = new LinkedHashMap<>();
        ((Map<?, ?>) value).forEach((key, mapValue) -> {
            assertThat(key).isInstanceOf(String.class);
            copy.put((String) key, mapValue);
        });
        return copy;
    }
}
