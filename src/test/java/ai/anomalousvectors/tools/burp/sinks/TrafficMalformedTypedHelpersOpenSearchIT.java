package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.JsonNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch.core.CountResponse;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.RefreshRequest;
import org.opensearch.client.json.JsonData;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;

@Tag("integration")
@ResourceLock("traffic-opensearch-index")
class TrafficMalformedTypedHelpersOpenSearchIT {

    @AfterEach
    public void cleanup() {
        deleteIndex("traffic");
    }

    @Test
    void typedResponseHelpers_indexCommonDates_andIgnoreMalformedValuesWithoutRejectingDocument() throws IOException {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        deleteIndex("traffic");
        createIndex("traffic");

        OpenSearchClient client = OpenSearchReachable.getClient();
        String indexName = IndexNaming.indexNameForShortName("traffic");
        Map<String, Object> normalDocument = Map.of(
                "request", Map.of(
                        "url", Map.of(
                                "raw", "https://example.com/normal-date",
                                "text", "https://example.com/normal-date")),
                "response", Map.of(
                        "headers", List.of(Map.of(
                                "name", "date",
                                "raw", "Date",
                                "value", "Fri, 27 Feb 2026 04:49:21 GMT",
                                "ordinal", 0)),
                        "header_attributes", Map.of("date", "Fri, 27 Feb 2026 04:49:21 GMT"),
                        "cookies", List.of(Map.of(
                                "name", "sid",
                                "value", "abc",
                                "expires", "Mon, 05-Oct-26 17:18:25 GMT",
                                "max_age", "15724800",
                                "raw", "sid=abc; Expires=Mon, 05-Oct-26 17:18:25 GMT; Max-Age=15724800",
                                "ordinal", 0))));
        Map<String, Object> observedVariantDocument = Map.of(
                "request", Map.of(
                        "url", Map.of(
                                "raw", "https://example.com/observed-date-variant",
                                "text", "https://example.com/observed-date-variant")),
                "response", Map.of(
                        "headers", List.of(Map.of(
                                "name", "date",
                                "raw", "Date",
                                "value", "Mon, 6 Apr 2026 14:59:38 GMT",
                                "ordinal", 0)),
                        "header_attributes", Map.of("date", "Mon, 6 Apr 2026 14:59:38 GMT"),
                        "cookies", List.of(Map.of(
                                "name", "sid",
                                "value", "abc",
                                "expires", "Sun, 13-Sep-2026 05:22:25 GMT",
                                "max_age", "15724800",
                                "raw", "sid=abc; Expires=Sun, 13-Sep-2026 05:22:25 GMT; Max-Age=15724800",
                                "ordinal", 0))));
        Map<String, Object> cookieEdgeVariantDocument = Map.of(
                "request", Map.of(
                        "url", Map.of(
                                "raw", "https://example.com/cookie-edge-date-variant",
                                "text", "https://example.com/cookie-edge-date-variant")),
                "response", Map.of(
                        "headers", List.of(Map.of(
                                "name", "date",
                                "raw", "Date",
                                "value", "Thu, 5 Feb 2026 20:32:05 GMT",
                                "ordinal", 0)),
                        "header_attributes", Map.of("date", "Thu, 5 Feb 2026 20:32:05 GMT"),
                        "cookies", List.of(
                                Map.of(
                                        "name", "browser",
                                        "value", "abc",
                                        "expires", "2026-09-18T01:39:10Z",
                                        "max_age", "7776000",
                                        "raw", "browser=abc; Expires=Fri Sep 18 2026 01:39:10 GMT+0000"
                                                + " (Coordinated Universal Time); Max-Age=7776000",
                                        "ordinal", 0),
                                Map.of(
                                        "name", "offset",
                                        "value", "abc",
                                        "expires", "Fri, 05-Feb-2027 20:32:14 GMT+0000",
                                        "max_age", "2592000000",
                                        "raw", "offset=abc; Expires=Fri, 05-Feb-2027 20:32:14 GMT+0000;"
                                                + " Max-Age=2592000000",
                                        "ordinal", 1),
                                Map.of(
                                        "name", "barez",
                                        "value", "abc",
                                        "expires", "05 Feb 2028 20:32:01 Z",
                                        "max_age", "31536000",
                                        "raw", "barez=abc; Expires=05 Feb 2028 20:32:01 Z; Max-Age=31536000",
                                        "ordinal", 2))));
        Map<String, Object> malformedDocument = Map.of(
                "request", Map.of(
                        "url", Map.of(
                                "raw", "https://example.com/malformed-cookie",
                                "text", "https://example.com/malformed-cookie")),
                "response", Map.of(
                        "headers", List.of(Map.of(
                                "name", "date",
                                "raw", "Date",
                                "value", "not a valid date",
                                "ordinal", 0)),
                        "header_attributes", Map.of("date", "not a valid date"),
                        "cookies", List.of(Map.of(
                                "name", "sid",
                                "value", "abc",
                                "expires", "not a valid cookie date",
                                "max_age", "not an integer",
                                "raw", "sid=abc; Expires=not a valid cookie date; Max-Age=not an integer",
                                "ordinal", 0))));

        client.index(i -> i.index(indexName).id("normal").document(normalDocument));
        client.index(i -> i.index(indexName).id("observed-variant").document(observedVariantDocument));
        client.index(i -> i.index(indexName).id("cookie-edge-variant").document(cookieEdgeVariantDocument));
        client.index(i -> i.index(indexName).id("malformed").document(malformedDocument));
        client.indices().refresh(new RefreshRequest.Builder().index(indexName).build());

        assertThat(countDateRange(client, indexName, "response.header_attributes.date")).isEqualTo(3L);
        assertThat(countNestedDateRange(client, indexName, "response.cookies", "response.cookies.expires"))
                .isEqualTo(3L);
        assertThat(countNestedLongRange(client, indexName, "response.cookies", "response.cookies.max_age"))
                .isEqualTo(1L);
        assertThat(countForIgnoredField(client, indexName, "response.cookies.expires")).isEqualTo(1L);
        assertThat(countForIgnoredField(client, indexName, "response.cookies.max_age")).isEqualTo(1L);
        assertThat(countForIgnoredField(client, indexName, "response.header_attributes.date")).isEqualTo(1L);

        JsonNode source = sourceForIgnoredField(client, indexName, "response.cookies.expires");
        JsonNode cookie = source.path("response").path("cookies").get(0);
        assertThat(cookie.path("expires").asString()).isEqualTo("not a valid cookie date");
        assertThat(cookie.path("max_age").asString()).isEqualTo("not an integer");
        assertThat(source.path("response").path("header_attributes").path("date").asString())
                .isEqualTo("not a valid date");

    }

    private static long countNestedLongRange(
            OpenSearchClient client,
            String indexName,
            String nestedPath,
            String longField) throws IOException {
        CountResponse response = client.count(c -> c
                .index(indexName)
                .query(q -> q.nested(n -> n
                        .path(nestedPath)
                        .query(nq -> nq.range(r -> r
                                .field(longField)
                                .gte(JsonData.of(2_147_483_648L)))))));
        return response.count();
    }

    private static long countDateRange(
            OpenSearchClient client,
            String indexName,
            String dateField) throws IOException {
        CountResponse response = client.count(c -> c
                .index(indexName)
                .query(q -> q.range(r -> r
                        .field(dateField)
                        .gte(JsonData.of("2026-01-01T00:00:00Z")))));
        return response.count();
    }

    private static long countNestedDateRange(
            OpenSearchClient client,
            String indexName,
            String nestedPath,
            String dateField) throws IOException {
        CountResponse response = client.count(c -> c
                .index(indexName)
                .query(q -> q.nested(n -> n
                        .path(nestedPath)
                        .query(nq -> nq.range(r -> r
                                .field(dateField)
                                .gte(JsonData.of("2026-01-01T00:00:00Z")))))));
        return response.count();
    }

    private static long countForIgnoredField(
            OpenSearchClient client,
            String indexName,
            String ignoredField) throws IOException {
        CountResponse response = client.count(c -> c
                .index(indexName)
                .query(q -> q.term(t -> t
                        .field("_ignored")
                        .value(FieldValue.of(ignoredField)))));
        return response.count();
    }

    private static JsonNode sourceForIgnoredField(
            OpenSearchClient client,
            String indexName,
            String ignoredField) throws IOException {
        SearchResponse<JsonNode> response = client.search(s -> s
                        .index(indexName)
                        .query(q -> q.term(t -> t
                                .field("_ignored")
                                .value(FieldValue.of(ignoredField)))),
                JsonNode.class);
        assertThat(response.hits().hits())
                .as("documents with _ignored=" + ignoredField)
                .isNotEmpty();
        return response.hits().hits().getFirst().source();
    }
}
