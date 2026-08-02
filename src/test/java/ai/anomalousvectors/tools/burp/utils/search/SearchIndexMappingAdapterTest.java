package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

class SearchIndexMappingAdapterTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MAPPING = """
            {
              "settings": {
                "number_of_shards": 1,
                "auto_expand_replicas": "0-1",
                "refresh_interval": "5s"
              },
              "mappings": {"dynamic": true}
            }
            """;

    @Test
    void adapt_amazonServerless_removesUnsupportedSettings() throws Exception {
        String adapted = SearchIndexMappingAdapter.adapt(
                MAPPING,
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON,
                "https://collection.us-east-1.aoss.amazonaws.com",
                ConfigState.DEPLOYMENT_AUTO);

        assertServerlessSettings(JSON.readTree(adapted), "10s");
    }

    @Test
    void adapt_elasticsearchServerless_removesUnsupportedSettings() throws Exception {
        String adapted = SearchIndexMappingAdapter.adapt(
                MAPPING,
                ConfigState.SearchDestination.ELASTICSEARCH,
                "https://project.es.us-east-1.aws.elastic.cloud",
                ConfigState.DEPLOYMENT_AUTO);

        assertServerlessSettings(JSON.readTree(adapted), "5s");
    }

    @Test
    void adapt_amazonHosted_retainsHostedDefaults() throws Exception {
        String adapted = SearchIndexMappingAdapter.adapt(
                MAPPING,
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON,
                "https://search-example.us-east-1.es.amazonaws.com",
                ConfigState.DEPLOYMENT_HOSTED);

        assertHostedSettings(JSON.readTree(adapted));
    }

    @Test
    void adapt_elasticsearchHosted_retainsHostedDefaults() throws Exception {
        String adapted = SearchIndexMappingAdapter.adapt(
                MAPPING,
                ConfigState.SearchDestination.ELASTICSEARCH,
                "https://example.us-east4.gcp.elastic-cloud.com",
                ConfigState.DEPLOYMENT_HOSTED);

        assertHostedSettings(JSON.readTree(adapted));
    }

    @Test
    void adapt_genericOpenSearch_retainsHostedDefaults() throws Exception {
        String adapted = SearchIndexMappingAdapter.adapt(
                MAPPING,
                ConfigState.SearchDestination.OPEN_SEARCH,
                "https://opensearch.url:9200",
                ConfigState.DEPLOYMENT_AUTO);

        assertHostedSettings(JSON.readTree(adapted));
    }

    private static void assertServerlessSettings(JsonNode root, String expectedRefreshInterval) {
        JsonNode settings = root.path("settings");
        assertThat(settings.has("number_of_shards")).isFalse();
        assertThat(settings.has("auto_expand_replicas")).isFalse();
        assertThat(settings.path("refresh_interval").asText()).isEqualTo(expectedRefreshInterval);
        assertThat(root.path("mappings").path("dynamic").asBoolean()).isTrue();
    }

    private static void assertHostedSettings(JsonNode root) {
        JsonNode settings = root.path("settings");
        assertThat(settings.path("number_of_shards").asInt()).isEqualTo(1);
        assertThat(settings.path("auto_expand_replicas").asText()).isEqualTo("0-1");
        assertThat(settings.path("refresh_interval").asText()).isEqualTo("5s");
        assertThat(root.path("mappings").path("dynamic").asBoolean()).isTrue();
    }
}
