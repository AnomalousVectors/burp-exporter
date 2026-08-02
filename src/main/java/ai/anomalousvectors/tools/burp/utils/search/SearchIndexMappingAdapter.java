package ai.anomalousvectors.tools.burp.utils.search;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

/**
 * Adapts bundled index settings to the selected search deployment.
 *
 * <p>Bundled resources retain hosted and self-hosted defaults. Serverless index creation removes
 * unsupported shard and replica-allocation settings. Amazon OpenSearch Serverless also raises the
 * bundled refresh interval to its ten-second minimum.</p>
 *
 * <p>Stateless and thread-safe.</p>
 */
public final class SearchIndexMappingAdapter {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String AMAZON_SERVERLESS_REFRESH_INTERVAL = "10s";

    private SearchIndexMappingAdapter() {
        throw new AssertionError("No instances");
    }

    /**
     * Returns mapping JSON suitable for the selected deployment.
     *
     * @param mappingJson bundled mapping JSON; required when serverless adaptation applies
     * @param destination selected database destination; {@code null} is generic OpenSearch
     * @param baseUrl selected endpoint URL used for auto-detection; may be {@code null}
     * @param deploymentType configured deployment type; null or unknown selects auto-detection
     * @return original JSON for non-serverless destinations, otherwise adapted JSON
     * @throws IllegalArgumentException when serverless adaptation receives malformed mapping JSON
     */
    public static String adapt(
            String mappingJson,
            ConfigState.SearchDestination destination,
            String baseUrl,
            String deploymentType) {
        if (!isServerless(destination, baseUrl, deploymentType)) {
            return mappingJson;
        }
        try {
            JsonNode parsed = JSON.readTree(mappingJson);
            if (!(parsed instanceof ObjectNode root)
                    || !(root.get("settings") instanceof ObjectNode settings)) {
                throw new IllegalArgumentException(
                        "Mapping JSON must contain an object-valued 'settings' member.");
            }
            settings.remove("number_of_shards");
            settings.remove("auto_expand_replicas");
            if (destination == ConfigState.SearchDestination.OPEN_SEARCH_AMAZON) {
                settings.put("refresh_interval", AMAZON_SERVERLESS_REFRESH_INTERVAL);
            }
            return JSON.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(
                    "Mapping JSON could not be adapted for Serverless.", e);
        }
    }

    private static boolean isServerless(
            ConfigState.SearchDestination destination,
            String baseUrl,
            String deploymentType) {
        if (destination == null || destination == ConfigState.SearchDestination.OPEN_SEARCH) {
            return false;
        }
        String deployment = ConfigState.normalizeDeploymentType(deploymentType);
        if (ConfigState.DEPLOYMENT_AUTO.equals(deployment)) {
            deployment = destination == ConfigState.SearchDestination.OPEN_SEARCH_AMAZON
                    ? SearchDeployment.detectAmazonOpenSearchDeploymentType(baseUrl)
                    : SearchDeployment.detectElasticsearchDeploymentType(baseUrl);
        }
        return ConfigState.DEPLOYMENT_SERVERLESS.equals(deployment);
    }
}
