package ai.anomalousvectors.tools.burp.sinks;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Compares an existing search index with the settings bundled for a new index.
 *
 * <p>Only settings retained by deployment adaptation are compared. Extra live settings are
 * ignored because search databases add many defaults that are not part of the extension's index
 * contract.</p>
 */
final class SearchIndexSettingsCompatibility {

    private static final ObjectMapper JSON = new ObjectMapper();

    private SearchIndexSettingsCompatibility() {
        throw new AssertionError("No instances");
    }

    static boolean isSettingsReadPermissionDenied(int status) {
        return status == 401 || status == 403;
    }

    /**
     * Returns an actionable mismatch description, or {@code null} when settings are compatible.
     *
     * @param expectedMappingJson adapted bundled mapping JSON
     * @param liveSettingsJson response from {@code GET /index/_settings?flat_settings=true}
     * @param indexName full index name
     * @return mismatch detail, or {@code null}
     */
    static String incompatibilityDetail(
            String expectedMappingJson, String liveSettingsJson, String indexName) {
        try {
            JsonNode expectedSettings = JSON.readTree(expectedMappingJson).path("settings");
            JsonNode liveRoot = JSON.readTree(liveSettingsJson);
            JsonNode liveSettings = liveRoot.path(indexName).path("settings");
            if (!expectedSettings.isObject()) {
                return "Bundled mapping has no object-valued settings.";
            }
            if (!liveSettings.isObject()) {
                return "Existing index settings could not be read.";
            }

            List<String> mismatches = new ArrayList<>();
            for (Map.Entry<String, JsonNode> expected : expectedSettings.properties()) {
                String liveKey = "index." + expected.getKey();
                JsonNode liveValue = liveSettings.get(liveKey);
                if (liveValue == null) {
                    liveValue = liveSettings.get(expected.getKey());
                }
                String expectedValue = scalarText(expected.getValue());
                String actualValue = liveValue == null ? "<missing>" : scalarText(liveValue);
                if (!expectedValue.equals(actualValue)) {
                    mismatches.add(liveKey + "=" + actualValue + " (expected " + expectedValue + ")");
                }
            }
            if (mismatches.isEmpty()) {
                return null;
            }
            return "Existing index settings are incompatible: "
                    + String.join(", ", mismatches)
                    + ". Delete/recreate the index or correct its settings before Start.";
        } catch (JsonProcessingException | RuntimeException e) {
            String message = e.getMessage();
            return "Existing index settings compatibility check failed: "
                    + (message == null || message.isBlank() ? e.getClass().getSimpleName() : message);
        }
    }

    private static String scalarText(JsonNode value) {
        return value != null && value.isTextual() ? value.textValue() : String.valueOf(value);
    }
}
