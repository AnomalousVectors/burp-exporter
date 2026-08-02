package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Iterator;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Compares bundled mapping requirements with an existing search index mapping.
 *
 * <p>Existing mappings may contain additional dynamically discovered fields. Compatibility
 * therefore requires every bundled mapping node to exist with the same value, but ignores extra
 * live nodes.</p>
 */
final class SearchIndexMappingCompatibility {

    private static final ObjectMapper JSON = new ObjectMapper();

    private SearchIndexMappingCompatibility() {
    }

    /**
     * Returns the first mapping incompatibility, or {@code null} when the live mapping contains
     * every bundled requirement.
     *
     * @param expectedIndexJson adapted bundled index JSON
     * @param liveMappingJson response from {@code GET /index/_mapping}
     * @param fullIndexName concrete index name
     * @return actionable incompatibility detail, or {@code null}
     * @throws IOException when either response is not valid JSON
     */
    static String incompatibilityDetail(
            String expectedIndexJson,
            String liveMappingJson,
            String fullIndexName) throws IOException {
        JsonNode expected = JSON.readTree(expectedIndexJson).path("mappings");
        JsonNode liveRoot = JSON.readTree(liveMappingJson);
        JsonNode liveIndex = liveRoot.path(fullIndexName);
        if (liveIndex.isMissingNode() && liveRoot.size() == 1) {
            liveIndex = liveRoot.elements().next();
        }
        JsonNode live = liveIndex.path("mappings");
        if (expected.isMissingNode() || !expected.isObject()) {
            return "Bundled mapping is missing the mappings object.";
        }
        if (live.isMissingNode() || !live.isObject()) {
            return "Existing index mapping response is missing mappings for " + fullIndexName + ".";
        }
        return compareRequiredNode(expected, live, "mappings");
    }

    private static String compareRequiredNode(JsonNode expected, JsonNode live, String path) {
        if (expected.isObject()) {
            if (!live.isObject()) {
                return "Existing index mapping differs at " + path + ": expected object.";
            }
            Iterator<Map.Entry<String, JsonNode>> fields = expected.properties().iterator();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String childPath = path + "." + field.getKey();
                JsonNode actual = live.get(field.getKey());
                if (actual == null) {
                    if (isOmittedEngineDefault(field.getKey(), field.getValue())) {
                        continue;
                    }
                    return "Existing index mapping is missing " + childPath + ".";
                }
                String mismatch = compareRequiredNode(field.getValue(), actual, childPath);
                if (mismatch != null) {
                    return mismatch;
                }
            }
            return null;
        }
        if (!equivalentScalar(expected, live)) {
            return "Existing index mapping differs at " + path
                    + ": expected " + expected + ", found " + live + ".";
        }
        return null;
    }

    private static boolean isOmittedEngineDefault(String fieldName, JsonNode expected) {
        if ("type".equals(fieldName)) {
            return expected.isTextual() && "object".equals(expected.textValue());
        }
        if ("enabled".equals(fieldName) || "index".equals(fieldName)) {
            return expected.isBoolean() && expected.booleanValue();
        }
        if ("doc_values".equals(fieldName) || "store".equals(fieldName)) {
            return expected.isBoolean() && !expected.booleanValue();
        }
        return false;
    }

    private static boolean equivalentScalar(JsonNode expected, JsonNode live) {
        if (expected.equals(live)) {
            return true;
        }
        if (expected.isBoolean() && live.isTextual()) {
            return Boolean.toString(expected.booleanValue()).equalsIgnoreCase(live.textValue());
        }
        if (expected.isTextual() && live.isBoolean()) {
            return expected.textValue().equalsIgnoreCase(Boolean.toString(live.booleanValue()));
        }
        if (expected.isNumber() && live.isTextual()) {
            return equivalentNumber(expected.asText(), live.textValue());
        }
        if (expected.isTextual() && live.isNumber()) {
            return equivalentNumber(expected.textValue(), live.asText());
        }
        return false;
    }

    private static boolean equivalentNumber(String left, String right) {
        try {
            return new BigDecimal(left).compareTo(new BigDecimal(right)) == 0;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }
}
