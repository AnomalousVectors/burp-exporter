package ai.anomalousvectors.tools.burp.utils.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Discovers export field paths from search mapping JSON resources.
 *
 * <p>Object nodes with child {@code properties} are directories (structural only): they are not
 * toggleable and must not appear in the Fields panel. Scalar and leaf object fields (e.g.
 * {@code event.data}) become dotted paths such as {@code burp.reporting_tool} and {@code burp.is_in_scope}.
 * {@code nested} mappings are also directories; their parent key is included in allowed export keys
 * only when at least one descendant leaf is enabled.</p>
 */
final class MappingFieldCatalog {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Map<String, JsonNode> PROPERTIES_CACHE = new ConcurrentHashMap<>();

    private MappingFieldCatalog() { }

    /**
     * Returns the cached {@code mappings.properties} node for an index mapping resource.
     *
     * @param indexShortName index short name (for example {@code "traffic"})
     * @return properties object, or {@code null} when the resource is missing or invalid
     */
    static JsonNode readMappingProperties(String indexShortName) {
        JsonNode cached = PROPERTIES_CACHE.get(indexShortName);
        if (cached != null) {
            return cached;
        }
        String resource = SearchMappingResources.DEFAULT_ROOT + indexShortName + ".json";
        try (InputStream is = MappingFieldCatalog.class.getResourceAsStream(resource)) {
            if (is == null) {
                return null;
            }
            JsonNode root = MAPPER.readTree(is);
            JsonNode properties = root.path("mappings").path("properties");
            if (properties.isObject()) {
                PROPERTIES_CACHE.put(indexShortName, properties);
                return properties;
            }
            return null;
        } catch (IOException e) {
            return null;
        }
    }

    static boolean isMappingDirectory(JsonNode field) {
        return isDirectory(field);
    }

    static boolean isMappingLeaf(JsonNode field) {
        return isLeaf(field);
    }

    static List<String> discoverToggleableLeaves(String indexShortName) {
        List<String> leaves = new ArrayList<>();
        JsonNode properties = readMappingProperties(indexShortName);
        if (properties != null) {
            collectLeaves(indexShortName, "", properties, leaves);
        }
        return List.copyOf(leaves);
    }

    private static void collectLeaves(String indexShortName, String prefix, JsonNode propertiesNode, List<String> out) {
        for (Map.Entry<String, JsonNode> entry : propertiesNode.properties()) {
            String name = entry.getKey();
            String path = prefix.isEmpty() ? name : prefix + "." + name;
            JsonNode field = entry.getValue();
            if (isDirectory(field)) {
                collectLeaves(indexShortName, path, field.path("properties"), out);
            } else if (isLeaf(field)) {
                if (!ExportFieldRegistry.isMetaLeafPath(path)) {
                    out.add(path);
                }
            }
        }
    }

    private static boolean isDirectory(JsonNode field) {
        JsonNode childProps = field.path("properties");
        return childProps.isObject() && !childProps.isEmpty();
    }

    private static boolean isLeaf(JsonNode field) {
        return !isDirectory(field) && field.has("type");
    }

}
