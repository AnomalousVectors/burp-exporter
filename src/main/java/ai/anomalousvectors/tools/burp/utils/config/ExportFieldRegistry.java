package ai.anomalousvectors.tools.burp.utils.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Defines the canonical export fields for each index.
 *
 * <p>This registry backs both the Fields panel and document filtering. Toggleable field keys are
 * discovered automatically from mapping JSON leaf paths (directories such as {@code burp} are
 * omitted; children like {@code burp.reporting_tool} are shown). Meta and response-body omission
 * semantics are required, so field filtering cannot conceal a deliberate capture limit.</p>
 */
public final class ExportFieldRegistry {

    private static final Map<String, List<String>> TOGGLEABLE_BY_INDEX = new LinkedHashMap<>();
    private static final Map<String, List<String>> REQUIRED_DISPLAY_BY_INDEX = new LinkedHashMap<>();
    private static final Map<String, List<String>> SYSTEM_BY_INDEX = new LinkedHashMap<>();

    /** Meta leaves always exported and shown as required (non-toggleable) in the Fields panel. */
    public static final List<String> META_LEAF_PATHS = List.of(
            "meta.schema_version",
            "meta.extension_version",
            "meta.indexed_at");

    /** Identity and observation semantics required to interpret immutable traffic snapshots. */
    public static final List<String> TRAFFIC_CAPTURE_LEAF_PATHS = List.of(
            "meta.capture.id", "meta.capture.source", "meta.capture.revision",
            "meta.capture.observed_at", "meta.capture.window_ends_at", "meta.capture.response_state",
            "meta.capture.observation_state", "meta.capture.grpc_status_state");

    static {
        for (String index : List.of("exporter", "traffic", "settings", "sitemap", "findings")) {
            TOGGLEABLE_BY_INDEX.put(index, MappingFieldCatalog.discoverToggleableLeaves(index));
            List<String> required = new ArrayList<>(META_LEAF_PATHS);
            if ("traffic".equals(index)) required.addAll(TRAFFIC_CAPTURE_LEAF_PATHS);
            List<String> bodyPolicy = bodyPolicyPaths(index);
            required.addAll(bodyPolicy);
            List<String> system = new ArrayList<>(List.of("meta"));
            system.addAll(bodyPolicy);
            SYSTEM_BY_INDEX.put(index, List.copyOf(system));
            REQUIRED_DISPLAY_BY_INDEX.put(index, List.copyOf(required));
        }

        for (String index : List.of("exporter", "traffic", "settings", "sitemap", "findings")) {
            Map<String, Integer> mappingOrder = readMappingTopLevelOrder(index);
            TOGGLEABLE_BY_INDEX.put(index, reorderByMapping(TOGGLEABLE_BY_INDEX.get(index), mappingOrder));
            REQUIRED_DISPLAY_BY_INDEX.put(
                    index, reorderDisplayByMapping(REQUIRED_DISPLAY_BY_INDEX.get(index), mappingOrder));
            SYSTEM_BY_INDEX.put(index, reorderByMapping(SYSTEM_BY_INDEX.get(index), mappingOrder));
        }
    }

    /**
     * Returns whether {@code path} is a required meta leaf (always exported, not user-toggleable).
     */
    public static boolean isMetaLeafPath(String path) {
        return path != null && (META_LEAF_PATHS.contains(path) || TRAFFIC_CAPTURE_LEAF_PATHS.contains(path));
    }

    /** Returns whether a leaf carries mandatory identity, observation or omission semantics. */
    public static boolean isRequiredLeafPath(String path) {
        return isMetaLeafPath(path) || isBodyPolicyLeafPath(path);
    }

    static boolean isBodyPolicyLeafPath(String path) {
        return path != null && (path.equals("response.body.omitted")
                || path.equals("response.body.omission_reason") || path.endsWith(".response.body.omitted")
                || path.endsWith(".response.body.omission_reason"));
    }

    private static List<String> bodyPolicyPaths(String index) {
        List<String> prefixes = switch (index) {
            case "traffic", "sitemap" -> List.of("response.body.");
            case "findings" -> List.of("requests_responses.response.body.", "collaborator.http.response.body.");
            default -> List.of();
        };
        return prefixes.stream().flatMap(prefix ->
                java.util.stream.Stream.of(prefix + "omitted", prefix + "omission_reason")).toList();
    }

    /**
     * Returns the top-level field names of the given index's mapping in declaration order, mapped
     * to their position index. Returns an empty map when the resource cannot be read so callers
     * fall back to the originally-registered order.
     */
    private static Map<String, Integer> readMappingTopLevelOrder(String indexShortName) {
        var properties = MappingFieldCatalog.readMappingProperties(indexShortName);
        if (properties == null || !properties.isObject()) {
            return Map.of();
        }
        Map<String, Integer> order = new HashMap<>();
        int i = 0;
        for (var it = properties.propertyNames().iterator(); it.hasNext(); ) {
            order.put(it.next(), i++);
        }
        return order;
    }

    private static List<String> reorderByMapping(List<String> fields, Map<String, Integer> mappingOrder) {
        if (fields == null || fields.isEmpty()) {
            return List.of();
        }
        if (mappingOrder.isEmpty()) {
            return fields;
        }
        List<String> known = new ArrayList<>();
        List<String> unknown = new ArrayList<>();
        for (String f : fields) {
            if (mappingOrder.containsKey(topLevelField(f))) {
                known.add(f);
            } else {
                unknown.add(f);
            }
        }
        known.sort((a, b) -> Integer.compare(mappingOrder.get(topLevelField(a)), mappingOrder.get(topLevelField(b))));
        List<String> out = new ArrayList<>(known.size() + unknown.size());
        out.addAll(known);
        out.addAll(unknown);
        return List.copyOf(out);
    }

    private static List<String> reorderDisplayByMapping(List<String> fields, Map<String, Integer> mappingOrder) {
        if (fields == null || fields.isEmpty()) {
            return List.of();
        }
        if (mappingOrder.isEmpty()) {
            return fields;
        }
        List<String> sorted = new ArrayList<>(fields);
        sorted.sort((a, b) -> {
            int left = mappingOrder.getOrDefault(topLevelField(a), Integer.MAX_VALUE);
            int right = mappingOrder.getOrDefault(topLevelField(b), Integer.MAX_VALUE);
            if (left != right) {
                return Integer.compare(left, right);
            }
            return Integer.compare(fields.indexOf(a), fields.indexOf(b));
        });
        return List.copyOf(sorted);
    }

    private static String topLevelField(String field) {
        if (field == null) {
            return "";
        }
        int dot = field.indexOf('.');
        return dot < 0 ? field : field.substring(0, dot);
    }

    /** Index short names in internal display order. */
    public static final List<String> INDEX_ORDER = List.of("exporter", "traffic", "settings", "sitemap", "findings");

    /** Index order shown in the Fields panel. */
    public static final List<String> INDEX_ORDER_FOR_FIELDS_PANEL = List.of("settings", "sitemap", "findings", "traffic", "exporter");

    private ExportFieldRegistry() { }

    /** Returns the hierarchical field catalog for the Index Fields panel. */
    public static ExportFieldCatalog.Node getFieldCatalog(String indexShortName) {
        return ExportFieldCatalog.catalogForIndex(indexShortName);
    }

    /** Returns the toggleable field keys for the index as an unmodifiable list. */
    public static List<String> getToggleableFields(String indexShortName) {
        List<String> list = TOGGLEABLE_BY_INDEX.get(indexShortName);
        return list == null ? List.of() : Collections.unmodifiableList(list);
    }

    /** Returns required meta leaf paths shown in the Fields panel for the index. */
    public static List<String> getRequiredDisplayFields(String indexShortName) {
        List<String> list = REQUIRED_DISPLAY_BY_INDEX.get(indexShortName);
        return list == null ? List.of() : Collections.unmodifiableList(list);
    }

    /** Returns the system field keys for the index (always written, never user-selectable). */
    public static List<String> getSystemFields(String indexShortName) {
        List<String> list = SYSTEM_BY_INDEX.get(indexShortName);
        return list == null ? List.of() : Collections.unmodifiableList(list);
    }

    /**
     * Reduces an enabled-fields map for JSON export by dropping indexes where every toggleable
     * field is selected.
     *
     * <p>Returns {@code null} when the entire {@code exportFields} object can be omitted (global
     * all-on). Indexes absent from {@code enabledByIndex} are treated as all-on and are not
     * written. An empty per-index set is kept so import can mean "no optional fields" for that
     * index only.</p>
     *
     * @param enabledByIndex inclusion sets from the Fields panel or import; {@code null} when all-on
     * @return sparse map suitable for {@code exportFields}, or {@code null} to omit the key
     */
    public static Map<String, Set<String>> compactEnabledFieldsForExport(
            Map<String, Set<String>> enabledByIndex) {
        if (enabledByIndex == null || enabledByIndex.isEmpty()) {
            return null;
        }
        Map<String, Set<String>> out = new LinkedHashMap<>();
        for (String index : INDEX_ORDER) {
            if (!enabledByIndex.containsKey(index)) {
                continue;
            }
            Set<String> enabled = enabledByIndex.get(index);
            if (enabled == null || isAllToggleableSelected(index, enabled)) {
                continue;
            }
            out.put(index, Set.copyOf(enabled));
        }
        return out.isEmpty() ? null : Map.copyOf(out);
    }

    /**
     * Returns the field keys allowed for documents written to the index.
     *
     * <p>The result always contains the system keys (including top-level {@code meta}). When
     * {@code enabledToggleable} is null, all toggleable keys are included. Otherwise only the
     * selected toggleable keys are added; an empty set intentionally means no optional fields.
     * Dotted leaves are copied into their parent containers by {@link ExportFieldFilter} without
     * enabling disabled siblings.</p>
     */
    public static Set<String> getAllowedKeys(String indexShortName, Set<String> enabledToggleable) {
        Set<String> out = new LinkedHashSet<>(getSystemFields(indexShortName));
        List<String> toggleable = getToggleableFields(indexShortName);
        if (enabledToggleable == null) {
            out.addAll(toggleable);
        } else {
            for (String f : toggleable) {
                if (enabledToggleable.contains(f)) {
                    out.add(f);
                }
            }
        }
        return Collections.unmodifiableSet(out);
    }

    private static boolean isAllToggleableSelected(String indexShortName, Set<String> enabledToggleable) {
        if (enabledToggleable.isEmpty()) {
            return false;
        }
        List<String> toggleable = getToggleableFields(indexShortName);
        return enabledToggleable.size() >= toggleable.size()
                && enabledToggleable.containsAll(toggleable);
    }
}
