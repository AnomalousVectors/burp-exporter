package ai.anomalousvectors.tools.burp.utils.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ai.anomalousvectors.tools.burp.utils.StringKeyedMaps;

/**
 * Filters a document map to only include keys allowed for export for the given index.
 * Used before push so disabled fields (Fields panel) are not sent to OpenSearch.
 */
public final class ExportFieldFilter {

    private static final Object ABSENT = new Object();

    private ExportFieldFilter() { }

    /**
     * Returns a copy of {@code document} containing only export keys enabled for {@code indexKey}.
     *
     * @param document full built document; {@code null} yields an empty map
     * @param indexKey index short name (for example {@code "traffic"})
     * @return filtered document safe to index; never {@code null}
     */
    public static Map<String, Object> filterDocument(Map<String, Object> document, String indexKey) {
        if (document == null) {
            return Map.of();
        }
        Set<String> allowed = RuntimeConfig.getAllowedExportKeys(indexKey);
        Object filtered = filterValue(document, "", allowed);
        if (filtered instanceof Map<?, ?> filteredMap) {
            return StringKeyedMaps.copy(filteredMap);
        }
        return Map.of();
    }

    private static Object filterValue(Object current, String pathPrefix, Set<String> allowed) {
        if (current == null) {
            return isIncluded(pathPrefix, allowed) ? null : ABSENT;
        }
        if (current instanceof Map<?, ?> currentMap) {
            return filterMap(currentMap, pathPrefix, allowed);
        }
        if (current instanceof List<?> currentList) {
            return filterList(currentList, pathPrefix, allowed);
        }
        return isIncluded(pathPrefix, allowed) ? current : ABSENT;
    }

    private static Object filterMap(Map<?, ?> currentMap, String pathPrefix, Set<String> allowed) {
        if (!isIncluded(pathPrefix, allowed)) {
            return ABSENT;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : currentMap.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                continue;
            }
            String childPath = pathPrefix.isEmpty() ? key : pathPrefix + '.' + key;
            if (!isIncluded(childPath, allowed)) {
                continue;
            }
            Object filtered = filterValue(entry.getValue(), childPath, allowed);
            if (filtered == ABSENT || isEmptyExportFragment(filtered)) {
                continue;
            }
            out.put(key, filtered);
        }
        return out.isEmpty() ? ABSENT : out;
    }

    private static Object filterList(List<?> currentList, String pathPrefix, Set<String> allowed) {
        if (!isIncluded(pathPrefix, allowed)) {
            return ABSENT;
        }
        if (currentList.isEmpty()) {
            return List.of();
        }
        List<Object> out = new ArrayList<>();
        for (Object item : currentList) {
            Object filtered = filterValue(item, pathPrefix, allowed);
            if (filtered == ABSENT || isEmptyExportFragment(filtered)) {
                continue;
            }
            out.add(filtered);
        }
        return out.isEmpty() ? ABSENT : out;
    }

    private static boolean isIncluded(String path, Set<String> allowed) {
        if (path == null || path.isEmpty()) {
            return true;
        }
        if (allowed.contains(path)) {
            return true;
        }
        String childPrefix = path + '.';
        for (String allowedPath : allowed) {
            if (allowedPath.startsWith(childPrefix)) {
                return true;
            }
            if (path.startsWith(allowedPath + '.')) {
                return true;
            }
        }
        return false;
    }

    private static boolean isEmptyExportFragment(Object fragment) {
        if (fragment instanceof Map<?, ?> map) {
            return map.isEmpty();
        }
        return false;
    }

}
