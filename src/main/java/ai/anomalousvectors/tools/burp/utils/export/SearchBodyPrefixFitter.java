package ai.anomalousvectors.tools.burp.utils.export;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;

/**
 * Pressure-aware search/database document fitting to the live {@link BulkByteBudget}.
 *
 * <p>When prepared NDJSON exceeds the live budget, deep-copies the document and repeatedly
 * prefix-truncates the largest remaining values. This best-effort fitting normally avoids
 * size-related permanent drops, but callers must still reject a result that exceeds the applicable
 * request ceiling. Used only on the search send path so file export can retain full prepared
 * documents.</p>
 *
 * <p>Shrink ladder:</p>
 * <ol>
 *   <li>HTTP {@code body} / WebSocket {@code payload} ({@code b64}/{@code text}; clear derived
 *       {@code html}; set {@code truncated=true}; keep original wire {@code length})</li>
 *   <li>Other large strings (header/cookie/param values, URLs, Collaborator {@code request_b64}/
 *       {@code response_b64}, finding prose, notes, …)</li>
 *   <li>Trim trailing elements from large nested lists when string shrinking is exhausted</li>
 *   <li>Shrink remaining non-metadata strings, including values shorter than the normal threshold</li>
 *   <li>Remove non-preserved map entries from the largest remaining maps</li>
 * </ol>
 */
public final class SearchBodyPrefixFitter {

    private static final int MAX_ROUNDS = 96;
    /** Ignore tiny strings; size pressure comes from large values. */
    private static final int MIN_STRING_CHARS = 16;
    private static final Set<String> TRIM_LIST_KEYS = Set.of(
            "headers",
            "cookies",
            "parameters",
            "requests_responses",
            "collaborator",
            "markers");
    private static final Set<String> PRESERVED_MAP_KEYS = Set.of(
            "meta",
            "schema_version",
            "extension_version",
            "indexed_at",
            "length",
            "search_truncated",
            "truncated");

    private SearchBodyPrefixFitter() {}

    /**
     * Returns a search-ready document that fits the live bulk budget.
     *
     * <p>When the original already fits, returns {@code original} unchanged (same instance).
     * Otherwise deep-copies the document map, normalizes every nested {@link Collection} to a
     * mutable list preserving iteration order, shrinks until under budget, and re-prepares NDJSON.
     * Never mutates {@code original}. Never returns {@code null} for a non-null input. Callers must
     * still verify the live budget immediately before HTTP because the budget can shrink
     * concurrently and a pathological metadata-only envelope may have no removable data.</p>
     *
     * @param original prepared document with a non-null document map; {@code null} yields
     *                 {@code null}
     * @return best-effort fitted document, or the original when already under budget; the result
     *         may still exceed the current budget
     * @throws NullPointerException if a non-null input has a {@code null} document map
     */
    public static PreparedExportDocument fitToLiveBudget(PreparedExportDocument original) {
        return fitToBudget(original, BulkByteBudget.currentMaxBytes());
    }

    /**
     * Returns a search-ready document fitted to an explicit byte budget.
     *
     * <p>This overload supports deterministic classification against both the current adaptive
     * budget and the absolute search request ceiling. It never mutates {@code original}. Fitting is
     * best-effort: a preserved metadata envelope can remain larger than the supplied ceiling, so
     * callers must verify {@link PreparedExportDocument#resolvedBulkBytes()} before sending.</p>
     *
     * @param original prepared document with a non-null document map; {@code null} yields
     *                 {@code null}
     * @param maxBytes target NDJSON byte ceiling; values below one are treated as one
     * @return best-effort fitted document, or the original when already under the supplied budget;
     *         the result may still exceed the normalized ceiling
     * @throws NullPointerException if a non-null input has a {@code null} document map
     */
    public static PreparedExportDocument fitToBudget(
            PreparedExportDocument original, long maxBytes) {
        if (original == null) {
            return null;
        }
        long targetBytes = Math.max(1L, maxBytes);
        if (original.resolvedBulkBytes() <= targetBytes) {
            return original;
        }
        Map<String, Object> working = deepCopyMap(original.document());
        markDocumentTruncated(working);

        PreparedExportDocument candidate = shrinkPayloadPhase(original, working, targetBytes);
        if (candidate.resolvedBulkBytes() <= targetBytes) {
            return candidate;
        }
        candidate = shrinkStringPhase(original, working, targetBytes);
        if (candidate.resolvedBulkBytes() <= targetBytes) {
            return candidate;
        }
        candidate = trimListPhase(original, working, targetBytes);
        if (candidate.resolvedBulkBytes() <= targetBytes) {
            return candidate;
        }
        candidate = shrinkRemainingStringPhase(original, working, targetBytes);
        if (candidate.resolvedBulkBytes() <= targetBytes) {
            return candidate;
        }
        candidate = pruneMapPhase(original, working, targetBytes);
        // The caller verifies the postcondition again immediately before HTTP. Production's 512 KiB
        // floor leaves ample room for the preserved metadata envelope after this final phase.
        return candidate;
    }

    /**
     * Returns the best request URL available for permanent-fit diagnostics.
     *
     * <p>The full URL is retained, including its query string. Carriage returns and newlines are
     * replaced so untrusted URL text cannot inject additional log lines.</p>
     *
     * @param document prepared export document
     * @return full request URL, or {@code "unknown"} when no supported document shape contains one
     */
    public static String diagnosticRequestUrl(PreparedExportDocument document) {
        if (document == null || document.document() == null) {
            return "unknown";
        }
        String url = requestUrlFromNode(document.document().get("request"));
        if (url == null) {
            url = targetUrlFromNode(document.document().get("target"));
        }
        if (url == null) {
            url = nestedRequestUrl(document.document());
        }
        if (url == null || url.isBlank()) {
            return "unknown";
        }
        return url.replace('\r', ' ').replace('\n', ' ');
    }

    /**
     * Returns whether {@code fitted} is a search-side truncation of {@code original}.
     *
     * @param original document before fit
     * @param fitted result from {@link #fitToLiveBudget(PreparedExportDocument)}
     * @return {@code true} when a new truncated document was produced
     */
    public static boolean didTruncate(PreparedExportDocument original, PreparedExportDocument fitted) {
        return original != null && fitted != null && fitted != original;
    }

    private static PreparedExportDocument shrinkPayloadPhase(
            PreparedExportDocument original,
            Map<String, Object> working,
            long maxBytes) {
        List<PayloadSlot> payloads = new ArrayList<>();
        collectPayloadSlots(working, payloads);
        PreparedExportDocument candidate = prepare(original, working);
        for (int round = 0; round < MAX_ROUNDS && candidate.resolvedBulkBytes() > maxBytes; round++) {
            PayloadSlot largest = largestPayload(payloads);
            if (largest == null) {
                break;
            }
            largest.halve();
            candidate = prepare(original, working);
        }
        if (candidate.resolvedBulkBytes() > maxBytes) {
            for (PayloadSlot slot : payloads) {
                slot.clearPayload();
            }
            candidate = prepare(original, working);
        }
        return candidate;
    }

    private static PreparedExportDocument shrinkStringPhase(
            PreparedExportDocument original,
            Map<String, Object> working,
            long maxBytes) {
        PreparedExportDocument candidate = prepare(original, working);
        for (int round = 0; round < MAX_ROUNDS && candidate.resolvedBulkBytes() > maxBytes; round++) {
            List<StringSlot> strings = new ArrayList<>();
            collectStringSlots(working, strings);
            StringSlot largest = largestString(strings);
            if (largest == null) {
                break;
            }
            largest.halve();
            candidate = prepare(original, working);
        }
        if (candidate.resolvedBulkBytes() > maxBytes) {
            List<StringSlot> strings = new ArrayList<>();
            collectStringSlots(working, strings);
            for (StringSlot slot : strings) {
                slot.clear();
            }
            candidate = prepare(original, working);
        }
        return candidate;
    }

    private static PreparedExportDocument trimListPhase(
            PreparedExportDocument original,
            Map<String, Object> working,
            long maxBytes) {
        PreparedExportDocument candidate = prepare(original, working);
        for (int round = 0; round < MAX_ROUNDS && candidate.resolvedBulkBytes() > maxBytes; round++) {
            ListRef largest = largestTrimList(working);
            if (largest == null) {
                break;
            }
            largest.list.remove(largest.list.size() - 1);
            candidate = prepare(original, working);
        }
        return candidate;
    }

    private static PreparedExportDocument prepare(
            PreparedExportDocument original, Map<String, Object> working) {
        return ExportDocumentIdentity.reprepareDerived(original, working);
    }

    private static PreparedExportDocument shrinkRemainingStringPhase(
            PreparedExportDocument original,
            Map<String, Object> working,
            long maxBytes) {
        PreparedExportDocument candidate = prepare(original, working);
        for (int round = 0; round < MAX_ROUNDS && candidate.resolvedBulkBytes() > maxBytes; round++) {
            List<StringSlot> strings = new ArrayList<>();
            collectStringSlots(working, strings, 1);
            StringSlot largest = largestString(strings, 1);
            if (largest == null) {
                break;
            }
            largest.halve();
            candidate = prepare(original, working);
        }
        if (candidate.resolvedBulkBytes() > maxBytes) {
            List<StringSlot> strings = new ArrayList<>();
            collectStringSlots(working, strings, 1);
            for (StringSlot slot : strings) {
                slot.clear();
            }
            candidate = prepare(original, working);
        }
        return candidate;
    }

    private static PreparedExportDocument pruneMapPhase(
            PreparedExportDocument original,
            Map<String, Object> working,
            long maxBytes) {
        PreparedExportDocument candidate = prepare(original, working);
        for (int round = 0; round < MAX_ROUNDS && candidate.resolvedBulkBytes() > maxBytes; round++) {
            List<MapSlot> maps = new ArrayList<>();
            collectMapSlots(working, maps);
            MapSlot largest = largestMap(maps);
            if (largest == null) {
                break;
            }
            largest.halve();
            candidate = prepare(original, working);
        }
        return candidate;
    }

    private static void markDocumentTruncated(Map<String, Object> working) {
        Map<String, Object> meta = new LinkedHashMap<>();
        Object existing = working.get("meta");
        if (existing instanceof Map<?, ?> existingMap) {
            for (Map.Entry<?, ?> entry : existingMap.entrySet()) {
                if (entry.getKey() instanceof String key) {
                    meta.put(key, entry.getValue());
                }
            }
        }
        meta.put("search_truncated", Boolean.TRUE);
        working.put("meta", meta);
    }

    private static void collectPayloadSlots(Object node, List<PayloadSlot> slots) {
        if (node instanceof Map<?, ?> mapObj) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) mapObj;
            if (isPayloadMap(map)) {
                slots.add(new PayloadSlot(map));
            }
            for (Object value : map.values()) {
                collectPayloadSlots(value, slots);
            }
            return;
        }
        if (node instanceof Collection<?> collection) {
            for (Object value : collection) {
                collectPayloadSlots(value, slots);
            }
        }
    }

    private static void collectStringSlots(Object node, List<StringSlot> slots) {
        collectStringSlots(node, slots, MIN_STRING_CHARS);
    }

    private static void collectStringSlots(Object node, List<StringSlot> slots, int minChars) {
        if (node instanceof Map<?, ?> mapObj) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) mapObj;
            // Payload b64/text handled in payload phase; skip to avoid double-shrinking empty stubs.
            boolean payload = isPayloadMap(map);
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if ("meta".equals(entry.getKey())) {
                    continue;
                }
                Object value = entry.getValue();
                if (value instanceof String s) {
                    if (payload && ("b64".equals(entry.getKey()) || "text".equals(entry.getKey()))) {
                        continue;
                    }
                    if (s.length() >= minChars) {
                        slots.add(new StringSlot(map, entry.getKey(), s));
                    }
                } else {
                    collectStringSlots(value, slots, minChars);
                }
            }
            return;
        }
        if (node instanceof Collection<?> collection) {
            for (Object value : collection) {
                collectStringSlots(value, slots, minChars);
            }
        }
    }

    private static void collectMapSlots(Object node, List<MapSlot> slots) {
        if (node instanceof Map<?, ?> mapObj) {
            for (Map.Entry<?, ?> entry : mapObj.entrySet()) {
                if (!"meta".equals(entry.getKey())) {
                    collectMapSlots(entry.getValue(), slots);
                }
            }
            MapSlot slot = new MapSlot(mapObj);
            if (slot.removableCount() > 0) {
                slots.add(slot);
            }
            return;
        }
        if (node instanceof Collection<?> collection) {
            for (Object value : collection) {
                collectMapSlots(value, slots);
            }
        }
    }

    private static boolean isPayloadMap(Map<String, Object> map) {
        return map.containsKey("length")
                && (map.containsKey("b64") || map.containsKey("text"));
    }

    private static String nestedRequestUrl(Object node) {
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if ("request".equals(entry.getKey())) {
                    String requestUrl = requestUrlFromNode(entry.getValue());
                    if (requestUrl != null) {
                        return requestUrl;
                    }
                }
                if ("target".equals(entry.getKey())) {
                    String targetUrl = targetUrlFromNode(entry.getValue());
                    if (targetUrl != null) {
                        return targetUrl;
                    }
                }
                String nested = nestedRequestUrl(entry.getValue());
                if (nested != null) {
                    return nested;
                }
            }
        } else if (node instanceof Collection<?> collection) {
            for (Object value : collection) {
                String nested = nestedRequestUrl(value);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static String requestUrlFromNode(Object node) {
        if (!(node instanceof Map<?, ?> request)) {
            return null;
        }
        Object url = request.get("url");
        if (url instanceof String text && !text.isBlank()) {
            return text;
        }
        if (url instanceof Map<?, ?> urlMap) {
            String raw = stringValue(urlMap.get("raw"));
            if (raw != null) {
                return raw;
            }
            return stringValue(urlMap.get("text"));
        }
        return null;
    }

    private static String targetUrlFromNode(Object node) {
        if (!(node instanceof Map<?, ?> target)) {
            return null;
        }
        return stringValue(target.get("url"));
    }

    private static String stringValue(Object value) {
        return value instanceof String text && !text.isBlank() ? text : null;
    }

    private static PayloadSlot largestPayload(List<PayloadSlot> slots) {
        PayloadSlot best = null;
        long bestSize = 0L;
        for (PayloadSlot slot : slots) {
            long size = slot.payloadChars();
            if (size > bestSize) {
                bestSize = size;
                best = slot;
            }
        }
        return bestSize > 0L ? best : null;
    }

    private static StringSlot largestString(List<StringSlot> slots) {
        return largestString(slots, MIN_STRING_CHARS);
    }

    private static StringSlot largestString(List<StringSlot> slots, int minChars) {
        StringSlot best = null;
        long bestSize = 0L;
        for (StringSlot slot : slots) {
            long size = slot.chars();
            if (size > bestSize) {
                bestSize = size;
                best = slot;
            }
        }
        return bestSize >= minChars ? best : null;
    }

    private static MapSlot largestMap(List<MapSlot> slots) {
        MapSlot best = null;
        long bestSize = 0L;
        for (MapSlot slot : slots) {
            long size = slot.removableSize();
            if (size > bestSize) {
                bestSize = size;
                best = slot;
            }
        }
        return best;
    }

    @SuppressWarnings("unchecked")
    private static ListRef largestTrimList(Object node) {
        ListRef best = null;
        long bestScore = 0L;
        if (node instanceof Map<?, ?> mapObj) {
            Map<String, Object> map = (Map<String, Object>) mapObj;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof List<?> list && !list.isEmpty()) {
                    String key = entry.getKey() == null ? "" : entry.getKey().toLowerCase(Locale.ROOT);
                    if (TRIM_LIST_KEYS.contains(key) || list.size() > 1) {
                        long score = estimateListScore(list);
                        if (score > bestScore) {
                            bestScore = score;
                            best = new ListRef((List<Object>) list);
                        }
                    }
                }
                ListRef nested = "meta".equals(entry.getKey()) ? null : largestTrimList(value);
                if (nested != null) {
                    long score = estimateListScore(nested.list);
                    if (score > bestScore) {
                        bestScore = score;
                        best = nested;
                    }
                }
            }
        } else if (node instanceof Collection<?> collection) {
            for (Object value : collection) {
                ListRef nested = largestTrimList(value);
                if (nested != null) {
                    long score = estimateListScore(nested.list);
                    if (score > bestScore) {
                        bestScore = score;
                        best = nested;
                    }
                }
            }
        }
        return bestScore > 0L ? best : null;
    }

    private static long estimateListScore(List<?> list) {
        if (list == null || list.isEmpty()) {
            return 0L;
        }
        // Prefer trimming the list with the largest last element footprint.
        Object last = list.get(list.size() - 1);
        return 1L + estimateValueChars(last);
    }

    private static long estimateValueChars(Object value) {
        if (value instanceof String s) {
            return s.length();
        }
        if (value instanceof Map<?, ?> map) {
            long total = 0L;
            for (Object v : map.values()) {
                total += estimateValueChars(v);
            }
            return total;
        }
        if (value instanceof Collection<?> collection) {
            long total = 0L;
            for (Object v : collection) {
                total += estimateValueChars(v);
            }
            return total;
        }
        return 0L;
    }

    private static Map<String, Object> deepCopyMap(Map<String, Object> source) {
        Map<String, Object> copy = new LinkedHashMap<>(source.size());
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            copy.put(entry.getKey(), deepCopyValue(entry.getValue()));
        }
        return copy;
    }

    @SuppressWarnings("unchecked")
    private static Object deepCopyValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            return deepCopyMap((Map<String, Object>) map);
        }
        if (value instanceof Collection<?> collection) {
            List<Object> copy = new ArrayList<>(collection.size());
            for (Object item : collection) {
                copy.add(deepCopyValue(item));
            }
            return copy;
        }
        return value;
    }

    private static final class ListRef {
        private final List<Object> list;

        private ListRef(List<Object> list) {
            this.list = list;
        }
    }

    private static final class MapSlot {
        private final Map<?, ?> map;

        private MapSlot(Map<?, ?> map) {
            this.map = map;
        }

        private int removableCount() {
            int count = 0;
            for (Object key : map.keySet()) {
                if (key instanceof String stringKey
                        && !PRESERVED_MAP_KEYS.contains(stringKey)) {
                    count++;
                }
            }
            return count;
        }

        private long removableSize() {
            long total = 0L;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() instanceof String key
                        && !PRESERVED_MAP_KEYS.contains(key)) {
                    total += key.length() + 1L + estimateValueChars(entry.getValue());
                }
            }
            return total;
        }

        private void halve() {
            int removable = removableCount();
            int remove = Math.max(1, removable / 2);
            List<?> keys = new ArrayList<>(map.keySet());
            for (int i = keys.size() - 1; i >= 0 && remove > 0; i--) {
                Object key = keys.get(i);
                if (key instanceof String stringKey
                        && !PRESERVED_MAP_KEYS.contains(stringKey)) {
                    map.remove(key);
                    remove--;
                }
            }
        }
    }

    private static final class StringSlot {
        private final Map<String, Object> map;
        private final String key;
        private String value;

        private StringSlot(Map<String, Object> map, String key, String value) {
            this.map = map;
            this.key = key;
            this.value = value;
        }

        private long chars() {
            return value == null ? 0L : value.length();
        }

        private void halve() {
            if (value == null || value.isEmpty()) {
                return;
            }
            int keep = Math.max(0, value.length() / 2);
            if (isBase64Key(key)) {
                value = prefixBase64(value, keep);
            } else {
                value = value.substring(0, keep);
            }
            map.put(key, value.isEmpty() ? null : value);
            markTruncated(map, key);
        }

        private void clear() {
            value = "";
            map.put(key, null);
            markTruncated(map, key);
        }

        private static boolean isBase64Key(String key) {
            if (key == null) {
                return false;
            }
            String k = key.toLowerCase(Locale.ROOT);
            return "b64".equals(k) || k.endsWith("_b64") || k.endsWith(".b64");
        }

        private static void markTruncated(Map<String, Object> map, String key) {
            // Body/payload maps and header/cookie/param objects (name+value) accept truncated.
            if (map.containsKey("length") || map.containsKey("name") || "value".equals(key) || "raw".equals(key)) {
                map.put("truncated", Boolean.TRUE);
            }
        }
    }

    private static final class PayloadSlot {
        private final Map<String, Object> map;
        private String b64;
        private String text;

        private PayloadSlot(Map<String, Object> map) {
            this.map = map;
            this.b64 = asString(map.get("b64"));
            this.text = asString(map.get("text"));
        }

        private long payloadChars() {
            long total = 0L;
            if (b64 != null) {
                total += b64.length();
            }
            if (text != null) {
                total += text.length();
            }
            Object html = map.get("html");
            if (html instanceof Map<?, ?> htmlMap && !htmlMap.isEmpty()) {
                total += 64L;
            }
            return total;
        }

        private void halve() {
            boolean changed = false;
            if (b64 != null && !b64.isEmpty()) {
                b64 = prefixBase64(b64, Math.max(0, b64.length() / 2));
                map.put("b64", b64.isEmpty() ? null : b64);
                changed = true;
            }
            if (text != null && !text.isEmpty()) {
                text = text.substring(0, Math.max(0, text.length() / 2));
                map.put("text", text.isEmpty() ? null : text);
                changed = true;
            }
            if (map.containsKey("html")) {
                map.remove("html");
                changed = true;
            }
            if (changed) {
                map.put("truncated", Boolean.TRUE);
            }
        }

        private void clearPayload() {
            if (b64 != null) {
                b64 = "";
                map.put("b64", null);
            }
            if (text != null) {
                text = "";
                map.put("text", null);
            }
            map.remove("html");
            map.put("truncated", Boolean.TRUE);
        }

        private static String asString(Object value) {
            return value instanceof String s ? s : null;
        }
    }

    private static String prefixBase64(String encoded, int targetChars) {
        if (encoded == null || encoded.isEmpty() || targetChars <= 0) {
            return "";
        }
        int keep = Math.min(encoded.length(), targetChars);
        keep -= keep % 4;
        if (keep <= 0) {
            return "";
        }
        return encoded.substring(0, keep);
    }
}
