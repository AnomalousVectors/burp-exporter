package ai.anomalousvectors.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Writes structured Parameter Integrity drill-down events to the Exporter index.
 *
 * <p>Rollup loggers use this helper when they have complete per-phase URL buckets. The LogPanel
 * remains a concise alert surface, while these documents carry the full or sampled URL lists
 * needed for OpenSearch/Dashboards validation.</p>
 */
final class ParameterIntegrityDetailReporter {

    static final String EVENT_TYPE = "parameter_integrity_detail";
    static final int URL_CHUNK_SIZE = 100;
    static final int SAMPLE_URL_CAP = 10;

    private static final String SCHEMA_VERSION = "1";
    private static final String WIKI_DATA_INTEGRITY_URL =
            "https://github.com/AnomalousVectors/burp-exporter/wiki/Data-Integrity";

    enum UrlListPolicy {
        FULL,
        SAMPLE_ONLY
    }

    private ParameterIntegrityDetailReporter() {}

    static void report(
            String phase,
            String category,
            int docCount,
            Map<String, Integer> urlCounts,
            Map<String, Object> metrics,
            String impact,
            UrlListPolicy urlListPolicy) {
        if (docCount <= 0 || category == null || category.isBlank()) {
            return;
        }
        List<Map<String, Object>> docs =
                buildDetailDocs(phase, category, docCount, urlCounts, metrics, impact, urlListPolicy);
        pushDocs(docs);
    }

    static List<Map<String, Object>> buildDetailDocs(
            String phase,
            String category,
            int docCount,
            Map<String, Integer> urlCounts,
            Map<String, Object> metrics,
            String impact,
            UrlListPolicy urlListPolicy) {
        List<String> urls = urls(urlCounts);
        UrlListPolicy effectivePolicy = urlListPolicy == null ? UrlListPolicy.FULL : urlListPolicy;
        if (effectivePolicy == UrlListPolicy.SAMPLE_ONLY) {
            return List.of(buildDoc(phase, category, docCount, urls, null, 1, 1, true, metrics, impact));
        }

        int chunkCount = Math.max(1, (urls.size() + URL_CHUNK_SIZE - 1) / URL_CHUNK_SIZE);
        List<Map<String, Object>> docs = new ArrayList<>(chunkCount);
        for (int chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
            int from = chunkIndex * URL_CHUNK_SIZE;
            int to = Math.min(urls.size(), from + URL_CHUNK_SIZE);
            List<String> chunkUrls = from >= to ? List.of() : urls.subList(from, to);
            docs.add(buildDoc(
                    phase,
                    category,
                    docCount,
                    urls,
                    chunkUrls,
                    chunkIndex + 1,
                    chunkCount,
                    chunkCount > 1,
                    metrics,
                    impact));
        }
        return docs;
    }

    static String detailPointer(String category) {
        return bluf(category) + " Wiki: " + wikiUrl(category);
    }

    static String compressedWireSummaryPointer() {
        return "No raw body data was lost; derived BODY parameters were corrected or protected. Wiki: "
                + wikiUrl("compressed_wire_body_params");
    }

    private static String wikiUrl(String anchor) {
        return WIKI_DATA_INTEGRITY_URL + "#" + anchor;
    }

    private static String bluf(String category) {
        return switch (category) {
            case "body_params_truncated" ->
                    "No raw request data was lost; request.parameters was capped.";
            case "url_params_truncated" ->
                    "No request body data was lost; URL/query helper fields were capped.";
            case "misgate_binary" ->
                    "No raw body data was lost; the exporter avoided indexing likely binary content as form parameters.";
            case "wire_dropped" ->
                    "No raw body data was lost; suspect Burp-derived BODY rows were dropped.";
            case "supplemental_rejected_non_form" ->
                    "No raw body data was lost; non-form data was not converted into fake form parameters.";
            case "wire_replaced" ->
                    "No raw body data was lost; derived BODY parameters were corrected.";
            case "supplemental_added" ->
                    "No raw body data was lost; derived BODY parameters were supplemented from safe form data.";
            case "skip_path_rescued" ->
                    "No raw body data was lost; safe form parameters were recovered.";
            default -> "Review this derived-field detail only if the affected endpoint matters.";
        };
    }

    private static void pushDocs(List<Map<String, Object>> docs) {
        if (docs.isEmpty() || !shouldPush()) {
            return;
        }
        String baseUrl = RuntimeConfig.searchBaseUrl();
        String indexName = RuntimeConfig.indexNameForKey("exporter");
        boolean bypassReadyGate = !RuntimeConfig.isExportReady();
        for (Map<String, Object> doc : docs) {
            OpenSearchClientWrapper.ShutdownDocumentPushResult result =
                    OpenSearchClientWrapper.pushDocumentDuringShutdown(
                            baseUrl, indexName, "exporter", doc, bypassReadyGate);
            SingleDocOutcomeRecorder.record(
                    "exporter",
                    result.success(),
                    RuntimeConfig.isSearchActive(),
                    "Parameter Integrity detail push failed");
        }
    }

    private static boolean shouldPush() {
        return RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_EXPORTER)
                && RuntimeConfig.isAnySinkEnabled()
                && RuntimeConfig.isExportRunning();
    }

    private static Map<String, Object> buildDoc(
            String phase,
            String category,
            int docCount,
            List<String> allUrls,
            List<String> chunkUrls,
            int chunk,
            int chunkCount,
            boolean logTruncated,
            Map<String, Object> metrics,
            String impact) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("phase", safe(phase));
        data.put("category", category);
        data.put("doc_count", docCount);
        data.put("unique_url_count", allUrls.size());
        data.put("sample_urls", sampleUrls(allUrls));
        if (chunkUrls != null) {
            data.put("urls", List.copyOf(chunkUrls));
        }
        data.put("chunk", chunk);
        data.put("chunk_count", chunkCount);
        data.put("log_truncated", logTruncated);
        data.put("impact", safe(impact));
        data.put("query_hints", Map.of(
                "lucene", "event.type:" + EVENT_TYPE + " AND event.data.category:" + category));
        if (metrics != null && !metrics.isEmpty()) {
            data.putAll(metrics);
        }

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("level", "DEBUG");
        event.put("source", "burp-exporter");
        event.put("thread", Thread.currentThread().getName());
        event.put("type", EVENT_TYPE);
        event.put("summary", EVENT_TYPE + " category=" + category + " phase=" + safe(phase)
                + " count=" + docCount);
        event.put("data", data);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("event", event);
        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    private static List<String> urls(Map<String, Integer> urlCounts) {
        if (urlCounts == null || urlCounts.isEmpty()) {
            return List.of();
        }
        List<String> urls = new ArrayList<>(urlCounts.size());
        for (String url : urlCounts.keySet()) {
            urls.add(url == null ? "unknown" : url);
        }
        return urls;
    }

    private static List<String> sampleUrls(List<String> urls) {
        if (urls.isEmpty()) {
            return List.of();
        }
        int to = Math.min(SAMPLE_URL_CAP, urls.size());
        return List.copyOf(urls.subList(0, to));
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
