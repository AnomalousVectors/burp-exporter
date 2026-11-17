package ai.anomalousvectors.tools.burp.sinks;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.Version;

/**
 * Shared exporter metadata values written under {@code meta}.
 */
final class ExportMetaFields {

    private static final String EXTENSION_VERSION = Version.get();

    private ExportMetaFields() {}

    /**
     * Builds the {@code meta} sub-document for an export row.
     *
     * @param schemaVersion document schema version string for the index family
     * @return mutable {@code meta} map (includes a fresh {@code indexed_at} timestamp)
     */
    static Map<String, Object> meta(String schemaVersion) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("schema_version", schemaVersion);
        meta.put("extension_version", EXTENSION_VERSION);
        meta.put("indexed_at", Instant.now().toString());
        return meta;
    }

    /** Labels a live HTTP observation without implying an association to a History row. */
    static Map<String, Object> liveHttp(String schemaVersion, boolean nativeProxy) {
        Map<String, Object> meta = meta(schemaVersion);
        meta.put("capture", Map.of("source", nativeProxy ? "live_proxy_callback" : "live_http_callback"));
        return meta;
    }
}
