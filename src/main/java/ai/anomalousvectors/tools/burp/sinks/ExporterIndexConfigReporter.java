package ai.anomalousvectors.tools.burp.sinks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;

/**
 * Pushes the current runtime configuration to the Exporter index.
 *
 * <p>This reporter emits a single {@code config_snapshot} document when export startup completes.
 * The snapshot is sent only while export is running, the {@code exporter} source is enabled, the
 * {@code config} sub-option is selected, and at least one sink is active.</p>
 */
public final class ExporterIndexConfigReporter {

    private static final String SCHEMA_VERSION = "1";
    private static final String EVENT_TYPE = "config_snapshot";
    private static final String SOURCE = "burp-exporter";

    private ExporterIndexConfigReporter() {}

    /**
     * Pushes one configuration snapshot to the enabled sinks.
     *
     * <p>Safe to call from any thread. Returns immediately when export is stopped, the exporter
     * config sub-option is disabled, or no sink is enabled. Delivery is fire-and-forget.</p>
     */
    public static void pushConfigSnapshot() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isExporterConfigEnabled()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            String baseUrl = RuntimeConfig.searchBaseUrl();
            boolean openSearchActive = RuntimeConfig.isSearchActive();
            Map<String, Object> doc = buildConfigDoc(RuntimeConfig.getState());
            boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, RuntimeConfig.indexNameForKey("exporter"), "exporter", doc);
            SingleDocOutcomeRecorder.record("exporter", ok, openSearchActive,
                    "Exporter config snapshot push failed");
            if (!ok && openSearchActive) {
                Logger.logWarnPanelOnly("[SnapshotExport] Exporter config: push failed.");
            }
        } catch (Exception e) {
            Logger.logWarnPanelOnly("[SnapshotExport] Exporter config: push failed: "
                    + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
        }
    }

    private static Map<String, Object> buildConfigDoc(ConfigState.State state) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("data_sources", state.dataSources() != null ? new ArrayList<>(state.dataSources()) : List.of());
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("settings", state.settingsSub() != null ? new ArrayList<>(state.settingsSub()) : List.of());
        opts.put("traffic", state.trafficToolTypes() != null ? new ArrayList<>(state.trafficToolTypes()) : List.of());
        opts.put("findings", state.findingsSeverities() != null ? new ArrayList<>(state.findingsSeverities()) : List.of());
        opts.put("exporter", state.exporterSubOptions() != null ? new ArrayList<>(state.exporterSubOptions()) : List.of());
        opts.put("exporter_stats_interval_seconds", state.exporterStatsIntervalSeconds());
        message.put("data_source_options", opts);
        Map<String, Object> indexNames = new LinkedHashMap<>();
        indexNames.put("base_template", state.indexNameBaseTemplate());
        indexNames.put("resolved_names", new LinkedHashMap<>(RuntimeConfig.allIndexNames()));
        message.put("index_names", indexNames);
        message.put("scope_type", state.scopeType());
        List<Map<String, Object>> custom = new ArrayList<>();
        if (state.customEntries() != null) {
            for (ConfigState.ScopeEntry e : state.customEntries()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("value", e.value());
                entry.put("kind", e.kind().name().toLowerCase(java.util.Locale.ROOT));
                custom.add(entry);
            }
        }
        message.put("custom_entries", custom);
        ConfigState.Sinks sinks = state.sinks();
        if (sinks != null) {
            Map<String, Object> sinksMap = new LinkedHashMap<>();
            sinksMap.put("files_enabled", sinks.filesEnabled());
            sinksMap.put("files_path", sinks.filesPath() != null ? sinks.filesPath() : "");
            sinksMap.put("file_jsonl_enabled", sinks.fileJsonlEnabled());
            sinksMap.put("file_bulk_ndjson_enabled", sinks.fileBulkNdjsonEnabled());
            sinksMap.put("os_enabled", sinks.databaseEnabled());
            sinksMap.put("open_search_url", sinks.openSearchUrl() != null ? sinks.openSearchUrl() : "");
            message.put("sinks", sinksMap);
        }

        String messageText = "config_snapshot scope=" + state.scopeType()
                + " sources=" + (state.dataSources() != null ? state.dataSources().size() : 0)
                + " exporter=" + (state.dataSources() != null && state.dataSources().contains(ConfigKeys.SRC_EXPORTER));

        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("level", "INFO");
        event.put("source", SOURCE);
        event.put("thread", Thread.currentThread().getName());
        event.put("type", EVENT_TYPE);
        event.put("data", message);
        event.put("summary", messageText);
        doc.put("event", event);
        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

}
