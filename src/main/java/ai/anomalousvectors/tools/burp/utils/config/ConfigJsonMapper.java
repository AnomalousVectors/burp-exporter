package ai.anomalousvectors.tools.burp.utils.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState.ScopeEntry;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState.Sinks;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState.State;

/**
 * Mapper between the typed {@link ConfigState.State} and the JSON produced/parsed
 * by {@link Json}. Keeps JSON shape 100% compatible by delegating to {@link Json}.
 */
public final class ConfigJsonMapper {

    private ConfigJsonMapper() { }

    /** Build JSON from a typed state using {@link Json} under the hood. */
    public static String build(State state) {
        return Json.buildFromState(state);
    }

    /**
     * Parses config JSON into a normalized typed state and import report.
     *
     * <p>Legacy payloads that predate explicit exporter options are normalized to include the
     * {@code exporter} source so Exporter-index export remains enabled by default.</p>
     *
     * @param json raw config JSON
     * @return parsed state and any non-fatal import warnings
     * @throws IOException when the JSON cannot be parsed
     */
    public static ConfigParseResult parse(String json) throws IOException {
        Json.ConfigJsonParseResult parsed = Json.parseConfigJsonWithReport(json);
        State state = stateFrom(parsed.config());
        return new ConfigParseResult(state, parsed.report());
    }

    /**
     * Parses config JSON into a normalized typed state (warnings discarded).
     *
     * @param json raw config JSON
     * @return normalized typed state
     * @throws IOException when the JSON cannot be parsed
     */
    public static State parseState(String json) throws IOException {
        return parse(json).state();
    }

    private static State stateFrom(Json.ImportedConfig cfg) {
        List<ScopeEntry> entries = entriesFrom(cfg);
        List<String> dataSources = new ArrayList<>(cfg.dataSources());
        if (!cfg.exporterOptionsPresent() && !dataSources.contains(ConfigKeys.SRC_EXPORTER)) {
            dataSources.add(ConfigKeys.SRC_EXPORTER);
        }

        Sinks sinks = new Sinks(
                cfg.filesEnabled(), cfg.filesPath(),
                cfg.fileJsonlEnabled(), cfg.fileBulkNdjsonEnabled(),
                cfg.fileTotalCapEnabled(), cfg.fileTotalCapGb(),
                cfg.fileDiskUsagePercentEnabled(), cfg.fileDiskUsagePercent(),
                cfg.openSearchEnabled(), cfg.openSearchUrl(),
                cfg.openSearchUser(), cfg.openSearchPassword(),
                cfg.openSearchTlsMode(),
                cfg.openSearchOptions(),
                cfg.searchDestination(),
                cfg.openSearchAmazonUrl(),
                cfg.openSearchAmazonOptions(),
                cfg.elasticSearchUrl(),
                cfg.elasticSearchOptions()
        );

        return new State(dataSources, cfg.scopeType(), entries, sinks,
                cfg.settingsSub(), cfg.trafficToolTypes(), cfg.findingsSeverities(),
                cfg.exporterSubOptions(), cfg.exporterStatsIntervalSeconds(),
                cfg.indexNameBaseTemplate(), cfg.enabledExportFieldsByIndex(), cfg.uiPreferences());
    }

    /** Extract ordered custom entries from the parsed config. */
    private static List<ScopeEntry> entriesFrom(Json.ImportedConfig cfg) {
        List<ScopeEntry> out = new ArrayList<>();
        if (!"custom".equals(cfg.scopeType())) return out;

        List<String> vals = cfg.scopeRegexes();
        if (vals == null || vals.isEmpty()) {
            return out;
        }
        List<String> kinds = cfg.scopeKinds(); // may be null
        int n = vals.size();

        boolean typed = kinds != null && kinds.size() == n;
        for (int i = 0; i < n; i++) {
            String v = vals.get(i);
            String k = "regex";
            if (typed && kinds != null) {
                k = kinds.get(i);
            }
            out.add(new ScopeEntry(v, "string".equalsIgnoreCase(k)
                    ? ConfigState.Kind.STRING
                    : ConfigState.Kind.REGEX));
        }
        return out;
    }
}
