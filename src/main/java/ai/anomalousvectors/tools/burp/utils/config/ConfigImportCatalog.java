package ai.anomalousvectors.tools.burp.utils.config;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Canonical allowlists for configuration import: known object keys and enumerated values.
 *
 * <p>Centralizes import-time validation so {@link Json} parsing and UI messaging stay aligned with
 * {@link ConfigKeys}, {@link ConfigState} defaults, and {@link ExportFieldRegistry}.</p>
 */
public final class ConfigImportCatalog {

    public static final List<String> ROOT_KEYS = List.of(
            "version",
            "dataSources",
            "dataSourceOptions",
            "scope",
            "sinks",
            "indexNames",
            "ui",
            "exportFields");

    public static final List<String> DATA_SOURCE_OPTIONS_KEYS = List.of(
            "settings",
            "traffic",
            "findings",
            "exporter",
            "exporterStatsIntervalSeconds");

    public static final List<String> INDEX_NAMES_KEYS = List.of("baseTemplate");

    public static final List<String> UI_KEYS = List.of("stats", "log");

    public static final List<String> UI_STATS_KEYS = List.of("chartStyle");

    public static final List<String> UI_LOG_KEYS = List.of(
            "minLevel",
            "pauseAutoscroll",
            "filterText",
            "filterCase",
            "filterRegex",
            "filterNegative",
            "searchText",
            "searchCase",
            "searchRegex");

    public static final Set<String> KNOWN_DATA_SOURCES = Set.of(
            ConfigKeys.SRC_SETTINGS,
            ConfigKeys.SRC_SITEMAP,
            ConfigKeys.SRC_FINDINGS,
            ConfigKeys.SRC_TRAFFIC,
            ConfigKeys.SRC_EXPORTER);

    /** Stable export order for {@code dataSources} inclusion arrays. */
    public static final List<String> DATA_SOURCES_EXPORT_ORDER = List.of(
            ConfigKeys.SRC_SETTINGS,
            ConfigKeys.SRC_SITEMAP,
            ConfigKeys.SRC_FINDINGS,
            ConfigKeys.SRC_TRAFFIC,
            ConfigKeys.SRC_EXPORTER);

    public static final Set<String> KNOWN_EXPORT_INDEXES =
            Set.copyOf(ExportFieldRegistry.INDEX_ORDER);

    private static final Set<String> COMMUNITY_DISABLED_SOURCES = Set.of(ConfigKeys.SRC_FINDINGS);

    private static final Set<String> COMMUNITY_DISABLED_TRAFFIC_TOOL_TYPES =
            Set.of("burp_ai", "scanner");

    private ConfigImportCatalog() { }

    /**
     * Returns every data source available in the running Burp edition.
     */
    public static List<String> allDataSourcesForEdition(boolean communityEdition) {
        List<String> out = new ArrayList<>();
        for (String source : DATA_SOURCES_EXPORT_ORDER) {
            if (communityEdition && COMMUNITY_DISABLED_SOURCES.contains(source)) {
                continue;
            }
            out.add(source);
        }
        return List.copyOf(out);
    }

    /**
     * Returns {@code null} to omit {@code dataSources} from exported JSON when every source for
     * this edition is selected; otherwise returns the selected sources in export order. An empty
     * list means explicit none.
     */
    public static List<String> compactDataSourcesForExport(
            List<String> sources,
            boolean communityEdition) {
        if (sources == null || sources.isEmpty()) {
            return sources == null ? List.of() : List.of();
        }
        if (isAllDataSourcesSelected(sources, communityEdition)) {
            return null;
        }
        Set<String> selected = new LinkedHashSet<>();
        for (String source : sources) {
            if (source != null && !source.isBlank()) {
                selected.add(source.trim().toLowerCase(Locale.ROOT));
            }
        }
        return DATA_SOURCES_EXPORT_ORDER.stream()
                .filter(selected::contains)
                .toList();
    }

    /**
     * Slices of {@code dataSourceOptions} that differ from defaults. {@code null} fields are omitted
     * on export and mean "use the default for that branch" on import.
     *
     * @param settings non-null when {@code settingsSub} differs from {@link ConfigState#DEFAULT_SETTINGS_SUB}
     * @param traffic non-null when tool types differ from the edition default list
     * @param findings non-null when severities differ from {@link ConfigState#DEFAULT_FINDINGS_SEVERITIES}
     * @param exporter non-null when sub-options differ from {@link ConfigState#DEFAULT_EXPORTER_SUB_OPTIONS}
     * @param exporterStatsIntervalSeconds non-null when not {@link ConfigState#DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS}
     */
    public record CompactDataSourceOptions(
            List<String> settings,
            List<String> traffic,
            List<String> findings,
            List<String> exporter,
            Integer exporterStatsIntervalSeconds) {

        boolean isEntireSectionOmittable() {
            return settings == null
                    && traffic == null
                    && findings == null
                    && exporter == null
                    && exporterStatsIntervalSeconds == null;
        }
    }

    /**
     * Returns traffic tool types selected by default for the running Burp edition.
     */
    public static List<String> defaultTrafficToolTypesForEdition(boolean communityEdition) {
        if (!communityEdition) {
            return ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES;
        }
        List<String> out = new ArrayList<>();
        for (String toolType : ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES) {
            if (!COMMUNITY_DISABLED_TRAFFIC_TOOL_TYPES.contains(toolType)) {
                out.add(toolType);
            }
        }
        return List.copyOf(out);
    }

    /**
     * Returns non-default {@code dataSourceOptions} fields for export, or {@code null} when the
     * whole object can be omitted.
     */
    public static CompactDataSourceOptions compactDataSourceOptionsForExport(
            List<String> settingsSub,
            List<String> trafficToolTypes,
            List<String> findingsSeverities,
            List<String> exporterSubOptions,
            int exporterStatsIntervalSeconds,
            boolean communityEdition) {
        List<String> trafficDefaults = defaultTrafficToolTypesForEdition(communityEdition);

        List<String> settingsOut = matchesDefaults(settingsSub, ConfigState.DEFAULT_SETTINGS_SUB)
                ? null
                : orderedInclusion(settingsSub, ConfigState.DEFAULT_SETTINGS_SUB);
        List<String> trafficOut = matchesDefaults(trafficToolTypes, trafficDefaults)
                ? null
                : orderedInclusion(trafficToolTypes, ConfigState.ALL_TRAFFIC_TOOL_TYPES);
        List<String> findingsOut = matchesDefaults(findingsSeverities, ConfigState.DEFAULT_FINDINGS_SEVERITIES)
                ? null
                : orderedInclusion(findingsSeverities, ConfigState.DEFAULT_FINDINGS_SEVERITIES);
        List<String> exporterOut = matchesDefaults(exporterSubOptions, ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS)
                ? null
                : orderedInclusion(exporterSubOptions, ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS);
        Integer statsOut = exporterStatsIntervalSeconds == ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS
                ? null
                : exporterStatsIntervalSeconds;

        CompactDataSourceOptions compact = new CompactDataSourceOptions(
                settingsOut, trafficOut, findingsOut, exporterOut, statsOut);
        return compact.isEntireSectionOmittable() ? null : compact;
    }

    public static boolean isAllDataSourcesSelected(List<String> sources, boolean communityEdition) {
        if (sources == null || sources.isEmpty()) {
            return false;
        }
        Set<String> selected = new LinkedHashSet<>();
        for (String source : sources) {
            if (source != null && !source.isBlank()) {
                selected.add(source.trim().toLowerCase(Locale.ROOT));
            }
        }
        return selected.equals(Set.copyOf(allDataSourcesForEdition(communityEdition)));
    }

    public static void collectUnknownRootKeys(JsonNode root, ConfigImportReport report) {
        if (root == null || !root.isObject() || report == null) {
            return;
        }
        collectUnknownObjectKeys(root, "", ROOT_KEYS, report);
    }

    public static void collectUnknownObjectKeys(
            JsonNode node,
            String path,
            List<String> allowedKeys,
            ConfigImportReport report) {
        if (node == null || node.isMissingNode() || node.isNull() || !node.isObject() || report == null) {
            return;
        }
        String prefix = path == null || path.isBlank() ? "" : path + ".";
        for (var it = node.fieldNames(); it.hasNext(); ) {
            String field = it.next();
            if (!allowedKeys.contains(field)) {
                report.add(ConfigImportReport.Kind.UNKNOWN_KEY, prefix + field, field);
            }
        }
    }

    public static List<String> filterKnownDataSources(
            List<String> raw,
            ConfigImportReport report,
            boolean communityEdition) {
        List<String> accepted = new ArrayList<>();
        for (String value : raw) {
            if (value == null || value.isBlank()) {
                continue;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if (!KNOWN_DATA_SOURCES.contains(normalized)) {
                report.add(ConfigImportReport.Kind.UNKNOWN_VALUE, "dataSources", value);
                continue;
            }
            if (communityEdition && COMMUNITY_DISABLED_SOURCES.contains(normalized)) {
                report.add(ConfigImportReport.Kind.EDITION_STRIPPED, "dataSources", value);
                continue;
            }
            accepted.add(normalized);
        }
        return List.copyOf(accepted);
    }

    public static List<String> filterKnownListValues(
            List<String> raw,
            Set<String> knownValues,
            String jsonPath,
            ConfigImportReport report) {
        List<String> accepted = new ArrayList<>();
        for (String value : raw) {
            if (value == null || value.isBlank()) {
                continue;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if (!knownValues.contains(normalized)) {
                report.add(ConfigImportReport.Kind.UNKNOWN_VALUE, jsonPath, value);
                continue;
            }
            accepted.add(normalized);
        }
        return List.copyOf(accepted);
    }

    public static List<String> filterTrafficToolTypes(
            List<String> raw,
            ConfigImportReport report,
            boolean communityEdition) {
        Set<String> known = Set.copyOf(ConfigState.ALL_TRAFFIC_TOOL_TYPES);
        List<String> accepted = new ArrayList<>();
        for (String value : raw) {
            if (value == null || value.isBlank()) {
                continue;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if (!known.contains(normalized)) {
                report.add(ConfigImportReport.Kind.UNKNOWN_VALUE, "dataSourceOptions.traffic", value);
                continue;
            }
            if (communityEdition && COMMUNITY_DISABLED_TRAFFIC_TOOL_TYPES.contains(normalized)) {
                report.add(ConfigImportReport.Kind.EDITION_STRIPPED, "dataSourceOptions.traffic", value);
                continue;
            }
            accepted.add(normalized);
        }
        return List.copyOf(accepted);
    }

    public static boolean isKnownExportIndex(String indexName) {
        return indexName != null
                && KNOWN_EXPORT_INDEXES.contains(indexName.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Returns a toggleable export field key when recognized; otherwise records a warning and
     * returns {@code null}.
     */
    public static String normalizeExportFieldKey(
            String indexName,
            String fieldKey,
            ConfigImportReport report) {
        if (indexName == null || fieldKey == null || fieldKey.isBlank()) {
            return null;
        }
        String trimmed = fieldKey.trim();
        if (ExportFieldRegistry.getToggleableFields(indexName).contains(trimmed)) {
            return trimmed;
        }
        report.add(
                ConfigImportReport.Kind.UNKNOWN_VALUE,
                "exportFields." + indexName,
                trimmed);
        return null;
    }

    private static boolean matchesDefaults(List<String> actual, List<String> defaults) {
        return normalizeValueSet(actual).equals(normalizeValueSet(defaults));
    }

    private static List<String> orderedInclusion(List<String> selected, List<String> canonicalOrder) {
        Set<String> chosen = normalizeValueSet(selected);
        List<String> out = new ArrayList<>();
        for (String value : canonicalOrder) {
            if (chosen.contains(value)) {
                out.add(value);
            }
        }
        return List.copyOf(out);
    }

    private static Set<String> normalizeValueSet(List<String> values) {
        Set<String> out = new LinkedHashSet<>();
        if (values == null) {
            return out;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                out.add(value.trim().toLowerCase(Locale.ROOT));
            }
        }
        return out;
    }
}
