package ai.anomalousvectors.tools.burp.utils.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ai.anomalousvectors.tools.burp.utils.Version;

/**
 * JSON marshaling for config import/export.
 * Produces pretty JSON with deterministic field order (stable insertion order).
 */
public final class Json {

    static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(SerializationFeature.INDENT_OUTPUT, true);

    // Version is obtained strictly from the JAR manifest's Implementation-Version.
    private static final String VERSION = Version.get();

    // Common literals
    private static final String LIT_SCOPE  = "scope";
    private static final String LIT_CUSTOM = "custom";
    private static final String LIT_REGEX  = "regex";
    private static final String LIT_STRING = "string";
    private static final List<String> ALLOWED_OPEN_SEARCH_AUTH_TYPES = List.of(
            "API key",
            "Bearer token",
            "Certificate",
            "Basic",
            "None");
    private static final List<String> ALLOWED_OPEN_SEARCH_AMAZON_AUTH_TYPES = List.of(
            "IAM (sigV4)",
            "Basic",
            "None");
    private static final List<String> ALLOWED_SEARCH_DESTINATIONS = List.of(
            ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
            ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
            ConfigState.SearchDestination.ELASTICSEARCH.configKey());
    private static final List<String> SINKS_KEYS = List.of("files", "database");
    private static final List<String> FILES_KEYS = List.of("enabled", "path", "formats", "limits");
    private static final List<String> FILE_LIMITS_KEYS = List.of(
            "totalEnabled",
            "totalGb",
            "diskUsedPercentEnabled",
            "maxDiskUsedPercent");
    private static final List<String> OPEN_SEARCH_KEYS = List.of(
            "url",
            "tlsMode",
            "auth",
            "pinnedTlsCertificate");
    private static final List<String> DATABASE_KEYS = List.of(
            "enabled",
            "type",
            "openSearch",
            "openSearchAmazon",
            "elasticsearch");
    private static final List<String> OPEN_SEARCH_AMAZON_KEYS = List.of(
            "url",
            "region",
            "profile",
            "tlsMode",
            "auth",
            "pinnedTlsCertificate");
    private static final List<String> ELASTICSEARCH_KEYS = List.of(
            "url",
            "tlsMode",
            "auth",
            "pinnedTlsCertificate");
    private static final List<String> OPEN_SEARCH_AUTH_KEYS = List.of(
            "type",
            "username",
            "apiKeyId",
            "certPath",
            "certKeyPath");
    private static final List<String> ELASTICSEARCH_AUTH_KEYS = List.of(
            "type",
            "username",
            "certPath",
            "certKeyPath");
    private static final List<String> OPEN_SEARCH_AMAZON_AUTH_KEYS = List.of(
            "type",
            "username");
    private static final List<String> PINNED_TLS_KEYS = List.of(
            "sourcePath",
            "fingerprintSha256",
            "encodedBase64");

    private Json() { }

    /** Dedicated runtime exception for config JSON errors. */
    public static final class ConfigJsonException extends RuntimeException {
        public ConfigJsonException(String message, Throwable cause) { super(message, cause); }
    }

    /**
     * Parsed config projection used by the UI and tests.
     * Null/empty defaulting behavior is handled via the canonical constructor.
     */
    public static final record ImportedConfig(
            List<String> dataSources,
            String scopeType,
            List<String> scopeRegexes,
            List<String> scopeKinds,
            boolean filesEnabled,
            String filesPath,
            boolean fileJsonlEnabled,
            boolean fileBulkNdjsonEnabled,
            boolean fileTotalCapEnabled,
            double fileTotalCapGb,
            boolean fileDiskUsagePercentEnabled,
            int fileDiskUsagePercent,
            boolean openSearchEnabled,
            String openSearchUrl,
            String openSearchUser,
            String openSearchPassword,
            String openSearchTlsMode,
            ConfigState.OpenSearchOptions openSearchOptions,
            String searchDestination,
            String openSearchAmazonUrl,
            ConfigState.OpenSearchAmazonOptions openSearchAmazonOptions,
            String elasticSearchUrl,
            ConfigState.ElasticsearchOptions elasticSearchOptions,
            List<String> settingsSub,
            List<String> trafficToolTypes,
            List<String> findingsSeverities,
            List<String> exporterSubOptions,
            int exporterStatsIntervalSeconds,
            boolean exporterOptionsPresent,
            String indexNameBaseTemplate,
            Map<String, Set<String>> enabledExportFieldsByIndex,
            ConfigState.UiPreferences uiPreferences) {

        public ImportedConfig(
                List<String> dataSources,
                String scopeType,
                List<String> scopeRegexes,
                List<String> scopeKinds,
                boolean filesEnabled,
                String filesPath,
                boolean fileJsonlEnabled,
                boolean fileBulkNdjsonEnabled,
                boolean fileTotalCapEnabled,
                double fileTotalCapGb,
                boolean fileDiskUsagePercentEnabled,
                int fileDiskUsagePercent,
                boolean openSearchEnabled,
                String openSearchUrl,
                String openSearchUser,
                String openSearchPassword,
                String openSearchTlsMode,
                ConfigState.OpenSearchOptions openSearchOptions,
                String searchDestination,
                String openSearchAmazonUrl,
                ConfigState.OpenSearchAmazonOptions openSearchAmazonOptions,
                String elasticSearchUrl,
                ConfigState.ElasticsearchOptions elasticSearchOptions,
                List<String> settingsSub,
                List<String> trafficToolTypes,
                List<String> findingsSeverities,
                List<String> exporterSubOptions,
                int exporterStatsIntervalSeconds,
                boolean exporterOptionsPresent,
                String indexNameBaseTemplate,
                Map<String, Set<String>> enabledExportFieldsByIndex,
                ConfigState.UiPreferences uiPreferences
        ) {
            this.dataSources = ConfigState.normalizeDataSources(dataSources);
            this.scopeType = ConfigState.normalizeScopeType(scopeType);
            this.scopeRegexes = scopeRegexes == null ? List.of() : List.copyOf(scopeRegexes);
            this.scopeKinds = scopeKinds == null ? null : List.copyOf(scopeKinds);
            this.filesEnabled = filesEnabled;
            this.filesPath = filesPath;
            this.fileJsonlEnabled = fileJsonlEnabled;
            this.fileBulkNdjsonEnabled = fileBulkNdjsonEnabled;
            this.fileTotalCapEnabled = fileTotalCapEnabled;
            this.fileTotalCapGb = ConfigState.normalizeFileTotalCapGb(fileTotalCapGb);
            this.fileDiskUsagePercentEnabled = fileDiskUsagePercentEnabled;
            this.fileDiskUsagePercent = fileDiskUsagePercent;
            this.openSearchEnabled = openSearchEnabled;
            this.openSearchUrl = openSearchUrl;
            this.openSearchUser = openSearchUser != null ? openSearchUser : "";
            this.openSearchPassword = openSearchPassword != null ? openSearchPassword : "";
            this.openSearchTlsMode = ConfigState.normalizeOpenSearchTlsMode(openSearchTlsMode);
            this.openSearchOptions = openSearchOptions == null ? ConfigState.defaultOpenSearchOptions() : openSearchOptions;
            this.searchDestination = ConfigState.normalizeSearchDestination(searchDestination).configKey();
            this.openSearchAmazonUrl = openSearchAmazonUrl != null ? openSearchAmazonUrl : "";
            this.openSearchAmazonOptions = openSearchAmazonOptions == null
                    ? ConfigState.defaultOpenSearchAmazonOptions()
                    : openSearchAmazonOptions;
            this.elasticSearchUrl = elasticSearchUrl != null ? elasticSearchUrl : "";
            this.elasticSearchOptions = elasticSearchOptions == null
                    ? ConfigState.defaultElasticsearchOptions()
                    : elasticSearchOptions;
            this.settingsSub = ConfigState.normalizeSettingsSub(settingsSub);
            this.trafficToolTypes = ConfigState.normalizeTrafficToolTypes(trafficToolTypes);
            this.findingsSeverities = ConfigState.normalizeFindingsSeverities(findingsSeverities);
            this.exporterSubOptions = ConfigState.normalizeExporterSubOptions(exporterSubOptions);
            this.exporterStatsIntervalSeconds = ConfigState.normalizeExporterStatsIntervalSeconds(exporterStatsIntervalSeconds);
            this.exporterOptionsPresent = exporterOptionsPresent;
            this.indexNameBaseTemplate = ConfigState.normalizeIndexNameBaseTemplate(indexNameBaseTemplate);
            this.enabledExportFieldsByIndex = copyMapOfSets(enabledExportFieldsByIndex);
            this.uiPreferences = uiPreferences == null ? ConfigState.defaultUiPreferences() : uiPreferences;
        }

        private static Map<String, Set<String>> copyMapOfSets(Map<String, Set<String>> map) {
            if (map == null || map.isEmpty()) return null;
            Map<String, Set<String>> out = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> e : map.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    out.put(e.getKey(), Collections.unmodifiableSet(new LinkedHashSet<>(e.getValue())));
                }
            }
            return out.isEmpty() ? null : Collections.unmodifiableMap(out);
        }
    }

    /* ======================== BUILD (from typed state) ======================== */

    // Package-private: only the typed mapper should call this.
    static String buildFromState(ConfigState.State state) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", VERSION);

        buildDataSources(root, state);
        buildDataSourceOptions(root, state);
        buildScope(root, state);
        buildSinks(root, state);
        buildIndexNames(root, state);
        buildUi(root, state);
        buildExportFields(root, state);

        try {
            return MAPPER.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new ConfigJsonException("JSON serialization error", e);
        }
    }

    private static void buildDataSources(ObjectNode root, ConfigState.State state) {
        List<String> sources = ConfigImportCatalog.compactDataSourcesForExport(
                state.dataSources(), RuntimeConfig.isCommunityEdition());
        if (sources == null) {
            return;
        }
        ArrayNode srcArr = root.putArray("dataSources");
        for (String s : sources) {
            if (s != null) {
                srcArr.add(s);
            }
        }
    }

    private static void buildDataSourceOptions(ObjectNode root, ConfigState.State state) {
        ConfigImportCatalog.CompactDataSourceOptions compact =
                ConfigImportCatalog.compactDataSourceOptionsForExport(
                        state.settingsSub(),
                        state.trafficToolTypes(),
                        state.findingsSeverities(),
                        state.exporterSubOptions(),
                        state.exporterStatsIntervalSeconds(),
                        RuntimeConfig.isCommunityEdition());
        if (compact == null) {
            return;
        }
        ObjectNode opts = root.putObject("dataSourceOptions");
        if (compact.settings() != null) {
            ArrayNode settingsArr = opts.putArray("settings");
            for (String s : compact.settings()) {
                if (s != null) {
                    settingsArr.add(s);
                }
            }
        }
        if (compact.traffic() != null) {
            ArrayNode trafficArr = opts.putArray("traffic");
            for (String s : compact.traffic()) {
                if (s != null) {
                    trafficArr.add(s);
                }
            }
        }
        if (compact.findings() != null) {
            ArrayNode findingsArr = opts.putArray("findings");
            for (String s : compact.findings()) {
                if (s != null) {
                    findingsArr.add(s);
                }
            }
        }
        if (compact.exporter() != null) {
            ArrayNode exporterArr = opts.putArray("exporter");
            for (String s : compact.exporter()) {
                if (s != null) {
                    exporterArr.add(s);
                }
            }
        }
        if (compact.exporterStatsIntervalSeconds() != null) {
            opts.put("exporterStatsIntervalSeconds", compact.exporterStatsIntervalSeconds());
        }
    }

    private static void buildScope(ObjectNode root, ConfigState.State state) {
        String scopeType = state.scopeType();

        // Simple radio scopes ("all", "burp") are represented as an array of strings, e.g.:
        //   "scope": ["all"]
        //   "scope": ["burp"]
        if ("all".equals(scopeType) || "burp".equals(scopeType)) {
            ArrayNode scopeArr = root.putArray(LIT_SCOPE);
            scopeArr.add(scopeType);
            return;
        }

        // Custom scope keeps object form for its entries, e.g.:
        //   "scope": { "custom": { "regex1": "^example$", "string1": "foo" } }
        ObjectNode scope = root.putObject(LIT_SCOPE);
        ObjectNode custom = scope.putObject(LIT_CUSTOM);
        int regexCount = 0;
        int stringCount = 0;

        for (ConfigState.ScopeEntry e : state.customEntries()) {
            // positive guard; no empty-body if, no continue
            if (e != null) {
                String value = e.value();
                if (value != null && !value.isBlank()) {
                    boolean isRegex = e.kind() != ConfigState.Kind.STRING;
                    if (isRegex) {
                        regexCount++;
                        custom.put(LIT_REGEX + regexCount, value);
                    } else {
                        stringCount++;
                        custom.put(LIT_STRING + stringCount, value);
                    }
                }
            }
        }
    }

    private static void buildSinks(ObjectNode root, ConfigState.State state) {
        var sinks = state.sinks();
        ObjectNode sinksNode = root.putObject("sinks");
        if (sinks == null) return;

        ObjectNode filesNode = sinksNode.putObject("files");
        filesNode.put("enabled", sinks.filesEnabled());
        String files = sinks.filesPath();
        if (files != null && !files.isBlank()) {
            filesNode.put("path", files);
        }
        ArrayNode fileFormats = filesNode.putArray("formats");
        if (sinks.fileJsonlEnabled()) {
            fileFormats.add("jsonl");
        }
        if (sinks.fileBulkNdjsonEnabled()) {
            fileFormats.add("bulkNdjson");
        }
        ObjectNode fileLimits = filesNode.putObject("limits");
        fileLimits.put("totalEnabled", sinks.fileTotalCapEnabled());
        fileLimits.put("totalGb", sinks.fileTotalCapGb());
        fileLimits.put("diskUsedPercentEnabled", sinks.fileDiskUsagePercentEnabled());
        fileLimits.put("maxDiskUsedPercent", sinks.fileDiskUsagePercent());

        ObjectNode databaseNode = sinksNode.putObject("database");
        databaseNode.put("enabled", sinks.osEnabled());
        databaseNode.put("type", sinks.searchDestinationKind().configKey());
        buildOpenSearchDestination(databaseNode.putObject("openSearch"), sinks);
        buildOpenSearchAmazonDestination(databaseNode.putObject("openSearchAmazon"), sinks);
        buildElasticsearchDestination(databaseNode.putObject("elasticsearch"), sinks);
    }

    private static void buildOpenSearchDestination(ObjectNode node, ConfigState.Sinks sinks) {
        String os = sinks.openSearchUrl();
        if (os != null && !os.isBlank()) {
            node.put("url", os);
        }
        node.put("tlsMode", ConfigState.normalizeOpenSearchTlsMode(sinks.openSearchTlsMode()));
        ObjectNode auth = node.putObject("auth");
        ConfigState.OpenSearchOptions options = sinks.openSearchOptions() == null
                ? ConfigState.defaultOpenSearchOptions()
                : sinks.openSearchOptions();
        String authType = options.authType();
        auth.put("type", authType);
        switch (authType) {
            case "Basic" -> {
                if (!sinks.openSearchUser().isBlank()) {
                    auth.put("username", sinks.openSearchUser());
                }
            }
            case "API key" -> { }
            case "Certificate" -> {
                if (!options.certPath().isBlank()) {
                    auth.put("certPath", options.certPath());
                }
                if (!options.certKeyPath().isBlank()) {
                    auth.put("certKeyPath", options.certKeyPath());
                }
            }
            case "Bearer token", "None" -> { }
            default -> throw new IllegalStateException("Unexpected OpenSearch auth type: " + authType);
        }
        buildPinnedTls(node, options.pinnedTlsCertificateSourcePath(),
                options.pinnedTlsCertificateFingerprintSha256(),
                options.pinnedTlsCertificateEncodedBase64());
    }

    private static void buildOpenSearchAmazonDestination(ObjectNode node, ConfigState.Sinks sinks) {
        String url = sinks.openSearchAmazonUrl();
        if (url != null && !url.isBlank()) {
            node.put("url", url);
        }
        ConfigState.OpenSearchAmazonOptions options = sinks.openSearchAmazonOptions() == null
                ? ConfigState.defaultOpenSearchAmazonOptions()
                : sinks.openSearchAmazonOptions();
        if (!options.region().isBlank()) {
            node.put("region", options.region());
        }
        if (!options.profile().isBlank()) {
            node.put("profile", options.profile());
        }
        node.put("tlsMode", ConfigState.normalizeOpenSearchTlsMode(options.tlsMode()));
        ObjectNode auth = node.putObject("auth");
        auth.put("type", options.authType());
        if ("Basic".equals(options.authType()) && !options.username().isBlank()) {
            auth.put("username", options.username());
        }
        buildPinnedTls(node, options.pinnedTlsCertificateSourcePath(),
                options.pinnedTlsCertificateFingerprintSha256(),
                options.pinnedTlsCertificateEncodedBase64());
    }

    private static void buildElasticsearchDestination(ObjectNode node, ConfigState.Sinks sinks) {
        String url = sinks.elasticSearchUrl();
        if (url != null && !url.isBlank()) {
            node.put("url", url);
        }
        ConfigState.ElasticsearchOptions options = sinks.elasticSearchOptions() == null
                ? ConfigState.defaultElasticsearchOptions()
                : sinks.elasticSearchOptions();
        node.put("tlsMode", ConfigState.normalizeOpenSearchTlsMode(options.tlsMode()));
        ObjectNode auth = node.putObject("auth");
        String authType = options.authType();
        auth.put("type", authType);
        switch (authType) {
            case "Basic" -> {
                if (!options.username().isBlank()) {
                    auth.put("username", options.username());
                }
            }
            case "API key" -> { }
            case "Certificate" -> {
                if (!options.certPath().isBlank()) {
                    auth.put("certPath", options.certPath());
                }
                if (!options.certKeyPath().isBlank()) {
                    auth.put("certKeyPath", options.certKeyPath());
                }
            }
            case "Bearer token", "None" -> { }
            default -> throw new IllegalStateException("Unexpected Elasticsearch auth type: " + authType);
        }
        buildPinnedTls(node, options.pinnedTlsCertificateSourcePath(),
                options.pinnedTlsCertificateFingerprintSha256(),
                options.pinnedTlsCertificateEncodedBase64());
    }

    private static void buildPinnedTls(
            ObjectNode node,
            String sourcePath,
            String fingerprintSha256,
            String encodedBase64) {
        if (isBlank(sourcePath) && isBlank(fingerprintSha256) && isBlank(encodedBase64)) {
            return;
        }
        ObjectNode pinned = node.putObject("pinnedTlsCertificate");
        if (!isBlank(sourcePath)) {
            pinned.put("sourcePath", sourcePath);
        }
        if (!isBlank(fingerprintSha256)) {
            pinned.put("fingerprintSha256", fingerprintSha256);
        }
        if (!isBlank(encodedBase64)) {
            pinned.put("encodedBase64", encodedBase64);
        }
    }

    private static void buildUi(ObjectNode root, ConfigState.State state) {
        ConfigState.UiPreferences uiPreferences = state.uiPreferences() == null
                ? ConfigState.defaultUiPreferences()
                : state.uiPreferences();
        ObjectNode uiNode = root.putObject("ui");
        ObjectNode statsNode = uiNode.putObject("stats");
        statsNode.put("chartStyle", uiPreferences.statsChartStyle());

        ConfigState.LogPanelPreferences log = uiPreferences.logPanel();
        ObjectNode logNode = uiNode.putObject("log");
        logNode.put("minLevel", ConfigState.normalizeLogMinLevel(log.minLevel()));
        logNode.put("pauseAutoscroll", log.pauseAutoscroll());
        logNode.put("filterText", log.filterText());
        logNode.put("filterCase", log.filterCase());
        logNode.put("filterRegex", log.filterRegex());
        logNode.put("filterNegative", log.filterNegative());
        logNode.put("searchText", log.searchText());
        logNode.put("searchCase", log.searchCase());
        logNode.put("searchRegex", log.searchRegex());
    }

    private static void buildIndexNames(ObjectNode root, ConfigState.State state) {
        ObjectNode indexNames = root.putObject("indexNames");
        indexNames.put("baseTemplate", state.indexNameBaseTemplate());
    }

    private static void buildExportFields(ObjectNode root, ConfigState.State state) {
        Map<String, Set<String>> byIndex =
                ExportFieldRegistry.compactEnabledFieldsForExport(state.enabledExportFieldsByIndex());
        if (byIndex == null || byIndex.isEmpty()) return;
        ObjectNode exportFields = root.putObject("exportFields");
        for (Map.Entry<String, Set<String>> e : byIndex.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            ArrayNode arr = exportFields.putArray(e.getKey());
            for (String field : e.getValue()) {
                if (field != null) arr.add(field);
            }
        }
    }

    /* ======================== PARSE (into ImportedConfig) ===================== */

    /**
     * Parsed config plus any non-fatal import warnings.
     */
    public static final record ConfigJsonParseResult(ImportedConfig config, ConfigImportReport report) { }

    public static ConfigJsonParseResult parseConfigJsonWithReport(String json) throws IOException {
        ConfigImportReport report = new ConfigImportReport();
        ImportedConfig config = parseConfigJson(json, report);
        return new ConfigJsonParseResult(config, report);
    }

    public static ImportedConfig parseConfigJson(String json) throws IOException {
        return parseConfigJson(json, new ConfigImportReport());
    }

    private static ImportedConfig parseConfigJson(String json, ConfigImportReport report) throws IOException {
        JsonNode root = MAPPER.readTree(json);
        if (!root.isObject()) {
            throw new IOException("Invalid config: root must be a JSON object.");
        }
        ConfigImportCatalog.collectUnknownRootKeys(root, report);
        boolean communityEdition = RuntimeConfig.isCommunityEdition();

        List<String> sources = parseDataSources(root, report, communityEdition);
        DataSourceOptionsParts opts = parseDataSourceOptions(root, report, communityEdition);
        ScopeParts scope = parseScope(root, report);
        SinksParts sinks = parseSinks(root, report);
        IndexNamesParts indexNames = parseIndexNames(root, report);
        UiParts ui = parseUi(root, report);
        Map<String, Set<String>> exportFields = parseExportFields(root, report);

        return new ImportedConfig(
                sources,
                scope.type(),
                scope.values(),
                scope.kinds(),
                sinks.filesEnabled(),
                sinks.files(),
                sinks.fileJsonlEnabled(),
                sinks.fileBulkNdjsonEnabled(),
                sinks.fileTotalCapEnabled(),
                sinks.fileTotalCapGb(),
                sinks.fileDiskUsagePercentEnabled(),
                sinks.fileDiskUsagePercent(),
                sinks.openSearchEnabled(),
                sinks.os(),
                sinks.osUser(),
                sinks.osPass(),
                sinks.openSearchTlsMode(),
                sinks.openSearchOptions(),
                sinks.searchDestination(),
                sinks.openSearchAmazonUrl(),
                sinks.openSearchAmazonOptions(),
                sinks.elasticSearchUrl(),
                sinks.elasticSearchOptions(),
                opts.settingsSub(),
                opts.trafficToolTypes(),
                opts.findingsSeverities(),
                opts.exporterSubOptions(),
                opts.exporterStatsIntervalSeconds(),
                opts.exporterOptionsPresent(),
                indexNames.baseTemplate(),
                exportFields,
                ui.uiPreferences()
        );
    }

    private static UiParts parseUi(JsonNode root, ConfigImportReport report) throws IOException {
        JsonNode ui = root.path("ui");
        if (!ui.isMissingNode() && !ui.isNull()) {
            if (!ui.isObject()) {
                throw new IOException("Invalid config: 'ui' must be an object.");
            }
            ConfigImportCatalog.collectUnknownObjectKeys(ui, "ui", ConfigImportCatalog.UI_KEYS, report);
        }
        JsonNode stats = ui.path("stats");
        if (stats.isObject()) {
            ConfigImportCatalog.collectUnknownObjectKeys(
                    stats, "ui.stats", ConfigImportCatalog.UI_STATS_KEYS, report);
        }
        JsonNode log = ui.path("log");
        if (log.isObject()) {
            ConfigImportCatalog.collectUnknownObjectKeys(
                    log, "ui.log", ConfigImportCatalog.UI_LOG_KEYS, report);
        }
        ConfigState.LogPanelPreferences logPreferences = new ConfigState.LogPanelPreferences(
                textOrNull(log.get("minLevel")),
                bool(log.get("pauseAutoscroll"), false),
                textOrEmpty(log.get("filterText")),
                bool(log.get("filterCase"), false),
                bool(log.get("filterRegex"), false),
                bool(log.get("filterNegative"), false),
                textOrEmpty(log.get("searchText")),
                bool(log.get("searchCase"), false),
                bool(log.get("searchRegex"), false));
        ConfigState.UiPreferences uiPreferences = new ConfigState.UiPreferences(
                intOr(stats.get("chartStyle"), ConfigState.DEFAULT_STATS_CHART_STYLE),
                logPreferences);
        return new UiParts(uiPreferences);
    }

    /* ----------------------- parse helpers ----------------------- */

    private static List<String> parseDataSources(
            JsonNode root,
            ConfigImportReport report,
            boolean communityEdition) {
        JsonNode ds = root.path("dataSources");
        if (ds.isMissingNode() || ds.isNull()) {
            return ConfigImportCatalog.allDataSourcesForEdition(communityEdition);
        }
        if (!ds.isArray()) {
            report.add(ConfigImportReport.Kind.UNKNOWN_KEY, "dataSources", "<non-array>");
            return ConfigImportCatalog.allDataSourcesForEdition(communityEdition);
        }
        List<String> raw = new ArrayList<>();
        for (JsonNode n : ds) {
            if (n.isTextual()) {
                raw.add(n.asText());
            }
        }
        return ConfigImportCatalog.filterKnownDataSources(raw, report, communityEdition);
    }

    /**
     * Parses dataSourceOptions. If absent, returns current defaults.
     */
    private static DataSourceOptionsParts parseDataSourceOptions(
            JsonNode root,
            ConfigImportReport report,
            boolean communityEdition) {
        JsonNode opts = root.path("dataSourceOptions");
        if (!opts.isObject()) {
            return new DataSourceOptionsParts(
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    false
            );
        }
        ConfigImportCatalog.collectUnknownObjectKeys(
                opts, "dataSourceOptions", ConfigImportCatalog.DATA_SOURCE_OPTIONS_KEYS, report);
        List<String> settings;
        if (!opts.has("settings")) {
            settings = List.copyOf(ConfigState.DEFAULT_SETTINGS_SUB);
        } else {
            List<String> filtered = ConfigImportCatalog.filterKnownListValues(
                    arrayToStringList(opts.path("settings")),
                    Set.copyOf(ConfigState.DEFAULT_SETTINGS_SUB),
                    "dataSourceOptions.settings",
                    report);
            settings = filtered.isEmpty() ? ConfigState.DEFAULT_SETTINGS_SUB : filtered;
        }
        List<String> traffic;
        if (!opts.has("traffic")) {
            traffic = ConfigImportCatalog.defaultTrafficToolTypesForEdition(communityEdition);
        } else {
            traffic = ConfigImportCatalog.filterTrafficToolTypes(
                    arrayToStringList(opts.path("traffic")),
                    report,
                    communityEdition);
        }
        List<String> findings;
        if (!opts.has("findings")) {
            findings = List.copyOf(ConfigState.DEFAULT_FINDINGS_SEVERITIES);
        } else {
            List<String> filtered = ConfigImportCatalog.filterKnownListValues(
                    arrayToStringList(opts.path("findings")),
                    Set.copyOf(ConfigState.DEFAULT_FINDINGS_SEVERITIES),
                    "dataSourceOptions.findings",
                    report);
            findings = filtered.isEmpty() ? ConfigState.DEFAULT_FINDINGS_SEVERITIES : filtered;
        }
        boolean exporterSpecified = opts.has("exporter");
        List<String> exporter;
        if (!exporterSpecified) {
            exporter = List.copyOf(ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS);
        } else {
            exporter = ConfigImportCatalog.filterKnownListValues(
                    arrayToStringList(opts.path("exporter")),
                    Set.copyOf(ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS),
                    "dataSourceOptions.exporter",
                    report);
        }
        boolean exporterOptionsPresent = opts.has("exporter") || opts.has("exporterStatsIntervalSeconds");
        int statsInterval = opts.has("exporterStatsIntervalSeconds")
                ? intOr(opts.get("exporterStatsIntervalSeconds"), ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS)
                : ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS;
        return new DataSourceOptionsParts(
                settings,
                traffic,
                findings,
                exporter,
                statsInterval,
                exporterOptionsPresent
        );
    }

    private static List<String> arrayToStringList(JsonNode arr) {
        List<String> out = new ArrayList<>();
        if (arr.isArray()) {
            for (JsonNode n : arr) {
                if (n.isTextual()) out.add(n.asText());
            }
        }
        return out;
    }

    private static ScopeParts parseScope(JsonNode root, ConfigImportReport report) {
        JsonNode scope = root.path(LIT_SCOPE);

        // Current representation: simple scopes as array of strings, e.g. ["all"] or ["burp"].
        if (scope.isArray() && !scope.isEmpty()) {
            JsonNode first = scope.get(0);
            if (first.isTextual()) {
                String v = first.asText();
                if ("all".equals(v) || "burp".equals(v)) {
                    return new ScopeParts(v, List.of(), null);
                }
                report.add(ConfigImportReport.Kind.UNRECOGNIZED_SCOPE, "scope", v);
            }
            // Unrecognized array: fall through to other accepted scope shapes below.
        }
        if (scope.isObject()) {
            ConfigImportCatalog.collectUnknownObjectKeys(
                    scope, "scope", List.of("all", "burp", LIT_CUSTOM, "customTypes"), report);
        }

        // Also accept object flags ("all": true / "burp": true).
        if (scope.path("all").asBoolean(false)) {
            return new ScopeParts("all", List.of(), null);
        }
        if (scope.path("burp").asBoolean(false)) {
            return new ScopeParts("burp", List.of(), null);
        }

        // Custom scope: either object or array (plus optional customTypes).
        JsonNode custom = scope.path(LIT_CUSTOM);
        if (custom.isObject()) {
            return parseCustomObject(custom);
        } else if (custom.isArray()) {
            return parseCustomArray(scope, custom);
        }
        // default to custom with no entries
        return new ScopeParts(LIT_CUSTOM, List.of(), null);
    }

    private static ScopeParts parseCustomObject(JsonNode custom) {
        List<String> vals = new ArrayList<>();
        List<String> kindsList = new ArrayList<>();
        for (Iterator<String> it = custom.fieldNames(); it.hasNext(); ) {
            String key = it.next();
            JsonNode v = custom.get(key);
            if (!v.isTextual()) {
                continue;
            }
            // stringX => string, everything else => regex
            String kind = key.startsWith(LIT_STRING) ? LIT_STRING : LIT_REGEX;
            kindsList.add(kind);
            vals.add(v.asText());
        }
        return new ScopeParts(LIT_CUSTOM, vals, kindsList);
    }

    private static ScopeParts parseCustomArray(JsonNode scope, JsonNode custom) {
        List<String> vals = new ArrayList<>();
        for (JsonNode n : custom) {
            if (n.isTextual()) vals.add(n.asText());
        }

        List<String> kindsList = null;
        JsonNode types = scope.path("customTypes");
        if (types.isArray() && types.size() == vals.size()) {
            kindsList = new ArrayList<>(types.size());
            for (JsonNode t : types) {
                kindsList.add(t.isTextual() ? t.asText() : LIT_REGEX);
            }
        }
        return new ScopeParts(LIT_CUSTOM, vals, kindsList);
    }

    private static SinksParts parseSinks(JsonNode root, ConfigImportReport report) throws IOException {
        JsonNode sinks = root.path("sinks");
        validateSinksShape(sinks, report);
        JsonNode filesNode = sinks.path("files");
        JsonNode databaseNode = sinks.path("database");

        String files = null;
        boolean fileJsonlEnabled = false;
        boolean fileBulkNdjsonEnabled = false;
        boolean fileTotalCapEnabled = true;
        double fileTotalCapGb = ConfigState.DEFAULT_FILE_TOTAL_CAP_GB;
        boolean fileDiskUsagePercentEnabled = true;
        int fileDiskUsagePercent = ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT;
        JsonNode filePathNode = filesNode.get("path");
        if (filePathNode != null && filePathNode.isTextual()) {
            String v = filePathNode.asText();
            if (!v.isBlank()) files = v;
        }
        boolean filesEnabled = bool(filesNode.get("enabled"), files != null);
        JsonNode fileFormatsNode = filesNode.path("formats");
        if (fileFormatsNode.isArray()) {
            for (int i = 0; i < fileFormatsNode.size(); i++) {
                JsonNode formatNode = fileFormatsNode.get(i);
                if (!formatNode.isTextual()) {
                    throw new IOException("Invalid config: 'sinks.files.formats[" + i + "]' must be a string.");
                }
                String format = formatNode.asText();
                switch (format) {
                    case "jsonl" -> fileJsonlEnabled = true;
                    case "bulkNdjson" -> fileBulkNdjsonEnabled = true;
                    default -> report.add(
                            ConfigImportReport.Kind.UNSUPPORTED_FORMAT,
                            "sinks.files.formats",
                            format);
                }
            }
        }
        JsonNode fileLimitsNode = filesNode.path("limits");
        if (fileLimitsNode.isObject()) {
            fileTotalCapEnabled = fileLimitsNode.path("totalEnabled").asBoolean(true);
            JsonNode totalGbNode = fileLimitsNode.get("totalGb");
            if (totalGbNode != null && totalGbNode.isNumber()) {
                fileTotalCapGb = totalGbNode.asDouble(ConfigState.DEFAULT_FILE_TOTAL_CAP_GB);
            }
            fileDiskUsagePercentEnabled = fileLimitsNode.path("diskUsedPercentEnabled").asBoolean(true);
            JsonNode diskPercentNode = fileLimitsNode.get("maxDiskUsedPercent");
            if (diskPercentNode != null && diskPercentNode.canConvertToInt()) {
                fileDiskUsagePercent = diskPercentNode.asInt(ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT);
            }
        }

        boolean databaseEnabled = bool(databaseNode.get("enabled"), false);
        String searchDestination = validateAndResolveSearchDestination(databaseNode);

        JsonNode openSearchNode = databaseNode.path("openSearch");
        String os = textIfNotBlank(openSearchNode.get("url"));
        String tlsMode = ConfigState.normalizeOpenSearchTlsMode(textOrNull(openSearchNode.get("tlsMode")));
        JsonNode authNode = openSearchNode.path("auth");
        String authType = validateAndResolveOpenSearchAuthType(authNode, "sinks.database.openSearch.auth.type");
        String username = textOrNull(authNode.get("username"));
        JsonNode pinnedTlsNode = openSearchNode.path("pinnedTlsCertificate");
        ConfigState.OpenSearchOptions openSearchOptions = new ConfigState.OpenSearchOptions(
                authType,
                textOrNull(authNode.get("apiKeyId")),
                textOrNull(authNode.get("certPath")),
                textOrNull(authNode.get("certKeyPath")),
                textOrNull(pinnedTlsNode.get("sourcePath")),
                textOrNull(pinnedTlsNode.get("fingerprintSha256")),
                textOrNull(pinnedTlsNode.get("encodedBase64")));
        validateOpenSearchAuthFieldCombination(
                "sinks.database.openSearch.auth", authType, username, openSearchOptions);

        JsonNode awsNode = databaseNode.path("openSearchAmazon");
        JsonNode awsAuthNode = awsNode.path("auth");
        String awsAuthType = validateAndResolveOpenSearchAmazonAuthType(awsAuthNode);
        String awsUsername = textOrNull(awsAuthNode.get("username"));
        JsonNode awsPinnedTlsNode = awsNode.path("pinnedTlsCertificate");
        ConfigState.OpenSearchAmazonOptions awsOptions = new ConfigState.OpenSearchAmazonOptions(
                awsAuthType,
                awsUsername,
                textOrNull(awsNode.get("region")),
                textOrNull(awsNode.get("profile")),
                textOrNull(awsNode.get("tlsMode")),
                textOrNull(awsPinnedTlsNode.get("sourcePath")),
                textOrNull(awsPinnedTlsNode.get("fingerprintSha256")),
                textOrNull(awsPinnedTlsNode.get("encodedBase64")));
        validateOpenSearchAmazonAuthFieldCombination(awsAuthType, awsUsername);

        JsonNode elasticNode = databaseNode.path("elasticsearch");
        JsonNode elasticAuthNode = elasticNode.path("auth");
        String elasticAuthType = validateAndResolveOpenSearchAuthType(
                elasticAuthNode,
                "sinks.database.elasticsearch.auth.type");
        String elasticUsername = textOrNull(elasticAuthNode.get("username"));
        JsonNode elasticPinnedTlsNode = elasticNode.path("pinnedTlsCertificate");
        ConfigState.ElasticsearchOptions elasticOptions = new ConfigState.ElasticsearchOptions(
                elasticAuthType,
                elasticUsername,
                textOrNull(elasticAuthNode.get("certPath")),
                textOrNull(elasticAuthNode.get("certKeyPath")),
                textOrNull(elasticNode.get("tlsMode")),
                textOrNull(elasticPinnedTlsNode.get("sourcePath")),
                textOrNull(elasticPinnedTlsNode.get("fingerprintSha256")),
                textOrNull(elasticPinnedTlsNode.get("encodedBase64")));
        validateElasticsearchAuthFieldCombination(elasticAuthType, elasticOptions);

        return new SinksParts(filesEnabled, files, fileJsonlEnabled, fileBulkNdjsonEnabled,
                fileTotalCapEnabled, fileTotalCapGb,
                fileDiskUsagePercentEnabled, fileDiskUsagePercent,
                databaseEnabled, os, username == null ? "" : username, "", tlsMode, openSearchOptions,
                searchDestination,
                textIfNotBlank(awsNode.get("url")),
                awsOptions,
                textIfNotBlank(elasticNode.get("url")),
                elasticOptions);
    }

    private static void validateSinksShape(JsonNode sinks, ConfigImportReport report) throws IOException {
        if (sinks.isMissingNode() || sinks.isNull()) {
            return;
        }
        if (!sinks.isObject()) {
            throw new IOException("Invalid config: 'sinks' must be an object.");
        }
        if (hasLegacyFlatSinksKeys(sinks) || sinks.has("openSearch")) {
            throw new IOException("Invalid config: database settings must live under nested 'sinks.database' "
                    + "with destination-specific objects (for example 'sinks.database.openSearch.url').");
        }
        ConfigImportCatalog.collectUnknownObjectKeys(sinks, "sinks", SINKS_KEYS, report);
        validateNestedSinkNode(sinks, "files", FILES_KEYS, report);
        validateNestedSinkNode(sinks, "database", DATABASE_KEYS, report);
        validateNestedObject(sinks.path("files").path("limits"), "sinks.files.limits", FILE_LIMITS_KEYS, report);
        validateFilesFormatsNode(sinks.path("files").path("formats"));
        JsonNode database = sinks.path("database");
        validateNestedObject(database.path("openSearch"), "sinks.database.openSearch", OPEN_SEARCH_KEYS, report);
        validateNestedObject(
                database.path("openSearch").path("auth"),
                "sinks.database.openSearch.auth",
                OPEN_SEARCH_AUTH_KEYS,
                report);
        validateNestedObject(
                database.path("openSearch").path("pinnedTlsCertificate"),
                "sinks.database.openSearch.pinnedTlsCertificate",
                PINNED_TLS_KEYS,
                report);
        validateNestedObject(
                database.path("openSearchAmazon"),
                "sinks.database.openSearchAmazon",
                OPEN_SEARCH_AMAZON_KEYS,
                report);
        validateNestedObject(
                database.path("openSearchAmazon").path("auth"),
                "sinks.database.openSearchAmazon.auth",
                OPEN_SEARCH_AMAZON_AUTH_KEYS,
                report);
        validateNestedObject(
                database.path("openSearchAmazon").path("pinnedTlsCertificate"),
                "sinks.database.openSearchAmazon.pinnedTlsCertificate",
                PINNED_TLS_KEYS,
                report);
        validateNestedObject(
                database.path("elasticsearch"),
                "sinks.database.elasticsearch",
                ELASTICSEARCH_KEYS,
                report);
        validateNestedObject(
                database.path("elasticsearch").path("auth"),
                "sinks.database.elasticsearch.auth",
                ELASTICSEARCH_AUTH_KEYS,
                report);
        validateNestedObject(
                database.path("elasticsearch").path("pinnedTlsCertificate"),
                "sinks.database.elasticsearch.pinnedTlsCertificate",
                PINNED_TLS_KEYS,
                report);
    }

    private static boolean hasLegacyFlatSinksKeys(JsonNode sinks) {
        return sinks.has("filesEnabled")
                || sinks.has("fileFormats")
                || sinks.has("fileLimits")
                || sinks.has("openSearchEnabled")
                || sinks.has("openSearchTlsMode")
                || sinks.has("openSearchUser")
                || sinks.has("openSearchPassword")
                || sinks.has("openSearchAuth")
                || sinks.has("openSearchPinnedTlsCertificate");
    }

    private static void validateNestedSinkNode(
            JsonNode sinks,
            String key,
            List<String> allowedKeys,
            ConfigImportReport report) throws IOException {
        JsonNode node = sinks.get(key);
        if (node != null && !node.isNull() && !node.isObject()) {
            throw new IOException("Invalid config: 'sinks." + key + "' must be an object.");
        }
        ConfigImportCatalog.collectUnknownObjectKeys(node, "sinks." + key, allowedKeys, report);
    }

    private static void validateNestedObject(
            JsonNode node,
            String path,
            List<String> allowedKeys,
            ConfigImportReport report) throws IOException {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return;
        }
        if (!node.isObject()) {
            throw new IOException("Invalid config: '" + path + "' must be an object.");
        }
        ConfigImportCatalog.collectUnknownObjectKeys(node, path, allowedKeys, report);
    }

    private static void validateFilesFormatsNode(JsonNode formatsNode) throws IOException {
        if (formatsNode == null || formatsNode.isMissingNode() || formatsNode.isNull()) {
            return;
        }
        if (!formatsNode.isArray()) {
            throw new IOException("Invalid config: 'sinks.files.formats' must be an array.");
        }
    }

    private static String validateAndResolveSearchDestination(JsonNode databaseNode) throws IOException {
        String rawType = textOrNull(databaseNode.get("type"));
        if (rawType == null || rawType.isBlank()) {
            return ConfigState.DEFAULT_SEARCH_DESTINATION;
        }
        String trimmed = rawType.trim();
        if (!ALLOWED_SEARCH_DESTINATIONS.contains(trimmed)) {
            throw new IOException("Invalid config: unsupported value '" + rawType + "' at 'sinks.database.type'. "
                    + "Allowed values: " + String.join(", ", ALLOWED_SEARCH_DESTINATIONS) + ".");
        }
        return trimmed;
    }

    private static String validateAndResolveOpenSearchAuthType(JsonNode authNode, String path) throws IOException {
        String rawAuthType = textOrNull(authNode.get("type"));
        if (rawAuthType == null || rawAuthType.isBlank()) {
            return ConfigState.DEFAULT_OPEN_SEARCH_AUTH_TYPE;
        }
        if (!ALLOWED_OPEN_SEARCH_AUTH_TYPES.contains(rawAuthType)) {
            throw new IOException("Invalid config: unsupported value '" + rawAuthType + "' at '" + path + "'. "
                    + "Allowed values: " + String.join(", ", ALLOWED_OPEN_SEARCH_AUTH_TYPES) + ".");
        }
        return rawAuthType;
    }

    private static String validateAndResolveOpenSearchAmazonAuthType(JsonNode authNode) throws IOException {
        String rawAuthType = textOrNull(authNode.get("type"));
        if (rawAuthType == null || rawAuthType.isBlank()) {
            return "IAM (sigV4)";
        }
        if (!ALLOWED_OPEN_SEARCH_AMAZON_AUTH_TYPES.contains(rawAuthType)) {
            throw new IOException("Invalid config: unsupported value '" + rawAuthType
                    + "' at 'sinks.database.openSearchAmazon.auth.type'. Allowed values: "
                    + String.join(", ", ALLOWED_OPEN_SEARCH_AMAZON_AUTH_TYPES) + ".");
        }
        return rawAuthType;
    }

    private static void validateOpenSearchAuthFieldCombination(
            String authPath,
            String authType,
            String username,
            ConfigState.OpenSearchOptions openSearchOptions) throws IOException {
        List<String> allowedFields = allowedAuthFieldsFor(authType);
        requireAllowedAuthField(authPath, authType, "username", username, allowedFields);
        requireAllowedAuthField(authPath, authType, "apiKeyId", openSearchOptions.apiKeyId(), allowedFields);
        requireAllowedAuthField(authPath, authType, "certPath", openSearchOptions.certPath(), allowedFields);
        requireAllowedAuthField(authPath, authType, "certKeyPath", openSearchOptions.certKeyPath(), allowedFields);
    }

    private static void validateOpenSearchAmazonAuthFieldCombination(
            String authType,
            String username) throws IOException {
        List<String> allowedFields = switch (authType) {
            case "Basic" -> List.of("username");
            case "IAM (sigV4)", "None" -> List.of();
            default -> throw new IllegalStateException("Unexpected Amazon OpenSearch auth type: " + authType);
        };
        requireAllowedAuthField(
                "sinks.database.openSearchAmazon.auth",
                authType,
                "username",
                username,
                allowedFields);
    }

    private static void validateElasticsearchAuthFieldCombination(
            String authType,
            ConfigState.ElasticsearchOptions elasticOptions) throws IOException {
        List<String> allowedFields = allowedAuthFieldsFor(authType);
        requireAllowedAuthField(
                "sinks.database.elasticsearch.auth",
                authType,
                "username",
                elasticOptions.username(),
                allowedFields);
        requireAllowedAuthField(
                "sinks.database.elasticsearch.auth",
                authType,
                "certPath",
                elasticOptions.certPath(),
                allowedFields);
        requireAllowedAuthField(
                "sinks.database.elasticsearch.auth",
                authType,
                "certKeyPath",
                elasticOptions.certKeyPath(),
                allowedFields);
    }

    private static List<String> allowedAuthFieldsFor(String authType) {
        return switch (authType) {
            case "Basic" -> List.of("username");
            case "API key" -> List.of("apiKeyId");
            case "Certificate" -> List.of("certPath", "certKeyPath");
            case "Bearer token", "None" -> List.of();
            default -> throw new IllegalStateException("Unexpected OpenSearch auth type: " + authType);
        };
    }

    private static void requireAllowedAuthField(
            String authPath,
            String authType,
            String fieldName,
            String value,
            List<String> allowedFields) throws IOException {
        if (value == null || value.isBlank() || allowedFields.contains(fieldName)) {
            return;
        }
        String allowed = allowedFields.isEmpty() ? "none" : String.join(", ", allowedFields);
        throw new IOException("Invalid config: '" + authPath + "." + fieldName
                + "' is not allowed when '" + authPath + ".type' is '" + authType
                + "'. Allowed non-secret fields for this auth type: " + allowed + ".");
    }

    private static IndexNamesParts parseIndexNames(JsonNode root, ConfigImportReport report) {
        JsonNode indexNames = root.path("indexNames");
        if (!indexNames.isObject()) {
            return new IndexNamesParts(ConfigState.DEFAULT_INDEX_NAME_BASE_TEMPLATE);
        }
        ConfigImportCatalog.collectUnknownObjectKeys(
                indexNames, "indexNames", ConfigImportCatalog.INDEX_NAMES_KEYS, report);
        String baseTemplate = textOrNull(indexNames.get("baseTemplate"));
        return new IndexNamesParts(ConfigState.normalizeIndexNameBaseTemplate(baseTemplate));
    }

    /** Returns null when absent (all fields enabled); empty per-index arrays disable optional fields. */
    private static Map<String, Set<String>> parseExportFields(JsonNode root, ConfigImportReport report) {
        JsonNode exportFields = root.path("exportFields");
        if (!exportFields.isObject()) {
            return null;
        }
        Map<String, Set<String>> out = new java.util.LinkedHashMap<>();
        for (Iterator<String> it = exportFields.fieldNames(); it.hasNext(); ) {
            String indexName = it.next();
            if (!ConfigImportCatalog.isKnownExportIndex(indexName)) {
                report.add(ConfigImportReport.Kind.UNKNOWN_KEY, "exportFields." + indexName, indexName);
                continue;
            }
            JsonNode arr = exportFields.get(indexName);
            if (!arr.isArray()) {
                report.add(ConfigImportReport.Kind.UNKNOWN_KEY, "exportFields." + indexName, "<non-array>");
                continue;
            }
            Set<String> set = new LinkedHashSet<>();
            for (JsonNode n : arr) {
                if (!n.isTextual()) {
                    continue;
                }
                String normalized = ConfigImportCatalog.normalizeExportFieldKey(
                        indexName, n.asText(), report);
                if (normalized != null) {
                    set.add(normalized);
                }
            }
            if (arr.isEmpty() || !set.isEmpty()) {
                out.put(indexName, Set.copyOf(set));
            }
        }
        return out.isEmpty() ? null : Map.copyOf(out);
    }

    private static String textOrNull(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
    }

    private static String textIfNotBlank(JsonNode node) {
        String value = textOrNull(node);
        return value == null || value.isBlank() ? null : value;
    }

    private static String textOrEmpty(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : "";
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static boolean bool(JsonNode node, boolean fallback) {
        return node != null && node.isBoolean() ? node.asBoolean() : fallback;
    }

    private static int intOr(JsonNode node, int fallback) {
        return node != null && node.canConvertToInt() ? node.asInt() : fallback;
    }

    /* ----------------------- small carrier records ----------------------- */

    private record ScopeParts(String type, List<String> values, List<String> kinds) { }
    private record SinksParts(boolean filesEnabled, String files, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                              boolean fileTotalCapEnabled, double fileTotalCapGb,
                              boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                              boolean openSearchEnabled,
                              String os, String osUser, String osPass, String openSearchTlsMode,
                              ConfigState.OpenSearchOptions openSearchOptions,
                              String searchDestination,
                              String openSearchAmazonUrl,
                              ConfigState.OpenSearchAmazonOptions openSearchAmazonOptions,
                              String elasticSearchUrl,
                              ConfigState.ElasticsearchOptions elasticSearchOptions) { }
    private record DataSourceOptionsParts(
            List<String> settingsSub,
            List<String> trafficToolTypes,
            List<String> findingsSeverities,
            List<String> exporterSubOptions,
            int exporterStatsIntervalSeconds,
            boolean exporterOptionsPresent) { }
    private record IndexNamesParts(String baseTemplate) { }
    private record UiParts(ConfigState.UiPreferences uiPreferences) { }
}
