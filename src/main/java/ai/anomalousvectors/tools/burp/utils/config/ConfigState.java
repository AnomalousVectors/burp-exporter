package ai.anomalousvectors.tools.burp.utils.config;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ai.anomalousvectors.tools.burp.utils.IndexNaming;

/**
 * Defines the typed configuration model used by the UI and JSON import/export.
 *
 * <p>The nested records normalize nullable inputs and defensively copy collections so callers can
 * treat each instance as an immutable snapshot.</p>
 */
public final class ConfigState {

    /** Default settings sub-options (project, user). */
    public static final List<String> DEFAULT_SETTINGS_SUB =
            List.of(ConfigKeys.SRC_SETTINGS_PROJECT, ConfigKeys.SRC_SETTINGS_USER);

    /** Default traffic tool types: all traffic sources enabled by default. */
    public static final List<String> DEFAULT_TRAFFIC_TOOL_TYPES = List.of(
            "burp_ai",
            "extensions",
            "intruder",
            "proxy",
            "proxy_history",
            "repeater",
            "repeater_tabs",
            "scanner",
            "sequencer");

    /** Default findings severities: all five. */
    public static final List<String> DEFAULT_FINDINGS_SEVERITIES =
            List.of("critical", "high", "medium", "low", "informational");

    /** Default exporter sub-options: all log levels plus stats and config snapshots. */
    public static final List<String> DEFAULT_EXPORTER_SUB_OPTIONS = List.of(
            ConfigKeys.SRC_EXPORTER_TRACE,
            ConfigKeys.SRC_EXPORTER_DEBUG,
            ConfigKeys.SRC_EXPORTER_INFO,
            ConfigKeys.SRC_EXPORTER_WARN,
            ConfigKeys.SRC_EXPORTER_ERROR,
            ConfigKeys.SRC_EXPORTER_STATS,
            ConfigKeys.SRC_EXPORTER_CONFIG);

    /** Default interval for exporter stats snapshots. */
    public static final int DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS = 30;
    /** Default base template used to derive default index names. */
    public static final String DEFAULT_INDEX_NAME_BASE_TEMPLATE = IndexNaming.DEFAULT_BASE_TEMPLATE;

    /** Default total cap across exporter files under the selected root, stored as human-friendly GB. */
    public static final double DEFAULT_FILE_TOTAL_CAP_GB = 5d;

    /** Default advanced disk-used threshold for file export. */
    public static final int DEFAULT_FILE_MAX_DISK_USED_PERCENT = 95;
    /** Default Stats panel chart style (2 = Smooth). */
    public static final int DEFAULT_STATS_CHART_STYLE = 2;
    /** Default minimum visible level in LogPanel. */
    public static final String DEFAULT_LOG_MIN_LEVEL = "trace";

    /** Verify OpenSearch TLS certificates against the system trust store. */
    public static final String OPEN_SEARCH_TLS_VERIFY = "verify";
    /** Trust only the session-imported pinned OpenSearch certificate. */
    public static final String OPEN_SEARCH_TLS_PINNED = "pinned";
    /** Trust all OpenSearch TLS certificates without verification. */
    public static final String OPEN_SEARCH_TLS_INSECURE = "insecure";
    /** Default persisted OpenSearch auth type selection. */
    public static final String DEFAULT_OPEN_SEARCH_AUTH_TYPE = "Basic";
    /** Default database destination selected in the Config UI. */
    public static final String DEFAULT_SEARCH_DESTINATION = "openSearch";

    /** Scope kind for {@link ScopeEntry}. */
    public enum Kind { REGEX, STRING }

    /** Supported database destinations. */
    public enum SearchDestination {
        /** Self-managed or upstream OpenSearch. */
        OPEN_SEARCH("openSearch", "OpenSearch"),
        /** Amazon OpenSearch Service. */
        OPEN_SEARCH_AMAZON("openSearchAmazon", "Amazon OpenSearch"),
        /** Elasticsearch. */
        ELASTICSEARCH("elasticsearch", "Elasticsearch");

        private final String configKey;
        private final String displayName;

        SearchDestination(String configKey, String displayName) {
            this.configKey = configKey;
            this.displayName = displayName;
        }

        /** Returns the stable JSON config key for this destination. */
        public String configKey() {
            return configKey;
        }

        /** Returns the UI/operator-facing destination name. */
        public String displayName() {
            return displayName;
        }
    }

    private static final BigDecimal GB_BYTES_DECIMAL = BigDecimal.valueOf(1024L * 1024L * 1024L);
    private static final BigDecimal LONG_MAX_DECIMAL = BigDecimal.valueOf(Long.MAX_VALUE);

    /** Ordered custom-scope entry. */
    public record ScopeEntry(String value, Kind kind) {
        public ScopeEntry {
            value = value == null ? "" : value;
            kind  = kind == null ? Kind.REGEX : kind;
        }
    }

    /**
     * Sinks selection and values.
     *
     * <p>File export can target document-only JSONL, bulk-compatible NDJSON, or both. Optional
     * OpenSearch basic-auth remains non-durable (empty = no auth). {@code openSearchTlsMode}
     * persists whether OpenSearch uses the system trust store, a session-imported pinned
     * certificate, or trust-all TLS.</p>
     */
    public record Sinks(boolean filesEnabled, String filesPath, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                        boolean fileTotalCapEnabled, double fileTotalCapGb,
                        boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                        boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                        String openSearchTlsMode, OpenSearchOptions openSearchOptions,
                        String searchDestination,
                        String openSearchAmazonUrl,
                        OpenSearchAmazonOptions openSearchAmazonOptions,
                        String elasticSearchUrl,
                        ElasticsearchOptions elasticSearchOptions) {
        public Sinks {
            filesPath = filesPath != null ? filesPath : "";
            fileTotalCapGb = normalizeFileTotalCapGb(fileTotalCapGb);
            fileDiskUsagePercent = Math.clamp(fileDiskUsagePercent, 1, 100);
            openSearchUrl = openSearchUrl != null ? openSearchUrl : "";
            openSearchUser = openSearchUser != null ? openSearchUser : "";
            openSearchPassword = openSearchPassword != null ? openSearchPassword : "";
            openSearchTlsMode = normalizeOpenSearchTlsMode(openSearchTlsMode);
            openSearchOptions = openSearchOptions == null ? defaultOpenSearchOptions() : openSearchOptions;
            searchDestination = normalizeSearchDestination(searchDestination).configKey();
            openSearchAmazonUrl = openSearchAmazonUrl != null ? openSearchAmazonUrl : "";
            openSearchAmazonOptions = openSearchAmazonOptions == null
                    ? defaultOpenSearchAmazonOptions()
                    : openSearchAmazonOptions;
            elasticSearchUrl = elasticSearchUrl != null ? elasticSearchUrl : "";
            elasticSearchOptions = elasticSearchOptions == null
                    ? defaultElasticsearchOptions()
                    : elasticSearchOptions;
        }

        /** Returns the configured file cap converted to bytes for runtime enforcement. */
        public long fileTotalCapBytes() {
            return gbToBytes(fileTotalCapGb);
        }

        /** Returns the selected database destination. */
        public SearchDestination searchDestinationKind() {
            return normalizeSearchDestination(searchDestination);
        }

        /** Returns the configured URL for the selected database destination. */
        public String selectedSearchUrl() {
            return switch (searchDestinationKind()) {
                case OPEN_SEARCH -> openSearchUrl;
                case OPEN_SEARCH_AMAZON -> openSearchAmazonUrl;
                case ELASTICSEARCH -> elasticSearchUrl;
            };
        }

        /** Returns the configured TLS mode for the selected database destination. */
        public String selectedSearchTlsMode() {
            return switch (searchDestinationKind()) {
                case OPEN_SEARCH -> openSearchTlsMode;
                case OPEN_SEARCH_AMAZON -> openSearchAmazonOptions.tlsMode();
                case ELASTICSEARCH -> elasticSearchOptions.tlsMode();
            };
        }

        public Sinks(boolean filesEnabled, String filesPath,
                     boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    true, DEFAULT_FILE_TOTAL_CAP_GB,
                    true, DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword, openSearchTlsMode,
                    defaultOpenSearchOptions());
        }

        public Sinks(boolean filesEnabled, String filesPath, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean fileTotalCapEnabled, double fileTotalCapGb,
                     boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    fileTotalCapEnabled, fileTotalCapGb,
                    fileDiskUsagePercentEnabled, fileDiskUsagePercent,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchTlsMode, defaultOpenSearchOptions());
        }

        public Sinks(boolean filesEnabled, String filesPath, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean fileTotalCapEnabled, double fileTotalCapGb,
                     boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     boolean openSearchInsecureSsl) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    fileTotalCapEnabled, fileTotalCapGb,
                    fileDiskUsagePercentEnabled, fileDiskUsagePercent,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchInsecureSsl ? OPEN_SEARCH_TLS_INSECURE : OPEN_SEARCH_TLS_VERIFY,
                    defaultOpenSearchOptions());
        }

        public Sinks(boolean filesEnabled, String filesPath,
                     boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     boolean openSearchInsecureSsl) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchInsecureSsl ? OPEN_SEARCH_TLS_INSECURE : OPEN_SEARCH_TLS_VERIFY);
        }

        /**
         * Convenience constructor for call sites that do not need to specify file formats.
         *
         * <p>When used, file export formats default to disabled until explicitly selected in the
         * UI or config.</p>
         */
        public Sinks(boolean filesEnabled, String filesPath,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode) {
            this(filesEnabled, filesPath, false, false,
                    true, DEFAULT_FILE_TOTAL_CAP_GB,
                    true, DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword, openSearchTlsMode,
                    defaultOpenSearchOptions());
        }

        public Sinks(boolean filesEnabled, String filesPath,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     boolean openSearchInsecureSsl) {
            this(filesEnabled, filesPath, osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchInsecureSsl ? OPEN_SEARCH_TLS_INSECURE : OPEN_SEARCH_TLS_VERIFY);
        }

        public Sinks(boolean filesEnabled, String filesPath, boolean fileJsonlEnabled, boolean fileBulkNdjsonEnabled,
                     boolean fileTotalCapEnabled, double fileTotalCapGb,
                     boolean fileDiskUsagePercentEnabled, int fileDiskUsagePercent,
                     boolean osEnabled, String openSearchUrl, String openSearchUser, String openSearchPassword,
                     String openSearchTlsMode, OpenSearchOptions openSearchOptions) {
            this(filesEnabled, filesPath, fileJsonlEnabled, fileBulkNdjsonEnabled,
                    fileTotalCapEnabled, fileTotalCapGb,
                    fileDiskUsagePercentEnabled, fileDiskUsagePercent,
                    osEnabled, openSearchUrl, openSearchUser, openSearchPassword,
                    openSearchTlsMode, openSearchOptions,
                    DEFAULT_SEARCH_DESTINATION,
                    "", defaultOpenSearchAmazonOptions(),
                    "", defaultElasticsearchOptions());
        }
    }

    /** Persisted non-secret OpenSearch settings that should survive config export/import. */
    public record OpenSearchOptions(
            String authType,
            String apiKeyId,
            String certPath,
            String certKeyPath,
            String pinnedTlsCertificateSourcePath,
            String pinnedTlsCertificateFingerprintSha256,
            String pinnedTlsCertificateEncodedBase64) {
        public OpenSearchOptions {
            authType = normalizeOpenSearchAuthType(authType);
            apiKeyId = apiKeyId == null ? "" : apiKeyId;
            certPath = certPath == null ? "" : certPath;
            certKeyPath = certKeyPath == null ? "" : certKeyPath;
            pinnedTlsCertificateSourcePath = pinnedTlsCertificateSourcePath == null ? "" : pinnedTlsCertificateSourcePath;
            pinnedTlsCertificateFingerprintSha256 = pinnedTlsCertificateFingerprintSha256 == null
                    ? "" : pinnedTlsCertificateFingerprintSha256;
            pinnedTlsCertificateEncodedBase64 = pinnedTlsCertificateEncodedBase64 == null
                    ? "" : pinnedTlsCertificateEncodedBase64;
        }
    }

    /** Persisted non-secret Amazon OpenSearch Service settings. */
    public record OpenSearchAmazonOptions(
            String authType,
            String username,
            String region,
            String profile,
            String tlsMode,
            String pinnedTlsCertificateSourcePath,
            String pinnedTlsCertificateFingerprintSha256,
            String pinnedTlsCertificateEncodedBase64) {
        public OpenSearchAmazonOptions {
            authType = normalizeOpenSearchAmazonAuthType(authType);
            username = username == null ? "" : username.trim();
            region = region == null ? "" : region.trim();
            profile = profile == null ? "" : profile.trim();
            tlsMode = normalizeOpenSearchTlsMode(tlsMode);
            pinnedTlsCertificateSourcePath = pinnedTlsCertificateSourcePath == null ? "" : pinnedTlsCertificateSourcePath;
            pinnedTlsCertificateFingerprintSha256 = pinnedTlsCertificateFingerprintSha256 == null
                    ? "" : pinnedTlsCertificateFingerprintSha256;
            pinnedTlsCertificateEncodedBase64 = pinnedTlsCertificateEncodedBase64 == null
                    ? "" : pinnedTlsCertificateEncodedBase64;
        }
    }

    /** Persisted non-secret Elasticsearch settings. */
    public record ElasticsearchOptions(
            String authType,
            String username,
            String certPath,
            String certKeyPath,
            String tlsMode,
            String pinnedTlsCertificateSourcePath,
            String pinnedTlsCertificateFingerprintSha256,
            String pinnedTlsCertificateEncodedBase64) {
        public ElasticsearchOptions {
            authType = normalizeElasticsearchAuthType(authType);
            username = username == null ? "" : username.trim();
            certPath = certPath == null ? "" : certPath.trim();
            certKeyPath = certKeyPath == null ? "" : certKeyPath.trim();
            tlsMode = normalizeOpenSearchTlsMode(tlsMode);
            pinnedTlsCertificateSourcePath = pinnedTlsCertificateSourcePath == null ? "" : pinnedTlsCertificateSourcePath;
            pinnedTlsCertificateFingerprintSha256 = pinnedTlsCertificateFingerprintSha256 == null
                    ? "" : pinnedTlsCertificateFingerprintSha256;
            pinnedTlsCertificateEncodedBase64 = pinnedTlsCertificateEncodedBase64 == null
                    ? "" : pinnedTlsCertificateEncodedBase64;
        }
    }

    /** Persisted preferences for the Log panel UI. */
    public record LogPanelPreferences(
            String minLevel,
            boolean pauseAutoscroll,
            String filterText,
            boolean filterCase,
            boolean filterRegex,
            boolean filterNegative,
            String searchText,
            boolean searchCase,
            boolean searchRegex) {
        public LogPanelPreferences {
            minLevel = normalizeLogMinLevel(minLevel);
            filterText = filterText == null ? "" : filterText;
            searchText = searchText == null ? "" : searchText;
        }
    }

    /** Persisted UI preferences that should survive save/export/import. */
    public record UiPreferences(int statsChartStyle, LogPanelPreferences logPanel) {
        public UiPreferences {
            statsChartStyle = Math.clamp(statsChartStyle, 1, 3);
            logPanel = logPanel == null ? defaultLogPanelPreferences() : logPanel;
        }
    }

    /**
     * Captures the full persisted exporter configuration.
     *
     * <p>Collection components are normalized to immutable snapshots. Missing exporter settings are
     * normalized to the current defaults so legacy imports retain the intended Exporter-index behavior.</p>
     *
     * @param dataSources selected top-level source keys such as {@code settings} or
     *                    {@code exporter}
     * @param scopeType scope mode: {@code all}, {@code burp}, or {@code custom}
     * @param customEntries ordered custom-scope entries used when {@code scopeType=custom}
     * @param sinks destination configuration for Files and OpenSearch
     * @param settingsSub selected Settings source sub-options
     * @param trafficToolTypes selected traffic-producing Burp tool types
     * @param findingsSeverities selected finding severities
     * @param exporterSubOptions selected exporter log/config/stats sub-options
     * @param exporterStatsIntervalSeconds stats snapshot interval in seconds
     * @param indexNameBaseTemplate base template used to derive default index names
     * @param enabledExportFieldsByIndex enabled optional field keys by index; {@code null} means
     *                                   all optional fields are enabled
     * @param uiPreferences persisted UI-only preferences that should survive save/import cycles
     */
    public record State(List<String> dataSources,
                        String scopeType,               // "all" | "burp" | "custom"
                        List<ScopeEntry> customEntries, // ordered; used when scopeType=custom
                        Sinks sinks,
                        List<String> settingsSub,       // "project", "user"; default both
                        List<String> trafficToolTypes,  // ToolType names; default empty (no traffic)
                        List<String> findingsSeverities, // AuditIssueSeverity names; default all five
                        List<String> exporterSubOptions, // trace/debug/info/warn/error/stats/config
                        int exporterStatsIntervalSeconds, // seconds; default 30
                        String indexNameBaseTemplate, // global base template used for default index names
                        Map<String, Set<String>> enabledExportFieldsByIndex, // index shortName -> enabled toggleable field keys; null = all enabled
                        UiPreferences uiPreferences) {

        public State {
            dataSources       = normalizeDataSources(dataSources);
            scopeType         = normalizeScopeType(scopeType);
            customEntries     = customEntries == null ? List.of() : List.copyOf(customEntries);
            settingsSub       = normalizeSettingsSub(settingsSub);
            trafficToolTypes  = normalizeTrafficToolTypes(trafficToolTypes);
            findingsSeverities = normalizeFindingsSeverities(findingsSeverities);
            exporterSubOptions = normalizeExporterSubOptions(exporterSubOptions);
            exporterStatsIntervalSeconds = normalizeExporterStatsIntervalSeconds(exporterStatsIntervalSeconds);
            indexNameBaseTemplate = normalizeIndexNameBaseTemplate(indexNameBaseTemplate);
            enabledExportFieldsByIndex = enabledExportFieldsByIndex == null ? null : copyMapOfSets(enabledExportFieldsByIndex);
            uiPreferences = uiPreferences == null ? defaultUiPreferences() : uiPreferences;
        }

        public State(List<String> dataSources,
                     String scopeType,
                     List<ScopeEntry> customEntries,
                     Sinks sinks,
                     List<String> settingsSub,
                     List<String> trafficToolTypes,
                     List<String> findingsSeverities,
                     List<String> exporterSubOptions,
                     int exporterStatsIntervalSeconds,
                     String indexNameBaseTemplate,
                     Map<String, Set<String>> enabledExportFieldsByIndex) {
            this(dataSources, scopeType, customEntries, sinks, settingsSub, trafficToolTypes,
                    findingsSeverities, exporterSubOptions, exporterStatsIntervalSeconds,
                    indexNameBaseTemplate, enabledExportFieldsByIndex,
                    defaultUiPreferences());
        }

        public State(List<String> dataSources,
                     String scopeType,
                     List<ScopeEntry> customEntries,
                     Sinks sinks,
                     List<String> settingsSub,
                     List<String> trafficToolTypes,
                     List<String> findingsSeverities,
                     List<String> exporterSubOptions,
                     int exporterStatsIntervalSeconds,
                     Map<String, Set<String>> enabledExportFieldsByIndex) {
            this(dataSources, scopeType, customEntries, sinks, settingsSub, trafficToolTypes,
                    findingsSeverities, exporterSubOptions, exporterStatsIntervalSeconds,
                    DEFAULT_INDEX_NAME_BASE_TEMPLATE, enabledExportFieldsByIndex,
                    defaultUiPreferences());
        }

        public State(List<String> dataSources,
                     String scopeType,
                     List<ScopeEntry> customEntries,
                     Sinks sinks,
                     List<String> settingsSub,
                     List<String> trafficToolTypes,
                     List<String> findingsSeverities,
                     List<String> exporterSubOptions,
                     int exporterStatsIntervalSeconds,
                     Map<String, Set<String>> enabledExportFieldsByIndex,
                     UiPreferences uiPreferences) {
            this(dataSources, scopeType, customEntries, sinks, settingsSub, trafficToolTypes,
                    findingsSeverities, exporterSubOptions, exporterStatsIntervalSeconds,
                    DEFAULT_INDEX_NAME_BASE_TEMPLATE, enabledExportFieldsByIndex, uiPreferences);
        }

        public State(List<String> dataSources,
                     String scopeType,
                     List<ScopeEntry> customEntries,
                     Sinks sinks,
                     List<String> settingsSub,
                     List<String> trafficToolTypes,
                     List<String> findingsSeverities,
                     Map<String, Set<String>> enabledExportFieldsByIndex,
                     UiPreferences uiPreferences) {
            this(dataSources, scopeType, customEntries, sinks, settingsSub, trafficToolTypes,
                    findingsSeverities, DEFAULT_EXPORTER_SUB_OPTIONS, DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    DEFAULT_INDEX_NAME_BASE_TEMPLATE, enabledExportFieldsByIndex, uiPreferences);
        }

        public State(List<String> dataSources,
                     String scopeType,
                     List<ScopeEntry> customEntries,
                     Sinks sinks,
                     List<String> settingsSub,
                     List<String> trafficToolTypes,
                     List<String> findingsSeverities,
                     Map<String, Set<String>> enabledExportFieldsByIndex) {
            this(dataSources, scopeType, customEntries, sinks, settingsSub, trafficToolTypes,
                    findingsSeverities, DEFAULT_EXPORTER_SUB_OPTIONS, DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    DEFAULT_INDEX_NAME_BASE_TEMPLATE, enabledExportFieldsByIndex,
                    defaultUiPreferences());
        }

        private static Map<String, Set<String>> copyMapOfSets(Map<String, Set<String>> map) {
            Map<String, Set<String>> out = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> e : map.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    out.put(e.getKey(), Collections.unmodifiableSet(new java.util.LinkedHashSet<>(e.getValue())));
                }
            }
            return Collections.unmodifiableMap(out);
        }
    }

    private ConfigState() { }

    /** Default persisted LogPanel preferences. */
    public static LogPanelPreferences defaultLogPanelPreferences() {
        return new LogPanelPreferences(DEFAULT_LOG_MIN_LEVEL, false, "", false, false, false, "", false, false);
    }

    /** Default persisted UI preferences. */
    public static UiPreferences defaultUiPreferences() {
        return new UiPreferences(DEFAULT_STATS_CHART_STYLE, defaultLogPanelPreferences());
    }

    /** Default persisted OpenSearch non-secret settings. */
    public static OpenSearchOptions defaultOpenSearchOptions() {
        return new OpenSearchOptions(DEFAULT_OPEN_SEARCH_AUTH_TYPE, "", "", "", "", "", "");
    }

    /** Default persisted Amazon OpenSearch Service non-secret settings. */
    public static OpenSearchAmazonOptions defaultOpenSearchAmazonOptions() {
        return new OpenSearchAmazonOptions("IAM (sigV4)", "", "", "", OPEN_SEARCH_TLS_VERIFY, "", "", "");
    }

    /** Default persisted Elasticsearch non-secret settings. */
    public static ElasticsearchOptions defaultElasticsearchOptions() {
        return new ElasticsearchOptions(DEFAULT_OPEN_SEARCH_AUTH_TYPE, "", "", "",
                OPEN_SEARCH_TLS_VERIFY, "", "", "");
    }

    /** Converts a human-friendly GB value to runtime bytes using half-up rounding. */
    public static long gbToBytes(double gb) {
        BigDecimal normalized = BigDecimal.valueOf(normalizeFileTotalCapGb(gb));
        BigDecimal bytes = normalized.multiply(GB_BYTES_DECIMAL).setScale(0, RoundingMode.HALF_UP);
        if (bytes.compareTo(LONG_MAX_DECIMAL) > 0) {
            return Long.MAX_VALUE;
        }
        return bytes.longValueExact();
    }

    /** Converts runtime bytes to the human-friendly GB value used in config state/export. */
    public static double bytesToGb(long bytes) {
        if (bytes <= 0) {
            return DEFAULT_FILE_TOTAL_CAP_GB;
        }
        return BigDecimal.valueOf(bytes)
                .divide(GB_BYTES_DECIMAL, 12, RoundingMode.HALF_UP)
                .doubleValue();
    }

    /** Returns a normalized persisted OpenSearch TLS mode, defaulting to {@link #OPEN_SEARCH_TLS_VERIFY}. */
    public static String normalizeOpenSearchTlsMode(String mode) {
        if (mode == null || mode.isBlank()) {
            return OPEN_SEARCH_TLS_VERIFY;
        }
        return switch (mode.trim().toLowerCase(java.util.Locale.ROOT)) {
            case OPEN_SEARCH_TLS_PINNED, "trust pinned certificate", "trust-pinned-certificate" -> OPEN_SEARCH_TLS_PINNED;
            case OPEN_SEARCH_TLS_INSECURE, "trust all certificates", "trust-all-certificates" -> OPEN_SEARCH_TLS_INSECURE;
            default -> OPEN_SEARCH_TLS_VERIFY;
        };
    }

    /** Returns a normalized persisted OpenSearch auth type, defaulting to {@link #DEFAULT_OPEN_SEARCH_AUTH_TYPE}. */
    public static String normalizeOpenSearchAuthType(String authType) {
        if (authType == null || authType.isBlank()) {
            return DEFAULT_OPEN_SEARCH_AUTH_TYPE;
        }
        return switch (authType.trim().toLowerCase(Locale.ROOT)) {
            case "api key", "apikey" -> "API key";
            case "bearer token", "bearer", "jwt" -> "Bearer token";
            case "certificate", "cert" -> "Certificate";
            case "none" -> "None";
            default -> "Basic";
        };
    }

    /** Returns a normalized database destination, defaulting to upstream OpenSearch. */
    public static SearchDestination normalizeSearchDestination(String destination) {
        if (destination == null || destination.isBlank()) {
            return SearchDestination.OPEN_SEARCH;
        }
        return switch (destination.trim().toLowerCase(Locale.ROOT)) {
            case "opensearch", "open_search", "open-search", "open search" -> SearchDestination.OPEN_SEARCH;
            case "opensearchamazon", "open_search_amazon", "open-search-amazon", "open search amazon",
                    "amazonopensearch", "amazon_opensearch", "amazon-opensearch", "amazon opensearch",
                    "amazon open search", "openSearchAmazon" -> SearchDestination.OPEN_SEARCH_AMAZON;
            case "elasticsearch", "elastic_search", "elastic-search", "elastic search" -> SearchDestination.ELASTICSEARCH;
            default -> SearchDestination.OPEN_SEARCH;
        };
    }

    /** Returns a normalized Amazon OpenSearch Service auth type. */
    public static String normalizeOpenSearchAmazonAuthType(String authType) {
        if (authType == null || authType.isBlank()) {
            return "IAM (sigV4)";
        }
        return switch (authType.trim().toLowerCase(Locale.ROOT)) {
            case "iam (sigv4)", "iam", "sigv4", "aws sigv4", "aws_sigv4" -> "IAM (sigV4)";
            case "basic" -> "Basic";
            case "none" -> "None";
            default -> "IAM (sigV4)";
        };
    }

    /** Returns a normalized Elasticsearch auth type. */
    public static String normalizeElasticsearchAuthType(String authType) {
        return normalizeOpenSearchAuthType(authType);
    }

    /** Returns one of trace/debug/info/warn/error, defaulting to trace. */
    public static String normalizeLogMinLevel(String raw) {
        if (raw == null || raw.isBlank()) {
            return DEFAULT_LOG_MIN_LEVEL;
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "trace", "debug", "info", "warn", "error" -> raw.trim().toLowerCase(Locale.ROOT);
            default -> DEFAULT_LOG_MIN_LEVEL;
        };
    }

    /** Normalizes stored file-cap GB values and falls back to the default when unset or invalid. */
    public static double normalizeFileTotalCapGb(double raw) {
        return raw > 0d ? raw : DEFAULT_FILE_TOTAL_CAP_GB;
    }

    /** Normalizes config data-source ids to lowercase. */
    public static List<String> normalizeDataSources(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes settings sub-option ids to lowercase. */
    public static List<String> normalizeSettingsSub(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes traffic tool ids to lowercase. */
    public static List<String> normalizeTrafficToolTypes(List<String> values) {
        Set<String> knownToolTypes = Set.copyOf(DEFAULT_TRAFFIC_TOOL_TYPES);
        return normalizeLowercaseList(values).stream()
                .filter(knownToolTypes::contains)
                .toList();
    }

    /** Normalizes finding severity ids to lowercase. */
    public static List<String> normalizeFindingsSeverities(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes exporter sub-option ids to lowercase. */
    public static List<String> normalizeExporterSubOptions(List<String> values) {
        return normalizeLowercaseList(values);
    }

    /** Normalizes the stored global index base template. */
    public static String normalizeIndexNameBaseTemplate(String template) {
        return IndexNaming.normalizeBaseTemplate(template);
    }

    /** Normalizes the exporter stats interval to a positive number of seconds. */
    public static int normalizeExporterStatsIntervalSeconds(int value) {
        return value > 0 ? value : DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS;
    }

    /** Normalizes persisted scope type values to lowercase supported ids. */
    public static String normalizeScopeType(String raw) {
        if (raw == null || raw.isBlank()) {
            return "all";
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "burp", "custom" -> raw.trim().toLowerCase(Locale.ROOT);
            default -> "all";
        };
    }

    private static List<String> normalizeLowercaseList(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            if (value == null || value.isBlank()) {
                continue;
            }
            normalized.add(value.trim().toLowerCase(Locale.ROOT));
        }
        return List.copyOf(normalized);
    }
}
