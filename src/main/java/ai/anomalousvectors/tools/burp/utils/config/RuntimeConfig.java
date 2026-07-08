package ai.anomalousvectors.tools.burp.utils.config;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.Logger;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ToolType;

/**
 * Holds the current runtime configuration used by live export pipelines.
 *
 * <p>UI actions update this state, and runtime exporters read it from worker threads. The core
 * state and run-suppression flags are kept in volatile fields so readers can consume the latest
 * snapshot without additional locking.</p>
 *
 * <p>The export-running flag gates whether traffic and reporter pipelines may send documents to
 * sinks. Start and Stop update that runtime gate without mutating the persisted config snapshot.</p>
 */
public final class RuntimeConfig {
    private static final Set<String> COMMUNITY_DISABLED_SOURCES = Set.of(ConfigKeys.SRC_FINDINGS);
    private static final Set<String> COMMUNITY_DISABLED_TRAFFIC_TOOL_TYPES = Set.of("burp_ai", "scanner");
    private static final int TRAFFIC_TOOL_BURP_AI = 1;
    private static final int TRAFFIC_TOOL_EXTENSIONS = 1 << 1;
    private static final int TRAFFIC_TOOL_INTRUDER = 1 << 2;
    private static final int TRAFFIC_TOOL_PROXY = 1 << 3;
    private static final int TRAFFIC_TOOL_PROXY_HISTORY = 1 << 4;
    private static final int TRAFFIC_TOOL_REPEATER = 1 << 5;
    private static final int TRAFFIC_TOOL_REPEATER_TABS = 1 << 6;
    private static final int TRAFFIC_TOOL_SCANNER = 1 << 7;
    private static final int TRAFFIC_TOOL_SEQUENCER = 1 << 8;

    private static volatile ConfigState.State state = defaultState();
    private static volatile boolean exportRunning = false;
    private static volatile boolean exportStarting = false;
    private static volatile boolean exportStopping = false;
    private static volatile boolean fileExportDisabledForCurrentRun = false;
    private static volatile boolean openSearchDisabledForCurrentRun = false;
    private static volatile Map<String, String> resolvedIndexNamesForCurrentRun = Map.of();
    private static volatile Instant resolvedIndexNamesAt = Instant.EPOCH;
    private static volatile TrafficExportGate trafficExportGate = new TrafficExportGate(false, false, 0);
    private static final CopyOnWriteArrayList<StateListener> listeners = new CopyOnWriteArrayList<>();

    /**
     * Cached hot-path view of the current traffic export gate.
     *
     * <p>Live HTTP and WebSocket callbacks can fire at high volume. This record lets those paths
     * perform one volatile read and one set lookup instead of repeatedly walking the full runtime
     * config, normalizing strings, and checking edition state.</p>
     */
    public record TrafficExportGate(
            boolean exportReady,
            boolean anyTrafficExportEnabled,
            int enabledToolMask) {

        public boolean allowsToolType(String normalizedToolType) {
            return exportReady
                    && anyTrafficExportEnabled
                    && normalizedToolType != null
                    && includesToolType(normalizedToolType);
        }

        public boolean includesToolType(String normalizedToolType) {
            return normalizedToolType != null
                    && (enabledToolMask & trafficToolTypeMask(normalizedToolType)) != 0;
        }
    }

    /** Listener notified when the normalized runtime state changes. */
    @FunctionalInterface
    public interface StateListener {
        void onStateChanged(ConfigState.State newState);
    }

    private RuntimeConfig() { }

    static {
        refreshTrafficExportGate();
    }

    /** Returns the current runtime config state. */
    public static ConfigState.State getState() {
        return state;
    }

    /**
     * Returns whether export is currently running (Start pressed).
     *
     * <p>When {@code false}, traffic and other exporters do not send data to sinks.</p>
     *
     * @return {@code true} if export has been started and not stopped
     */
    public static boolean isExportRunning() {
        return exportRunning;
    }

    /** Returns whether the active Burp instance is Community Edition. */
    public static boolean isCommunityEdition() {
        try {
            var api = MontoyaApiProvider.get();
            if (api == null || api.burpSuite() == null) {
                return false;
            }
            var version = api.burpSuite().version();
            return version != null && version.edition() == BurpSuiteEdition.COMMUNITY_EDITION;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Returns whether export is fully active and allowed to emit runtime documents.
     *
     * <p>This stays {@code false} during Start/bootstrap work so background listeners do not
     * begin pushing traffic or exporter-log documents before OpenSearch preflight and index
     * bootstrap have succeeded.</p>
     */
    public static boolean isExportReady() {
        return exportRunning && !exportStarting;
    }

    /** Returns whether export startup/bootstrap is still in progress. */
    public static boolean isExportStarting() {
        return exportStarting;
    }

    /** Returns whether the UI is showing the Stop-in-progress state. */
    public static boolean isExportStopping() {
        return exportStopping;
    }

    /**
     * Sets whether export shutdown is in progress (Stop clicked, workers still draining).
     *
     * <p>While {@code true}, {@link ai.anomalousvectors.tools.burp.ui.ConfigPanel} ignores
     * background control-status posts so phased stop lines are not overwritten.</p>
     */
    public static void setExportStopping(boolean stopping) {
        exportStopping = stopping;
    }

    /**
     * Sets the export-running flag.
     *
     * <p>Start button sets {@code true}; Stop button sets {@code false}.</p>
     *
     * @param running new running state
     */
    public static void setExportRunning(boolean running) {
        boolean wasRunning = exportRunning;
        exportRunning = running;
        if (!running) {
            exportStarting = false;
            exportStopping = false;
            fileExportDisabledForCurrentRun = false;
            openSearchDisabledForCurrentRun = false;
            clearResolvedIndexNamesForCurrentRun();
        } else if (!wasRunning) {
            fileExportDisabledForCurrentRun = false;
            openSearchDisabledForCurrentRun = false;
        }
        refreshTrafficExportGate();
    }

    /**
     * Sets whether export startup/bootstrap is still in progress.
     *
     * <p>When {@code true}, the UI may show a starting state while runtime exporters remain
     * gated until startup succeeds, and phased start lines are not overwritten by
     * {@link ai.anomalousvectors.tools.burp.utils.ControlStatusBridge}.</p>
     */
    public static void setExportStarting(boolean starting) {
        exportStarting = exportRunning && starting;
        refreshTrafficExportGate();
    }

    /** Updates the runtime config state with a normalized, non-null value. */
    public static void updateState(ConfigState.State newState) {
        state = applyCurrentRunDestinationSuppression(normalize(newState));
        refreshTrafficExportGate();
        notifyListeners(state);
    }

    /** Returns a cached traffic export gate for high-volume listener paths. */
    public static TrafficExportGate trafficExportGate() {
        return trafficExportGate;
    }

    /** Returns the lowercase {@link ToolType#name()} key used by traffic export gating. */
    public static String normalizedToolTypeKey(ToolType toolType) {
        return toolType == null ? null : toolType.name().toLowerCase(Locale.ROOT);
    }

    /**
     * Disables only the OpenSearch destination in the current runtime state.
     *
     * <p>This is used for runtime shutdown of a failing destination while allowing any configured
     * file export destination to continue. The disable remains sticky for the active export run so
     * later UI refreshes do not silently re-enable OpenSearch until export is stopped.</p>
     *
     * @return {@code true} when OpenSearch was enabled and is now disabled; {@code false} otherwise
     */
    public static boolean disableOpenSearchDestination() {
        ConfigState.State current = normalize(state);
        ConfigState.Sinks sinks = current.sinks();
        if (sinks == null || !sinks.osEnabled()) {
            return false;
        }
        if (exportRunning || exportStarting) {
            openSearchDisabledForCurrentRun = true;
        }
        updateState(withOpenSearchEnabled(current, false));
        return true;
    }

    /**
     * Disables only the file destination in the current runtime state.
     *
     * <p>This is used for runtime shutdown of a failing file destination while allowing any
     * configured OpenSearch destination to continue. The disable remains sticky for the active
     * export run so later UI refreshes do not silently re-enable Files until export is stopped.</p>
     *
     * @return {@code true} when Files were enabled and are now disabled; {@code false} otherwise
     */
    public static boolean disableFileDestination() {
        ConfigState.State current = normalize(state);
        ConfigState.Sinks sinks = current.sinks();
        if (sinks == null || !sinks.filesEnabled()) {
            return false;
        }
        if (exportRunning || exportStarting) {
            fileExportDisabledForCurrentRun = true;
        }
        updateState(withFilesEnabled(current, false));
        return true;
    }

    /** True when Files export has been suppressed for the active export run. */
    public static boolean isFileExportDisabledForCurrentRun() {
        return fileExportDisabledForCurrentRun;
    }

    /** True when OpenSearch has been suppressed for the active export run. */
    public static boolean isOpenSearchDisabledForCurrentRun() {
        return openSearchDisabledForCurrentRun;
    }

    /** Registers a listener for runtime-state changes and immediately replays the current state. */
    public static void registerStateListener(StateListener listener) {
        if (listener == null) {
            return;
        }
        listeners.addIfAbsent(listener);
        listener.onStateChanged(state);
    }

    /** Removes a previously registered runtime-state listener. */
    public static void unregisterStateListener(StateListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    /** True when the selected wired database export destination has a non-blank runtime URL. */
    public static boolean isOpenSearchExportEnabled() {
        return isSearchExportEnabled();
    }

    /** True when the selected database destination is enabled and has a non-blank runtime URL. */
    public static boolean isSearchExportEnabled() {
        ConfigState.State current = state;
        return current != null
                && current.sinks() != null
                && current.sinks().osEnabled()
                && isSearchDestinationExportWired(current.sinks().searchDestinationKind())
                && !safe(current.sinks().selectedSearchUrl()).isBlank();
    }

    /** True when wired database export is enabled for traffic and at least one tool type is selected. */
    public static boolean isOpenSearchTrafficEnabled() {
        return isSearchTrafficEnabled();
    }

    /** True when database export is enabled for the traffic source and at least one tool type is selected. */
    public static boolean isSearchTrafficEnabled() {
        ConfigState.State current = state;
        return current != null
                && isSearchExportEnabled()
                && isDataSourceEnabled(ConfigKeys.SRC_TRAFFIC)
                && current.trafficToolTypes() != null
                && !current.trafficToolTypes().isEmpty();
    }

    /** True when any export sink is enabled and sufficiently configured to accept documents. */
    public static boolean isAnySinkEnabled() {
        ConfigState.State current = state;
        if (current == null || current.sinks() == null) {
            return false;
        }
        return isAnyFileExportEnabled() || isSearchExportEnabled();
    }

    /**
     * Returns a human-readable summary of the currently enabled export destinations.
     *
     * <p>The result is intended for UI and log messages such as start/stop status updates. It
     * reflects the current runtime sink selection and returns {@code "no destinations"} when
     * neither Files nor a database destination is enabled.</p>
     *
     * @return destination summary suitable for operator-facing status text
     */
    public static String activeSinkSummary() {
        boolean files = isAnyFileExportEnabled();
        boolean search = isSearchExportEnabled();
        if (files && search) {
            return "Files and " + searchDestinationDisplayName();
        }
        if (files) {
            return "Files";
        }
        if (search) {
            return searchDestinationDisplayName();
        }
        return "no destinations";
    }

    /** True when traffic export has at least one destination sink enabled. */
    public static boolean isAnyTrafficExportEnabled() {
        ConfigState.State current = state;
        return current != null
                && isDataSourceEnabled(ConfigKeys.SRC_TRAFFIC)
                && current.trafficToolTypes() != null
                && !current.trafficToolTypes().isEmpty()
                && (isSearchTrafficEnabled() || isAnyFileExportEnabled());
    }

    /** Returns whether the exporter source is enabled with at least one sub-option selected. */
    public static boolean isAnyExporterExportEnabled() {
        ConfigState.State current = state;
        return current != null
                && isDataSourceEnabled(ConfigKeys.SRC_EXPORTER)
                && current.exporterSubOptions() != null
                && !current.exporterSubOptions().isEmpty()
                && (isSearchExportEnabled() || isAnyFileExportEnabled());
    }

    /** Returns whether the named data source is currently enabled after edition normalization. */
    public static boolean isDataSourceEnabled(String source) {
        if (source == null || source.isBlank()) {
            return false;
        }
        String normalizedSource = source.trim().toLowerCase(Locale.ROOT);
        if (isCommunityEdition() && COMMUNITY_DISABLED_SOURCES.contains(normalizedSource)) {
            return false;
        }
        ConfigState.State current = state;
        return current != null
                && current.dataSources() != null
                && current.dataSources().contains(normalizedSource);
    }

    /** Returns whether the given traffic tool type is currently enabled after edition normalization. */
    public static boolean isTrafficToolTypeEnabled(String toolType) {
        if (toolType == null || toolType.isBlank()) {
            return false;
        }
        String normalizedToolType = toolType.trim().toLowerCase(Locale.ROOT);
        if (isCommunityEdition() && COMMUNITY_DISABLED_TRAFFIC_TOOL_TYPES.contains(normalizedToolType)) {
            return false;
        }
        ConfigState.State current = state;
        return current != null
                && current.trafficToolTypes() != null
                && current.trafficToolTypes().contains(normalizedToolType);
    }

    /** Returns whether the named exporter sub-option is currently enabled. */
    public static boolean isExporterSubOptionEnabled(String option) {
        if (option == null || option.isBlank() || !isDataSourceEnabled(ConfigKeys.SRC_EXPORTER)) {
            return false;
        }
        String normalizedOption = option.trim().toLowerCase(Locale.ROOT);
        ConfigState.State current = state;
        return current != null
                && current.exporterSubOptions() != null
                && current.exporterSubOptions().contains(normalizedOption);
    }

    /** Returns whether any exporter log level is currently enabled. */
    public static boolean isAnyExporterLogLevelEnabled() {
        return isExporterSubOptionEnabled(ConfigKeys.SRC_EXPORTER_TRACE)
                || isExporterSubOptionEnabled(ConfigKeys.SRC_EXPORTER_DEBUG)
                || isExporterSubOptionEnabled(ConfigKeys.SRC_EXPORTER_INFO)
                || isExporterSubOptionEnabled(ConfigKeys.SRC_EXPORTER_WARN)
                || isExporterSubOptionEnabled(ConfigKeys.SRC_EXPORTER_ERROR);
    }

    /** Returns whether the given exporter log level is enabled. */
    public static boolean isExporterLogLevelEnabled(String level) {
        if (level == null || level.isBlank()) {
            return false;
        }
        return isExporterSubOptionEnabled(level);
    }

    /** Returns whether exporter stats snapshots are enabled. */
    public static boolean isExporterStatsEnabled() {
        return isExporterSubOptionEnabled(ConfigKeys.SRC_EXPORTER_STATS);
    }

    /** Returns whether exporter config snapshots are enabled. */
    public static boolean isExporterConfigEnabled() {
        return isExporterSubOptionEnabled(ConfigKeys.SRC_EXPORTER_CONFIG);
    }

    /** Returns the configured exporter stats interval in seconds. */
    public static int exporterStatsIntervalSeconds() {
        ConfigState.State current = state;
        return current == null
                ? ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS
                : ConfigState.normalizeExporterStatsIntervalSeconds(current.exporterStatsIntervalSeconds());
    }

    /**
     * Resolves and stores the index names that should remain stable for the active export run.
     *
     * <p>Call this exactly once during Start after the latest UI state has been pushed into runtime
     * config. When validation fails, the previous run snapshot remains unchanged.</p>
     */
    public static IndexNaming.ResolutionResult prepareIndexNamesForCurrentRun() {
        ConfigState.State current = normalize(state);
        IndexNaming.ResolutionResult resolution = IndexNaming.resolveAllConfiguredNames(current, Instant.now());
        if (resolution.valid()) {
            resolvedIndexNamesForCurrentRun = resolution.namesByKey();
            resolvedIndexNamesAt = resolution.resolvedAt();
        }
        return resolution;
    }

    /** Returns the effective concrete index name for the provided logical key. */
    public static String indexNameForKey(String indexKey) {
        String normalizedKey = indexKey == null ? "exporter" : indexKey.trim().toLowerCase(Locale.ROOT);
        Map<String, String> resolvedForRun = resolvedIndexNamesForCurrentRun;
        if ((exportRunning || exportStarting) && resolvedForRun.containsKey(normalizedKey)) {
            return resolvedForRun.get(normalizedKey);
        }
        return IndexNaming.resolveConfiguredIndexName(state, normalizedKey, Instant.now());
    }

    /** Returns all effective concrete index names for the current state or run snapshot. */
    public static Map<String, String> allIndexNames() {
        Map<String, String> resolvedForRun = resolvedIndexNamesForCurrentRun;
        if ((exportRunning || exportStarting) && !resolvedForRun.isEmpty()) {
            return resolvedForRun;
        }
        return IndexNaming.resolveAllConfiguredNames(state, Instant.now()).namesByKey();
    }

    /** Returns the instant used when the current run's index names were resolved. */
    public static Instant resolvedIndexNamesAt() {
        return resolvedIndexNamesAt;
    }

    /** Current selected database URL for runtime exports; blank when database export is disabled. */
    public static String openSearchUrl() {
        return searchBaseUrl();
    }

    /** Current selected database URL for runtime exports; blank when database export is disabled. */
    public static String searchBaseUrl() {
        if (!isSearchExportEnabled()) {
            return "";
        }
        ConfigState.State current = state;
        return current == null || current.sinks() == null ? "" : safe(current.sinks().selectedSearchUrl());
    }

    /**
     * Returns {@code true} when selected database export is enabled and resolved to a non-blank base URL.
     */
    public static boolean isOpenSearchActive() {
        return isSearchActive();
    }

    /**
     * Returns whether selected database writes should be attempted now.
     *
     * @return {@code true} when a configured database destination has a non-blank URL
     */
    public static boolean isSearchActive() {
        String baseUrl = searchBaseUrl();
        return baseUrl != null && !baseUrl.isBlank();
    }

    /** Returns the currently selected database destination. */
    public static ConfigState.SearchDestination searchDestinationKind() {
        ConfigState.State current = state;
        return current == null || current.sinks() == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : current.sinks().searchDestinationKind();
    }

    /** Returns the operator-facing name of the selected database destination. */
    public static String searchDestinationDisplayName() {
        return searchDestinationKind().displayName();
    }

    /** Returns whether Start/export is currently implemented for the selected database destination. */
    public static boolean isSearchDestinationExportWired(ConfigState.SearchDestination destination) {
        ConfigState.SearchDestination normalized = destination == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : destination;
        return normalized == ConfigState.SearchDestination.OPEN_SEARCH
                || normalized == ConfigState.SearchDestination.ELASTICSEARCH;
    }

    /** Optional OpenSearch username for basic auth (empty = no auth). */
    public static String openSearchUser() {
        ConfigState.State current = state;
        return current == null ? "" : safe(current.sinks().openSearchUser());
    }

    /** Optional OpenSearch password for basic auth (empty = no auth). */
    public static String openSearchPassword() {
        ConfigState.State current = state;
        return current == null ? "" : safe(current.sinks().openSearchPassword());
    }

    /** Current OpenSearch TLS mode. */
    public static String openSearchTlsMode() {
        ConfigState.State current = state;
        return current == null || current.sinks() == null
                ? ConfigState.OPEN_SEARCH_TLS_VERIFY
                : ConfigState.normalizeOpenSearchTlsMode(current.sinks().openSearchTlsMode());
    }

    /** Current selected database TLS mode. */
    public static String searchTlsMode() {
        ConfigState.State current = state;
        return current == null || current.sinks() == null
                ? ConfigState.OPEN_SEARCH_TLS_VERIFY
                : ConfigState.normalizeOpenSearchTlsMode(current.sinks().selectedSearchTlsMode());
    }

    /** Returns the persisted UI preferences currently attached to runtime config. */
    public static ConfigState.UiPreferences uiPreferences() {
        ConfigState.State current = state;
        return current == null || current.uiPreferences() == null
                ? ConfigState.defaultUiPreferences()
                : current.uiPreferences();
    }

    /** Returns the configured StatsPanel chart style in the range 1-3. */
    public static int statsChartStyle() {
        return uiPreferences().statsChartStyle();
    }

    /** Returns the configured LogPanel preferences. */
    public static ConfigState.LogPanelPreferences logPanelPreferences() {
        return uiPreferences().logPanel();
    }

    /** Updates only the persisted StatsPanel chart style while preserving all other runtime config. */
    public static void updateStatsChartStyle(int chartStyle) {
        updateUiPreferences(new ConfigState.UiPreferences(
                chartStyle,
                logPanelPreferences()));
    }

    /** Updates only the persisted LogPanel preferences while preserving all other runtime config. */
    public static void updateLogPanelPreferences(ConfigState.LogPanelPreferences logPanelPreferences) {
        updateUiPreferences(new ConfigState.UiPreferences(
                statsChartStyle(),
                logPanelPreferences));
    }

    private static void updateUiPreferences(ConfigState.UiPreferences uiPreferences) {
        ConfigState.State current = normalize(state);
        updateState(new ConfigState.State(
                current.dataSources(),
                current.scopeType(),
                current.customEntries(),
                current.sinks(),
                current.settingsSub(),
                current.trafficToolTypes(),
                current.findingsSeverities(),
                current.exporterSubOptions(),
                current.exporterStatsIntervalSeconds(),
                current.indexNameBaseTemplate(),
                current.enabledExportFieldsByIndex(),
                uiPreferences));
    }

    private static ConfigState.State normalize(ConfigState.State incoming) {
        if (incoming == null) {
            return defaultState();
        }

        List<String> sources = incoming.dataSources() == null
                ? List.of()
                : List.copyOf(incoming.dataSources());
        List<String> normalizedSources = normalizeSourcesForEdition(sources);
        List<ConfigState.ScopeEntry> custom = incoming.customEntries() == null
                ? List.of()
                : List.copyOf(incoming.customEntries());

        ConfigState.Sinks sinks = incoming.sinks();
        ConfigState.Sinks normalizedSinks = sinks == null
                ? new ConfigState.Sinks(false, "", false, false,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false, "", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY)
                : new ConfigState.Sinks(
                        sinks.filesEnabled(),
                        safe(sinks.filesPath()),
                        sinks.fileJsonlEnabled(),
                        sinks.fileBulkNdjsonEnabled(),
                        sinks.fileTotalCapEnabled(),
                        sinks.fileTotalCapGb(),
                        sinks.fileDiskUsagePercentEnabled(),
                        sinks.fileDiskUsagePercent(),
                        sinks.osEnabled(),
                        safe(sinks.openSearchUrl()),
                        safe(sinks.openSearchUser()),
                        safe(sinks.openSearchPassword()),
                        sinks.openSearchTlsMode(),
                        sinks.openSearchOptions(),
                        sinks.searchDestination(),
                        safe(sinks.openSearchAmazonUrl()),
                        sinks.openSearchAmazonOptions(),
                        safe(sinks.elasticSearchUrl()),
                        sinks.elasticSearchOptions()
                );

        String scopeType = ConfigState.normalizeScopeType(incoming.scopeType());

        List<String> settingsSub = incoming.settingsSub() != null && !incoming.settingsSub().isEmpty()
                ? ConfigState.normalizeSettingsSub(incoming.settingsSub())
                : ConfigState.DEFAULT_SETTINGS_SUB;
        List<String> trafficToolTypes = incoming.trafficToolTypes() != null
                ? ConfigState.normalizeTrafficToolTypes(incoming.trafficToolTypes())
                : ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES;
        List<String> normalizedTrafficToolTypes = normalizeTrafficToolTypesForEdition(trafficToolTypes);
        List<String> findingsSeverities = incoming.findingsSeverities() != null && !incoming.findingsSeverities().isEmpty()
                ? ConfigState.normalizeFindingsSeverities(incoming.findingsSeverities())
                : ConfigState.DEFAULT_FINDINGS_SEVERITIES;
        List<String> exporterSubOptions = incoming.exporterSubOptions() != null && !incoming.exporterSubOptions().isEmpty()
                ? ConfigState.normalizeExporterSubOptions(incoming.exporterSubOptions())
                : ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS;
        int exporterStatsIntervalSeconds = ConfigState.normalizeExporterStatsIntervalSeconds(
                incoming.exporterStatsIntervalSeconds());

        logCommunityNormalizationIfNeeded(sources, normalizedSources, trafficToolTypes, normalizedTrafficToolTypes);

        Map<String, java.util.Set<String>> enabledFields = incoming.enabledExportFieldsByIndex();
        return new ConfigState.State(normalizedSources, scopeType, custom, normalizedSinks,
                settingsSub, normalizedTrafficToolTypes, findingsSeverities,
                exporterSubOptions, exporterStatsIntervalSeconds,
                incoming.indexNameBaseTemplate(), enabledFields,
                incoming.uiPreferences());
    }

    private static List<String> normalizeSourcesForEdition(List<String> sources) {
        if (!isCommunityEdition() || sources == null || sources.isEmpty()) {
            return sources == null ? List.of() : sources;
        }
        return sources.stream()
                .map(source -> source == null ? "" : source.trim().toLowerCase(Locale.ROOT))
                .filter(source -> !source.isBlank())
                .filter(source -> !COMMUNITY_DISABLED_SOURCES.contains(source))
                .toList();
    }

    private static List<String> normalizeTrafficToolTypesForEdition(List<String> trafficToolTypes) {
        if (!isCommunityEdition() || trafficToolTypes == null || trafficToolTypes.isEmpty()) {
            return trafficToolTypes == null ? List.of() : trafficToolTypes;
        }
        return trafficToolTypes.stream()
                .map(toolType -> toolType == null ? "" : toolType.trim().toLowerCase(Locale.ROOT))
                .filter(toolType -> !toolType.isBlank())
                .filter(toolType -> !COMMUNITY_DISABLED_TRAFFIC_TOOL_TYPES.contains(toolType))
                .toList();
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private static ConfigState.State defaultState() {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_EXPORTER),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, false,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        false, "", "", "", ConfigState.OPEN_SEARCH_TLS_VERIFY),
                ConfigState.DEFAULT_SETTINGS_SUB,
                normalizeTrafficToolTypesForEdition(ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                ConfigState.DEFAULT_INDEX_NAME_BASE_TEMPLATE,
                null,  // all export fields enabled
                ConfigState.defaultUiPreferences()
        );
    }

    private static void logCommunityNormalizationIfNeeded(
            List<String> originalSources,
            List<String> normalizedSources,
            List<String> originalTrafficToolTypes,
            List<String> normalizedTrafficToolTypes) {
        if (!isCommunityEdition()) {
            return;
        }
        Set<String> removedSources = new LinkedHashSet<>(originalSources != null ? originalSources : List.of());
        removedSources.removeAll(normalizedSources != null ? normalizedSources : List.of());
        Set<String> removedTrafficToolTypes = new LinkedHashSet<>(originalTrafficToolTypes != null ? originalTrafficToolTypes : List.of());
        removedTrafficToolTypes.removeAll(normalizedTrafficToolTypes != null ? normalizedTrafficToolTypes : List.of());
        if (removedSources.isEmpty() && removedTrafficToolTypes.isEmpty()) {
            return;
        }
        StringBuilder msg = new StringBuilder("[Community] Stripped unsupported selections from runtime config:");
        if (!removedSources.isEmpty()) {
            msg.append(" sources=").append(removedSources);
        }
        if (!removedTrafficToolTypes.isEmpty()) {
            msg.append(" traffic=").append(removedTrafficToolTypes);
        }
        Logger.logDebug(msg.toString());
    }

    private static ConfigState.State applyCurrentRunDestinationSuppression(ConfigState.State candidate) {
        if (candidate == null) {
            return candidate;
        }
        ConfigState.State suppressed = candidate;
        if (fileExportDisabledForCurrentRun) {
            ConfigState.Sinks sinks = suppressed.sinks();
            if (sinks != null && sinks.filesEnabled()) {
                suppressed = withFilesEnabled(suppressed, false);
            }
        }
        if (openSearchDisabledForCurrentRun) {
            ConfigState.Sinks sinks = suppressed.sinks();
            if (sinks != null && sinks.osEnabled()) {
                suppressed = withOpenSearchEnabled(suppressed, false);
            }
        }
        return suppressed;
    }

    private static void refreshTrafficExportGate() {
        trafficExportGate = buildTrafficExportGate(state, isExportReady());
    }

    private static TrafficExportGate buildTrafficExportGate(ConfigState.State current, boolean ready) {
        if (current == null || current.trafficToolTypes() == null) {
            return new TrafficExportGate(ready, false, 0);
        }
        return new TrafficExportGate(
                ready,
                isTrafficExportEnabledForState(current),
                trafficToolTypeMask(current.trafficToolTypes()));
    }

    private static int trafficToolTypeMask(List<String> trafficToolTypes) {
        if (trafficToolTypes == null || trafficToolTypes.isEmpty()) {
            return 0;
        }
        int mask = 0;
        for (String toolType : trafficToolTypes) {
            mask |= trafficToolTypeMask(toolType);
        }
        return mask;
    }

    private static int trafficToolTypeMask(String normalizedToolType) {
        if (normalizedToolType == null) {
            return 0;
        }
        return switch (normalizedToolType) {
            case "burp_ai" -> TRAFFIC_TOOL_BURP_AI;
            case "extensions" -> TRAFFIC_TOOL_EXTENSIONS;
            case "intruder" -> TRAFFIC_TOOL_INTRUDER;
            case "proxy" -> TRAFFIC_TOOL_PROXY;
            case "proxy_history" -> TRAFFIC_TOOL_PROXY_HISTORY;
            case "repeater" -> TRAFFIC_TOOL_REPEATER;
            case "repeater_tabs" -> TRAFFIC_TOOL_REPEATER_TABS;
            case "scanner" -> TRAFFIC_TOOL_SCANNER;
            case "sequencer" -> TRAFFIC_TOOL_SEQUENCER;
            default -> 0;
        };
    }

    private static boolean isTrafficExportEnabledForState(ConfigState.State current) {
        return current != null
                && current.dataSources() != null
                && current.dataSources().contains(ConfigKeys.SRC_TRAFFIC)
                && current.trafficToolTypes() != null
                && !current.trafficToolTypes().isEmpty()
                && (isSearchTrafficEnabledForState(current) || isAnyFileExportEnabledForState(current));
    }

    private static boolean isSearchTrafficEnabledForState(ConfigState.State current) {
        return current != null
                && current.dataSources() != null
                && current.dataSources().contains(ConfigKeys.SRC_TRAFFIC)
                && current.trafficToolTypes() != null
                && !current.trafficToolTypes().isEmpty()
                && isSearchExportEnabledForState(current);
    }

    private static boolean isSearchExportEnabledForState(ConfigState.State current) {
        return current != null
                && current.sinks() != null
                && current.sinks().osEnabled()
                && !safe(current.sinks().selectedSearchUrl()).isBlank();
    }

    private static boolean isAnyFileExportEnabledForState(ConfigState.State current) {
        if (current == null || current.sinks() == null) {
            return false;
        }
        ConfigState.Sinks sinks = current.sinks();
        return sinks.filesEnabled()
                && !safe(sinks.filesPath()).isBlank()
                && (sinks.fileJsonlEnabled() || sinks.fileBulkNdjsonEnabled());
    }

    private static ConfigState.State withOpenSearchEnabled(ConfigState.State current, boolean enabled) {
        ConfigState.Sinks sinks = current.sinks();
        if (sinks == null) {
            return current;
        }
        return new ConfigState.State(
                current.dataSources(),
                current.scopeType(),
                current.customEntries(),
                new ConfigState.Sinks(
                        sinks.filesEnabled(),
                        sinks.filesPath(),
                        sinks.fileJsonlEnabled(),
                        sinks.fileBulkNdjsonEnabled(),
                        sinks.fileTotalCapEnabled(),
                        sinks.fileTotalCapGb(),
                        sinks.fileDiskUsagePercentEnabled(),
                        sinks.fileDiskUsagePercent(),
                        enabled,
                        sinks.openSearchUrl(),
                        sinks.openSearchUser(),
                        sinks.openSearchPassword(),
                        sinks.openSearchTlsMode(),
                        sinks.openSearchOptions(),
                        sinks.searchDestination(),
                        sinks.openSearchAmazonUrl(),
                        sinks.openSearchAmazonOptions(),
                        sinks.elasticSearchUrl(),
                        sinks.elasticSearchOptions()),
                current.settingsSub(),
                current.trafficToolTypes(),
                current.findingsSeverities(),
                current.exporterSubOptions(),
                current.exporterStatsIntervalSeconds(),
                current.indexNameBaseTemplate(),
                current.enabledExportFieldsByIndex(),
                current.uiPreferences());
    }

    private static ConfigState.State withFilesEnabled(ConfigState.State current, boolean enabled) {
        ConfigState.Sinks sinks = current.sinks();
        if (sinks == null) {
            return current;
        }
        return new ConfigState.State(
                current.dataSources(),
                current.scopeType(),
                current.customEntries(),
                new ConfigState.Sinks(
                        enabled,
                        sinks.filesPath(),
                        sinks.fileJsonlEnabled(),
                        sinks.fileBulkNdjsonEnabled(),
                        sinks.fileTotalCapEnabled(),
                        sinks.fileTotalCapGb(),
                        sinks.fileDiskUsagePercentEnabled(),
                        sinks.fileDiskUsagePercent(),
                        sinks.osEnabled(),
                        sinks.openSearchUrl(),
                        sinks.openSearchUser(),
                        sinks.openSearchPassword(),
                        sinks.openSearchTlsMode(),
                        sinks.openSearchOptions(),
                        sinks.searchDestination(),
                        sinks.openSearchAmazonUrl(),
                        sinks.openSearchAmazonOptions(),
                        sinks.elasticSearchUrl(),
                        sinks.elasticSearchOptions()),
                current.settingsSub(),
                current.trafficToolTypes(),
                current.findingsSeverities(),
                current.exporterSubOptions(),
                current.exporterStatsIntervalSeconds(),
                current.indexNameBaseTemplate(),
                current.enabledExportFieldsByIndex(),
                current.uiPreferences());
    }

    private static void clearResolvedIndexNamesForCurrentRun() {
        resolvedIndexNamesForCurrentRun = Map.of();
        resolvedIndexNamesAt = Instant.EPOCH;
    }

    private static void notifyListeners(ConfigState.State currentState) {
        for (StateListener listener : listeners) {
            listener.onStateChanged(currentState);
        }
    }

    /**
     * Returns the dotted field paths and required container keys allowed for the given index.
     * Used for document filtering (which fields to include in pushed documents). When no
     * field selection is saved, returns required + all toggleable fields.
     */
    public static java.util.Set<String> getAllowedExportKeys(String indexShortName) {
        ConfigState.State current = state;
        java.util.Set<String> enabled = current != null && current.enabledExportFieldsByIndex() != null
                ? current.enabledExportFieldsByIndex().get(indexShortName)
                : null;
        return ExportFieldRegistry.getAllowedKeys(indexShortName, enabled);
    }

    /** Returns whether any runtime file export format is enabled and a root path is set. */
    public static boolean isAnyFileExportEnabled() {
        ConfigState.State current = state;
        if (current == null || current.sinks() == null) {
            return false;
        }
        ConfigState.Sinks sinks = current.sinks();
        return sinks.filesEnabled()
                && !safe(sinks.filesPath()).isBlank()
                && (sinks.fileJsonlEnabled() || sinks.fileBulkNdjsonEnabled());
    }

    /** Returns whether document-only JSONL export is enabled. */
    public static boolean isFileJsonlEnabled() {
        ConfigState.State current = state;
        return current != null && current.sinks() != null
                && current.sinks().filesEnabled()
                && current.sinks().fileJsonlEnabled()
                && !safe(current.sinks().filesPath()).isBlank();
    }

    /** Returns whether bulk-compatible NDJSON export is enabled. */
    public static boolean isFileBulkNdjsonEnabled() {
        ConfigState.State current = state;
        return current != null && current.sinks() != null
                && current.sinks().filesEnabled()
                && current.sinks().fileBulkNdjsonEnabled()
                && !safe(current.sinks().filesPath()).isBlank();
    }

    /** Returns the configured file export root, or blank when unset. */
    public static String fileExportRoot() {
        ConfigState.State current = state;
        return current == null || current.sinks() == null ? "" : safe(current.sinks().filesPath());
    }

    /** True when the total exporter-file cap is enabled. */
    public static boolean isFileTotalCapEnabled() {
        ConfigState.State current = state;
        return current != null && current.sinks() != null && current.sinks().fileTotalCapEnabled();
    }

    /** Configured total cap across exporter files under the selected root. */
    public static long fileTotalCapBytes() {
        ConfigState.State current = state;
        return current == null || current.sinks() == null
                ? ConfigState.gbToBytes(ConfigState.DEFAULT_FILE_TOTAL_CAP_GB)
                : current.sinks().fileTotalCapBytes();
    }

    /** True when the optional destination-volume used-percent threshold is enabled. */
    public static boolean isFileDiskUsagePercentEnabled() {
        ConfigState.State current = state;
        return current != null && current.sinks() != null && current.sinks().fileDiskUsagePercentEnabled();
    }

    /** Configured destination-volume used-percent threshold for file export. */
    public static int fileDiskUsagePercent() {
        ConfigState.State current = state;
        return current == null || current.sinks() == null
                ? ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT
                : current.sinks().fileDiskUsagePercent();
    }
}
