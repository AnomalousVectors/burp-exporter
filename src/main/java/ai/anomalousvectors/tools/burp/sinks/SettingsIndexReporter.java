package ai.anomalousvectors.tools.burp.sinks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.LazyScheduler;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;

/**
 * Pushes Burp project and user settings to the settings index when export is
 * running and "Settings" is selected. Initial push on Start; thereafter only
 * pushes when a change is detected (scheduler checks every 30 seconds). Each
 * push sends the full config and logs a short success/failure message at info
 * level.
 */
public final class SettingsIndexReporter {

    private static final int INTERVAL_SECONDS = 30;
    private static final String SCHEMA_VERSION = "1";
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    /**
     * Single-owner scheduler for settings-change polling.
     *
     * <p>Created lazily by {@link LazyScheduler#getOrStart()} on {@link #start()} and torn down
     * by {@link #stop()} during UI stop or extension unload. A subsequent {@link #start()}
     * lazily recreates the executor.</p>
     */
    private static final LazyScheduler SCHEDULER =
            new LazyScheduler("burp-exporter-settings-reporter");
    private static volatile String lastPushedHash;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicBoolean projectOptionsFailureLogged = new AtomicBoolean();
    private static final AtomicBoolean userOptionsFailureLogged = new AtomicBoolean();
    private static final AtomicBoolean projectIdFallbackLogged = new AtomicBoolean();
    private static final AtomicBoolean burpVersionFallbackLogged = new AtomicBoolean();

    private SettingsIndexReporter() {}

    private static String settingsIndexName() {
        return RuntimeConfig.indexNameForKey("settings");
    }

    /**
     * Pushes one settings snapshot immediately (e.g. initial push on Start).
     * Always pushes and logs; does not compare to last pushed hash. Safe to call
     * from any thread. No-op if export is not running, no sink is enabled,
     * or Settings is not in the selected data sources.
     */
    public static void pushSnapshotNow() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            String baseUrl = RuntimeConfig.searchBaseUrl();
            boolean openSearchActive = RuntimeConfig.isSearchActive();
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SETTINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            String projectJson = safeProjectOptionsJson(api);
            String userJson = safeUserOptionsJson(api);
            ConfigState.State state = RuntimeConfig.getState();
            Map<String, Object> doc = buildSettingsDoc(api, projectJson, userJson, state);
            boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, settingsIndexName(), "settings", doc);
            SingleDocOutcomeRecorder.record("settings", ok, openSearchActive, "Settings index push failed");
            if (ok) {
                lastPushedHash = hashSettingsForEnabled(state, projectJson, userJson);
                Logger.logInfoPanelOnly("[SnapshotExport] Settings: pushed to "
                        + RuntimeConfig.activeSinkSummary() + ".");
            } else {
                Logger.logWarnPanelOnly("[SnapshotExport] Settings: push failed for "
                        + RuntimeConfig.activeSinkSummary() + " (index request did not succeed).");
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            SingleDocOutcomeRecorder.record("settings", false, RuntimeConfig.isSearchActive(), msg);
            Logger.logWarnPanelOnly("[SnapshotExport] Settings: push failed for "
                    + RuntimeConfig.activeSinkSummary() + ": " + msg);
        }
    }

    /**
     * Starts the 30-second change-check scheduler. Does not perform an initial
     * push (caller must call {@link #pushSnapshotNow()} once on Start). Safe to
     * call from any thread.
     */
    public static void start() {
        RuntimeConfig.ExportRunToken token = RuntimeConfig.currentExportRunToken();
        SCHEDULER.startRecurring(
                () -> {
                    if (RuntimeConfig.isExportRunActive(token)) {
                        pushSnapshotIfChanged();
                    }
                },
                INTERVAL_SECONDS,
                INTERVAL_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Stops the periodic scheduler and clears the last pushed hash.
     *
     * <p>Safe to call from any thread. The next {@link #start()} call creates a fresh scheduler.</p>
     */
    public static void stop() {
        SCHEDULER.stop();
        lastPushedHash = null;
        projectOptionsFailureLogged.set(false);
        userOptionsFailureLogged.set(false);
        projectIdFallbackLogged.set(false);
        burpVersionFallbackLogged.set(false);
    }

    /**
     * Called by the scheduler. Pushes only when current settings hash differs
     * from last pushed; logs at info level when a push is performed.
     */
    static void pushSnapshotIfChanged() {
        try {
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!RuntimeConfig.isAnySinkEnabled()) {
                return;
            }
            String baseUrl = RuntimeConfig.searchBaseUrl();
            boolean openSearchActive = RuntimeConfig.isSearchActive();
            List<String> sources = RuntimeConfig.getState().dataSources();
            if (sources == null || !sources.contains(ConfigKeys.SRC_SETTINGS)) {
                return;
            }
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null) {
                return;
            }
            String projectJson = safeProjectOptionsJson(api);
            String userJson = safeUserOptionsJson(api);
            ConfigState.State state = RuntimeConfig.getState();
            String currentHash = hashSettingsForEnabled(state, projectJson, userJson);
            if (currentHash.equals(lastPushedHash)) {
                return;
            }
            Map<String, Object> doc = buildSettingsDoc(api, projectJson, userJson, state);
            boolean ok = OpenSearchClientWrapper.pushDocument(baseUrl, settingsIndexName(), "settings", doc);
            SingleDocOutcomeRecorder.record("settings", ok, openSearchActive, "Settings index push failed");
            if (ok) {
                lastPushedHash = currentHash;
                Logger.logInfoPanelOnly("[PeriodicExport] Settings: pushed to "
                        + RuntimeConfig.activeSinkSummary() + " (change detected).");
            } else {
                Logger.logWarnPanelOnly("[PeriodicExport] Settings: push failed for "
                        + RuntimeConfig.activeSinkSummary() + " (index request did not succeed).");
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            SingleDocOutcomeRecorder.record("settings", false, RuntimeConfig.isSearchActive(), msg);
            Logger.logWarnPanelOnly("[PeriodicExport] Settings: push failed for "
                    + RuntimeConfig.activeSinkSummary() + ": " + msg);
        }
    }

    private static String hashSettings(String projectJson, String userJson) {
        String combined = (projectJson != null ? projectJson : "") + "\n" + (userJson != null ? userJson : "");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(combined.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(combined.hashCode());
        }
    }

    /** Hash only the enabled settings parts for change detection. */
    private static String hashSettingsForEnabled(ConfigState.State state, String projectJson, String userJson) {
        var sub = state != null && state.settingsSub() != null ? state.settingsSub() : java.util.List.<String>of();
        String projectPart = sub.contains(ConfigKeys.SRC_SETTINGS_PROJECT) ? (projectJson != null ? projectJson : "") : "";
        String userPart = sub.contains(ConfigKeys.SRC_SETTINGS_USER) ? (userJson != null ? userJson : "") : "";
        return hashSettings(projectPart, userPart);
    }

    private static Map<String, Object> buildSettingsDoc(MontoyaApi api, String projectOptionsJson, String userOptionsJson, ConfigState.State state) {
        String projectId = safeProjectId(api);
        var sub = state != null && state.settingsSub() != null ? state.settingsSub() : java.util.List.<String>of();
        Map<String, Object> settingsProject = sub.contains(ConfigKeys.SRC_SETTINGS_PROJECT) ? parseJsonToMap(projectOptionsJson) : Map.of();
        Map<String, Object> settingsUser = sub.contains(ConfigKeys.SRC_SETTINGS_USER) ? parseJsonToMap(userOptionsJson) : Map.of();

        Map<String, Object> doc = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("project_id", projectId != null ? projectId : "");
        burp.put("version", safeBurpVersion(api));
        doc.put("burp", burp);
        doc.put("project", settingsProject != null ? settingsProject : Map.of());
        doc.put("user", settingsUser != null ? settingsUser : Map.of());
        doc.put("meta", ExportMetaFields.meta(SCHEMA_VERSION));
        return doc;
    }

    private static String safeProjectOptionsJson(MontoyaApi api) {
        try {
            if (api == null || api.burpSuite() == null) {
                return null;
            }
            return api.burpSuite().exportProjectOptionsAsJson();
        } catch (RuntimeException e) {
            logSettingsCapabilityFailureOnce(projectOptionsFailureLogged, "project options export", e);
            return null;
        }
    }

    private static String safeUserOptionsJson(MontoyaApi api) {
        try {
            if (api == null || api.burpSuite() == null) {
                return null;
            }
            return api.burpSuite().exportUserOptionsAsJson();
        } catch (RuntimeException e) {
            logSettingsCapabilityFailureOnce(userOptionsFailureLogged, "user options export", e);
            return null;
        }
    }

    private static String safeProjectId(MontoyaApi api) {
        try {
            if (api != null && api.project() != null) {
                String projectId = api.project().id();
                if (projectId != null && !projectId.isBlank()) {
                    return projectId;
                }
            }
        } catch (RuntimeException e) {
            logSettingsCapabilityFailureOnce(projectIdFallbackLogged, "project id lookup", e);
        }
        if (projectIdFallbackLogged.compareAndSet(false, true)) {
            Logger.logDebug("[Settings] Project id unavailable; using fallback label for settings export.");
        }
        return BurpRuntimeMetadata.projectIdOrUnknown();
    }

    private static String safeBurpVersion(MontoyaApi api) {
        try {
            if (api != null && api.burpSuite() != null && api.burpSuite().version() != null) {
                return String.valueOf(api.burpSuite().version());
            }
        } catch (RuntimeException e) {
            logSettingsCapabilityFailureOnce(burpVersionFallbackLogged, "Burp version lookup", e);
        }
        return BurpRuntimeMetadata.burpVersion();
    }

    private static void logSettingsCapabilityFailureOnce(AtomicBoolean logged, String capability, RuntimeException e) {
        if (!logged.compareAndSet(false, true)) {
            return;
        }
        String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
        Logger.logDebug("[Settings] " + capability + " unavailable; continuing with fallback values: " + msg);
    }

    private static Map<String, Object> parseJsonToMap(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> map = JSON.readValue(json, MAP_TYPE);
            return map != null ? map : Map.of();
        } catch (java.io.IOException | RuntimeException e) {
            return Map.of();
        }
    }
}
