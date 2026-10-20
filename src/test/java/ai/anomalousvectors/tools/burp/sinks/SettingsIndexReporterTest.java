package ai.anomalousvectors.tools.burp.sinks;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.project.Project;

/**
 * Ensures {@link SettingsIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Settings not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class SettingsIndexReporterTest {
    private final ConfigState.State previousState = RuntimeConfig.getState();
    private final MontoyaApi previousApi = MontoyaApiProvider.get();

    private void resetState() {
        SettingsIndexReporter.stop();
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
        // Restore the edition dependency before normalizing the saved selections.
        MontoyaApiProvider.set(previousApi);
        RuntimeConfig.updateState(previousState);
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenApiNull() {
        try {
            RuntimeConfig.setExportRunning(true);
            MontoyaApiProvider.set(null);
            SettingsIndexReporter.pushSnapshotNow();
            // No exception; may no-op because api is null
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            SettingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotIfChanged_completesWithoutThrow_whenApiNull() {
        try {
            RuntimeConfig.setExportRunning(true);
            MontoyaApiProvider.set(null);
            SettingsIndexReporter.pushSnapshotIfChanged();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotIfChanged_completesWithoutThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            SettingsIndexReporter.pushSnapshotIfChanged();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenSettingsApisFallBack() {
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);

            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Project project = mock(Project.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(api.project()).thenReturn(project);
            when(burpSuite.exportProjectOptionsAsJson()).thenThrow(new IllegalStateException("project export unavailable"));
            when(burpSuite.exportUserOptionsAsJson()).thenThrow(new IllegalStateException("user export unavailable"));
            when(project.id()).thenThrow(new IllegalStateException("project id unavailable"));
            MontoyaApiProvider.set(api);

            SettingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void buildSettingsDoc_usesFallbackProjectIdAndEmptyMaps_whenSettingsApisUnavailable() {
        try {
            BurpRuntimeMetadata.clear();
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Project project = mock(Project.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(api.project()).thenReturn(project);
            when(burpSuite.exportProjectOptionsAsJson()).thenThrow(new IllegalStateException("project export unavailable"));
            when(burpSuite.exportUserOptionsAsJson()).thenThrow(new IllegalStateException("user export unavailable"));
            when(project.id()).thenThrow(new IllegalStateException("project id unavailable"));

            ConfigState.State state = new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null);

            String projectJson = (String) Reflect.callStatic(SettingsIndexReporter.class, "safeProjectOptionsJson", api);
            String userJson = (String) Reflect.callStatic(SettingsIndexReporter.class, "safeUserOptionsJson", api);
            Map<?, ?> doc = (Map<?, ?>) Reflect.callStatic(
                    SettingsIndexReporter.class, "buildSettingsDoc", api, projectJson, userJson, state);

            assertThat(projectJson).isNull();
            assertThat(userJson).isNull();
            Map<?, ?> burp = (Map<?, ?>) doc.get("burp");
            assertThat(burp.get("project_id")).isEqualTo(BurpRuntimeMetadata.UNKNOWN_PROJECT_ID);
            assertThat(burp.containsKey("version")).isTrue();
            assertThat(doc.get("project")).isEqualTo(Map.of());
            assertThat(doc.get("user")).isEqualTo(Map.of());
            assertThat(doc.keySet().stream().anyMatch("meta"::equals)).isTrue();
        } finally {
            BurpRuntimeMetadata.clear();
            resetState();
        }
    }
}
