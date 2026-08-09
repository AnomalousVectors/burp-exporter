package ai.anomalousvectors.tools.burp.utils.config;

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;

class RuntimeConfigCommunityEditionTest {

    private final ConfigState.State previousState = RuntimeConfig.getState();
    private final MontoyaApi previousApi = MontoyaApiProvider.get();

    @Test
    void updateState_stripsCommunityUnsupportedSourcesAndTrafficTools() {
        try {
            MontoyaApiProvider.set(mockEditionApi(BurpSuiteEdition.COMMUNITY_EDITION));

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_FINDINGS, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy", "scanner", "burp_ai", "repeater"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));

            assertThat(RuntimeConfig.getState().dataSources())
                    .containsExactly(ConfigKeys.SRC_SETTINGS, ConfigKeys.SRC_TRAFFIC);
            assertThat(RuntimeConfig.getState().trafficToolTypes())
                    .containsExactly("proxy", "repeater");
            assertThat(RuntimeConfig.isDataSourceEnabled(ConfigKeys.SRC_FINDINGS)).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("scanner")).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("burp_ai")).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("proxy")).isTrue();
        } finally {
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
            MontoyaApiProvider.set(previousApi);
        }
    }

    @Test
    void updateState_null_usesCommunitySafeDefaultTrafficSelection() {
        try {
            MontoyaApiProvider.set(mockEditionApi(BurpSuiteEdition.COMMUNITY_EDITION));

            RuntimeConfig.updateState(null);

            assertThat(RuntimeConfig.getState().trafficToolTypes())
                    .containsExactly("extensions", "intruder", "proxy", "proxy_history", "repeater", "sequencer");
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("repeater_tabs")).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("burp_ai")).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("scanner")).isFalse();
            assertThat(RuntimeConfig.isTrafficToolTypeEnabled("proxy")).isTrue();
        } finally {
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
            MontoyaApiProvider.set(previousApi);
        }
    }

    @Test
    void updateState_logsWhenCommunityStripsUnsupportedSelections() {
        try {
            MontoyaApiProvider.set(mockEditionApi(BurpSuiteEdition.COMMUNITY_EDITION));
            Logger.resetState();
            List<String> seen = new ArrayList<>();
            Logger.LogListener listener = (level, message) -> seen.add(level + ":" + message);
            Logger.registerListener(listener);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS, ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", false, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy", "scanner"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            try {
                SwingUtilities.invokeAndWait(() -> { });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw new RuntimeException(e);
            }

            assertThat(seen)
                    .anyMatch(msg -> msg.startsWith("DEBUG:[Community] Stripped unsupported selections from runtime config:")
                            && msg.contains("findings")
                            && msg.contains("scanner"));
            Logger.unregisterListener(listener);
        } finally {
            Logger.resetState();
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
            MontoyaApiProvider.set(previousApi);
        }
    }

    private static MontoyaApi mockEditionApi(BurpSuiteEdition edition) {
        MontoyaApi api = mock(MontoyaApi.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Version version = mock(Version.class);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(burpSuite.version()).thenReturn(version);
        when(version.edition()).thenReturn(edition);
        return api;
    }
}
