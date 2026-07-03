package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static org.mockito.ArgumentMatchers.anyString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.awt.FlowLayout;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JLabel;
import org.junit.jupiter.api.Test;

import javax.swing.JTabbedPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.mockito.Answers;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

class RepeaterTabsIndexReporterTest {

    @Test
    void buildDocument_returnsNull_whenBurpScopeRejectsRepeaterTab() {
        ConfigState.State previousState = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_BURP,
                    java.util.List.of(),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(false);
            MontoyaApiProvider.set(api);

            Object doc = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildDocument",
                    scopedRepeaterRequestResponse("https://out.example/smoke"),
                    "Out Tab",
                    null);

            assertThat(doc).isNull();
        } finally {
            RuntimeConfig.updateState(previousState);
            MontoyaApiProvider.set(null);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void buildDocument_returnsNull_whenCustomScopeRejectsRepeaterTab() {
        ConfigState.State previousState = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_CUSTOM,
                    java.util.List.of(new ConfigState.ScopeEntry("in.example", ConfigState.Kind.STRING)),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            MontoyaApiProvider.set(api);

            Object doc = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildDocument",
                    scopedRepeaterRequestResponse("https://out.example/smoke"),
                    "Out Tab",
                    null);

            assertThat(doc).isNull();
        } finally {
            RuntimeConfig.updateState(previousState);
            MontoyaApiProvider.set(null);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void buildDocument_returnsDocument_whenCustomScopeAcceptsRepeaterTab() {
        ConfigState.State previousState = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_CUSTOM,
                    java.util.List.of(new ConfigState.ScopeEntry("in.example", ConfigState.Kind.STRING)),
                    null,
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(false);
            MontoyaApiProvider.set(api);

            Object doc = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildDocument",
                    scopedRepeaterRequestResponse("https://in.example/smoke"),
                    "In Tab",
                    null);

            assertThat(doc).isInstanceOf(Map.class);
        } finally {
            RuntimeConfig.updateState(previousState);
            MontoyaApiProvider.set(null);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_queuesOncePerCaptureKey_evenWhenPushSnapshotNowRuns() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(
                            false,
                            "",
                            false,
                            false,
                            false,
                            0,
                            false,
                            0,
                            true,
                            "https://opensearch.url:9200",
                            "",
                            "",
                            "insecure",
                            null),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);
            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            startupSelectionField.set(null, repeaterTabMetadata("GetGateway", "Concurrent", "startup-slot-7"));

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            HttpRequestResponse requestResponse = repeaterRequestResponseWithResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

            TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
                SwingUtilities.invokeAndWait(() ->
                        RepeaterTabsIndexReporter.captureFromEditorContext(
                                context, requestResponse, "request_editor", null));
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);

                RepeaterTabsIndexReporter.pushSnapshotNow();
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);

                SwingUtilities.invokeAndWait(() ->
                        RepeaterTabsIndexReporter.captureFromEditorContext(
                                context, requestResponse, "response_editor", null));
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);

                RepeaterTabsIndexReporter.pushSnapshotNow();
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
            });
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_dedupesRepeatedRepeaterBindings() {
        try {
            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            HttpRequestResponse requestResponse = repeaterRequestResponseWithResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

            RepeaterTabsIndexReporter.captureFromEditorContext(context, requestResponse, "request_editor", null);
            RepeaterTabsIndexReporter.captureFromEditorContext(context, requestResponse, "response_editor", null);

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(1);
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_ignoresPartialBindings_withoutResponse() {
        try {
            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            RepeaterTabsIndexReporter.captureFromEditorContext(
                    context,
                    repeaterRequestResponse("GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n"),
                    "request_editor",
                    null);

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isZero();
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_ignoresNonRepeaterEditors() {
        try {
            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.PROXY);

            RepeaterTabsIndexReporter.captureFromEditorContext(
                    context,
                    repeaterRequestResponseWithResponse(
                            "GET /proxy HTTP/1.1\r\nHost: example.test\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                    "request_editor",
                    null);

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isZero();
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void markStartupSlotForCurrentRun_allowsOnlyFirstCapture_forSameTabSlot() {
        try {
            assertThat(RepeaterTabsIndexReporter.markStartupSlotForCurrentRun("Group Alpha|3", "fp-1")).isTrue();
            assertThat(RepeaterTabsIndexReporter.markStartupSlotForCurrentRun("Group Alpha|3", "fp-1")).isFalse();
            assertThat(RepeaterTabsIndexReporter.markStartupSlotForCurrentRun("Group Alpha|3", "fp-2")).isFalse();

            RepeaterTabsIndexReporter.clearRunState();

            assertThat(RepeaterTabsIndexReporter.markStartupSlotForCurrentRun("Group Alpha|3", "fp-2")).isTrue();
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_ignoresLiveRunRebinds_afterStartupCaptureWindowCloses() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            SwingUtilities.invokeAndWait(() -> {
                try {
                    startupSelectionField.set(null, repeaterTabMetadata("HistoricTab", null, "startup-slot-live-window"));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                RepeaterTabsIndexReporter.captureFromEditorContext(
                        context,
                        repeaterRequestResponseWithResponse(
                                "GET /historic HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                        "request_editor",
                        null);
            });
            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(1);

            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            RepeaterTabsIndexReporter.captureFromEditorContext(
                    context,
                    repeaterRequestResponseWithResponse(
                            "GET /after-window HTTP/1.1\r\nHost: example.test\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                    "request_editor",
                    null);
            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(1);
        } finally {
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void startupSlotKey_usesSlotIdentityWhenPresent() throws Exception {
        try {
            RepeaterTabsIndexReporter.RepeaterTabMetadata metadata =
                    (RepeaterTabsIndexReporter.RepeaterTabMetadata) repeaterTabMetadata(
                    "myRepeaterGroupTwoTabOne",
                    "myRepeaterGroupTwo",
                    "startup-slot-5");

            assertThat(RepeaterTabsCapturePolicy.startupSlotKey(metadata)).isEqualTo("startup-slot-5");
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void isAuxiliaryRepeaterTabLabel_recognizesMessageViews_notRequestTabNames() {
        assertThat(RepeaterTabMetadataHeuristics.isAuxiliaryRepeaterTabLabel("Explanations")).isTrue();
        assertThat(RepeaterTabMetadataHeuristics.isAuxiliaryRepeaterTabLabel("Raw")).isTrue();
        assertThat(RepeaterTabMetadataHeuristics.isAuxiliaryRepeaterTabLabel("GetGateway")).isFalse();
        assertThat(RepeaterTabMetadataHeuristics.isAuxiliaryRepeaterTabLabel(null)).isFalse();
    }

    @Test
    void capturePolicy_decide_ignoresAuxiliaryRightRailTabNamesDuringStartup() throws Exception {
        try {
            RepeaterTabsIndexReporter.RepeaterTabMetadata metadata =
                    (RepeaterTabsIndexReporter.RepeaterTabMetadata) repeaterTabMetadata(
                            "Explanations",
                            "Concurrent",
                            "startup-slot-rail");

            RepeaterTabsCapturePolicy.CaptureDecision decision =
                    RepeaterTabsCapturePolicy.decide("fp-1", metadata, true);

            assertThat(decision.ignoreAuxiliaryTabNameBinding()).isTrue();
            assertThat(decision.captureKey()).isEqualTo("slot:startup-slot-rail");
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void capturePolicy_decide_ignoresAuxiliaryTabNameOutsideStartupWindow() throws Exception {
        try {
            RepeaterTabsIndexReporter.RepeaterTabMetadata metadata =
                    (RepeaterTabsIndexReporter.RepeaterTabMetadata) repeaterTabMetadata(
                            "Notes",
                            "Concurrent",
                            null);

            RepeaterTabsCapturePolicy.CaptureDecision decision =
                    RepeaterTabsCapturePolicy.decide("fp-notes", metadata, false);

            assertThat(decision.ignoreAuxiliaryTabNameBinding()).isTrue();
            assertThat(decision.captureKey()).isEqualTo("fp-notes");
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_skipsAuxiliaryRightRailTabNameDuringStartup() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);
            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            startupSelectionField.set(null, repeaterTabMetadata("Explanations", "Concurrent", "startup-slot-rail"));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                            "request_editor",
                            null));

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isZero();
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_skipsAuxiliaryRightRailTabNameAfterStartupWindowClosed() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);
            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            startupSelectionField.set(null, repeaterTabMetadata("Inspector", "Concurrent", "slot-rail-live"));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                            "request_editor",
                            null));

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isZero();
        } finally {
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_dedupesDifferentFingerprints_forSameStartupSlot() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);
            startupSelectionField.set(null, repeaterTabMetadata(
                    "myRepeaterGroupTwoTabOne",
                    "myRepeaterGroupTwo",
                    "startup-slot-5"));

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            HttpRequestResponse firstBinding = repeaterRequestResponseWithResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            HttpRequestResponse reboundBinding = repeaterRequestResponseWithResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            SwingUtilities.invokeAndWait(() -> {
                RepeaterTabsIndexReporter.captureFromEditorContext(context, firstBinding, "request_editor", null);
                RepeaterTabsIndexReporter.captureFromEditorContext(context, reboundBinding, "request_editor", null);
            });

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(1);
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_keepsIdenticalFingerprints_forDifferentStartupSlots() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        Field capturedField = RepeaterTabsIndexReporter.class.getDeclaredField("CAPTURED");
        capturedField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            HttpRequestResponse firstTabBinding = repeaterRequestResponseWithResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
            HttpRequestResponse secondTabBinding = repeaterRequestResponseWithResponse(
                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            startupSelectionField.set(null, repeaterTabMetadata("GetGateway", "Concurrent", "startup-slot-7"));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            firstTabBinding,
                            "request_editor",
                            null));

            startupSelectionField.set(null, repeaterTabMetadata("385", "Concurrent", "startup-slot-8"));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            secondTabBinding,
                            "request_editor",
                            null));

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(2);
            assertThat(((java.util.Map<?, ?>) capturedField.get(null)).keySet().stream()
                    .map(String::valueOf)
                    .toList())
                    .containsExactlyInAnyOrder("slot:startup-slot-7", "slot:startup-slot-8");
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_ignoresStartupBindings_withoutLogicalTabIdentity() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            startupSelectionField.set(null, repeaterTabMetadata(null, null, null));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                            "response_editor",
                            null));

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isZero();
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_keepsStartupBindings_withReadableTabMetadata_evenWithoutSlotIdentity() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            startupSelectionField.set(null, repeaterTabMetadata("ReadableTab", null, null));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                            "request_editor",
                            null));

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(1);
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void describeStartupMetadataSummary_keepsPerTabDetailAtTrace_only() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Method recordMethod = RepeaterTabsIndexReporter.class.getDeclaredMethod(
                "recordStartupMetadataObservation",
                String.class,
                String.class,
                String.class,
                Class.forName("ai.anomalousvectors.tools.burp.sinks.RepeaterTabsIndexReporter$RepeaterTabMetadata"));
        recordMethod.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            List<String> seen = new ArrayList<>();
            Logger.LogListener listener = (level, message) -> seen.add(level + ":" + message);
            Logger.registerListener(listener);

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            recordMethod.invoke(
                    null,
                    "request_editor",
                    "slot:slot-1",
                    "fp-1",
                    repeaterTabMetadata("GetUserToken", null, "slot-1"));
            recordMethod.invoke(
                    null,
                    "response_editor",
                    "fp-2",
                    "fp-2",
                    repeaterTabMetadata("SensitiveContentInUrl", "Findings", "slot-2"));
            SwingUtilities.invokeAndWait(() -> { });

            assertThat(seen).hasSize(2);
            assertThat(seen).allMatch(entry -> entry.startsWith("TRACE:[RepeaterTabs] Startup metadata via "));
            assertThat(seen.getFirst())
                    .contains("startupSession=g")
                    .contains("metadataSource=startup_slot")
                    .contains("captureKey=slot:slot-1")
                    .contains("tab=GetUserToken")
                    .contains("group=<null>");
            assertThat(seen.get(1))
                    .contains("startupSession=g")
                    .contains("metadataSource=startup_fingerprint")
                    .contains("captureKey=fp-2")
                    .contains("tab=SensitiveContentInUrl")
                    .contains("group=Findings");
            assertThat(RepeaterTabsIndexReporter.describeStartupMetadataSummary())
                    .contains("observations=2")
                    .contains("grouped=1")
                    .contains("standalone=1")
                    .contains("uniqueSlots=2")
                    .contains("uniqueTabGroupPairs=2")
                    .contains("groups=[Findings=1]")
                    .contains("noIdentityObservationsSkipped=0")
                    .contains("alreadyCapturedSlotObservations=0")
                    .contains("metadataUpgrades=0")
                    .contains("request_editor=1")
                    .contains("response_editor=1")
                    .doesNotContain("GetUserToken")
                    .doesNotContain("SensitiveContentInUrl");

            RepeaterTabsIndexReporter.clearRunState();

            assertThat(RepeaterTabsIndexReporter.describeStartupMetadataSummary()).isEqualTo("none");
        } finally {
            Logger.resetState();
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void startupMetadataSummary_reportsIgnoredDuplicateAndUpgradeCounters_withoutPerTabLeakage() {
        RepeaterTabsStartupMetadataSummary summary = new RepeaterTabsStartupMetadataSummary();
        RepeaterTabsIndexReporter.RepeaterTabMetadata standalone =
                new RepeaterTabsIndexReporter.RepeaterTabMetadata("GetUserToken", null, "root", "slot-1");
        RepeaterTabsIndexReporter.RepeaterTabMetadata grouped =
                new RepeaterTabsIndexReporter.RepeaterTabMetadata("SensitiveContentInUrl", "Findings", "root", "slot-2");

        summary.recordObservation("request_editor", standalone);
        summary.recordObservation("response_editor", grouped);
        summary.recordIgnoredAnonymousBinding("response_editor");
        summary.recordDuplicateSlotSuppression("request_editor", "slot-1");
        summary.recordMetadataUpgrade("response_editor");

        assertThat(summary.describe())
                .contains("observations=2")
                .contains("grouped=1")
                .contains("standalone=1")
                .contains("uniqueSlots=2")
                .contains("uniqueTabGroupPairs=2")
                .contains("groups=[Findings=1]")
                .contains("noIdentityObservationsSkipped=1")
                .contains("alreadyCapturedSlotObservations=1")
                .contains("metadataUpgrades=1")
                .contains("capturePaths=[request_editor=1, response_editor=1]")
                .contains("noIdentityPaths=[response_editor=1]")
                .contains("alreadyCapturedSlotPaths=[request_editor=1]")
                .contains("alreadyCapturedSlotHighlights=[slot-1|request_editor=1]")
                .contains("upgradedPaths=[response_editor=1]")
                .doesNotContain("GetUserToken")
                .doesNotContain("SensitiveContentInUrl");
    }

    @Test
    void captureFromEditorContext_coalescesDuplicateStartupSlotTraceAfterThreshold() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            List<String> seen = new ArrayList<>();
            Logger.LogListener listener = (level, message) -> seen.add(level + ":" + message);
            Logger.registerListener(listener);

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();
            startupSelectionField.set(null, repeaterTabMetadata("GetUserToken", null, "slot-1"));

            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                            "request_editor",
                            null));
            for (int i = 0; i < 5; i++) {
                SwingUtilities.invokeAndWait(() ->
                        RepeaterTabsIndexReporter.captureFromEditorContext(
                                context,
                                repeaterRequestResponseWithResponse(
                                        "GET /repeat HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                                "request_editor",
                                null));
            }

            List<String> duplicateLogs = seen.stream()
                    .filter(entry -> entry.contains(
                            "Skipped additional startup editor observation for logical slot already captured"))
                    .toList();
            List<String> coalescedLogs = seen.stream()
                    .filter(entry -> entry.contains(
                            "will be summarized instead of logged individually"))
                    .toList();

            assertThat(duplicateLogs).hasSize(3);
            assertThat(coalescedLogs).hasSize(1);
            assertThat(RepeaterTabsIndexReporter.describeStartupMetadataSummary())
                    .contains("alreadyCapturedSlotObservations=5")
                    .contains("alreadyCapturedSlotHighlights=[slot-1|request_editor=5]");
        } finally {
            Logger.resetState();
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void captureFromEditorContext_mixedStartupBindings_doNotLeaveAnonymousCapturedEntries() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
        startupSelectionField.setAccessible(true);
        Field capturedField = RepeaterTabsIndexReporter.class.getDeclaredField("CAPTURED");
        capturedField.setAccessible(true);
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    java.util.List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    java.util.List.of(),
                    new ConfigState.Sinks(false, null, false, null, null, null, false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    java.util.List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();

            startupSelectionField.set(null, repeaterTabMetadata("GetBearerToken", null, "slot-1"));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"),
                            "request_editor",
                            null));

            startupSelectionField.set(null, repeaterTabMetadata(null, null, null));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /anonymous HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB"),
                            "response_editor",
                            null));

            startupSelectionField.set(null, repeaterTabMetadata("GetUserToken", null, "slot-2"));
            SwingUtilities.invokeAndWait(() ->
                    RepeaterTabsIndexReporter.captureFromEditorContext(
                            context,
                            repeaterRequestResponseWithResponse(
                                    "GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nC"),
                            "request_editor",
                            null));

            Field tabNameField = Class.forName(
                    "ai.anomalousvectors.tools.burp.sinks.RepeaterTabsIndexReporter$CapturedRepeaterItem")
                    .getDeclaredField("repeaterTabName");
            tabNameField.setAccessible(true);
            Field groupNameField = Class.forName(
                    "ai.anomalousvectors.tools.burp.sinks.RepeaterTabsIndexReporter$CapturedRepeaterItem")
                    .getDeclaredField("repeaterGroupName");
            groupNameField.setAccessible(true);

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(2);
            assertThat(((Map<?, ?>) capturedField.get(null)).values().stream()
                    .map(item -> {
                        try {
                            return String.valueOf(tabNameField.get(item)) + "|" + String.valueOf(groupNameField.get(item));
                        } catch (IllegalAccessException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .toList())
                    .containsExactlyInAnyOrder("GetBearerToken|null", "GetUserToken|null");
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            startupSelectionField.set(null, null);
            RuntimeConfig.updateState(previousState);
            RuntimeConfig.setExportRunning(previousRunning);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void buildDocument_includesRepeaterTabAndGroupNames_whenProvided() {
        try {
            Map<String, Object> document = objectMap(callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildDocument",
                    repeaterRequestResponse("GET /grouped HTTP/1.1\r\nHost: example.test\r\n\r\n"),
                    "2",
                    "Group Alpha"));

            assertThat(burpRepeater(document)).containsEntry("tab_name", "2");
            assertThat(burpRepeater(document)).containsEntry("tab_group", "Group Alpha");
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void buildDocument_sameHttpDifferentTabNames_produceDistinctPreparedDocuments() throws Exception {
        try {
            HttpRequestResponse sharedHttp = repeaterRequestResponseWithResponse(
                    "GET /shared HTTP/1.1\r\nHost: example.test\r\n\r\n",
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            Map<String, Object> tab385 = objectMap(callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildDocument",
                    sharedHttp,
                    "385",
                    "Group A"));
            Map<String, Object> tab391 = objectMap(callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildDocument",
                    sharedHttp,
                    "391",
                    "Group A"));

            String indexName = IndexNaming.indexNameForShortName("traffic");
            PreparedExportDocument prepared385 = ExportDocumentIdentity.prepare(indexName, "traffic", tab385);
            PreparedExportDocument prepared391 = ExportDocumentIdentity.prepare(indexName, "traffic", tab391);

            assertThat(prepared385.document()).isNotSameAs(prepared391.document());
            assertThat(metaString(tab385, "schema_version")).isEqualTo("1");
            assertThat(metaString(tab391, "schema_version")).isEqualTo("1");
            assertThat(objectMap(tab385.get("meta")).containsKey("export_id")).isFalse();
            assertThat(objectMap(tab391.get("meta")).containsKey("identity_key")).isFalse();
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void buildDocument_survivesMalformedRequestAccessors_byFallingBackToRawRequestLine() {
        try {
            HttpRequest request = mock(HttpRequest.class);
            HttpResponse response = mock(HttpResponse.class);
            HttpService service = mock(HttpService.class);
            HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
            ByteArray requestBytes = mock(ByteArray.class);
            ByteArray responseBytes = mock(ByteArray.class);

            when(requestResponse.request()).thenReturn(request);
            when(requestResponse.response()).thenReturn(response);
            when(requestResponse.httpService()).thenReturn(service);
            when(service.host()).thenReturn("example.test");
            when(service.port()).thenReturn(443);
            when(service.secure()).thenReturn(true);

            when(request.url()).thenThrow(new IllegalArgumentException("URL is invalid."));
            when(request.method()).thenThrow(new IllegalArgumentException("URL is invalid."));
            when(request.path()).thenThrow(new IllegalArgumentException("URL is invalid."));
            when(request.pathWithoutQuery()).thenThrow(new IllegalArgumentException("URL is invalid."));
            when(request.query()).thenThrow(new IllegalArgumentException("URL is invalid."));
            when(request.fileExtension()).thenThrow(new IllegalArgumentException("URL is invalid."));
            when(request.httpVersion()).thenThrow(new IllegalArgumentException("URL is invalid."));
            when(request.headers()).thenReturn(java.util.List.of());
            when(request.parameters()).thenReturn(java.util.List.of());
            when(request.body()).thenReturn(null);
            when(request.bodyOffset()).thenReturn(0);
            when(request.markers()).thenReturn(java.util.List.of());
            when(request.contentType()).thenReturn(null);
            when(requestBytes.getBytes()).thenReturn(
                    "POST /fallback/path?q=1 HTTP/2\r\nHost: example.test\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            when(request.toByteArray()).thenReturn(requestBytes);
            when(requestResponse.annotations()).thenReturn(null);

            when(response.statusCode()).thenReturn((short) 200);
            when(response.reasonPhrase()).thenReturn("OK");
            when(response.httpVersion()).thenReturn("HTTP/1.1");
            when(response.headers()).thenReturn(java.util.List.of());
            when(response.cookies()).thenReturn(java.util.List.of());
            when(response.mimeType()).thenReturn(null);
            when(response.body()).thenReturn(null);
            when(response.bodyOffset()).thenReturn(0);
            when(response.markers()).thenReturn(java.util.List.of());
            when(responseBytes.getBytes()).thenReturn("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            when(response.toByteArray()).thenReturn(responseBytes);

            Map<String, Object> document = objectMap(callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildDocument",
                    requestResponse,
                    "FallbackTab",
                    null));

            assertThat(burpRepeater(document)).containsEntry("tab_name", "FallbackTab");

            Map<String, Object> requestDoc = objectMap(document.get("request"));
            assertThat(objectMap(requestDoc.get("url")).get("raw"))
                    .isEqualTo("https://example.test/fallback/path?q=1");
            assertThat(requestDoc.get("method")).isEqualTo("POST");
            Map<String, Object> path = objectMap(requestDoc.get("path"));
            assertThat(path.get("with_query")).isEqualTo("/fallback/path?q=1");
            assertThat(path.get("without_query")).isEqualTo("/fallback/path");
            assertThat(path.get("query")).isEqualTo("q=1");
            Map<String, Object> protocol = objectMap(requestDoc.get("protocol"));
            assertThat(protocol.get("http_version")).isEqualTo("HTTP/2");
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void currentRepeaterTabMetadata_prefersAnchorOverStaleStartupSelection() throws Exception {
        try {
            Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
            startupSelectionField.setAccessible(true);
            startupSelectionField.set(null, repeaterTabMetadata("383", "myOtherRepeaterGroup", "slot-383"));

            JTabbedPane pane = new JTabbedPane();
            JPanel tabTwo = new JPanel();
            JPanel tabThree = new JPanel();
            JPanel anchor = new JPanel();
            tabTwo.add(anchor);
            pane.addTab("2", tabTwo);
            pane.addTab("3", tabThree);
            pane.setSelectedIndex(0);

            Object[] resultHolder = new Object[1];
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Method method = RepeaterTabsIndexReporter.class.getDeclaredMethod(
                            "currentRepeaterTabMetadata",
                            java.awt.Component.class);
                    method.setAccessible(true);
                    resultHolder[0] = method.invoke(null, anchor);
                } catch (ReflectiveOperationException e) {
                    throw new RuntimeException(e);
                }
            });

            Object metadata = resultHolder[0];
            Method tabName = metadata.getClass().getDeclaredMethod("tabName");
            tabName.setAccessible(true);
            Method groupName = metadata.getClass().getDeclaredMethod("groupName");
            groupName.setAccessible(true);

            assertThat(tabName.invoke(metadata)).isEqualTo("2");
            assertThat(groupName.invoke(metadata)).isNull();
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
            Field startupSelectionField = RepeaterTabsIndexReporter.class.getDeclaredField("currentStartupSelectionMetadata");
            startupSelectionField.setAccessible(true);
            startupSelectionField.set(null, null);
        }
    }

    @Test
    void inferRepeaterGroupName_usesNearestPaneGroupForNumericLeafTabs() throws Exception {
        try {
            JTabbedPane pane = new JTabbedPane();
            pane.addTab("2", new JPanel());
            pane.addTab("myRepeaterGroup", new JPanel());
            pane.addTab("3", new JPanel());
            pane.addTab("382", new JPanel());
            pane.addTab("myOtherRepeaterGroup", new JPanel());
            pane.addTab("383", new JPanel());

            SwingUtilities.invokeAndWait(() -> {
                pane.setTabComponentAt(1, groupHeader("myRepeaterGroup", "2"));
                pane.setTabComponentAt(4, groupHeader("myOtherRepeaterGroup", "1"));

                pane.setSelectedIndex(0);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("2");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();

                pane.setSelectedIndex(2);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("3");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane))
                        .isEqualTo("myRepeaterGroup");

                pane.setSelectedIndex(3);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("382");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane))
                        .isEqualTo("myRepeaterGroup");

                pane.setSelectedIndex(5);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("383");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane))
                        .isEqualTo("myOtherRepeaterGroup");
            });
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void inferRepeaterGroupName_usesNearestPaneGroupForNamedLeafTabs() throws Exception {
        try {
            JTabbedPane pane = new JTabbedPane();
            pane.addTab("myStandAloneTab", new JPanel());
            pane.addTab("myRepeaterGroupOne", new JPanel());
            pane.addTab("myRepeaterGroupOneTabOne", new JPanel());
            pane.addTab("myRepeaterGroupOneTabTwo", new JPanel());
            pane.addTab("myRepeaterGroupTwo", new JPanel());
            pane.addTab("myRepeaterGroupTwoTabOne", new JPanel());

            SwingUtilities.invokeAndWait(() -> {
                pane.setTabComponentAt(1, groupHeader("myRepeaterGroupOne", "2"));
                pane.setTabComponentAt(4, groupHeader("myRepeaterGroupTwo", "1"));

                pane.setSelectedIndex(0);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane))
                        .isEqualTo("myStandAloneTab");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();

                pane.setSelectedIndex(2);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane))
                        .isEqualTo("myRepeaterGroupOneTabOne");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane))
                        .isEqualTo("myRepeaterGroupOne");

                pane.setSelectedIndex(3);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane))
                        .isEqualTo("myRepeaterGroupOneTabTwo");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane))
                        .isEqualTo("myRepeaterGroupOne");

                pane.setSelectedIndex(5);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane))
                        .isEqualTo("myRepeaterGroupTwoTabOne");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane))
                        .isEqualTo("myRepeaterGroupTwo");
            });
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void inferRepeaterGroupName_returnsNull_whenRepeatedSiblingLabelCouldBeTabNotGroup() throws Exception {
        try {
            JTabbedPane pane = new JTabbedPane();
            pane.addTab("DeletePiggybank", new JPanel());
            pane.addTab("149", new JPanel());
            pane.addTab("150", new JPanel());
            pane.addTab("DeletePiggybank", new JPanel());
            pane.addTab("151", new JPanel());
            pane.addTab("DeletePiggybank", new JPanel());

            SwingUtilities.invokeAndWait(() -> {
                pane.setSelectedIndex(4);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("151");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();
            });
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void inferRepeaterGroupName_returnsNull_whenSinglePrefixedSiblingLooksLikeStandaloneTab() throws Exception {
        try {
            JTabbedPane pane = new JTabbedPane();
            pane.addTab("DeletePiggy", new JPanel());
            pane.addTab("DeletePiggybank", new JPanel());
            pane.addTab("151", new JPanel());

            SwingUtilities.invokeAndWait(() -> {
                pane.setSelectedIndex(1);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("DeletePiggybank");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();
            });
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void inferRepeaterGroupName_stopsAtExplicitHeaderCountBoundary() throws Exception {
        try {
            JTabbedPane pane = new JTabbedPane();
            pane.addTab("Findings", new JPanel());
            pane.addTab("SensitiveContentInUrl", new JPanel());
            pane.addTab("CAPTCHARemoved", new JPanel());
            pane.addTab("Web-InaccurateBalance", new JPanel());
            pane.addTab("Mobile-AccurateBalance", new JPanel());
            pane.addTab("CardNumber-Invalid", new JPanel());
            pane.addTab("1", new JPanel());
            pane.addTab("2", new JPanel());
            pane.addTab("3", new JPanel());
            pane.addTab("4", new JPanel());

            SwingUtilities.invokeAndWait(() -> {
                pane.setTabComponentAt(0, groupHeader("Findings", "5"));

                pane.setSelectedIndex(1);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isEqualTo("Findings");

                pane.setSelectedIndex(5);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isEqualTo("Findings");

                pane.setSelectedIndex(6);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();

                pane.setSelectedIndex(9);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();
            });
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void inferRepeaterGroupName_returnsNull_whenStandaloneNamedTabHasNoExplicitGroupMarker() throws Exception {
        try {
            JTabbedPane pane = new JTabbedPane();
            pane.addTab("Web-Update", new JPanel());
            pane.addTab("72", new JPanel());
            pane.addTab("73", new JPanel());

            SwingUtilities.invokeAndWait(() -> {
                pane.setSelectedIndex(1);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("72");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();

                pane.setSelectedIndex(2);
                assertThat(RepeaterTabsIndexReporter.inferRepeaterTabName(pane)).isEqualTo("73");
                assertThat(RepeaterTabsIndexReporter.inferRepeaterGroupName(pane)).isNull();
            });
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void inferRepeaterTabMetadata_treatsSingleStandaloneCandidateAsTabName_whenPrimaryMissing()
            throws Exception {
        try {
            Method method = RepeaterTabsIndexReporter.class.getDeclaredMethod(
                    "inferRepeaterTabMetadata",
                    java.util.List.class,
                    String.class);
            method.setAccessible(true);

            Object snapshot = selectedTabSnapshot(
                    null,
                    java.util.List.of("myStandAloneTab"),
                    java.util.List.of("myStandAloneTab"),
                    java.util.List.of(),
                    java.util.List.of(),
                    "burp.Zr4u",
                    0,
                    1);

            Object metadata = method.invoke(null, java.util.List.of(snapshot), "burp.Zr4u");
            Method tabName = metadata.getClass().getDeclaredMethod("tabName");
            tabName.setAccessible(true);
            Method groupName = metadata.getClass().getDeclaredMethod("groupName");
            groupName.setAccessible(true);

            assertThat(tabName.invoke(metadata)).isEqualTo("myStandAloneTab");
            assertThat(groupName.invoke(metadata)).isNull();
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    @Test
    void inferRepeaterTabMetadataFromAnchor_ignoresAuxiliaryNestedTabsInSlotIdentity() throws Exception {
        try {
            JTabbedPane outerPane = new JTabbedPane();
            JPanel standalone = new JPanel();
            JPanel groupedTab = new JPanel();
            JTabbedPane messageViewTabs = new JTabbedPane();
            messageViewTabs.addTab("Inspector", new JPanel());
            messageViewTabs.addTab("Notes", new JPanel());
            messageViewTabs.addTab("Explanations", new JPanel());
            JPanel customActions = new JPanel();
            JPanel anchor = new JPanel();
            customActions.add(anchor);
            messageViewTabs.addTab("Custom actions", customActions);
            messageViewTabs.setSelectedIndex(3);
            groupedTab.add(messageViewTabs);
            outerPane.addTab("myStandAloneTab", standalone);
            outerPane.addTab("myRepeaterGroupTwoTabOne", groupedTab);
            outerPane.setSelectedIndex(1);

            Object[] metadataHolder = new Object[1];
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Method method = RepeaterTabsIndexReporter.class.getDeclaredMethod(
                            "inferRepeaterTabMetadataFromAnchor",
                            java.awt.Component.class);
                    method.setAccessible(true);
                    metadataHolder[0] = method.invoke(null, anchor);
                } catch (ReflectiveOperationException e) {
                    throw new RuntimeException(e);
                }
            });

            Object metadata = metadataHolder[0];
            Method slotIdentityKey = metadata.getClass().getDeclaredMethod("slotIdentityKey");
            slotIdentityKey.setAccessible(true);
            Method tabName = metadata.getClass().getDeclaredMethod("tabName");
            tabName.setAccessible(true);

            assertThat(slotIdentityKey.invoke(metadata)).isEqualTo("javax.swing.JTabbedPane#1");
            assertThat(tabName.invoke(metadata)).isEqualTo("myRepeaterGroupTwoTabOne");
        } finally {
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    private static HttpRequestResponse repeaterRequestResponse(String rawRequest) {
        HttpRequest request = mock(HttpRequest.class);
        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn(rawRequest.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);
        when(requestResponse.copyToTempFile()).thenReturn(requestResponse);
        return requestResponse;
    }

    private static HttpRequestResponse repeaterRequestResponseWithResponse(String rawRequest, String rawResponse) {
        HttpRequestResponse requestResponse = repeaterRequestResponse(rawRequest);
        HttpResponse response = mock(HttpResponse.class);
        ByteArray responseBytes = mock(ByteArray.class);
        when(responseBytes.getBytes()).thenReturn(rawResponse.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(response.toByteArray()).thenReturn(responseBytes);
        when(requestResponse.response()).thenReturn(response);
        return requestResponse;
    }

    private static HttpRequestResponse scopedRepeaterRequestResponse(String url) {
        URI uri = URI.create(url);
        String query = uri.getQuery() == null ? "" : uri.getQuery();
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        String pathWithQuery = query.isBlank() ? path : path + "?" + query;

        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(url);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn(pathWithQuery);
        when(request.pathWithoutQuery()).thenReturn(path);
        when(request.query()).thenReturn(query);
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn(uri.getHost());
        when(service.port()).thenReturn(uri.getPort() < 0 ? 443 : uri.getPort());
        when(service.secure()).thenReturn("https".equalsIgnoreCase(uri.getScheme()));

        HttpResponse response = mock(HttpResponse.class);
        ByteArray responseBytes = mock(ByteArray.class);
        when(responseBytes.getBytes()).thenReturn("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(response.toByteArray()).thenReturn(responseBytes);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);
        when(requestResponse.response()).thenReturn(response);
        when(requestResponse.httpService()).thenReturn(service);
        when(requestResponse.annotations()).thenReturn(null);
        when(requestResponse.copyToTempFile()).thenReturn(requestResponse);
        return requestResponse;
    }

    private static Object repeaterTabMetadata(
            String tabName,
            String groupName,
            String slotIdentityKey) throws Exception {
        Class<?> metadataClass = Class.forName(
                "ai.anomalousvectors.tools.burp.sinks.RepeaterTabsIndexReporter$RepeaterTabMetadata");
        Constructor<?> constructor = metadataClass.getDeclaredConstructor(
                String.class,
                String.class,
                String.class,
                String.class);
        constructor.setAccessible(true);
        return constructor.newInstance(
                tabName,
                groupName,
                "test-root",
                slotIdentityKey);
    }

    private static Object selectedTabSnapshot(
            String primaryLabel,
            java.util.List<String> candidateLabels,
            java.util.List<String> paneCandidateLabels,
            java.util.List<Object> paneTabs,
            java.util.List<String> panePrimaryLabels,
            String paneClass,
            int selectedIndex,
            int tabCount) throws Exception {
        Class<?> snapshotClass = Class.forName(
                "ai.anomalousvectors.tools.burp.sinks.RepeaterTabMetadataHeuristics$SelectedTabSnapshot");
        Constructor<?> constructor = snapshotClass.getDeclaredConstructor(
                String.class,
                java.util.List.class,
                java.util.List.class,
                java.util.List.class,
                java.util.List.class,
                String.class,
                int.class,
                int.class);
        constructor.setAccessible(true);
        return constructor.newInstance(
                primaryLabel,
                candidateLabels,
                paneCandidateLabels,
                paneTabs,
                panePrimaryLabels,
                paneClass,
                selectedIndex,
                tabCount);
    }

    private static JPanel groupHeader(String groupName, String childCount) {
        JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        header.add(new JLabel(groupName));
        header.add(new JLabel(childCount));
        return header;
    }

    private static Map<String, Object> burpRepeater(Map<String, Object> doc) {
        return objectMap(objectMap(doc.get("burp")).get("repeater"));
    }

    private static Map<String, Object> objectMap(Object value) {
        if (!(value instanceof Map<?, ?> source)) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                out.put(key, entry.getValue());
            }
        }
        return out;
    }

    private static String metaString(Map<String, Object> doc, String key) {
        return String.valueOf(objectMap(doc.get("meta")).get(key));
    }
}
