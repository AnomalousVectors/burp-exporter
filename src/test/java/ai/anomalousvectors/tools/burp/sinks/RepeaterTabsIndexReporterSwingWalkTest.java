package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;

class RepeaterTabsIndexReporterSwingWalkTest {

    @Test
    void inferRepeaterTabName_returnsSelectedTabLabel_whenGroupedHeaderAlsoContainsGroupName() throws Exception {
        AtomicReference<String> tabNameRef = new AtomicReference<>();
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane groupedTabs = new JTabbedPane();
            groupedTabs.addTab("2", new JPanel());
            groupedTabs.addTab("3", new JPanel());
            groupedTabs.setSelectedIndex(0);

            JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            tabHeader.add(new JLabel("myRepeaterGroup"));
            tabHeader.add(new JLabel("2"));
            tabHeader.add(new JLabel("3"));
            tabHeader.add(new JLabel("382"));
            JButton closeButton = new JButton();
            closeButton.setName("tabbedPaneTabCloseButton");
            tabHeader.add(closeButton);
            groupedTabs.setTabComponentAt(0, tabHeader);

            JTabbedPane auxiliaryTabs = new JTabbedPane();
            auxiliaryTabs.addTab("Inspector", new JPanel());
            auxiliaryTabs.addTab("Custom actions", new JPanel());
            auxiliaryTabs.setSelectedIndex(0);

            JPanel selectedTabBody = new JPanel(new BorderLayout());
            selectedTabBody.add(auxiliaryTabs, BorderLayout.CENTER);
            groupedTabs.setComponentAt(0, selectedTabBody);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(groupedTabs, BorderLayout.CENTER);

            tabNameRef.set(RepeaterTabsIndexReporter.inferRepeaterTabName(repeaterRoot));
            groupNameRef.set(RepeaterTabsIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(tabNameRef.get()).isEqualTo("2");
        assertThat(groupNameRef.get()).isEqualTo("myRepeaterGroup");
    }

    @Test
    void inferRepeaterGroupName_usesSiblingPaneTitle_whenBurpStoresGroupOutsideSelectedHeader() throws Exception {
        AtomicReference<String> tabNameRef = new AtomicReference<>();
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane groupedTabs = new JTabbedPane();
            groupedTabs.addTab("myRepeaterGroup", new JPanel());
            groupedTabs.addTab("2", new JPanel());
            groupedTabs.addTab("382", new JPanel());
            groupedTabs.setSelectedIndex(1);
            groupedTabs.setTabComponentAt(0, groupHeader("myRepeaterGroup", "2"));
            groupedTabs.setTabComponentAt(1, new JLabel("2"));
            groupedTabs.setTabComponentAt(2, new JLabel("382"));

            JTabbedPane auxiliaryTabs = new JTabbedPane();
            auxiliaryTabs.addTab("Inspector", new JPanel());
            auxiliaryTabs.addTab("Custom actions", new JPanel());
            auxiliaryTabs.setSelectedIndex(0);

            JPanel selectedTabBody = new JPanel(new BorderLayout());
            selectedTabBody.add(auxiliaryTabs, BorderLayout.CENTER);
            groupedTabs.setComponentAt(1, selectedTabBody);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(groupedTabs, BorderLayout.CENTER);

            tabNameRef.set(RepeaterTabsIndexReporter.inferRepeaterTabName(repeaterRoot));
            groupNameRef.set(RepeaterTabsIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(tabNameRef.get()).isEqualTo("2");
        assertThat(groupNameRef.get()).isEqualTo("myRepeaterGroup");
    }

    @Test
    void inferRepeaterGroupName_returnsSelectedOuterTabLabel_whenGrouped() throws Exception {
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane responseTabs = new JTabbedPane();
            responseTabs.addTab("Raw", new JPanel());
            responseTabs.addTab("Pretty", new JPanel());

            JTabbedPane groupedRequests = new JTabbedPane();
            groupedRequests.addTab("Req A", new JPanel());
            JPanel groupedRequestView = new JPanel(new BorderLayout());
            groupedRequestView.add(responseTabs, BorderLayout.CENTER);
            groupedRequests.addTab("Req B", groupedRequestView);
            groupedRequests.setSelectedIndex(1);

            JTabbedPane groupTabs = new JTabbedPane();
            groupTabs.addTab("Group Alpha", groupedRequests);
            groupTabs.addTab("Group Beta", new JPanel());
            groupTabs.setSelectedIndex(0);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(groupTabs, BorderLayout.CENTER);

            groupNameRef.set(RepeaterTabsIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(groupNameRef.get()).isEqualTo("Group Alpha");
    }

    @Test
    void inferRepeaterTabName_returnsSelectedTabLabel_whenNoGroupContainerExists() throws Exception {
        AtomicReference<String> tabNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("Req A", new JPanel());
            repeaterTabs.addTab("Req B", new JPanel());
            repeaterTabs.setSelectedIndex(1);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            tabNameRef.set(RepeaterTabsIndexReporter.inferRepeaterTabName(repeaterRoot));
        });

        assertThat(tabNameRef.get()).isEqualTo("Req B");
    }

    @Test
    void inferRepeaterGroupName_returnsNull_whenNoGroupContainerExists() throws Exception {
        AtomicReference<String> groupNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("Req A", new JPanel());
            repeaterTabs.addTab("Req B", new JPanel());
            repeaterTabs.setSelectedIndex(1);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            groupNameRef.set(RepeaterTabsIndexReporter.inferRepeaterGroupName(repeaterRoot));
        });

        assertThat(groupNameRef.get()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Inspector", "Notes", "Explanations", "Custom actions"})
    void inferRepeaterTabName_ignoresRightRailMessageViewSelection(String selectedRailTab) throws Exception {
        AtomicReference<String> tabNameRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane messageViewTabs = new JTabbedPane();
            messageViewTabs.addTab("Inspector", new JPanel());
            messageViewTabs.addTab("Notes", new JPanel());
            messageViewTabs.addTab("Explanations", new JPanel());
            messageViewTabs.addTab("Custom actions", new JPanel());
            for (int i = 0; i < messageViewTabs.getTabCount(); i++) {
                if (selectedRailTab.equals(messageViewTabs.getTitleAt(i))) {
                    messageViewTabs.setSelectedIndex(i);
                    break;
                }
            }

            JPanel requestTabBody = new JPanel(new BorderLayout());
            requestTabBody.add(messageViewTabs, BorderLayout.CENTER);

            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("GetGateway", requestTabBody);
            repeaterTabs.addTab("385", new JPanel());
            repeaterTabs.setSelectedIndex(0);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            tabNameRef.set(RepeaterTabsIndexReporter.inferRepeaterTabName(repeaterRoot));
        });

        assertThat(tabNameRef.get()).isEqualTo("GetGateway");
    }

    @Test
    void performStartupTabWalk_doesNotCycleRightRailMessageViewTabs() throws Exception {
        AtomicReference<RepeaterTabsIndexReporter.StartupTabWalkResult> resultRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> messageViewTabsRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane messageViewTabs = new JTabbedPane();
            messageViewTabs.addTab("Inspector", new JPanel());
            messageViewTabs.addTab("Notes", new JPanel());
            messageViewTabs.addTab("Explanations", new JPanel());
            messageViewTabs.addTab("Custom actions", new JPanel());
            messageViewTabs.setSelectedIndex(3);

            JPanel requestTabBody = new JPanel(new BorderLayout());
            requestTabBody.add(messageViewTabs, BorderLayout.CENTER);

            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("GetGateway", requestTabBody);
            repeaterTabs.addTab("385", new JPanel());
            repeaterTabs.setSelectedIndex(0);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            JTabbedPane toolTabs = new JTabbedPane();
            toolTabs.addTab("Dashboard", new JPanel());
            toolTabs.addTab("Repeater", repeaterRoot);
            toolTabs.setSelectedIndex(0);

            JPanel root = new JPanel(new BorderLayout());
            root.add(toolTabs, BorderLayout.CENTER);

            resultRef.set(RepeaterTabsIndexReporter.performStartupTabWalk(List.of(root)));
            messageViewTabsRef.set(messageViewTabs);
        });

        assertThat(resultRef.get().tabbedPaneCount()).isEqualTo(1);
        assertThat(messageViewTabsRef.get().getSelectedIndex()).isEqualTo(3);
    }

    @Test
    void startupTabWalkPlan_oneStepPerRequestTab_notPerDescendantEditorTab() throws Exception {
        AtomicInteger stepCountRef = new AtomicInteger();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane messageViewTabs = new JTabbedPane();
            messageViewTabs.addTab("Inspector", new JPanel());
            messageViewTabs.addTab("Notes", new JPanel());
            messageViewTabs.addTab("Explanations", new JPanel());
            messageViewTabs.addTab("Custom actions", new JPanel());

            JTabbedPane jsonViewerTabs = new JTabbedPane();
            jsonViewerTabs.addTab("JSON", new JPanel());
            jsonViewerTabs.addTab("Tree", new JPanel());

            JTabbedPane hackvertorTabs = new JTabbedPane();
            hackvertorTabs.addTab("Encode", jsonViewerTabs);
            hackvertorTabs.addTab("Decode", new JPanel());

            JPanel requestTabBody = new JPanel(new BorderLayout());
            requestTabBody.add(messageViewTabs, BorderLayout.WEST);
            requestTabBody.add(hackvertorTabs, BorderLayout.CENTER);

            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("GetGateway", requestTabBody);
            repeaterTabs.addTab("385", new JPanel());
            repeaterTabs.addTab("386", new JPanel());

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            JTabbedPane toolTabs = new JTabbedPane();
            toolTabs.addTab("Dashboard", new JPanel());
            toolTabs.addTab("Repeater", repeaterRoot);

            JPanel root = new JPanel(new BorderLayout());
            root.add(toolTabs, BorderLayout.CENTER);

            Object repeaterLocation = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "findToolTabLocation",
                    List.of(root),
                    "Repeater");
            Object plan = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildStartupTabWalkPlan",
                    repeaterLocation);
            List<?> steps = get(plan, "steps", List.class);
            stepCountRef.set(steps.size());
        });

        assertThat(stepCountRef.get()).isEqualTo(3);
    }

    @Test
    void startupTabWalkPlan_keepsTopLevelSlotKeysStable_whenDescendantEditorsRebuild() throws Exception {
        AtomicReference<List<String>> firstSlotsRef = new AtomicReference<>();
        AtomicReference<List<String>> secondSlotsRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("GetModels", editorBody("Hackvertor", "Encode", "Decode"));
            repeaterTabs.addTab("2", editorBody("JSON Viewer", "JSON", "Tree"));
            repeaterTabs.addTab("3", editorBody("Hackvertor", "Encode", "Fake"));

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            JTabbedPane toolTabs = new JTabbedPane();
            toolTabs.addTab("Dashboard", new JPanel());
            toolTabs.addTab("Repeater", repeaterRoot);

            JPanel root = new JPanel(new BorderLayout());
            root.add(toolTabs, BorderLayout.CENTER);

            Object repeaterLocation = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "findToolTabLocation",
                    List.of(root),
                    "Repeater");
            Object firstPlan = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildStartupTabWalkPlan",
                    repeaterLocation);
            firstSlotsRef.set(planSlotKeys(firstPlan));

            repeaterTabs.setComponentAt(1, editorBody("Different Extension", "One", "Two"));
            Object secondPlan = callStatic(
                    RepeaterTabsIndexReporter.class,
                    "buildStartupTabWalkPlan",
                    repeaterLocation);
            secondSlotsRef.set(planSlotKeys(secondPlan));
        });

        assertThat(firstSlotsRef.get())
                .containsExactly(
                        "top-level:0:javax.swing.JTabbedPane#1",
                        "top-level:0:javax.swing.JTabbedPane#2",
                        "top-level:0:javax.swing.JTabbedPane#0");
        assertThat(secondSlotsRef.get()).containsExactlyElementsOf(firstSlotsRef.get());
    }

    @Test
    void performStartupTabWalk_capturesOnlyThreeTopLevelTabs_withThirdPartyEditorTabs() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        boolean previousRunning = RuntimeConfig.isExportRunning();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
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
                    List.of("repeater_tabs"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                    ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                    null));
            RuntimeConfig.setExportRunning(true);
            RepeaterTabsIndexReporter.clearSessionState();
            RepeaterTabsIndexReporter.openCaptureWindowForCurrentRun();

            EditorCreationContext context = mock(EditorCreationContext.class);
            ToolSource toolSource = mock(ToolSource.class);
            when(context.toolSource()).thenReturn(toolSource);
            when(toolSource.toolType()).thenReturn(ToolType.REPEATER);

            List<HttpRequestResponse> topLevelMessages = List.of(
                    requestResponse("GetModels"),
                    requestResponse("2"),
                    requestResponse("3"));
            List<HttpRequestResponse> nestedMessages = List.of(
                    requestResponse("nested-get-models"),
                    requestResponse("nested-2"),
                    requestResponse("nested-3"));

            TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
                SwingUtilities.invokeAndWait(() -> {
                        JTabbedPane repeaterTabs = new JTabbedPane();
                        List<JPanel> topLevelBodies = new ArrayList<>();
                        for (int index = 0; index < topLevelMessages.size(); index++) {
                            JTabbedPane extensionTabs = new JTabbedPane();
                            JPanel firstExtensionTab = new JPanel();
                            JPanel secondExtensionTab = new JPanel();
                            extensionTabs.addTab("Encode", firstExtensionTab);
                            extensionTabs.addTab("JSON Viewer", secondExtensionTab);
                            int messageIndex = index;
                            extensionTabs.addChangeListener(ignored ->
                                    RepeaterTabsIndexReporter.captureFromEditorContext(
                                            context,
                                            nestedMessages.get(messageIndex),
                                            "request_editor",
                                            extensionTabs.getSelectedComponent()));

                            JPanel body = new JPanel(new BorderLayout());
                            body.add(extensionTabs, BorderLayout.CENTER);
                            topLevelBodies.add(body);
                        }
                        repeaterTabs.addTab("GetModels", topLevelBodies.get(0));
                        repeaterTabs.addTab("2", topLevelBodies.get(1));
                        repeaterTabs.addTab("3", topLevelBodies.get(2));
                        repeaterTabs.setSelectedIndex(0);
                        repeaterTabs.addChangeListener(ignored -> {
                            int selectedIndex = repeaterTabs.getSelectedIndex();
                            RepeaterTabsIndexReporter.captureFromEditorContext(
                                    context,
                                    topLevelMessages.get(selectedIndex),
                                    "request_editor",
                                    topLevelBodies.get(selectedIndex));
                        });

                        JPanel repeaterRoot = new JPanel(new BorderLayout());
                        repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);
                        JTabbedPane toolTabs = new JTabbedPane();
                        toolTabs.addTab("Dashboard", new JPanel());
                        toolTabs.addTab("Repeater", repeaterRoot);
                        JPanel root = new JPanel(new BorderLayout());
                        root.add(toolTabs, BorderLayout.CENTER);

                        RepeaterTabsIndexReporter.StartupTabWalkResult result =
                                RepeaterTabsIndexReporter.performStartupTabWalk(List.of(root));

                    assertThat(result.tabbedPaneCount()).isEqualTo(1);
                });
                RepeaterTabsIndexReporter.pushSnapshotNow();
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(3);
            });

            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(3);
            assertThat(capturedKeys())
                    .containsExactlyInAnyOrder(
                            "slot:top-level:0:javax.swing.JTabbedPane#0",
                            "slot:top-level:0:javax.swing.JTabbedPane#1",
                            "slot:top-level:0:javax.swing.JTabbedPane#2");
        } finally {
            RepeaterTabsIndexReporter.closeCaptureWindowForCurrentRun();
            RuntimeConfig.setExportRunning(previousRunning);
            RuntimeConfig.updateState(previousState);
            RepeaterTabsIndexReporter.clearSessionState();
            TrafficExportQueue.stopWorker();
            TrafficExportQueue.clearPendingWork();
        }
    }

    @Test
    void performStartupTabWalk_visitsRepeaterToolTree_andRestoresSelections() throws Exception {
        AtomicReference<RepeaterTabsIndexReporter.StartupTabWalkResult> resultRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> toolTabsRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> repeaterTabsRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> responseTabsRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane responseTabs = new JTabbedPane();
            responseTabs.addTab("Raw", new JPanel());
            responseTabs.addTab("Pretty", new JPanel());
            responseTabs.setSelectedIndex(1);

            JPanel secondRepeaterTab = new JPanel(new BorderLayout());
            secondRepeaterTab.add(responseTabs, BorderLayout.CENTER);

            JTabbedPane repeaterTabs = new JTabbedPane();
            repeaterTabs.addTab("Req A", new JPanel());
            repeaterTabs.addTab("Req B", secondRepeaterTab);
            repeaterTabs.addTab("Req C", new JPanel());
            repeaterTabs.setSelectedIndex(2);

            JPanel repeaterRoot = new JPanel(new BorderLayout());
            repeaterRoot.add(repeaterTabs, BorderLayout.CENTER);

            JTabbedPane toolTabs = new JTabbedPane();
            toolTabs.addTab("Dashboard", new JPanel());
            toolTabs.addTab("Repeater", repeaterRoot);
            toolTabs.addTab("Proxy", new JPanel());
            toolTabs.setSelectedIndex(0);

            JPanel root = new JPanel(new BorderLayout());
            root.add(toolTabs, BorderLayout.CENTER);

            resultRef.set(RepeaterTabsIndexReporter.performStartupTabWalk(List.of(root)));
            toolTabsRef.set(toolTabs);
            repeaterTabsRef.set(repeaterTabs);
            responseTabsRef.set(responseTabs);
        });

        RepeaterTabsIndexReporter.StartupTabWalkResult result = resultRef.get();
        assertThat(result.locatedRepeaterToolTab()).isTrue();
        assertThat(result.tabbedPaneCount()).isEqualTo(1);
        assertThat(result.selectionChangeCount()).isEqualTo(4);
        assertThat(toolTabsRef.get().getSelectedIndex()).isEqualTo(0);
        assertThat(repeaterTabsRef.get().getSelectedIndex()).isEqualTo(2);
        assertThat(responseTabsRef.get().getSelectedIndex()).isEqualTo(1);
    }

    @Test
    void performStartupTabWalk_returnsNotLocated_whenRepeaterToolTabMissing() throws Exception {
        AtomicReference<RepeaterTabsIndexReporter.StartupTabWalkResult> resultRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane toolTabs = new JTabbedPane();
            toolTabs.addTab("Dashboard", new JPanel());
            toolTabs.addTab("Proxy", new JPanel());

            JPanel root = new JPanel(new BorderLayout());
            root.add(toolTabs, BorderLayout.CENTER);

            resultRef.set(RepeaterTabsIndexReporter.performStartupTabWalk(List.of(root)));
        });

        RepeaterTabsIndexReporter.StartupTabWalkResult result = resultRef.get();
        assertThat(result.locatedRepeaterToolTab()).isFalse();
        assertThat(result.tabbedPaneCount()).isZero();
        assertThat(result.selectionChangeCount()).isZero();
    }

    private static JPanel groupHeader(String groupName, String childCount) {
        JPanel tabHeader = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        tabHeader.add(new JLabel(groupName));
        tabHeader.add(new JLabel(childCount));
        return tabHeader;
    }

    private static JPanel editorBody(String paneTitle, String firstTab, String secondTab) {
        JTabbedPane editorTabs = new JTabbedPane();
        editorTabs.setName(paneTitle);
        editorTabs.addTab(firstTab, new JPanel());
        editorTabs.addTab(secondTab, new JPanel());
        JPanel body = new JPanel(new BorderLayout());
        body.add(editorTabs, BorderLayout.CENTER);
        return body;
    }

    private static List<String> planSlotKeys(Object plan) {
        List<?> steps = get(plan, "steps", List.class);
        return steps.stream()
                .map(step -> get(step, "metadata", Object.class))
                .map(metadata -> get(metadata, "slotIdentityKey", String.class))
                .toList();
    }

    private static List<String> capturedKeys() {
        java.util.Map<?, ?> captured = getStatic(
                RepeaterTabsIndexReporter.class,
                "CAPTURED",
                java.util.Map.class);
        return captured.keySet().stream().map(String::valueOf).toList();
    }

    private static HttpRequestResponse requestResponse(String marker) {
        HttpRequest request = mock(HttpRequest.class);
        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn(("GET /" + marker
                        + " HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .getBytes(StandardCharsets.UTF_8));
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpResponse response = mock(HttpResponse.class);
        ByteArray responseBytes = mock(ByteArray.class);
        when(responseBytes.getBytes()).thenReturn(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        when(response.toByteArray()).thenReturn(responseBytes);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);
        when(requestResponse.response()).thenReturn(response);
        when(requestResponse.copyToTempFile()).thenReturn(requestResponse);
        return requestResponse;
    }
}
