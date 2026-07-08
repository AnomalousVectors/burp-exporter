package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.mapping.Property;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.GetMappingRequest;
import org.opensearch.client.opensearch.indices.GetMappingResponse;
import org.opensearch.client.opensearch.indices.RefreshRequest;

import static org.assertj.core.api.Assertions.assertThat;

import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.testutils.OpenSearchTestConfig;
import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getComboBox;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration test: when Start is clicked in ConfigPanel, indexes are created explicitly
 * (via createSelectedIndexes) before any documents are pushed. Uses real OpenSearch.
 * Verifies the findings index exists with explicit mapping (e.g. requests_responses nested)
 * and has at least one document after Start.
 */
@Tag("integration")
class ConfigPanelStartCreatesIndexesBeforePushIT {

    private static final String BASE_URL = OpenSearchReachable.BASE_URL;

    private static final class TestUi implements ConfigController.Ui {
        @Override public void onFileStatus(String m) { }
        @Override public void onDatabaseStatus(String m) { }
        @Override public void onControlStatus(String m) { }
    }

    private static String findingsIndexName() {
        return IndexNaming.indexNameForShortName("findings");
    }

    private ConfigPanel createPanel() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");

        deleteFindingsIndex();

        MontoyaApiProvider.set(mockMontoyaApiWithOneIssue());
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", true, BASE_URL, config.username(), config.password(), false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));

        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel p = new ConfigPanel(new ConfigController(new TestUi()));
            if (p.getWidth() <= 0 || p.getHeight() <= 0) {
                p.setSize(1000, 700);
            }
            p.doLayout();
            JTextField urlField = JTextField.class.cast(get(p, "openSearchUrlField"));
            urlField.setText(BASE_URL);
            javax.swing.AbstractButton osCheckbox = javax.swing.AbstractButton.class.cast(get(p, "openSearchSinkCheckbox"));
            if (!osCheckbox.isSelected()) osCheckbox.doClick();
            JCheckBox issuesCheckbox = JCheckBox.class.cast(get(p, "issuesCheckbox"));
            issuesCheckbox.setEnabled(true);
            if (!issuesCheckbox.isSelected()) issuesCheckbox.doClick();
            javax.swing.JComboBox<?> authCombo = getComboBox(p, "openSearchAuthTypeCombo");
            if (authCombo != null && config.username() != null && !config.username().isBlank()) {
                authCombo.setSelectedItem("Basic");
                JTextField userField = JTextField.class.cast(get(p, "openSearchUserField"));
                JTextField passField = JTextField.class.cast(get(p, "openSearchPasswordField"));
                if (userField != null) userField.setText(config.username());
                if (passField != null) passField.setText(config.password() != null ? config.password() : "");
            }
            ref.set(p);
        });
        return ref.get();
    }

    private void tearDown() {
        RuntimeConfig.setExportRunning(false);
        MontoyaApiProvider.set(null);
        deleteFindingsIndex();
    }

    @Test
    void start_click_createsFindingsIndexWithExplicitMapping_beforeDocsPushed() throws Exception {
        ConfigPanel panel = createPanel();
        try {
            JButton startStop = findByName(panel, "control.startStop", JButton.class);
            assertThat(startStop).as("Start button").isNotNull();
            JButton startButton = startStop;
            assertThat(startButton.getText()).isEqualTo("Start");

            SwingUtilities.invokeAndWait(startButton::doClick);
            SwingUtilities.invokeAndWait(() -> { /* flush EDT so deferred start action runs */ });

            awaitFindingsIndexWithAtLeastOneDoc();

            OpenSearchClient client = OpenSearchReachable.getClient();
            GetMappingResponse mappingResp = client.indices()
                    .getMapping(new GetMappingRequest.Builder().index(findingsIndexName()).build());
            assertThat(mappingResp.result()).containsKey(findingsIndexName());

            var indexMapping = mappingResp.result().get(findingsIndexName());
            assertThat(indexMapping).isNotNull();
            assertThat(indexMapping.mappings()).isNotNull();
            var properties = indexMapping.mappings().properties();
            assertThat(properties).as("explicit mapping").containsKey("requests_responses");
            Property reqRespProp = properties.get("requests_responses");
            assertThat(reqRespProp).isNotNull();
        } finally {
            tearDown();
        }
    }

    private static MontoyaApi mockMontoyaApiWithOneIssue() {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        HttpService httpService = mock(HttpService.class);
        BurpSuite burpSuite = mock(BurpSuite.class);
        Version version = mock(Version.class);

        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(api.burpSuite()).thenReturn(burpSuite);
        when(burpSuite.version()).thenReturn(version);
        when(version.edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL);
        when(scope.isInScope(anyString())).thenReturn(true);
        when(siteMap.issues()).thenReturn(List.of(issue));

        when(issue.name()).thenReturn("Test issue");
        when(issue.baseUrl()).thenReturn("https://example.com/");
        when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.httpService()).thenReturn(httpService);
        when(issue.detail()).thenReturn("Detail");
        when(issue.remediation()).thenReturn("Remediation");
        when(issue.definition()).thenReturn(definition);
        when(issue.requestResponses()).thenReturn(List.of());

        when(httpService.host()).thenReturn("example.com");
        when(httpService.port()).thenReturn(443);
        when(httpService.secure()).thenReturn(true);

        when(definition.typeIndex()).thenReturn(0);
        when(definition.typicalSeverity()).thenReturn(AuditIssueSeverity.HIGH);
        when(definition.background()).thenReturn("Background");
        when(definition.remediation()).thenReturn("Remediation");

        return api;
    }

    private void awaitFindingsIndexWithAtLeastOneDoc() {
        OpenSearchClient client = OpenSearchReachable.getClient();
        long deadline = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                client.indices().refresh(new RefreshRequest.Builder().index(findingsIndexName()).build());
                SearchResponse<?> resp = client.search(
                        new SearchRequest.Builder().index(findingsIndexName()).size(1).build(),
                        Object.class);
                if (resp.hits().hits().size() >= 1) {
                    return;
                }
            } catch (IOException | RuntimeException ignored) {
                // index may not exist yet
            }
            LockSupport.parkNanos(200_000_000L);
        }
        throw new AssertionError("Findings index did not get at least one document within 30s");
    }

    private static void deleteFindingsIndex() {
        try {
            OpenSearchClient client = OpenSearchReachable.getClient();
            client.indices().delete(new DeleteIndexRequest.Builder().index(findingsIndexName()).build());
        } catch (IOException | RuntimeException ignored) {
            // index may not exist
        }
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        if (type.isInstance(root)) {
            T typedRoot = type.cast(root);
            if (name.equals(typedRoot.getName())) {
                return typedRoot;
            }
        }
        for (Component c : root.getComponents()) {
            if (c instanceof Container cont) {
                T found = findByName(cont, name, type);
                if (found != null) return found;
            }
            if (type.isInstance(c)) {
                T typedComponent = type.cast(c);
                if (name.equals(typedComponent.getName())) {
                    return typedComponent;
                }
            }
        }
        return null;
    }
}
