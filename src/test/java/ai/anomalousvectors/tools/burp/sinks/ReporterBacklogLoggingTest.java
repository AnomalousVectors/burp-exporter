package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;

/**
 * Locks exact INFO backlog lines and completion semantics for reporters that export
 * historic backlogs at Start.
 */
class ReporterBacklogLoggingTest {

    private final List<String> infoMessages = new ArrayList<>();
    private final Logger.LogListener listener = (level, message) -> {
        if ("INFO".equals(level)) {
            infoMessages.add(message);
        }
    };

    @BeforeEach
    public void resetReportersBeforeTest() {
        FindingsIndexReporter.stop();
        SitemapIndexReporter.stop();
        ProxyHistoryIndexReporter.stop();
        ProxyWebSocketIndexReporter.stop();
    }

    @AfterEach
    public void tearDown() {
        Logger.unregisterListener(listener);
        Logger.resetState();
        FindingsIndexReporter.stop();
        SitemapIndexReporter.stop();
        ProxyHistoryIndexReporter.stop();
        ProxyWebSocketIndexReporter.stop();
        TrafficExportQueue.stopWorker();
        TrafficExportQueue.clearPendingWork();
        MontoyaApiProvider.set(null);
        RuntimeConfig.setExportRunning(false);
    }

    @Test
    void findings_pushSnapshotNow_logsBacklogStart_andSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            SiteMap siteMap = mock(SiteMap.class);
            Scope scope = mock(Scope.class);
            AuditIssue first = mock(AuditIssue.class);
            AuditIssue second = mock(AuditIssue.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope()).thenReturn(scope);
            when(scope.isInScope(anyString())).thenReturn(true);
            when(siteMap.issues()).thenReturn(List.of(first, second));
            stubMinimalIssue(first, "https://a.example/");
            stubMinimalIssue(second, "https://b.example/");
            MontoyaApiProvider.set(api);

            configureFindingsExport();
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            awaitInfoLine("[StartupExport] Findings: exporting backlog: 2 issue(s) with adaptive startup slices.");
            awaitInfoLineStartingWith("[SnapshotExport] Findings: snapshot complete: captured=");
            awaitInfoLineStartingWith("[SnapshotExport] Findings: backlog filters: seen=");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void sitemap_pushSnapshotNow_exportsDistinctRowsWithSameMethodAndUrl() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            SiteMap siteMap = mock(SiteMap.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            HttpRequestResponse first = mockSitemapItem("GET", "https://example.com/a", "body-a");
            HttpRequestResponse second = mockSitemapItem("GET", "https://example.com/a", "body-b");
            when(siteMap.requestResponses()).thenReturn(List.of(first, second));
            MontoyaApiProvider.set(api);

            configureSitemapExport();
            SitemapIndexReporter.start();
            SitemapIndexReporter.pushSnapshotNow();

            awaitInfoLine("[StartupExport] Sitemap: exporting backlog: 2 item(s) with adaptive startup slices.");
            awaitInfoLineStartingWith("[SnapshotExport] Sitemap: backlog filters: seen=2 exported=2 skipped_scope=0");
            assertThat(infoMessages.stream().noneMatch(line -> line.contains("skipped_duplicate"))).isTrue();
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void sitemap_pushSnapshotNow_logsBacklogStart_andSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            SiteMap siteMap = mock(SiteMap.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            HttpRequestResponse item = mock(HttpRequestResponse.class);
            when(siteMap.requestResponses()).thenReturn(List.of(item));
            MontoyaApiProvider.set(api);

            configureSitemapExport();
            SitemapIndexReporter.start();
            SitemapIndexReporter.pushSnapshotNow();

            awaitInfoLine("[StartupExport] Sitemap: exporting backlog: 1 item(s) with adaptive startup slices.");
            awaitInfoLineStartingWith("[SnapshotExport] Sitemap: snapshot complete: captured=");
            awaitInfoLineStartingWith("[SnapshotExport] Sitemap: backlog filters: seen=");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void findings_pushSnapshotNow_excludesFalsePositiveFromSkippedSeverity() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            SiteMap siteMap = mock(SiteMap.class);
            Scope scope = mock(Scope.class);
            AuditIssue high = mock(AuditIssue.class);
            AuditIssue falsePositive = mock(AuditIssue.class);
            AuditIssue informational = mock(AuditIssue.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope()).thenReturn(scope);
            when(scope.isInScope(anyString())).thenReturn(true);
            when(siteMap.issues()).thenReturn(List.of(high, falsePositive, informational));
            stubMinimalIssue(high, "https://a.example/", AuditIssueSeverity.HIGH);
            stubMinimalIssue(falsePositive, "https://b.example/", AuditIssueSeverity.FALSE_POSITIVE);
            stubMinimalIssue(informational, "https://c.example/", AuditIssueSeverity.INFORMATION);
            MontoyaApiProvider.set(api);

            configureFindingsExport();
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            awaitInfoLine("[StartupExport] Findings: exporting backlog: 3 issue(s) with adaptive startup slices.");
            awaitInfoLineStartingWith(
                    "[SnapshotExport] Findings: backlog filters: seen=3 exported=2 skipped_scope=0 skipped_severity=0 skipped_non_exportable=1");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void findings_pushSnapshotNow_countsNullIssueAsNonExportable() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            SiteMap siteMap = mock(SiteMap.class);
            Scope scope = mock(Scope.class);
            AuditIssue high = mock(AuditIssue.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope()).thenReturn(scope);
            when(scope.isInScope(anyString())).thenReturn(true);
            when(siteMap.issues()).thenReturn(Arrays.asList(high, null));
            stubMinimalIssue(high, "https://a.example/", AuditIssueSeverity.HIGH);
            MontoyaApiProvider.set(api);

            configureFindingsExport();
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            awaitInfoLine("[StartupExport] Findings: exporting backlog: 2 issue(s) with adaptive startup slices.");
            awaitInfoLineStartingWith(
                    "[SnapshotExport] Findings: backlog filters: seen=2 exported=1 skipped_scope=0 skipped_severity=0 skipped_non_exportable=1");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void findings_pushSnapshotNow_countsOperatorFilteredSeverityInSkippedSeverity() throws Exception {
        Logger.registerListener(listener);
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            SiteMap siteMap = mock(SiteMap.class);
            Scope scope = mock(Scope.class);
            AuditIssue high = mock(AuditIssue.class);
            AuditIssue informational = mock(AuditIssue.class);
            when(api.siteMap()).thenReturn(siteMap);
            when(api.scope()).thenReturn(scope);
            when(scope.isInScope(anyString())).thenReturn(true);
            when(siteMap.issues()).thenReturn(List.of(high, informational));
            stubMinimalIssue(high, "https://a.example/", AuditIssueSeverity.HIGH);
            stubMinimalIssue(informational, "https://b.example/", AuditIssueSeverity.INFORMATION);
            MontoyaApiProvider.set(api);

            configureFindingsExport(List.of("high"));
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();

            awaitInfoLine("[StartupExport] Findings: exporting backlog: 2 issue(s) with adaptive startup slices.");
            awaitInfoLineStartingWith(
                    "[SnapshotExport] Findings: backlog filters: seen=2 exported=1 skipped_scope=0 skipped_severity=1 skipped_non_exportable=0");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void proxyWebSocket_pushHistoricSnapshotNow_logsBacklogStart_only_noSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            ProxyWebSocketMessage frame = ProxyWebSocketIndexReporterTest.webSocketMessage(1, 1);
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            when(api.proxy().webSocketHistory()).thenReturn(List.of(frame));
            MontoyaApiProvider.set(api);

            configureProxyWebSocketExport();
            ProxyWebSocketIndexReporter.pushHistoricSnapshotNow();

            awaitInfoLine(
                    "[StartupExport] ProxyWebSocket: exporting history backlog: 1 frame(s) with adaptive startup slices.");
            assertThat(infoMessages).noneMatch(line -> line.contains("snapshot complete"));
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void proxyHistory_pushSnapshotNow_logsBacklogStart_andSnapshotComplete() throws Exception {
        Logger.registerListener(listener);
        try {
            ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
            MontoyaApi api = mock(MontoyaApi.class, Answers.RETURNS_DEEP_STUBS);
            when(api.scope().isInScope(anyString())).thenReturn(true);
            when(api.proxy().history()).thenReturn(List.of(item));
            MontoyaApiProvider.set(api);

            configureProxyHistoryExport();
            ProxyHistoryIndexReporter.pushSnapshotNow();

            awaitInfoLine(
                    "[StartupExport] ProxyHistory: exporting backlog: 1 item(s) with adaptive startup slices.");
            awaitInfoLineStartingWith("[SnapshotExport] ProxyHistory: snapshot complete: captured=");
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    private void awaitInfoLine(String expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            if (infoMessages.contains(expected)) {
                return;
            }
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(20);
        }
        assertThat(infoMessages).contains(expected);
    }

    private void awaitInfoLineStartingWith(String prefix) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            if (infoMessages.stream().anyMatch(line -> line.startsWith(prefix))) {
                return;
            }
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(20);
        }
        assertThat(infoMessages).anyMatch(line -> line.startsWith(prefix));
    }

    private static void stubMinimalIssue(AuditIssue issue, String baseUrl) {
        stubMinimalIssue(issue, baseUrl, AuditIssueSeverity.HIGH);
    }

    private static void stubMinimalIssue(AuditIssue issue, String baseUrl, AuditIssueSeverity severity) {
        when(issue.baseUrl()).thenReturn(baseUrl);
        when(issue.severity()).thenReturn(severity);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.requestResponses()).thenReturn(List.of());
        when(issue.definition()).thenReturn(null);
    }

    private static HttpRequestResponse mockSitemapItem(String method, String url, String body) {
        byte[] raw = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn(raw);
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn(method);
        when(request.url()).thenReturn(url);
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpRequestResponse item = mock(HttpRequestResponse.class);
        when(item.request()).thenReturn(request);
        when(item.response()).thenReturn(null);
        when(item.annotations()).thenReturn(null);
        when(item.hasResponse()).thenReturn(false);
        return item;
    }

    private static void configureFindingsExport() {
        configureFindingsExport(ConfigState.DEFAULT_FINDINGS_SEVERITIES);
    }

    private static void configureFindingsExport(List<String> findingsSeverities) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                findingsSeverities,
                null));
        RuntimeConfig.setExportRunning(true);
    }

    private static void configureSitemapExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SITEMAP),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }

    private static void configureProxyWebSocketExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }

    private static void configureProxyHistoryExport() {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of("traffic"),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, true, "https://opensearch.url:9200", null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy_history"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
        RuntimeConfig.setExportRunning(true);
    }
}
