package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.documentCount;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushAndAwaitIndexedDocument;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.sitemap.SiteMap;

/**
 * OpenSearch integration tests for {@link FindingsIndexReporter} severity filtering and periodic
 * deduplication against {@link OpenSearchReachable#BASE_URL}.
 */
@Tag("integration")
@ResourceLock("findings-opensearch-index")
class FindingsIndexReporterIT {

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    public void cleanup() {
        FindingsIndexReporter.stop();
        MontoyaApiProvider.set(null);
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        deleteIndex("findings");
    }

    @Test
    void informationalFinding_indexesWithInformationSeverity() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        createIndex("findings");

        ConfigState.State state = findingsExportState();
        AuditIssue issue = mockIssue(
                "Informational finding",
                "https://example.test/info",
                AuditIssueSeverity.INFORMATION,
                10,
                "Passive scan note");

        Map<String, Object> built = FindingsIndexReporter.buildFindingDoc(issue);
        Map<String, Object> stored = pushAndAwaitIndexedDocument(
                "findings", built, state, "issue.name.raw", "Informational finding");

        assertThat(nestedMap(stored, "issue").get("severity")).isEqualTo("INFORMATION");
    }

    @Test
    void pushSnapshotNow_excludesFalsePositiveFromOpenSearchExport() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        deleteIndex("findings");
        createIndex("findings");
        configureFindingsExport();

        AuditIssue high = mockIssue("High issue", "https://a.example/", AuditIssueSeverity.HIGH, 1, "high detail");
        AuditIssue falsePositive = mockIssue(
                "Dismissed", "https://b.example/", AuditIssueSeverity.FALSE_POSITIVE, 2, "fp detail");
        mockApiWithIssues(List.of(high, falsePositive));

        List<String> infoLines = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("INFO".equals(level)) {
                infoLines.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();
            awaitInfoLogStartingWith(
                    infoLines,
                    "[SnapshotExport] Findings: backlog filters: seen=2 exported=1 skipped_scope=0 skipped_severity=0 skipped_non_exportable=1");
            awaitDocumentCountAtLeast(1);
            assertThat(documentCount("findings")).isEqualTo(1);
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void pushNewIssuesOnly_doesNotDuplicateAfterBacklog() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        deleteIndex("findings");
        createIndex("findings");
        configureFindingsExport();

        AuditIssue issue = mockIssue("XSS", "https://example.test/xss", AuditIssueSeverity.HIGH, 5, "Reflected");
        mockApiWithIssues(List.of(issue));

        List<String> lines = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("INFO".equals(level) || "DEBUG".equals(level)) {
                lines.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();
            awaitInfoLogStartingWith(lines, "[SnapshotExport] Findings: snapshot complete: captured=");
            assertThat(documentCount("findings")).isEqualTo(1);

            FindingsIndexReporter.pushNewIssuesOnly();
            FindingsIndexReporter.pushNewIssuesOnly();

            assertThat(documentCount("findings")).isEqualTo(1);
            assertThat(lines.stream().anyMatch(line -> line.contains("[PeriodicExport] Findings: no new issues")))
                    .isTrue();
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void pushSnapshotNow_exportsDistinctIssuesWhenDetailDiffers() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        deleteIndex("findings");
        createIndex("findings");
        configureFindingsExport();

        AuditIssue first = mockIssue("XSS", "https://example.test/", AuditIssueSeverity.HIGH, 7, "detail alpha");
        AuditIssue second = mockIssue("XSS", "https://example.test/", AuditIssueSeverity.HIGH, 7, "detail beta");
        mockApiWithIssues(List.of(first, second));

        List<String> infoLines = new CopyOnWriteArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("INFO".equals(level)) {
                infoLines.add(message);
            }
        };
        Logger.registerListener(listener);
        try {
            FindingsIndexReporter.start();
            FindingsIndexReporter.pushSnapshotNow();
            awaitInfoLogStartingWith(
                    infoLines,
                    "[SnapshotExport] Findings: backlog filters: seen=2 exported=2 skipped_scope=0 skipped_severity=0 skipped_non_exportable=0");
            assertThat(documentCount("findings")).isEqualTo(2);
        } finally {
            Logger.unregisterListener(listener);
        }
    }

    @Test
    void pushNewIssuesOnly_exportsOnlyNewDetailFingerprintAfterBacklog() throws Exception {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        deleteIndex("findings");
        createIndex("findings");
        configureFindingsExport();

        AuditIssue backlog = mockIssue("XSS", "https://example.test/", AuditIssueSeverity.HIGH, 3, "seen in backlog");
        MontoyaApi api = mockApiWithIssues(List.of(backlog));

        FindingsIndexReporter.start();
        FindingsIndexReporter.pushSnapshotNow();
        awaitDocumentCountAtLeast(1);
        assertThat(documentCount("findings")).isEqualTo(1);

        AuditIssue newDetail = mockIssue("XSS", "https://example.test/", AuditIssueSeverity.HIGH, 3, "new periodic detail");
        when(api.siteMap().issues()).thenReturn(List.of(backlog, newDetail));

        FindingsIndexReporter.pushNewIssuesOnly();
        awaitDocumentCountAtLeast(2);
        assertThat(documentCount("findings")).isEqualTo(2);
    }

    private static ConfigState.State findingsExportState() {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_FINDINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);
    }

    private static void configureFindingsExport() {
        RuntimeConfig.updateState(findingsExportState());
        RuntimeConfig.setExportRunning(true);
    }

    private static MontoyaApi mockApiWithIssues(List<AuditIssue> issues) {
        MontoyaApi api = mock(MontoyaApi.class);
        SiteMap siteMap = mock(SiteMap.class);
        Scope scope = mock(Scope.class);
        when(api.siteMap()).thenReturn(siteMap);
        when(api.scope()).thenReturn(scope);
        when(scope.isInScope(anyString())).thenReturn(true);
        when(siteMap.issues()).thenReturn(issues);
        MontoyaApiProvider.set(api);
        return api;
    }

    private static AuditIssue mockIssue(
            String name,
            String baseUrl,
            AuditIssueSeverity severity,
            int typeId,
            String detail) {
        AuditIssue issue = mock(AuditIssue.class);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        HttpService service = mock(HttpService.class);
        when(definition.typeIndex()).thenReturn(typeId);
        when(issue.definition()).thenReturn(definition);
        when(issue.name()).thenReturn(name);
        when(issue.baseUrl()).thenReturn(baseUrl);
        when(issue.severity()).thenReturn(severity);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.detail()).thenReturn(detail);
        when(issue.remediation()).thenReturn("fix");
        when(issue.httpService()).thenReturn(service);
        when(issue.requestResponses()).thenReturn(List.of());
        when(service.host()).thenReturn("example.test");
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        return issue;
    }

    private static void awaitDocumentCountAtLeast(long expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (System.nanoTime() < deadline) {
            if (documentCount("findings") >= expected) {
                return;
            }
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(50);
        }
        assertThat(documentCount("findings")).isGreaterThanOrEqualTo(expected);
    }

    private static void awaitInfoLogStartingWith(List<String> infoLines, String prefix)
            throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (System.nanoTime() < deadline) {
            if (infoLines.stream().anyMatch(line -> line.startsWith(prefix))) {
                return;
            }
            java.util.concurrent.TimeUnit.MILLISECONDS.sleep(20);
        }
        assertThat(infoLines).anyMatch(line -> line.startsWith(prefix));
    }
}
