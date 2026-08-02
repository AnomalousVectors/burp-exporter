package ai.anomalousvectors.tools.burp.sinks;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ai.anomalousvectors.tools.burp.testutils.LazySchedulers;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.DnsQueryType;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionId;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Ensures {@link FindingsIndexReporter} completes without throwing when
 * preconditions are not met (no API, export not running, or Findings not
 * selected). Does not start the scheduler to avoid leaving a daemon thread.
 */
class FindingsIndexReporterTest {
    private final ConfigState.State previousState = RuntimeConfig.getState();
    private final MontoyaApi previousApi = MontoyaApiProvider.get();

    private void resetState() {
        FindingsIndexReporter.stop();
        RuntimeConfig.updateState(previousState);
        MontoyaApiProvider.set(previousApi);
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void start_defersSchedulerUntilStartupSnapshotCompletes() {
        try {
            RuntimeConfig.setExportRunning(true);

            FindingsIndexReporter.start();

            assertThat(LazySchedulers.peek(FindingsIndexReporter.class, "SCHEDULER")).isNull();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenApiNull() {
        try {
            RuntimeConfig.setExportRunning(true);
            MontoyaApiProvider.set(null);
            FindingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            FindingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void pushSnapshotNow_completesWithoutThrow_whenFindingsNotInDataSources() {
        try {
            ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false);
            ConfigState.State state = new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    sinks,
                    ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null);
            RuntimeConfig.updateState(state);
            RuntimeConfig.setExportRunning(true);
            FindingsIndexReporter.pushSnapshotNow();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenApiNull() {
        try {
            RuntimeConfig.setExportRunning(true);
            MontoyaApiProvider.set(null);
            FindingsIndexReporter.pushNewIssuesOnly();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenExportNotRunning() {
        try {
            RuntimeConfig.setExportRunning(false);
            FindingsIndexReporter.pushNewIssuesOnly();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_completesWithoutThrow_whenFindingsNotInDataSources() {
        try {
            ConfigState.Sinks sinks = new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false);
            ConfigState.State state = new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    sinks,
                    ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null);
            RuntimeConfig.updateState(state);
            RuntimeConfig.setExportRunning(true);
            FindingsIndexReporter.pushNewIssuesOnly();
        } finally {
            resetState();
        }
    }

    @Test
    void pushNewIssuesOnly_skipsSiteMapIssues_whenCommunityEditionStripsFindingsSource() {
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Version version = mock(Version.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(burpSuite.version()).thenReturn(version);
            when(version.edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION);
            MontoyaApiProvider.set(api);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);

            FindingsIndexReporter.pushNewIssuesOnly();

            assertThat(RuntimeConfig.getState().dataSources()).doesNotContain(ConfigKeys.SRC_FINDINGS);
            verify(api, never()).siteMap();
        } finally {
            resetState();
        }
    }

    @Test
    void buildFindingDoc_survivesMalformedRequestInRequestResponses() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/login");
        when(request.pathWithoutQuery()).thenReturn("/login");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenThrow(new IllegalStateException("malformed"));
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(request);
        when(rr.hasResponse()).thenReturn(false);

        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("auth.example.com");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);

        AuditIssue issue = mock(AuditIssue.class);
        when(issue.name()).thenReturn("Test Issue");
        when(issue.baseUrl()).thenReturn("https://auth.example.com/login");
        when(issue.severity()).thenReturn(AuditIssueSeverity.MEDIUM);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.detail()).thenReturn("details");
        when(issue.remediation()).thenReturn("fix it");
        when(issue.httpService()).thenReturn(svc);
        when(issue.requestResponses()).thenReturn(List.of(rr));
        when(issue.definition()).thenReturn(null);

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);

        assertThat(doc).isNotNull();
        Map<?, ?> issueDoc = (Map<?, ?>) doc.get("issue");
        Map<?, ?> targetDoc = (Map<?, ?>) doc.get("target");
        assertThat(issueDoc.get("name")).isEqualTo("Test Issue");
        assertThat(issueDoc.get("severity")).isEqualTo("MEDIUM");
        assertThat(targetDoc.get("url")).isEqualTo("https://auth.example.com/login");
        assertThat(doc.containsKey("request_responses_missing")).isFalse();
        assertThat(doc.get("requests_responses"))
                .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class))
                .hasSize(1);
    }

    @Test
    void buildFindingDoc_groupsTargetService_andDoesNotEmitFlatProtocolFields() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/login");
        when(request.pathWithoutQuery()).thenReturn("/login");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/2");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(request);
        when(rr.hasResponse()).thenReturn(false);

        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("auth.example.com");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);

        AuditIssue issue = baseIssue(svc, List.of(rr));

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);
        assertThat(doc).isNotNull();
        Map<?, ?> target = (Map<?, ?>) doc.get("target");
        Map<?, ?> protocol = (Map<?, ?>) target.get("protocol");
        assertThat(target.get("host")).isEqualTo("auth.example.com");
        assertThat(target.get("port")).isEqualTo(443);
        assertThat(protocol.get("scheme")).isEqualTo("https");
        assertThat(doc.keySet()).doesNotContain("host");
        assertThat(doc.keySet()).doesNotContain("port");
        assertThat(doc.keySet()).doesNotContain("protocol_application");
        assertThat(doc.keySet()).doesNotContain("protocol_sub");
        assertThat(doc.keySet()).doesNotContain("protocol_transport");
    }

    @Test
    void buildFindingDoc_overridesMarkersWithScannerPairLevelEvidence_whenPresent() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("POST");
        when(request.path()).thenReturn("/api/items");
        when(request.pathWithoutQuery()).thenReturn("/api/items");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(request);
        when(rr.hasResponse()).thenReturn(false);
        Range issueRange = mock(Range.class);
        when(issueRange.startIndexInclusive()).thenReturn(120);
        when(issueRange.endIndexExclusive()).thenReturn(135);
        Marker issueMarker = mock(Marker.class);
        when(issueMarker.range()).thenReturn(issueRange);
        when(rr.requestMarkers()).thenReturn(List.of(issueMarker));
        when(rr.responseMarkers()).thenReturn(List.of());

        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("api.example.com");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);

        AuditIssue issue = baseIssue(svc, List.of(rr));

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);
        assertThat(doc).isNotNull();

        List<?> pairs = (List<?>) doc.get("requests_responses");
        assertThat(pairs).hasSize(1);
        Map<?, ?> pair = (Map<?, ?>) pairs.get(0);
        Map<?, ?> reqDoc = (Map<?, ?>) pair.get("request");
        Map<?, ?> reqBody = (Map<?, ?>) reqDoc.get("body");
        List<?> reqMarkers = (List<?>) reqBody.get("markers");
        assertThat(reqMarkers).hasSize(1);
        Map<?, ?> firstMarker = (Map<?, ?>) reqMarkers.get(0);
        assertThat(firstMarker.get("start_inclusive")).isEqualTo(120);
        assertThat(firstMarker.get("end_exclusive")).isEqualTo(135);
    }

    @Test
    void buildFindingDoc_populatesPairAnnotations_fromHttpRequestResponseAnnotations() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/x");
        when(request.pathWithoutQuery()).thenReturn("/x");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        Annotations ann = mock(Annotations.class);
        when(ann.hasNotes()).thenReturn(true);
        when(ann.notes()).thenReturn("analyst note");
        when(ann.hasHighlightColor()).thenReturn(true);
        when(ann.highlightColor()).thenReturn(HighlightColor.RED);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(request);
        when(rr.hasResponse()).thenReturn(false);
        when(rr.annotations()).thenReturn(ann);

        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("h"); when(svc.port()).thenReturn(443); when(svc.secure()).thenReturn(true);
        AuditIssue issue = baseIssue(svc, List.of(rr));

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);
        Map<?, ?> pair = (Map<?, ?>) ((List<?>) doc.get("requests_responses")).get(0);
        Map<?, ?> burpDoc = (Map<?, ?>) pair.get("burp");
        assertThat(burpDoc).isNotNull();
        assertThat(burpDoc.get("notes")).isEqualTo("analyst note");
        assertThat(burpDoc.get("highlight")).isEqualTo("RED");
    }

    @Test
    void buildFindingDoc_populatesPairTiming_fromHttpRequestResponseTimingData() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/timed");
        when(request.pathWithoutQuery()).thenReturn("/timed");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        TimingData timing = mock(TimingData.class);
        ZonedDateTime sent = ZonedDateTime.parse("2026-01-01T00:00:00Z");
        when(timing.timeRequestSent()).thenReturn(sent);
        when(timing.timeBetweenRequestSentAndStartOfResponse()).thenReturn(Duration.ofMillis(125));
        when(timing.timeBetweenRequestSentAndEndOfResponse()).thenReturn(Duration.ofMillis(500));

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(request);
        when(rr.hasResponse()).thenReturn(false);
        when(rr.timingData()).thenReturn(java.util.Optional.of(timing));

        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("h");
        when(svc.port()).thenReturn(443);
        when(svc.secure()).thenReturn(true);
        AuditIssue issue = baseIssue(svc, List.of(rr));

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);
        Map<?, ?> pair = (Map<?, ?>) ((List<?>) doc.get("requests_responses")).get(0);
        Map<?, ?> burpDoc = (Map<?, ?>) pair.get("burp");
        Map<?, ?> timingDoc = (Map<?, ?>) burpDoc.get("timing");

        assertThat(timingDoc.get("req_sent")).isEqualTo("2026-01-01T00:00:00Z");
        assertThat(timingDoc.get("req_sent_to_res_start")).isEqualTo(125);
        assertThat(timingDoc.get("req_sent_to_res_end")).isEqualTo(500);
        assertThat(timingDoc.get("end")).isEqualTo("2026-01-01T00:00:00.500Z");
    }

    @Test
    void buildFindingDoc_capturesCollaboratorInteractions_dnsEntry() {
        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("h"); when(svc.port()).thenReturn(443); when(svc.secure()).thenReturn(true);

        InteractionId iid = mock(InteractionId.class);
        when(iid.toString()).thenReturn("00000000000000abc123");
        DnsDetails dnsDetails = mock(DnsDetails.class);
        when(dnsDetails.queryType()).thenReturn(DnsQueryType.A);
        ByteArray queryBytes = mock(ByteArray.class);
        when(queryBytes.getBytes()).thenReturn(new byte[]{0x01, 0x02, 0x03});
        when(dnsDetails.query()).thenReturn(queryBytes);

        Interaction interaction = mock(Interaction.class);
        when(interaction.id()).thenReturn(iid);
        when(interaction.type()).thenReturn(InteractionType.DNS);
        when(interaction.timeStamp()).thenReturn(java.time.ZonedDateTime.parse("2026-01-01T00:00:00Z"));
        try {
            when(interaction.clientIp()).thenReturn(java.net.InetAddress.getByName("198.51.100.42"));
        } catch (java.net.UnknownHostException e) {
            throw new AssertionError(e);
        }
        when(interaction.clientPort()).thenReturn(54321);
        when(interaction.dnsDetails()).thenReturn(java.util.Optional.of(dnsDetails));
        when(interaction.httpDetails()).thenReturn(java.util.Optional.empty());
        when(interaction.smtpDetails()).thenReturn(java.util.Optional.empty());
        when(interaction.customData()).thenReturn(java.util.Optional.empty());

        AuditIssue issue = baseIssue(svc, List.of());
        when(issue.collaboratorInteractions()).thenReturn(List.of(interaction));

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);
        List<?> interactions = (List<?>) doc.get("collaborator");
        assertThat(interactions).hasSize(1);
        Map<?, ?> entry = (Map<?, ?>) interactions.get(0);
        assertThat(entry.get("id")).isEqualTo("00000000000000abc123");
        assertThat(entry.get("type")).isEqualTo("DNS");
        assertThat(entry.get("client_ip")).isEqualTo("198.51.100.42");
        assertThat(entry.get("client_port")).isEqualTo(54321);
        Map<?, ?> dns = (Map<?, ?>) entry.get("dns");
        assertThat(dns.get("query_type")).isEqualTo("A");
        assertThat(dns.get("query_b64")).isEqualTo("AQID");
    }

    @Test
    void buildFindingDoc_capturesCollaboratorHttpInteraction_asRawAndParsedTrafficShape() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/callback");
        when(request.pathWithoutQuery()).thenReturn("/callback");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);
        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn("GET /callback HTTP/1.1\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(request.toByteArray()).thenReturn(requestBytes);

        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.body()).thenReturn(null);
        when(response.markers()).thenReturn(List.of());
        when(response.inferredMimeType()).thenReturn(null);
        when(response.statedMimeType()).thenReturn(null);
        ByteArray responseBytes = mock(ByteArray.class);
        when(responseBytes.getBytes()).thenReturn("HTTP/1.1 200 OK\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(response.toByteArray()).thenReturn(responseBytes);

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn("collab.example.net");
        when(service.port()).thenReturn(80);
        when(service.secure()).thenReturn(false);

        HttpRequestResponse hrr = mock(HttpRequestResponse.class);
        when(hrr.request()).thenReturn(request);
        when(hrr.hasResponse()).thenReturn(true);
        when(hrr.response()).thenReturn(response);
        when(hrr.httpService()).thenReturn(service);
        when(hrr.requestMarkers()).thenReturn(List.of());
        when(hrr.responseMarkers()).thenReturn(List.of());

        HttpDetails httpDetails = mock(HttpDetails.class);
        when(httpDetails.requestResponse()).thenReturn(hrr);

        Interaction interaction = mock(Interaction.class);
        when(interaction.id()).thenReturn(mock(InteractionId.class));
        when(interaction.type()).thenReturn(InteractionType.HTTP);
        when(interaction.dnsDetails()).thenReturn(java.util.Optional.empty());
        when(interaction.httpDetails()).thenReturn(java.util.Optional.of(httpDetails));
        when(interaction.smtpDetails()).thenReturn(java.util.Optional.empty());
        when(interaction.customData()).thenReturn(java.util.Optional.empty());

        AuditIssue issue = baseIssue(service, List.of());
        when(issue.collaboratorInteractions()).thenReturn(List.of(interaction));

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);
        Map<?, ?> entry = (Map<?, ?>) ((List<?>) doc.get("collaborator")).get(0);
        Map<?, ?> http = (Map<?, ?>) entry.get("http");
        Map<?, ?> parsedRequest = (Map<?, ?>) http.get("request");
        Map<?, ?> parsedResponse = (Map<?, ?>) http.get("response");

        assertThat(http.get("request_b64")).isEqualTo("R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ0KDQo=");
        assertThat(http.get("response_b64")).isEqualTo("SFRUUC8xLjEgMjAwIE9LDQoNCg==");
        assertThat(parsedRequest.get("method")).isEqualTo("GET");
        Map<?, ?> parsedUrl = (Map<?, ?>) parsedRequest.get("url");
        assertThat(parsedUrl.get("port")).isEqualTo(80);
        assertThat(parsedUrl.get("scheme")).isEqualTo("http");
        assertThat(((Map<?, ?>) parsedRequest.get("protocol")).containsKey("scheme")).isFalse();
        assertThat(((Map<?, ?>) parsedResponse.get("status")).get("code")).isEqualTo(200);
    }

    @Test
    void buildFindingDoc_emitsEmptyCollaboratorInteractions_whenNonePresent() {
        HttpService svc = mock(HttpService.class);
        when(svc.host()).thenReturn("h"); when(svc.port()).thenReturn(443); when(svc.secure()).thenReturn(true);
        AuditIssue issue = baseIssue(svc, List.of());
        when(issue.collaboratorInteractions()).thenReturn(null);

        Map<String, Object> doc = FindingsIndexReporter.buildFindingDoc(issue);
        assertThat(doc.get("collaborator"))
                .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(Object.class))
                .isEmpty();
    }

    /** Builds a minimally-configured {@link AuditIssue} mock for buildFindingDoc tests. */
    private static AuditIssue baseIssue(HttpService svc, List<HttpRequestResponse> rrs) {
        AuditIssue issue = mock(AuditIssue.class);
        when(issue.name()).thenReturn("Test Issue");
        when(issue.baseUrl()).thenReturn("https://example.com/");
        when(issue.severity()).thenReturn(AuditIssueSeverity.MEDIUM);
        when(issue.confidence()).thenReturn(AuditIssueConfidence.CERTAIN);
        when(issue.detail()).thenReturn("details");
        when(issue.remediation()).thenReturn("fix it");
        when(issue.httpService()).thenReturn(svc);
        when(issue.requestResponses()).thenReturn(rrs);
        when(issue.definition()).thenReturn(null);
        return issue;
    }

    @Test
    void pushSnapshotNow_skipsSiteMap_whenCommunityEditionStripsFindingsSource() {
        try {
            MontoyaApi api = mock(MontoyaApi.class);
            BurpSuite burpSuite = mock(BurpSuite.class);
            Version version = mock(Version.class);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(burpSuite.version()).thenReturn(version);
            when(version.edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION);
            MontoyaApiProvider.set(api);

            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_FINDINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(false, "", true, "https://opensearch.url:9200", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);

            FindingsIndexReporter.pushSnapshotNow();

            assertThat(RuntimeConfig.getState().dataSources()).doesNotContain(ConfigKeys.SRC_FINDINGS);
            verify(api, never()).siteMap();
        } finally {
            resetState();
        }
    }
}
