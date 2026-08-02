package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ai.anomalousvectors.tools.burp.utils.IndexNaming;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.export.BulkOutcomeBreakdown;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;

/** Verifies Repeater recovery replay stays separate from the live traffic and Files paths. */
class RepeaterSearchRecoveryReplayTest {

    @TempDir
    Path root;

    @Test
    void recoveryReplayIsSynchronousDatabaseOnlyAndRetainsOrdinaryTraffic() throws Exception {
        ConfigState.State previousState = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(recoveryState(root));
            captureRepeaterSnapshot();
            assertThat(RepeaterTabsIndexReporter.capturedItemCount()).isEqualTo(1);

            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.ExportRunToken token = RuntimeConfig.currentExportRunToken();
            List<List<PreparedExportDocument>> sentBatches = new ArrayList<>();

            TrafficExportQueueTestSupport.withDrainWorkerDisabled(() -> {
                RuntimeConfig.setSearchRecoveryReplay(true);
                TrafficExportQueue.offer(ordinaryProxyDocument());
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);

                boolean completed = RepeaterTabsIndexReporter.replaySearchRecoverySnapshot(
                        token,
                        (baseUrl, indexName, indexKey, documents) -> {
                            assertThat(RuntimeConfig.isSearchRecoveryReplay()).isTrue();
                            sentBatches.add(List.copyOf(documents));
                            return new BulkPushOutcome(
                                    documents.size(),
                                    documents.size(),
                                    BulkOutcomeBreakdown.classified(
                                            documents.size(), documents.size()));
                        });

                assertThat(completed).isTrue();
                assertThat(sentBatches).hasSize(1);
                assertThat(sentBatches.getFirst()).hasSize(1);
                assertThat(TrafficExportQueue.getCurrentSize()).isEqualTo(1);
                assertThat(root.resolve(IndexNaming.indexNameForShortName("traffic") + ".jsonl"))
                        .doesNotExist();
            });
        } finally {
            RuntimeConfig.setSearchRecoveryReplay(false);
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.updateState(previousState);
            RepeaterTabsIndexReporter.clearSessionState();
        }
    }

    private static ConfigState.State recoveryState(Path root) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        true,
                        root.toString(),
                        true,
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
                List.of("proxy", "repeater_tabs"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                null);
    }

    private static void captureRepeaterSnapshot() {
        EditorCreationContext context = mock(EditorCreationContext.class);
        ToolSource toolSource = mock(ToolSource.class);
        when(context.toolSource()).thenReturn(toolSource);
        when(toolSource.toolType()).thenReturn(ToolType.REPEATER);
        RepeaterTabsIndexReporter.captureFromEditorContext(
                context,
                requestResponse("https://example.test/recovery"),
                "request_editor",
                null);
    }

    private static Map<String, Object> ordinaryProxyDocument() {
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", "Proxy");
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("burp", burp);
        document.put("meta", Map.of("schema_version", "1"));
        return document;
    }

    private static HttpRequestResponse requestResponse(String url) {
        URI uri = URI.create(url);
        HttpRequest request = mock(HttpRequest.class);
        ByteArray requestBytes = mock(ByteArray.class);
        when(requestBytes.getBytes()).thenReturn(
                "GET /recovery HTTP/1.1\r\nHost: example.test\r\n\r\n"
                        .getBytes(StandardCharsets.UTF_8));
        when(request.toByteArray()).thenReturn(requestBytes);
        when(request.url()).thenReturn(url);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn(uri.getRawPath());
        when(request.pathWithoutQuery()).thenReturn(uri.getRawPath());
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.markers()).thenReturn(List.of());

        HttpResponse response = mock(HttpResponse.class);
        ByteArray responseBytes = mock(ByteArray.class);
        when(responseBytes.getBytes()).thenReturn(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                        .getBytes(StandardCharsets.UTF_8));
        when(response.toByteArray()).thenReturn(responseBytes);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.cookies()).thenReturn(List.of());
        when(response.markers()).thenReturn(List.of());

        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn(uri.getHost());
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);
        when(requestResponse.response()).thenReturn(response);
        when(requestResponse.httpService()).thenReturn(service);
        when(requestResponse.copyToTempFile()).thenReturn(requestResponse);
        return requestResponse;
    }
}
