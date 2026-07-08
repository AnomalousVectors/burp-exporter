package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.awaitSingleIndexedDocument;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.createIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.deleteIndex;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.nestedMap;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.openSearchSinks;
import static ai.anomalousvectors.tools.burp.testutils.PartialFieldOpenSearchTestSupport.pushOneDocument;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.anomalousvectors.tools.burp.testutils.OpenSearchReachable;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

@Tag("integration")
@ResourceLock("sitemap-opensearch-index")
class SitemapPartialFieldSelectionOpenSearchIT {

    private static final String ITEM_URL = "https://example.com/sitemap-partial";

    private final ConfigState.State previous = RuntimeConfig.getState();

    @AfterEach
    public void cleanup() {
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        deleteIndex("sitemap");
    }

    @Test
    void partialSitemapFieldSelection_indexesSparseRequestOnly() {
        Assumptions.assumeTrue(OpenSearchReachable.isReachable(), "OpenSearch dev cluster not reachable");
        createIndex("sitemap");

        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SITEMAP),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                openSearchSinks(),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                ConfigState.DEFAULT_EXPORTER_SUB_OPTIONS,
                ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS,
                Map.of("sitemap", Set.of("request.url.raw", "burp.is_in_scope")));

        Map<String, Object> built = SitemapIndexReporter.buildSitemapDoc(mockSitemapItem());
        pushOneDocument("sitemap", built, state);
        Map<String, Object> stored = awaitSingleIndexedDocument("sitemap");

        assertThat(stored).containsKeys("meta", "request", "burp");
        assertThat(stored).doesNotContainKey("response");
        assertThat(nestedMap(nestedMap(stored, "request"), "url").get("raw")).isEqualTo(ITEM_URL);
        assertThat(nestedMap(stored, "burp").containsKey("is_in_scope")).isTrue();
        assertThat(nestedMap(stored, "burp").containsKey("timing")).isFalse();
    }

    private static HttpRequestResponse mockSitemapItem() {
        HttpRequestResponse item = mock(HttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        HttpResponse response = mock(HttpResponse.class);
        HttpService httpService = mock(HttpService.class);

        when(item.request()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.httpService()).thenReturn(httpService);
        when(item.timingData()).thenReturn(Optional.empty());

        when(request.url()).thenReturn(ITEM_URL);
        when(request.method()).thenReturn("GET");
        when(request.path()).thenReturn("/sitemap-partial");
        when(request.pathWithoutQuery()).thenReturn("/sitemap-partial");
        when(request.query()).thenReturn("");
        when(request.fileExtension()).thenReturn("");
        when(request.httpVersion()).thenReturn("HTTP/1.1");
        when(request.headers()).thenReturn(List.of());
        when(request.parameters()).thenReturn(List.of());
        when(request.body()).thenReturn(null);
        when(request.markers()).thenReturn(List.of());
        when(request.contentType()).thenReturn(null);

        when(httpService.host()).thenReturn("example.com");
        when(httpService.port()).thenReturn(443);
        when(httpService.secure()).thenReturn(true);

        when(response.statusCode()).thenReturn((short) 200);
        when(response.reasonPhrase()).thenReturn("OK");
        when(response.mimeType()).thenReturn(burp.api.montoya.http.message.MimeType.HTML);
        when(response.statedMimeType()).thenReturn(burp.api.montoya.http.message.MimeType.HTML);
        when(response.inferredMimeType()).thenReturn(burp.api.montoya.http.message.MimeType.HTML);
        when(response.httpVersion()).thenReturn("HTTP/1.1");
        when(response.headers()).thenReturn(List.of());
        when(response.cookies()).thenReturn(List.of());
        when(response.body()).thenReturn(null);
        when(response.bodyOffset()).thenReturn(0);
        when(response.markers()).thenReturn(List.of());

        return item;
    }
}
