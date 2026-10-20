package ai.anomalousvectors.tools.burp.testutils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.indices.DeleteIndexRequest;
import org.opensearch.client.opensearch.indices.OpenSearchIndicesClient;

/** Proves fixed index ownership and failure cleanup without touching a live cluster. */
class OpenSearchTestIndexTest {

    @Test
    void scope_deletesOnlyExactDefaultIndexes_beforeAndAfterEachScenario() throws Exception {
        for (String key : List.of("exporter", "findings", "settings", "sitemap", "traffic")) {
            OpenSearchClient before = client();
            OpenSearchClient after = client();
            AtomicInteger requests = new AtomicInteger();
            try (OpenSearchTestIndex index = OpenSearchTestIndex.open(
                    key, () -> requests.getAndIncrement() == 0 ? before : after)) {
                assertThat(index.name()).isEqualTo("tool-burp-" + key);
                assertDeletion(before, index.name());
                verifyNoInteractions(after.indices());
            }
            assertDeletion(after, "tool-burp-" + key);
            assertThat(requests).hasValue(2);
        }
    }

    @Test
    void scope_rejectsCustomNamesWildcardsAndUnknownKeys_beforeAcquiringAnyClient() {
        AtomicInteger requests = new AtomicInteger();
        Supplier<OpenSearchClient> clients = () -> {
            requests.incrementAndGet();
            throw new AssertionError("Invalid names must never acquire a client");
        };
        for (String key : List.of("", "af-test-123", "tool-burp-traffic", "*", "traffic*", "../traffic")) {
            assertThatThrownBy(() -> OpenSearchTestIndex.open(key, clients))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> OpenSearchTestIndex.open(null, clients))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(requests).hasValue(0);
    }

    @Test
    void assertionFailure_stillCleansWithAFreshClient() throws Exception {
        OpenSearchClient before = client();
        OpenSearchClient after = client();
        AtomicInteger requests = new AtomicInteger();
        AssertionError failure = new AssertionError("scenario failed after index creation");
        assertThatThrownBy(() -> {
            try (OpenSearchTestIndex index = OpenSearchTestIndex.open(
                    "traffic", () -> requests.getAndIncrement() == 0 ? before : after)) {
                assertThat(index.name()).isEqualTo("tool-burp-traffic");
                throw failure;
            }
        }).isSameAs(failure);
        assertDeletion(after, "tool-burp-traffic");
    }

    @Test
    void cleanupFailure_isSuppressedWithoutMaskingTheScenarioFailure() throws Exception {
        OpenSearchClient before = client();
        OpenSearchClient after = client();
        IOException cleanupFailure = new IOException("cleanup transport failed");
        OpenSearchIndicesClient indices = after.indices();
        doThrow(cleanupFailure).when(indices).delete(any(DeleteIndexRequest.class));
        AtomicInteger requests = new AtomicInteger();
        AssertionError scenarioFailure = new AssertionError("scenario failed");
        assertThatThrownBy(() -> {
            try (OpenSearchTestIndex index = OpenSearchTestIndex.open(
                    "exporter", () -> requests.getAndIncrement() == 0 ? before : after)) {
                assertThat(index.name()).isEqualTo("tool-burp-exporter");
                throw scenarioFailure;
            }
        }).isSameAs(scenarioFailure).hasSuppressedException(cleanupFailure);
    }

    @Test
    void cleanupFailure_afterSuccessfulScenarioFailsTheOwningTest() throws Exception {
        OpenSearchClient before = client();
        OpenSearchClient after = client();
        IOException failure = new IOException("cleanup authorization failed");
        OpenSearchIndicesClient indices = after.indices();
        doThrow(failure).when(indices).delete(any(DeleteIndexRequest.class));
        AtomicInteger requests = new AtomicInteger();
        assertThatThrownBy(() -> {
            try (OpenSearchTestIndex index = OpenSearchTestIndex.open(
                    "traffic", () -> requests.getAndIncrement() == 0 ? before : after)) {
                assertThat(index.name()).isEqualTo("tool-burp-traffic");
            }
        }).isSameAs(failure);
    }

    private static OpenSearchClient client() {
        OpenSearchClient client = mock(OpenSearchClient.class);
        OpenSearchIndicesClient indices = mock(OpenSearchIndicesClient.class);
        when(client.indices()).thenReturn(indices);
        return client;
    }

    private static void assertDeletion(OpenSearchClient client, String name) throws IOException {
        ArgumentCaptor<DeleteIndexRequest> request = ArgumentCaptor.forClass(DeleteIndexRequest.class);
        verify(client.indices()).delete(request.capture());
        assertThat(request.getValue().index()).containsExactly(name);
        assertThat(request.getValue().ignoreUnavailable()).isTrue();
    }
}
