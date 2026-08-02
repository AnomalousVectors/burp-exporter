package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensearch.client.opensearch.OpenSearchClient;

import ai.anomalousvectors.tools.burp.testutils.Reflect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link OpenSearchConnector}.
 * The connector configures the HTTP client with {@code HttpVersionPolicy.NEGOTIATE} so that
 * HTTP/2 is preferred with fallback to HTTP/1.1; see {@link OpenSearchConnector#buildClient}.
 */
class OpenSearchConnectorTest {

    private static final String DUMMY_URL = "https://localhost:9243";

    // The connector uses static caches; ensure each test starts and ends with a clean slate so
    // interactions between tests (identity checks, rebuild-after-close) do not bleed over.

    @BeforeEach
    public void clearCachesBefore() {
        OpenSearchConnector.closeAll();
    }

    @AfterEach
    public void clearCachesAfter() {
        OpenSearchConnector.closeAll();
    }

    @Test
    void getClient_returnsNonNull() {
        OpenSearchClient client = OpenSearchConnector.getClient(DUMMY_URL);
        assertThat(client).isNotNull();
    }

    @Test
    void getClient_withSameKey_returnsSameCachedInstance() {
        OpenSearchClient a = OpenSearchConnector.getClient(DUMMY_URL);
        OpenSearchClient b = OpenSearchConnector.getClient(DUMMY_URL);
        assertThat(a).isSameAs(b);
    }

    @Test
    void getClient_withCredentials_returnsNonNull() {
        OpenSearchClient client = OpenSearchConnector.getClient(DUMMY_URL, "user", "pass");
        assertThat(client).isNotNull();
    }

    @Test
    void getClassicHttpClient_returnsNonNull() {
        CloseableHttpClient client = OpenSearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        assertThat(client).isNotNull();
    }

    @Test
    void getClassicHttpClient_withSameKey_returnsSameCachedInstance() {
        CloseableHttpClient a = OpenSearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        CloseableHttpClient b = OpenSearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        assertThat(a).isSameAs(b);
    }

    @Test
    void closeAll_dropsCachedClientsSoNextGetRebuilds() {
        // Prime both caches so there's something for closeAll() to release.
        OpenSearchClient opensearchBefore = OpenSearchConnector.getClient(DUMMY_URL);
        CloseableHttpClient classicBefore = OpenSearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");

        OpenSearchConnector.closeAll();

        // After closeAll(), a second getClient(...) must rebuild rather than return the closed
        // instance; identity comparison is the simplest observable way to assert cache clearance
        // without exposing package-private state.
        OpenSearchClient opensearchAfter = OpenSearchConnector.getClient(DUMMY_URL);
        CloseableHttpClient classicAfter = OpenSearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        assertThat(opensearchAfter).isNotSameAs(opensearchBefore);
        assertThat(classicAfter).isNotSameAs(classicBefore);
    }

    @Test
    void redactKey_stripsCredentialsAndPreservesInsecureMarker() {
        // Auth-bearing key: "<url>|<user>|<pass>|insecure=<bool>|tls=...|pin=...". The redacted
        // form must drop the user/password segment but keep the |insecure= tail so debug/warn
        // logs still surface useful environmental signal without leaking credentials.
        String redacted = OpenSearchConnector.redactKey(
                "https://os.example:9200|admin|s3cret|insecure=false|tls=DEFAULT|pin=");
        assertThat(redacted)
                .doesNotContain("admin")
                .doesNotContain("s3cret")
                .startsWith("https://os.example:9200")
                .contains("|insecure=false");
    }

    @Test
    void redactKey_handlesNullAndAuthlessKeys() {
        // No-auth key: no "|" separator; redaction must be a no-op.
        assertThat(OpenSearchConnector.redactKey(null)).isEqualTo("null");
        assertThat(OpenSearchConnector.redactKey("https://os.example:9200"))
                .isEqualTo("https://os.example:9200");
    }

    @Test
    void closeAll_isIdempotentOnEmptyAndPopulatedCaches() {
        // Empty: no clients primed.
        assertThatCode(OpenSearchConnector::closeAll).doesNotThrowAnyException();

        // Populated: prime, close, then call again.
        OpenSearchConnector.getClient(DUMMY_URL);
        OpenSearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        OpenSearchConnector.closeAll();
        assertThatCode(OpenSearchConnector::closeAll).doesNotThrowAnyException();
    }

    @Test
    void cacheCreationAndDetachment_shareOneLifecycleLock() throws Exception {
        Object lifecycleLock = Reflect.getStatic(
                OpenSearchConnector.class, "clientLifecycleLock", Object.class);
        CountDownLatch ready = new CountDownLatch(2);
        AtomicBoolean getterDone = new AtomicBoolean();
        AtomicBoolean closerDone = new AtomicBoolean();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread getter = new Thread(() -> {
            ready.countDown();
            try {
                OpenSearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
                getterDone.set(true);
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        });
        Thread closer = new Thread(() -> {
            ready.countDown();
            try {
                OpenSearchConnector.closeAll();
                closerDone.set(true);
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        });

        synchronized (lifecycleLock) {
            getter.start();
            closer.start();
            assertThat(ready.await(1, TimeUnit.SECONDS)).isTrue();
            TimeUnit.MILLISECONDS.sleep(50L);
            assertThat(getterDone.get()).isFalse();
            assertThat(closerDone.get()).isFalse();
        }
        getter.join(2_000L);
        closer.join(2_000L);

        assertThat(failure.get()).isNull();
        assertThat(getterDone.get()).isTrue();
        assertThat(closerDone.get()).isTrue();
    }
}
