package ai.anomalousvectors.tools.burp.utils.search;

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
 * Unit tests for {@link SearchConnector}.
 * The connector configures the HTTP client with {@code HttpVersionPolicy.NEGOTIATE} so that
 * HTTP/2 is preferred with fallback to HTTP/1.1; see {@link SearchConnector#buildClient}.
 */
class SearchConnectorTest {

    private static final String DUMMY_URL = "https://localhost:9243";

    // The connector uses static caches; ensure each test starts and ends with a clean slate so
    // interactions between tests (identity checks, rebuild-after-close) do not bleed over.

    @BeforeEach
    public void clearCachesBefore() {
        SearchConnector.closeAll();
    }

    @AfterEach
    public void clearCachesAfter() {
        SearchConnector.closeAll();
    }

    @Test
    void getClient_returnsNonNull() {
        OpenSearchClient client = SearchConnector.getClient(DUMMY_URL);
        assertThat(client).isNotNull();
    }

    @Test
    void getClient_withSameKey_returnsSameCachedInstance() {
        OpenSearchClient a = SearchConnector.getClient(DUMMY_URL);
        OpenSearchClient b = SearchConnector.getClient(DUMMY_URL);
        assertThat(a).isSameAs(b);
    }

    @Test
    void getClient_withEquivalentRootUrls_returnsSameCachedInstance() {
        OpenSearchClient a = SearchConnector.getClient("HTTPS://LOCALHOST:443/");
        OpenSearchClient b = SearchConnector.getClient("https://localhost");
        assertThat(a).isSameAs(b);
    }

    @Test
    void getClient_withCredentials_returnsNonNull() {
        OpenSearchClient client = SearchConnector.getClient(DUMMY_URL, "user", "pass");
        assertThat(client).isNotNull();
    }

    @Test
    void getClient_cacheSeparatesAuthenticationModesAndSecretValues() {
        String url = "http://localhost:9200";
        OpenSearchClient basic = SearchConnector.getClient(url, SearchAuth.basic("user", "first"));
        OpenSearchClient basicAgain = SearchConnector.getClient(url, SearchAuth.basic("user", "first"));
        OpenSearchClient differentBasic = SearchConnector.getClient(
                url, SearchAuth.basic("user", "second"));
        OpenSearchClient apiKey = SearchConnector.getClient(url, SearchAuth.apiKey("first"));
        OpenSearchClient bearer = SearchConnector.getClient(url, SearchAuth.bearerToken("first"));

        assertThat(basicAgain).isSameAs(basic);
        assertThat(differentBasic).isNotSameAs(basic);
        assertThat(apiKey).isNotSameAs(basic).isNotSameAs(differentBasic);
        assertThat(bearer).isNotSameAs(basic).isNotSameAs(differentBasic).isNotSameAs(apiKey);
    }

    @Test
    void getClassicHttpClient_returnsNonNull() {
        CloseableHttpClient client = SearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        assertThat(client).isNotNull();
    }

    @Test
    void getClassicHttpClient_withSameKey_returnsSameCachedInstance() {
        CloseableHttpClient a = SearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        CloseableHttpClient b = SearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        assertThat(a).isSameAs(b);
    }

    @Test
    void getClassicHttpClient_withEquivalentRootUrls_returnsSameCachedInstance() {
        CloseableHttpClient a = SearchConnector.getClassicHttpClient(
                "http://LOCALHOST:80/", "user", "pass");
        CloseableHttpClient b = SearchConnector.getClassicHttpClient(
                "http://localhost", "user", "pass");
        assertThat(a).isSameAs(b);
    }

    @Test
    void closeAll_dropsCachedClientsSoNextGetRebuilds() {
        // Prime both caches so there's something for closeAll() to release.
        OpenSearchClient opensearchBefore = SearchConnector.getClient(DUMMY_URL);
        CloseableHttpClient classicBefore = SearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");

        SearchConnector.closeAll();

        // After closeAll(), a second getClient(...) must rebuild rather than return the closed
        // instance; identity comparison is the simplest observable way to assert cache clearance
        // without exposing package-private state.
        OpenSearchClient opensearchAfter = SearchConnector.getClient(DUMMY_URL);
        CloseableHttpClient classicAfter = SearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        assertThat(opensearchAfter).isNotSameAs(opensearchBefore);
        assertThat(classicAfter).isNotSameAs(classicBefore);
    }

    @Test
    void redactKey_stripsCredentialsAndPreservesInsecureMarker() {
        // Auth-bearing key: "<url>|<user>|<pass>|insecure=<bool>|tls=...|pin=...". The redacted
        // form must drop the user/password segment but keep the |insecure= tail so debug/warn
        // logs still surface useful environmental signal without leaking credentials.
        String redacted = SearchConnector.redactKey(
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
        assertThat(SearchConnector.redactKey(null)).isEqualTo("null");
        assertThat(SearchConnector.redactKey("https://os.example:9200"))
                .isEqualTo("https://os.example:9200");
    }

    @Test
    void closeAll_isIdempotentOnEmptyAndPopulatedCaches() {
        // Empty: no clients primed.
        assertThatCode(SearchConnector::closeAll).doesNotThrowAnyException();

        // Populated: prime, close, then call again.
        SearchConnector.getClient(DUMMY_URL);
        SearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
        SearchConnector.closeAll();
        assertThatCode(SearchConnector::closeAll).doesNotThrowAnyException();
    }

    @Test
    void cacheCreationAndDetachment_shareOneLifecycleLock() throws Exception {
        Object lifecycleLock = Reflect.getStatic(
                SearchConnector.class, "clientLifecycleLock", Object.class);
        CountDownLatch ready = new CountDownLatch(2);
        AtomicBoolean getterDone = new AtomicBoolean();
        AtomicBoolean closerDone = new AtomicBoolean();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread getter = new Thread(() -> {
            ready.countDown();
            try {
                SearchConnector.getClassicHttpClient(DUMMY_URL, "user", "pass");
                getterDone.set(true);
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        });
        Thread closer = new Thread(() -> {
            ready.countDown();
            try {
                SearchConnector.closeAll();
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
