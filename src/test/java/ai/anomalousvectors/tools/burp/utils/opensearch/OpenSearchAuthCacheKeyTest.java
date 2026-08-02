package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OpenSearchAuthCacheKeyTest {

    @Test
    void certificateCacheKey_distinguishesDifferentNonblankPassphrases() {
        String first = OpenSearchAuth.certificate("client.pem", "client-key.pem", "first-secret").cacheKey();
        String second = OpenSearchAuth.certificate("client.pem", "client-key.pem", "second-secret").cacheKey();

        assertThat(first).isNotEqualTo(second);
        assertThat(first).doesNotContain("first-secret");
        assertThat(second).doesNotContain("second-secret");
    }

    @Test
    void certificateCacheKey_isStableForIdenticalInputs() {
        String first = OpenSearchAuth.certificate("client.pem", "client-key.pem", "same-secret").cacheKey();
        String second = OpenSearchAuth.certificate("client.pem", "client-key.pem", "same-secret").cacheKey();

        assertThat(first).isEqualTo(second);
        assertThat(first).doesNotContain("same-secret");
    }
}
