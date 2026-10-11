package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OpenSearchAuthCacheKeyTest {

    @Test
    void basicCacheKey_distinguishesSecretsWithoutRetainingThem() {
        assertSecretSeparated(
                OpenSearchAuth.basic("same-user", "first-password"),
                OpenSearchAuth.basic("same-user", "second-password"),
                "first-password",
                "second-password");
    }

    @Test
    void apiKeyCacheKey_distinguishesSecretsWithoutRetainingThem() {
        assertSecretSeparated(
                OpenSearchAuth.apiKey("first-api-key"),
                OpenSearchAuth.apiKey("second-api-key"),
                "first-api-key",
                "second-api-key");
    }

    @Test
    void bearerCacheKey_distinguishesSecretsWithoutRetainingThem() {
        assertSecretSeparated(
                OpenSearchAuth.bearerToken("first-bearer-token"),
                OpenSearchAuth.bearerToken("second-bearer-token"),
                "first-bearer-token",
                "second-bearer-token");
    }

    @Test
    void cacheKey_isStableForIdenticalHttpAuthenticationInputs() {
        assertThat(OpenSearchAuth.basic("same-user", "same-password").cacheKey())
                .isEqualTo(OpenSearchAuth.basic("same-user", "same-password").cacheKey());
        assertThat(OpenSearchAuth.apiKey("same-api-key").cacheKey())
                .isEqualTo(OpenSearchAuth.apiKey("same-api-key").cacheKey());
        assertThat(OpenSearchAuth.bearerToken("same-bearer-token").cacheKey())
                .isEqualTo(OpenSearchAuth.bearerToken("same-bearer-token").cacheKey());
    }

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

    private static void assertSecretSeparated(
            OpenSearchAuth first,
            OpenSearchAuth second,
            String firstSecret,
            String secondSecret) {
        String firstKey = first.cacheKey();
        String secondKey = second.cacheKey();

        assertThat(firstKey).isNotEqualTo(secondKey);
        assertThat(firstKey).doesNotContain(firstSecret).doesNotContain(secondSecret);
        assertThat(secondKey).doesNotContain(firstSecret).doesNotContain(secondSecret);
    }
}
