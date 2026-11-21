package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SearchAuthCacheKeyTest {

    @Test
    void basicCacheKey_distinguishesSecretsWithoutRetainingThem() {
        assertSecretSeparated(
                SearchAuth.basic("same-user", "first-password"),
                SearchAuth.basic("same-user", "second-password"),
                "first-password",
                "second-password");
    }

    @Test
    void apiKeyCacheKey_distinguishesSecretsWithoutRetainingThem() {
        assertSecretSeparated(
                SearchAuth.apiKey("first-api-key"),
                SearchAuth.apiKey("second-api-key"),
                "first-api-key",
                "second-api-key");
    }

    @Test
    void bearerCacheKey_distinguishesSecretsWithoutRetainingThem() {
        assertSecretSeparated(
                SearchAuth.bearerToken("first-bearer-token"),
                SearchAuth.bearerToken("second-bearer-token"),
                "first-bearer-token",
                "second-bearer-token");
    }

    @Test
    void cacheKey_isStableForIdenticalHttpAuthenticationInputs() {
        assertThat(SearchAuth.basic("same-user", "same-password").cacheKey())
                .isEqualTo(SearchAuth.basic("same-user", "same-password").cacheKey());
        assertThat(SearchAuth.apiKey("same-api-key").cacheKey())
                .isEqualTo(SearchAuth.apiKey("same-api-key").cacheKey());
        assertThat(SearchAuth.bearerToken("same-bearer-token").cacheKey())
                .isEqualTo(SearchAuth.bearerToken("same-bearer-token").cacheKey());
    }

    @Test
    void certificateCacheKey_distinguishesDifferentNonblankPassphrases() {
        String first = SearchAuth.certificate("client.pem", "client-key.pem", "first-secret").cacheKey();
        String second = SearchAuth.certificate("client.pem", "client-key.pem", "second-secret").cacheKey();

        assertThat(first).isNotEqualTo(second);
        assertThat(first).doesNotContain("first-secret");
        assertThat(second).doesNotContain("second-secret");
    }

    @Test
    void certificateCacheKey_isStableForIdenticalInputs() {
        String first = SearchAuth.certificate("client.pem", "client-key.pem", "same-secret").cacheKey();
        String second = SearchAuth.certificate("client.pem", "client-key.pem", "same-secret").cacheKey();

        assertThat(first).isEqualTo(second);
        assertThat(first).doesNotContain("same-secret");
    }

    private static void assertSecretSeparated(
            SearchAuth first,
            SearchAuth second,
            String firstSecret,
            String secondSecret) {
        String firstKey = first.cacheKey();
        String secondKey = second.cacheKey();

        assertThat(firstKey).isNotEqualTo(secondKey);
        assertThat(firstKey).doesNotContain(firstSecret).doesNotContain(secondSecret);
        assertThat(secondKey).doesNotContain(firstSecret).doesNotContain(secondSecret);
    }
}
