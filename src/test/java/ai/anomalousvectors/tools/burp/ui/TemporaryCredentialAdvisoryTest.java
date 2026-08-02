package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

class TemporaryCredentialAdvisoryTest {

    @Test
    void forAmazonSessionToken_requiresStaticAuthAndNonBlankToken() {
        assertThat(TemporaryCredentialAdvisory.forAmazonSessionToken(
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC, "temp-token"))
                .isPresent()
                .get()
                .satisfies(active -> {
                    assertThat(active.kind()).isEqualTo(TemporaryCredentialAdvisory.Kind.AWS_SESSION_TOKEN);
                    assertThat(active.uiText()).contains("Elevated risk");
                    assertThat(active.logMessage()).contains("session token is set");
                });

        assertThat(TemporaryCredentialAdvisory.forAmazonSessionToken(
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC, "  ")).isEmpty();
        assertThat(TemporaryCredentialAdvisory.forAmazonSessionToken(
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE, "temp-token")).isEmpty();
    }

    @Test
    void forBearerToken_requiresBearerAuthTypeOnly() {
        assertThat(TemporaryCredentialAdvisory.forBearerToken("OpenSearch", "Bearer token", "jwt"))
                .isPresent()
                .get()
                .satisfies(active -> {
                    assertThat(active.kind()).isEqualTo(TemporaryCredentialAdvisory.Kind.BEARER_TOKEN);
                    assertThat(active.logMessage()).contains("[OpenSearch]");
                    assertThat(active.logMessage()).contains("Bearer token auth is selected");
                });

        assertThat(TemporaryCredentialAdvisory.forBearerToken("Elasticsearch", "Bearer token", ""))
                .isPresent();
        assertThat(TemporaryCredentialAdvisory.forBearerToken("OpenSearch", "API key", "jwt")).isEmpty();
    }

    @Test
    void forRuntimeSelection_readsAmazonSessionTokenFromStore() {
        SecureCredentialStore.clearAll();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_SETTINGS),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(
                            false, "", false, true,
                            true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                            true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                            true, "https://opensearch.url:9200", "", "",
                            ConfigState.OPEN_SEARCH_TLS_VERIFY,
                            ConfigState.defaultOpenSearchOptions(),
                            ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                            "https://my-hosted-opensearch-project-00000000000000000000abc123.us-east-1.es.amazonaws.com",
                            new ConfigState.OpenSearchAmazonOptions(
                                    ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC,
                                    "",
                                    "us-east-1",
                                    "",
                                    "",
                                    "",
                                    ConfigState.DEPLOYMENT_HOSTED,
                                    ConfigState.OPEN_SEARCH_TLS_VERIFY,
                                    "",
                                    "",
                                    ""),
                            "https://elasticsearch.url:443",
                            ConfigState.defaultElasticsearchOptions()),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));

            SecureCredentialStore.saveAwsStaticCredentials(
                    ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                    "AKIAEXAMPLE",
                    "secret",
                    "session-token");

            TemporaryCredentialAdvisory.Active active = TemporaryCredentialAdvisory.forRuntimeSelection()
                    .orElseThrow();
            assertThat(active.kind()).isEqualTo(TemporaryCredentialAdvisory.Kind.AWS_SESSION_TOKEN);
        } finally {
            SecureCredentialStore.clearAll();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportStarting(false);
        }
    }

    @Test
    void defaultAmazonAuthType_isProfile() {
        assertThat(ConfigState.DEFAULT_OPEN_SEARCH_AMAZON_AUTH_TYPE)
                .isEqualTo(ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE);
        assertThat(ConfigState.defaultOpenSearchAmazonOptions().authType())
                .isEqualTo(ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE);
        assertThat(ConfigState.normalizeOpenSearchAmazonAuthType("IAM (sigV4)"))
                .isEqualTo(ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC);
        assertThat(ConfigState.normalizeOpenSearchAmazonAuthType(""))
                .isEqualTo(ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE);
    }
}
