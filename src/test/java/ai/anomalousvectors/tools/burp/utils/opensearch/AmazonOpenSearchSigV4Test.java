package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;

/**
 * Unit coverage for Amazon SigV4 signing setup.
 *
 * <p>Setup/teardown run explicitly from each {@code @Test} (no lifecycle hooks) so IDE
 * "never used" hints do not fire.</p>
 */
class AmazonOpenSearchSigV4Test {

    private final ConfigState.State previous = RuntimeConfig.getState();

    private void prepareStaticAmazonRuntime() {
        prepareStaticAmazonRuntime(
                "",
                ConfigState.DEPLOYMENT_HOSTED,
                "https://search-example.us-east-1.es.amazonaws.com");
    }

    private void prepareStaticAmazonRuntime(
            String sessionToken,
            String deploymentType,
            String endpoint) {
        SecureCredentialStore.saveAwsStaticCredentials(
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                "AKIATESTACCESSKEY12",
                "testSecretAccessKeyValue123456789012",
                sessionToken);
        applyAmazonRuntime(
                endpoint,
                new ConfigState.OpenSearchAmazonOptions(
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC,
                        "",
                        "us-east-1",
                        "",
                        "",
                        "",
                        deploymentType,
                        ConfigState.OPEN_SEARCH_TLS_VERIFY,
                        "",
                        "",
                        ""));
    }

    private void prepareProfileAmazonRuntime(Path credentialsFile) {
        applyAmazonRuntime(
                "https://search-example.us-east-1.es.amazonaws.com",
                new ConfigState.OpenSearchAmazonOptions(
                        ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE,
                        "",
                        "us-east-1",
                        "test-profile",
                        credentialsFile.toString(),
                        "",
                        ConfigState.DEPLOYMENT_HOSTED,
                        ConfigState.OPEN_SEARCH_TLS_VERIFY,
                        "",
                        "",
                        ""));
    }

    private static void applyAmazonRuntime(
            String endpoint,
            ConfigState.OpenSearchAmazonOptions amazonOptions) {
        RuntimeConfig.updateState(new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, "", false, true,
                        true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        true, "https://opensearch.url:9200", "", "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY,
                        ConfigState.defaultOpenSearchOptions(),
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                        endpoint,
                        amazonOptions,
                        "http://localhost:9201",
                        ConfigState.defaultElasticsearchOptions()),
                ConfigState.DEFAULT_SETTINGS_SUB,
                ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null));
    }

    private void restore() {
        SecureCredentialStore.clearAwsStaticCredentials(
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
        RuntimeConfig.updateState(previous);
        RuntimeConfig.setExportRunning(false);
        RuntimeConfig.setExportStarting(false);
    }

    @Test
    void sign_staticCredentials_addsAuthorizationHeader() {
        prepareStaticAmazonRuntime();
        try {
            assertThat(AmazonOpenSearchSigV4.validationMessage(
                    "https://search-example.us-east-1.es.amazonaws.com")).isBlank();
            HttpGet get = new HttpGet("/");
            assertThatCode(() -> AmazonOpenSearchSigV4.sign(
                    get,
                    "GET",
                    "https://search-example.us-east-1.es.amazonaws.com",
                    "/",
                    new byte[0])).doesNotThrowAnyException();
            assertThat(get.containsHeader("Authorization")).isTrue();
            assertThat(get.getFirstHeader("Authorization").getValue()).startsWith("AWS4-HMAC-SHA256");
        } finally {
            restore();
        }
    }

    @Test
    void sign_staticSessionCredentials_usesServerlessScopeAndSecurityToken() {
        String endpoint = "https://collection.us-east-1.aoss.amazonaws.com";
        prepareStaticAmazonRuntime(
                "test-session-token",
                ConfigState.DEPLOYMENT_SERVERLESS,
                endpoint);
        try {
            HttpGet get = new HttpGet("/");

            AmazonOpenSearchSigV4.sign(get, "GET", endpoint, "/", new byte[0]);

            assertThat(get.getFirstHeader("Authorization").getValue())
                    .contains("/aoss/aws4_request");
            assertThat(get.getFirstHeader("X-Amz-Security-Token").getValue())
                    .isEqualTo("test-session-token");
        } finally {
            restore();
        }
    }

    @Test
    void sign_profileCredentials_usesConfiguredProfileFile() throws Exception {
        Path credentialsFile = TestPathSupport.createFile("aws-profile", ".credentials");
        Files.writeString(credentialsFile, """
                [test-profile]
                aws_access_key_id = AKIAPROFILEACCESS12
                aws_secret_access_key = profileSecretAccessKeyValue123456789
                """);
        prepareProfileAmazonRuntime(credentialsFile);
        try {
            HttpGet get = new HttpGet("/");

            AmazonOpenSearchSigV4.sign(
                    get,
                    "GET",
                    "https://search-example.us-east-1.es.amazonaws.com",
                    "/",
                    new byte[0]);

            assertThat(get.getFirstHeader("Authorization").getValue())
                    .contains("Credential=AKIAPROFILEACCESS12/");
        } finally {
            restore();
        }
    }

    @Test
    void buildSdkRequest_separatesEncodedPathAndRepeatedQueryParameters() throws Exception {
        Object request = AmazonOpenSearchSigV4.buildSdkRequest(
                "GET",
                "/tool-burp-traffic/_settings"
                        + "?flat_settings=true&tag=first&tag=second&encoded=a%2Fb%20c&blank=",
                URI.create("https://search-example.us-east-1.es.amazonaws.com"),
                new byte[0]);

        Class<?> requestType = Class.forName("software.amazon.awssdk.http.SdkHttpRequest");
        assertThat(requestType.getMethod("encodedPath").invoke(request))
                .isEqualTo("/tool-burp-traffic/_settings");

        Object rawParameters = requestType.getMethod("rawQueryParameters").invoke(request);
        assertThat(rawParameters).isInstanceOf(Map.class);
        Map<?, ?> parameters = (Map<?, ?>) rawParameters;
        assertThat(parameters.get("flat_settings")).isEqualTo(List.of("true"));
        assertThat(parameters.get("tag")).isEqualTo(List.of("first", "second"));
        assertThat(parameters.get("encoded")).isEqualTo(List.of("a/b c"));
        List<?> blankValues = (List<?>) parameters.get("blank");
        assertThat(blankValues).hasSize(1);
        assertThat(blankValues.getFirst()).isNull();
    }
}
