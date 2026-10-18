package ai.anomalousvectors.tools.burp.packaging;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.ServiceLoader;

import javax.net.ssl.SSLContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.luben.zstd.Zstd;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import jakarta.json.Json;
import jakarta.json.spi.JsonProvider;

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.brotli.dec.BrotliInputStream;
import org.slf4j.LoggerFactory;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClassicHttpSupport;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;
import ai.anomalousvectors.tools.burp.utils.search.SearchConnectionTester;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.http.SdkHttpService;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sso.SsoClient;
import software.amazon.awssdk.services.sso.auth.SsoCredentialsProvider;
import software.amazon.awssdk.services.ssooidc.SsoOidcClient;
import software.amazon.awssdk.services.sts.StsClient;

/**
 * Exercises only shipped dependencies in an isolated classloader.
 *
 * <p>Invoked reflectively by {@link PackagedJarTest}; this harness has no JUnit, Mockito, or
 * test-helper dependency. Network requests target only its own loopback fixture. Each invocation
 * closes its clients/server and leaves the operator's files and credentials untouched.</p>
 */
public final class PackagedRuntimeProbe {

    private PackagedRuntimeProbe() { }

    /**
     * Initializes critical non-AWS runtime paths using only the distributable and JDK.
     *
     * @throws Exception if a provider, codec, TLS context, or destination operation fails
     */
    public static void coreAndDestinations() throws Exception {
        check(JsonProvider.provider().getClass().getName().equals("org.eclipse.parsson.JsonProviderImpl"),
                "Explicit Parsson provider was not selected");
        try (var reader = Json.createReader(new java.io.StringReader("{\"ok\":true}"))) {
            check(reader.readObject().getBoolean("ok"), "JSON-P read failed");
        }
        check(new ObjectMapper().readTree("{\"ok\":true}").get("ok").asBoolean(), "Jackson read failed");
        check(LoggerFactory.getILoggerFactory().getClass().getName().equals("ch.qos.logback.classic.LoggerContext"),
                "Logback SLF4J provider was not selected");
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);
        check(context.getSocketFactory() != null, "TLS initialization failed");
        compression();

        HttpServer server = startServer();
        String endpoint = "http://127.0.0.1:" + server.getAddress().getPort();
        try {
            var client = OpenSearchConnector.getClient(endpoint, OpenSearchAuth.none());
            check(client.indices().create(request -> request.index("packaging-probe")
                    .mappings(mapping -> mapping.properties("marker", property -> property.keyword(k -> k))))
                    .acknowledged(), "OpenSearch index/mapping JSON-P path failed");
            var http = OpenSearchConnector.getClassicHttpClient(endpoint, OpenSearchAuth.none());
            HttpPost post = new HttpPost("/_bulk");
            post.setEntity(new StringEntity("{\"index\":{}}\n{\"marker\":\"packaged\"}\n",
                    org.apache.hc.core5.http.ContentType.APPLICATION_JSON));
            check(http.execute(OpenSearchClassicHttpSupport.hostForBaseUrl(endpoint), post,
                    response -> response.getCode()) == 200, "Classic bulk transport failed");
            SecureCredentialStore.saveBasicCredentials(ConfigState.SearchDestination.ELASTICSEARCH.configKey(),
                    "fixture-user", "fixture-password");
            var status = SearchConnectionTester.safeTestConnection(ConfigState.SearchDestination.ELASTICSEARCH, endpoint);
            check(status.success(), "Reflective Elasticsearch Test Connection failed: " + status.message());
            // Construct both TLS-capable client families without contacting an external host.
            OpenSearchConnector.getClassicHttpClient("https://127.0.0.1:1", OpenSearchAuth.none());
            OpenSearchConnector.getAsyncHttpClient("https://127.0.0.1:1", OpenSearchAuth.none());
        } finally {
            OpenSearchConnector.closeAll();
            server.stop(0);
            stopLogging();
        }
    }

    /**
     * Resolves profile credentials and calls retained AWS clients against a loopback fixture.
     *
     * <p>The STS role profile exercises the SDK's reflective profile factory and default synchronous
     * transport selection; SSO resolves an explicit refresh request without reading a user's token
     * cache. OIDC registration verifies the separately retained SSO login dependency.</p>
     *
     * @throws Exception if signing, credential resolution, service loading, or transport fails
     */
    public static void awsProfilesAndTransport() throws Exception {
        var services = ServiceLoader.load(SdkHttpService.class).stream()
                .map(provider -> provider.type().getName()).toList();
        check(services.equals(List.of("software.amazon.awssdk.http.apache5.Apache5SdkHttpService")),
                "Expected only the retained Apache5 synchronous transport: " + services);
        HttpServer server = startServer();
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        String previousEndpoint = System.getProperty("aws.endpointUrlSts");
        try {
            System.setProperty("aws.endpointUrlSts", endpoint.toString());
            ProfileFile profiles = ProfileFile.builder().type(ProfileFile.Type.CREDENTIALS)
                    .content(new ByteArrayInputStream("""
                            [source]
                            aws_access_key_id = packaging-access
                            aws_secret_access_key = packaging-secret
                            [role]
                            role_arn = arn:aws:iam::123456789012:role/packaging
                            source_profile = source
                            region = us-east-1
                            """.getBytes(StandardCharsets.UTF_8))).build();
            try (var basic = ProfileCredentialsProvider.builder().profileFile(profiles).profileName("source").build();
                    var role = ProfileCredentialsProvider.builder().profileFile(profiles).profileName("role").build()) {
                check(basic.resolveCredentials().accessKeyId().equals("packaging-access"), "Static profile failed");
                check(role.resolveCredentials().accessKeyId().equals("role-access"), "STS role profile failed");
            }
            var credentials = StaticCredentialsProvider.create(AwsBasicCredentials.create("fixture", "fixture"));
            var timeouts = ClientOverrideConfiguration.builder().apiCallTimeout(Duration.ofSeconds(5))
                    .apiCallAttemptTimeout(Duration.ofSeconds(3)).build();
            try (var sts = StsClient.builder().region(Region.US_EAST_1).credentialsProvider(credentials)
                    .overrideConfiguration(timeouts).endpointOverride(endpoint).build();
                    var sso = SsoClient.builder().region(Region.US_EAST_1).credentialsProvider(credentials)
                            .overrideConfiguration(timeouts).endpointOverride(endpoint).build();
                    var oidc = SsoOidcClient.builder().region(Region.US_EAST_1).credentialsProvider(credentials)
                            .overrideConfiguration(timeouts).endpointOverride(endpoint).build();
                    var ssoCredentials = ssoProvider(sso)) {
                check(sts.getCallerIdentity().account().equals("123456789012"), "STS synchronous client failed");
                check(ssoCredentials.resolveCredentials().accessKeyId().equals("sso-access"), "SSO resolution failed");
                check(oidc.registerClient(request -> request.clientName("packaging").clientType("public"))
                        .clientId().equals("loopback-client"), "SSO OIDC client failed");
            }
            Class.forName("software.amazon.awssdk.services.sso.auth.SsoProfileCredentialsProviderFactory")
                    .getConstructor().newInstance();
            signWithApplication();
        } finally {
            if (previousEndpoint == null) {
                System.clearProperty("aws.endpointUrlSts");
            } else {
                System.setProperty("aws.endpointUrlSts", previousEndpoint);
            }
            server.stop(0);
            stopLogging();
        }
    }

    private static SsoCredentialsProvider ssoProvider(SsoClient client) {
        SsoCredentialsProvider.Builder builder = SsoCredentialsProvider.builder();
        builder.ssoClient(client);
        builder.refreshRequest(software.amazon.awssdk.services.sso.model.GetRoleCredentialsRequest.builder()
                .accountId("123456789012").roleName("packaging").accessToken("loopback-fixture-token").build());
        return builder.build();
    }

    private static void stopLogging() throws ReflectiveOperationException {
        Object context = LoggerFactory.getILoggerFactory();
        context.getClass().getMethod("stop").invoke(context);
    }

    private static void signWithApplication() {
        var previous = RuntimeConfig.getState();
        var sinks = previous.sinks();
        String endpoint = "https://search-fixture.us-east-1.es.amazonaws.com";
        var options = new ConfigState.OpenSearchAmazonOptions(ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC,
                "", "us-east-1", "", "", "", ConfigState.DEPLOYMENT_HOSTED,
                ConfigState.OPEN_SEARCH_TLS_VERIFY, "", "", "");
        RuntimeConfig.updateState(new ConfigState.State(previous.dataSources(), previous.scopeType(), previous.customEntries(),
                new ConfigState.Sinks(false, "", false, false, true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT, true, endpoint, "", "",
                        ConfigState.OPEN_SEARCH_TLS_VERIFY, sinks.openSearchOptions(),
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(), endpoint, options,
                        "", ConfigState.defaultElasticsearchOptions()),
                previous.settingsSub(), previous.trafficToolTypes(), previous.findingsSeverities(),
                previous.enabledExportFieldsByIndex()));
        SecureCredentialStore.saveAwsStaticCredentials(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                "fixture-access", "fixture-secret", "fixture-token");
        try {
            HttpPost request = new HttpPost("/_bulk");
            AmazonOpenSearchSigV4.sign(request, "POST", endpoint, "/_bulk", new byte[] {1, 2, 3});
            check(request.getFirstHeader("Authorization").getValue().contains("/es/aws4_request"),
                    "Application reflective SigV4 signing failed");
            check(request.getFirstHeader("X-Amz-Security-Token").getValue().equals("fixture-token"),
                    "Session token signing failed");
        } finally {
            SecureCredentialStore.clearAwsStaticCredentials(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
            RuntimeConfig.updateState(previous);
        }
    }

    private static void compression() throws Exception {
        byte[] plain = "packaged compression".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = Zstd.compress(plain);
        check(Arrays.equals(Zstd.decompress(compressed, plain.length), plain), "Zstandard native round trip failed");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (var output = new BZip2CompressorOutputStream(bytes)) {
            output.write(plain);
        }
        try (var input = new BZip2CompressorInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            check(Arrays.equals(input.readAllBytes(), plain), "Commons Compress round trip failed");
        }
        // A fixed uncompressed Brotli stream avoids bundling a test encoder in the distributable.
        byte[] brotli = Base64.getDecoder().decode("CwKAcHJvYmUD");
        try (var input = new BrotliInputStream(new ByteArrayInputStream(brotli))) {
            check(new String(input.readAllBytes(), StandardCharsets.UTF_8).equals("probe"), "Brotli decoding failed");
        }
    }

    private static HttpServer startServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", PackagedRuntimeProbe::respond);
        server.start();
        return server;
    }

    private static void respond(HttpExchange exchange) throws java.io.IOException {
        try (exchange) {
            String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String body;
            boolean sts = request.contains("Action=");
            if (request.contains("Action=AssumeRole")) {
                body = """
                        <AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
                        <AssumeRoleResult><Credentials><AccessKeyId>role-access</AccessKeyId>
                        <SecretAccessKey>role-secret</SecretAccessKey><SessionToken>role-token</SessionToken>
                        <Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>
                        <AssumedRoleUser><AssumedRoleId>fixture:packaging</AssumedRoleId>
                        <Arn>arn:aws:sts::123456789012:assumed-role/packaging/fixture</Arn></AssumedRoleUser>
                        </AssumeRoleResult></AssumeRoleResponse>
                        """;
            } else if (sts) {
                body = """
                        <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
                        <GetCallerIdentityResult><Account>123456789012</Account><UserId>fixture</UserId>
                        <Arn>arn:aws:iam::123456789012:user/fixture</Arn></GetCallerIdentityResult>
                        </GetCallerIdentityResponse>
                        """;
            } else if (exchange.getRequestURI().getPath().contains("federation/credentials")) {
                body = """
                        {"roleCredentials":{"accessKeyId":"sso-access","secretAccessKey":"sso-secret",
                        "sessionToken":"sso-token","expiration":4070908800000}}
                        """;
            } else if (exchange.getRequestURI().getPath().contains("client/register")) {
                body = "{\"clientId\":\"loopback-client\",\"clientSecret\":\"fixture\"}";
            } else if (exchange.getRequestMethod().equals("PUT")) {
                body = "{\"acknowledged\":true,\"shards_acknowledged\":true,\"index\":\"packaging-probe\"}";
            } else {
                body = "{\"version\":{\"number\":\"9.5.4\"},\"cluster_uuid\":\"fixture\",\"errors\":false,\"items\":[]}";
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", sts ? "text/xml" : "application/json");
            exchange.getResponseHeaders().set("X-Elastic-Product", "Elasticsearch");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
