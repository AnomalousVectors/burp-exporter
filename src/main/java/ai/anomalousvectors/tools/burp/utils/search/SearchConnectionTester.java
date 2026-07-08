package ai.anomalousvectors.tools.burp.utils.search;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.hc.core5.ssl.SSLContextBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchLogFormat;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchTlsSupport;

/**
 * Routes search-destination connection tests to destination-specific client implementations.
 */
public final class SearchConnectionTester {
    private static final ObjectMapper JSON = new ObjectMapper();

    private SearchConnectionTester() {
        throw new AssertionError("No instances");
    }

    /** Tests connectivity for the selected database destination. */
    public static SearchConnectionStatus safeTestConnection(ConfigState.SearchDestination destination, String baseUrl) {
        return switch (destination) {
            case OPEN_SEARCH -> OpenSearchClientWrapper.safeTestConnection(baseUrl, OpenSearchAuth.fromRuntime());
            case OPEN_SEARCH_AMAZON -> safeTestOpenSearchAmazonConnection(baseUrl);
            case ELASTICSEARCH -> safeTestElasticsearchConnection(baseUrl);
        };
    }

    private static SearchConnectionStatus safeTestElasticsearchConnection(String baseUrl) {
        OpenSearchAuth auth = elasticsearchAuthFromSession();
        if (!auth.isComplete()) {
            String msg = auth.validationMessage().replace("OpenSearch", "Elasticsearch");
            Logger.logWarnPanelOnly("[Elasticsearch] Test connection skipped: " + msg);
            return new SearchConnectionStatus("Elasticsearch", false, "", "", msg,
                    "Failed", "Failed", "Not tested");
        }
        try {
            return testElasticsearchConnection(baseUrl, auth);
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            String msg = rootMessage(e);
            Logger.logWarnPanelOnly("[Elasticsearch] Test connection failed for " + baseUrl + ": " + msg);
            return new SearchConnectionStatus("Elasticsearch", false, "", "", msg,
                    "Failed", "Not tested", OpenSearchTlsSupport.failureTrustSummary(
                            baseUrl, msg, ConfigState.SearchDestination.ELASTICSEARCH));
        }
    }

    private static SearchConnectionStatus testElasticsearchConnection(String baseUrl, OpenSearchAuth auth)
            throws GeneralSecurityException, IOException {
        Object restClient = null;
        try {
            Class<?> restClientClass = Class.forName("org.elasticsearch.client.RestClient");
            Class<?> httpHostClass = Class.forName("org.apache.http.HttpHost");
            Object host = httpHostClass.getMethod("create", String.class).invoke(null, baseUrl);
            Object hosts = Array.newInstance(httpHostClass, 1);
            Array.set(hosts, 0, host);
            Object builder = restClientClass.getMethod("builder", hosts.getClass()).invoke(null, hosts);
            String tlsMode = elasticsearchTlsMode();
            applyElasticsearchSecurity(builder, baseUrl, auth, tlsMode);
            restClient = builder.getClass().getMethod("build").invoke(builder);

            RawHttpResult result = performElasticsearchRootGet(restClient, baseUrl, auth);
            if (result.statusCode() > 0) {
                Logger.logDebug("[Elasticsearch] Request:\n" + OpenSearchLogFormat.indentRaw(result.requestForLog()));
                String responseLog = OpenSearchLogFormat.buildRawResponseWithHeaders(
                        result.body(), result.protocol(), result.statusCode(), result.reasonPhrase(),
                        result.responseHeaderLines());
                Logger.logDebug("[Elasticsearch] Response:\n" + OpenSearchLogFormat.indentRaw(responseLog));
            }
            if (result.statusCode() != 200) {
                String msg = result.statusCode() == 0
                        ? (result.reasonPhrase() == null || result.reasonPhrase().isBlank()
                                ? "Connection failed"
                                : result.reasonPhrase())
                        : "HTTP " + result.statusCode()
                                + (result.reasonPhrase() == null || result.reasonPhrase().isBlank()
                                        ? ""
                                        : " " + result.reasonPhrase());
                return new SearchConnectionStatus("Elasticsearch", false, "", "", msg,
                        "Failed", authStatusForHttpFailure(auth, result.statusCode()),
                        result.statusCode() == 0
                                ? OpenSearchTlsSupport.failureTrustSummary(
                                        baseUrl, msg, ConfigState.SearchDestination.ELASTICSEARCH)
                                : OpenSearchTlsSupport.successTrustSummary(
                                        baseUrl, ConfigState.SearchDestination.ELASTICSEARCH));
            }
            String version = elasticsearchVersionFromBody(result.body());
            String authStatus = auth.mode() == OpenSearchAuth.Mode.NONE ? "Not used" : "Successful";
            Logger.logDebug("[Elasticsearch] Connection test succeeded: auth=" + authStatus
                    + ", version=" + version);
            return new SearchConnectionStatus("Elasticsearch", true, "", version,
                    "Connection successful", "Success", authStatus,
                    OpenSearchTlsSupport.successTrustSummary(baseUrl, ConfigState.SearchDestination.ELASTICSEARCH));
        } catch (ReflectiveOperationException e) {
            throw new IOException("Elasticsearch client invocation failed: " + rootMessage(e), e);
        } finally {
            closeQuietly(restClient);
        }
    }

    private record RawHttpResult(
            int statusCode,
            String protocol,
            String reasonPhrase,
            String body,
            String requestForLog,
            List<String> responseHeaderLines) {
    }

    private static RawHttpResult performElasticsearchRootGet(Object restClient, String baseUrl, OpenSearchAuth auth)
            throws ReflectiveOperationException, IOException {
        Class<?> requestClass = Class.forName("org.elasticsearch.client.Request");
        Object request = requestClass.getConstructor(String.class, String.class).newInstance("GET", "/");
        Object response;
        try {
            response = restClient.getClass().getMethod("performRequest", requestClass).invoke(restClient, request);
        } catch (InvocationTargetException e) {
            Throwable invocationCause = e.getCause();
            Object errorResponse = elasticsearchResponseFromException(invocationCause);
            if (errorResponse != null) {
                return elasticsearchResponseToRawResult(errorResponse, baseUrl, auth);
            }
            Throwable cause = invocationCause == null ? e : invocationCause;
            String requestForLog = OpenSearchLogFormat.formatRequestForLog(
                    "GET", "/", baseUrl, OpenSearchLogFormat.parseProtocolFromException(cause),
                    auth.redactedAuthorizationForLog());
            return new RawHttpResult(0, null, rootMessage(cause), "", requestForLog, List.of());
        }
        return elasticsearchResponseToRawResult(response, baseUrl, auth);
    }

    private static Object elasticsearchResponseFromException(Throwable throwable) {
        if (throwable == null) {
            return null;
        }
        try {
            return throwable.getClass().getMethod("getResponse").invoke(throwable);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return null;
        }
    }

    private static RawHttpResult elasticsearchResponseToRawResult(
            Object response, String baseUrl, OpenSearchAuth auth)
            throws ReflectiveOperationException, IOException {
        Object statusLine = response.getClass().getMethod("getStatusLine").invoke(response);
        int statusCode = ((Number) statusLine.getClass().getMethod("getStatusCode").invoke(statusLine)).intValue();
        Object protocolValue = statusLine.getClass().getMethod("getProtocolVersion").invoke(statusLine);
        String protocol = protocolValue == null ? null : String.valueOf(protocolValue);
        Object reasonValue = statusLine.getClass().getMethod("getReasonPhrase").invoke(statusLine);
        String reason = reasonValue == null ? "" : String.valueOf(reasonValue);
        String requestForLog = OpenSearchLogFormat.formatRequestForLog(
                "GET", "/", baseUrl, protocol, auth.redactedAuthorizationForLog());
        return new RawHttpResult(
                statusCode,
                protocol,
                reason,
                elasticsearchResponseBody(response),
                requestForLog,
                elasticsearchHeaderLines(response));
    }

    private static List<String> elasticsearchHeaderLines(Object response) throws ReflectiveOperationException {
        Object headers = response.getClass().getMethod("getHeaders").invoke(response);
        int length = headers == null || !headers.getClass().isArray() ? 0 : Array.getLength(headers);
        List<String> lines = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            Object header = Array.get(headers, i);
            if (header == null) {
                continue;
            }
            String name = String.valueOf(header.getClass().getMethod("getName").invoke(header));
            Object value = header.getClass().getMethod("getValue").invoke(header);
            lines.add(name + ": " + (OpenSearchLogFormat.shouldRedactHeader(name)
                    ? "***"
                    : value == null ? "" : String.valueOf(value)));
        }
        return lines;
    }

    private static String elasticsearchResponseBody(Object response) throws ReflectiveOperationException, IOException {
        Object entity = response.getClass().getMethod("getEntity").invoke(response);
        if (entity == null) {
            return "";
        }
        Object content = entity.getClass().getMethod("getContent").invoke(entity);
        if (!(content instanceof InputStream input)) {
            return "";
        }
        try (input) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String authStatusForHttpFailure(OpenSearchAuth auth, int statusCode) {
        return switch (statusCode) {
            case 401, 403 -> "Failed";
            case 0 -> "Not tested";
            default -> auth.mode() == OpenSearchAuth.Mode.NONE ? "Not used" : "Attempted";
        };
    }

    private static SearchConnectionStatus safeTestOpenSearchAmazonConnection(String baseUrl) {
        try {
            ConfigState.State state = RuntimeConfig.getState();
            ConfigState.OpenSearchAmazonOptions options = state == null || state.sinks() == null
                    ? ConfigState.defaultOpenSearchAmazonOptions()
                    : state.sinks().openSearchAmazonOptions();
            if (options.region().isBlank()) {
                return new SearchConnectionStatus("Amazon OpenSearch", false, "", "", "AWS region is required.",
                        "Failed", "Not tested", "Not tested");
            }
            if ("Basic".equals(options.authType())) {
                SecureCredentialStore.BasicCredentials basic =
                        SecureCredentialStore.loadBasicCredentials(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
                if (basic.username().isBlank() || basic.password().isBlank()) {
                    return new SearchConnectionStatus("Amazon OpenSearch", false, "", "",
                            "Amazon OpenSearch Basic auth requires username and password.",
                            "Failed", "Failed", "Not tested");
                }
                return new SearchConnectionStatus("Amazon OpenSearch", false, "", "",
                        "Amazon OpenSearch Basic credentials are present in session memory. Live signed domain requests are not wired for Test Connection yet.",
                        "Not tested", "Credentials present", "Not tested");
            }
            Object provider = options.profile().isBlank()
                    ? buildDefaultAwsCredentialsProvider()
                    : buildProfileAwsCredentialsProvider(options.profile());
            Object credentials = provider.getClass().getMethod("resolveCredentials").invoke(provider);
            String accessKeyId = String.valueOf(credentials.getClass().getMethod("accessKeyId").invoke(credentials));
            boolean resolved = accessKeyId != null && !accessKeyId.isBlank() && !"null".equals(accessKeyId);
            String detail = resolved
                    ? "AWS credentials resolved for SigV4 only; no signed OpenSearch domain request was sent."
                    : "AWS credentials were not resolved.";
            Logger.logInfoPanelOnly("[Amazon OpenSearch] " + detail);
            return new SearchConnectionStatus("Amazon OpenSearch", false, "", "", detail,
                    "Not tested", resolved ? "Credentials resolved" : "Failed", "Not tested");
        } catch (ReflectiveOperationException | RuntimeException e) {
            String msg = rootMessage(e);
            Logger.logWarnPanelOnly("[Amazon OpenSearch] Credential resolution failed for " + baseUrl + ": " + msg);
            return new SearchConnectionStatus("Amazon OpenSearch", false, "", "", msg,
                    "Failed", "Failed", "Not tested");
        }
    }

    private static OpenSearchAuth elasticsearchAuthFromSession() {
        return OpenSearchAuth.fromRuntime(ConfigState.SearchDestination.ELASTICSEARCH);
    }

    private static void applyElasticsearchSecurity(Object builder, String baseUrl, OpenSearchAuth auth, String tlsMode)
            throws ReflectiveOperationException, GeneralSecurityException, IOException {
        if (auth != null && auth.usesAuthorizationHeader()) {
            Class<?> headerClass = Class.forName("org.apache.http.Header");
            Class<?> basicHeaderClass = Class.forName("org.apache.http.message.BasicHeader");
            Object header = basicHeaderClass
                    .getConstructor(String.class, String.class)
                    .newInstance("Authorization", auth.authorizationHeaderValue());
            Object headers = Array.newInstance(headerClass, 1);
            Array.set(headers, 0, header);
            builder.getClass().getMethod("setDefaultHeaders", headers.getClass()).invoke(builder, headers);
        }
        if (requiresElasticsearchTlsCallback(baseUrl, auth, tlsMode)) {
            SSLContext sslContext = sslContextForElasticsearch(auth, tlsMode);
            Class<?> callbackClass = Class.forName("org.elasticsearch.client.RestClientBuilder$HttpClientConfigCallback");
            Object callback = Proxy.newProxyInstance(
                    callbackClass.getClassLoader(),
                    new Class<?>[] { callbackClass },
                    (proxy, method, args) -> {
                        if ("customizeHttpClient".equals(method.getName()) && args != null && args.length == 1) {
                            Object httpClientBuilder = args[0];
                            httpClientBuilder.getClass()
                                    .getMethod("setSSLContext", SSLContext.class)
                                    .invoke(httpClientBuilder, sslContext);
                            if (OpenSearchTlsSupport.isInsecureMode(tlsMode)) {
                                HostnameVerifier trustAllHostnames = (hostname, session) -> true;
                                httpClientBuilder.getClass()
                                        .getMethod("setSSLHostnameVerifier", HostnameVerifier.class)
                                        .invoke(httpClientBuilder, trustAllHostnames);
                            }
                            return httpClientBuilder;
                        }
                        if ("toString".equals(method.getName())) {
                            return "ElasticsearchTlsCallback";
                        }
                        return null;
                    });
            builder.getClass().getMethod("setHttpClientConfigCallback", callbackClass).invoke(builder, callback);
        }
    }

    private static boolean requiresElasticsearchTlsCallback(String baseUrl, OpenSearchAuth auth, String tlsMode) {
        boolean https = baseUrl != null && baseUrl.trim().toLowerCase(java.util.Locale.ROOT).startsWith("https://");
        if (!https) {
            return false;
        }
        boolean certificateAuth = auth != null && auth.mode() == OpenSearchAuth.Mode.CERTIFICATE;
        return certificateAuth || OpenSearchTlsSupport.isInsecureMode(tlsMode)
                || OpenSearchTlsSupport.isPinnedMode(tlsMode);
    }

    private static SSLContext sslContextForElasticsearch(OpenSearchAuth auth, String tlsMode)
            throws GeneralSecurityException, IOException {
        SSLContextBuilder sslBuilder = isPinnedTlsMode(tlsMode)
                ? OpenSearchTlsSupport.pinnedSslContextBuilder(ConfigState.SearchDestination.ELASTICSEARCH)
                : SSLContextBuilder.create();
        if (OpenSearchTlsSupport.isInsecureMode(tlsMode)) {
            sslBuilder.loadTrustMaterial(null, (chain, authType) -> true);
        }
        if (auth != null && auth.mode() == OpenSearchAuth.Mode.CERTIFICATE) {
            auth.loadClientKeyMaterial(sslBuilder);
        }
        return sslBuilder.build();
    }

    private static String elasticsearchTlsMode() {
        ConfigState.State state = RuntimeConfig.getState();
        ConfigState.ElasticsearchOptions options = state == null || state.sinks() == null
                ? ConfigState.defaultElasticsearchOptions()
                : state.sinks().elasticSearchOptions();
        return ConfigState.normalizeOpenSearchTlsMode(options.tlsMode());
    }

    private static boolean isPinnedTlsMode(String tlsMode) {
        return OpenSearchTlsSupport.isPinnedMode(tlsMode);
    }

    private static Object buildDefaultAwsCredentialsProvider() throws ReflectiveOperationException {
        Object builder = Class.forName("software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider")
                .getMethod("builder")
                .invoke(null);
        return builder.getClass().getMethod("build").invoke(builder);
    }

    private static Object buildProfileAwsCredentialsProvider(String profile) throws ReflectiveOperationException {
        return Class.forName("software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider")
                .getMethod("create", String.class)
                .invoke(null, profile);
    }

    private static String elasticsearchVersionFromBody(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }
        try {
            JsonNode root = JSON.readTree(body);
            return root.path("version").path("number").asText("");
        } catch (IOException | RuntimeException ignored) {
            return "";
        }
    }

    private static void closeQuietly(Object value) {
        if (value == null) {
            return;
        }
        try {
            if (value instanceof AutoCloseable closeable) {
                closeable.close();
                return;
            }
            Method close = value.getClass().getMethod("close");
            close.invoke(value);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Best effort cleanup for optional reflected clients.
        } catch (Exception ignored) {
            // AutoCloseable permits checked exceptions; connection-test cleanup stays best effort.
        }
    }

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null) {
            c = c.getCause();
        }
        return c.getMessage() == null ? c.toString() : c.getMessage();
    }
}
