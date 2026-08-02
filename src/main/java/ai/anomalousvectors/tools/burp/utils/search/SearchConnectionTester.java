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

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.ssl.SSLContextBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.AmazonOpenSearchSigV4;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClassicHttpSupport;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchLogFormat;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchTlsSupport;

/**
 * Routes search-destination connection tests to destination-specific client implementations.
 *
 * <p>Tests perform blocking network and credential-provider work and emit diagnostic log events.
 * Callers must invoke them from a worker thread, not the EDT. Independent calls are thread-safe,
 * although they read the current session credentials and runtime destination options.</p>
 */
public final class SearchConnectionTester {
    private static final ObjectMapper JSON = new ObjectMapper();

    private SearchConnectionTester() {
        throw new AssertionError("No instances");
    }

    /**
     * Tests connectivity for the selected database destination.
     *
     * <p>Expected transport, authentication, TLS, and malformed-response failures are converted to
     * an unsuccessful status. A null destination is a caller error.</p>
     *
     * @param destination non-null destination kind
     * @param baseUrl configured endpoint URL
     * @return destination-neutral connection status
     * @throws NullPointerException if {@code destination} is null
     */
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
            String clusterUuid = clusterUuidFromBody(result.body());
            String authStatus = auth.mode() == OpenSearchAuth.Mode.NONE ? "Not used" : "Successful";
            Logger.logDebug("[Elasticsearch] Connection test succeeded: auth=" + authStatus
                    + ", version=" + version);
            return new SearchConnectionStatus("Elasticsearch", true, "", version, clusterUuid,
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

    /**
     * Returns the Amazon OpenSearch auth status line for Test Connection results.
     *
     * <p>SigV4 is separate from {@link OpenSearchAuth.Mode}; when signing is enabled the UI must not
     * report {@code Not used} merely because the auth mode is {@code NONE}.</p>
     *
     * @param auth resolved Amazon auth descriptor
     * @param sigV4Enabled whether IAM SigV4 signing is active for this test
     * @param statusCode HTTP status, or {@code 0} when no response was received
     * @param success whether the probe is treated as a successful connection test
     * @return status label for the Authentication result row
     */
    static String amazonAuthStatus(
            OpenSearchAuth auth,
            boolean sigV4Enabled,
            int statusCode,
            boolean success) {
        if (success) {
            if (sigV4Enabled) {
                return "Successful";
            }
            return auth.mode() == OpenSearchAuth.Mode.NONE ? "Not used" : "Successful";
        }
        if (sigV4Enabled) {
            return switch (statusCode) {
                case 401, 403 -> "Failed";
                case 0 -> "Not tested";
                default -> "Attempted";
            };
        }
        return authStatusForHttpFailure(auth, statusCode);
    }

    /**
     * Returns the HTTP path used for Amazon OpenSearch Test Connection.
     *
     * <p>Hosted domains answer {@code GET /} with cluster metadata. OpenSearch Serverless collections
     * typically return {@code 404} for {@code GET /} even when healthy and authenticated, so serverless
     * probes use {@code /_cat/indices} instead.</p>
     *
     * @param resolvedDeployment normalized deployment type ({@code hosted}, {@code serverless}, or
     *        {@code auto})
     * @return absolute path beginning with {@code /}
     */
    static String amazonProbePath(String resolvedDeployment) {
        return ConfigState.DEPLOYMENT_SERVERLESS.equals(ConfigState.normalizeDeploymentType(resolvedDeployment))
                ? "/_cat/indices"
                : "/";
    }

    /**
     * Resolves the Amazon deployment type used for probing and status text.
     *
     * @param baseUrl configured endpoint
     * @param options Amazon OpenSearch options from runtime config
     * @return normalized deployment type, preferring an explicit selection over auto-detection
     */
    static String resolvedAmazonDeployment(String baseUrl, ConfigState.OpenSearchAmazonOptions options) {
        String selected = options == null
                ? ConfigState.DEPLOYMENT_AUTO
                : ConfigState.normalizeDeploymentType(options.deploymentType());
        if (!ConfigState.DEPLOYMENT_AUTO.equals(selected)) {
            return selected;
        }
        return SearchDeployment.detectAmazonOpenSearchDeploymentType(baseUrl);
    }

    private static SearchConnectionStatus safeTestOpenSearchAmazonConnection(String baseUrl) {
        try {
            ConfigState.State state = RuntimeConfig.getState();
            ConfigState.OpenSearchAmazonOptions options = state == null || state.sinks() == null
                    ? ConfigState.defaultOpenSearchAmazonOptions()
                    : state.sinks().openSearchAmazonOptions();
            OpenSearchAuth auth = OpenSearchAuth.fromRuntime(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON);
            if (!auth.isComplete()) {
                String msg = auth.validationMessage().replace("OpenSearch", "Amazon OpenSearch");
                Logger.logWarnPanelOnly("[Amazon OpenSearch] Test connection skipped: " + msg);
                return new SearchConnectionStatus("Amazon OpenSearch", false, "", "", msg,
                        "Failed", "Failed", "Not tested");
            }
            if (AmazonOpenSearchSigV4.isEnabledForRuntime()) {
                String validation = AmazonOpenSearchSigV4.validationMessage(baseUrl);
                if (!validation.isBlank()) {
                    Logger.logWarnPanelOnly("[Amazon OpenSearch] Test connection skipped: " + validation);
                    return new SearchConnectionStatus("Amazon OpenSearch", false, "", "", validation,
                            "Failed", "Failed", "Not tested");
                }
            }
            return testAmazonProbeGet(baseUrl, auth, options);
        } catch (IOException | RuntimeException e) {
            String msg = rootMessage(e);
            Logger.logWarnPanelOnly("[Amazon OpenSearch] Test connection failed for " + baseUrl + ": " + msg);
            // Transport/probe IO failures are connectivity/capacity, not authentication rejection.
            OpenSearchAuth auth = OpenSearchAuth.fromRuntime(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON);
            String authStatus = auth.mode() == OpenSearchAuth.Mode.NONE
                    && !AmazonOpenSearchSigV4.isEnabledForRuntime()
                    ? "Not used"
                    : "Attempted";
            return new SearchConnectionStatus("Amazon OpenSearch", false, "", "", msg,
                    "Failed", authStatus, OpenSearchTlsSupport.failureTrustSummary(
                            baseUrl, msg, ConfigState.SearchDestination.OPEN_SEARCH_AMAZON));
        }
    }

    private static SearchConnectionStatus testAmazonProbeGet(
            String baseUrl,
            OpenSearchAuth auth,
            ConfigState.OpenSearchAmazonOptions options) throws IOException {
        String deployment = resolvedAmazonDeployment(baseUrl, options);
        String path = amazonProbePath(deployment);
        boolean sigV4 = AmazonOpenSearchSigV4.isEnabledForRuntime();
        var client = OpenSearchConnector.getClassicHttpClient(baseUrl, auth);
        HttpHost host = OpenSearchClassicHttpSupport.hostForBaseUrl(baseUrl);
        HttpGet get = new HttpGet(path);
        auth.applyTo(get);
        String redactedAuth = auth.redactedAuthorizationForLog();
        if (sigV4) {
            AmazonOpenSearchSigV4.sign(get, "GET", baseUrl, path, new byte[0]);
            redactedAuth = AmazonOpenSearchSigV4.redactedAuthorizationForLog();
        }
        String requestLog = OpenSearchLogFormat.formatRequestForLog("GET", path, baseUrl, null, redactedAuth);
        Logger.logDebug("[Amazon OpenSearch] Request:\n" + OpenSearchLogFormat.indentRaw(requestLog));
        Logger.logDebug("[Amazon OpenSearch] Probe path=" + path
                + ", deployment=" + deployment
                + ", sigV4=" + sigV4);
        return client.execute(host, get, response -> {
            int status = response.getCode();
            String body;
            try {
                body = response.getEntity() == null
                        ? ""
                        : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse Amazon OpenSearch response.", e);
            }
            String responseLog = OpenSearchLogFormat.buildRawResponseWithHeaders(
                    body, response.getVersion() == null ? null : response.getVersion().toString(),
                    status, response.getReasonPhrase(), List.of());
            Logger.logDebug("[Amazon OpenSearch] Response:\n" + OpenSearchLogFormat.indentRaw(responseLog));
            boolean success = status >= 200 && status < 300;
            String authStatus = amazonAuthStatus(auth, sigV4, status, success);
            if (!success) {
                String msg = "HTTP " + status
                        + (response.getReasonPhrase() == null || response.getReasonPhrase().isBlank()
                                ? ""
                                : " " + response.getReasonPhrase())
                        + " on " + path;
                if (ConfigState.DEPLOYMENT_SERVERLESS.equals(deployment) && "/".equals(path) && status == 404) {
                    msg += " (OpenSearch Serverless often returns 404 for GET /; probe /_cat/indices instead)";
                }
                Logger.logDebug("[Amazon OpenSearch] Probe failed: path=" + path
                        + ", status=" + status
                        + ", authStatus=" + authStatus
                        + ", sigV4=" + sigV4);
                return new SearchConnectionStatus("Amazon OpenSearch", false, "", "", msg,
                        "Failed", authStatus,
                        OpenSearchTlsSupport.successTrustSummary(
                                baseUrl, ConfigState.SearchDestination.OPEN_SEARCH_AMAZON));
            }
            String version = "/".equals(path) ? elasticsearchVersionFromBody(body) : "";
            String clusterUuid = "/".equals(path) ? clusterUuidFromBody(body) : "";
            if (version.isBlank() && ConfigState.DEPLOYMENT_SERVERLESS.equals(deployment)) {
                version = "serverless";
            }
            String message = ConfigState.DEPLOYMENT_AUTO.equals(deployment)
                    ? "Connection successful"
                    : "Connection successful (" + deployment + ")";
            Logger.logDebug("[Amazon OpenSearch] Probe succeeded: path=" + path
                    + ", authStatus=" + authStatus
                    + ", version=" + (version.isBlank() ? "unknown" : version));
            return new SearchConnectionStatus("Amazon OpenSearch", true, "", version, clusterUuid, message,
                    "Success", authStatus,
                    OpenSearchTlsSupport.successTrustSummary(
                            baseUrl, ConfigState.SearchDestination.OPEN_SEARCH_AMAZON));
        });
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

    /**
     * Extracts a cluster UUID from a root-response body.
     *
     * @param body response JSON; null, blank, or malformed input is treated as unavailable
     * @return cluster UUID, or empty when unavailable
     */
    static String clusterUuidFromBody(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }
        try {
            JsonNode root = JSON.readTree(body);
            return root.path("cluster_uuid").asText("");
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

    /**
     * Returns a single-line operator detail from the deepest reachable cause.
     *
     * <p>Identity-like or empty messages fall back to the exception type name. Cause cycles stop at
     * a self-reference.</p>
     *
     * @param t non-null failure
     * @return non-empty, single-line detail
     */
    private static String rootMessage(Throwable t) {
        Throwable deepest = t;
        while (deepest.getCause() != null && deepest.getCause() != deepest) {
            deepest = deepest.getCause();
        }
        String typeName = deepest.getClass().getSimpleName();
        if (typeName == null || typeName.isEmpty()) {
            typeName = "Error";
        }
        String rawMessage = deepest.getMessage();
        if (rawMessage == null) {
            return typeName;
        }
        String cleanedMessage = rawMessage.replaceAll("[\\r\\n]+", " ").trim();
        if (cleanedMessage.isEmpty() || cleanedMessage.indexOf('@') > 0) {
            return typeName;
        }
        return cleanedMessage;
    }
}
