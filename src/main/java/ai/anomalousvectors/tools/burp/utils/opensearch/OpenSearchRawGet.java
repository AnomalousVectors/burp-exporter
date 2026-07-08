package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.net.URI;
import java.util.concurrent.Future;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.util.Timeout;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

/**
 * Performs a raw HTTP GET to the OpenSearch root (/) with the same auth, SSL, and
 * HTTP version policy (NEGOTIATE) as {@link OpenSearchConnector}, so we can log the
 * actual protocol and status line from the wire (including HTTP/2 when negotiated).
 */
public final class OpenSearchRawGet {

    private OpenSearchRawGet() {}

    /**
     * Result of a raw GET / request: status line details, body, and log strings (real request/response with redaction).
     * When the request fails before receiving a response, {@code protocol} is null and {@code statusCode} is 0.
     */
    public record RawGetResult(
            int statusCode, String protocol, String reasonPhrase, String body,
            String requestForLog, java.util.List<String> responseHeaderLines) {}

    /**
     * Performs GET / against baseUrl with the same credentials and insecure-SSL behavior as the connector.
     * Uses the async client with {@code HttpVersionPolicy.NEGOTIATE} so HTTP/2 is used when supported.
     * Returns the actual HTTP version, status code, reason phrase, and response body from the wire.
     */
    public static RawGetResult performRawGet(String baseUrl, String username, String password) {
        OpenSearchAuth auth = username == null || username.isBlank() || password == null || password.isBlank()
                ? OpenSearchAuth.none()
                : OpenSearchAuth.basic(username, password);
        return performRawGet(baseUrl, auth);
    }

    /** Performs GET / against baseUrl with the selected OpenSearch auth mode. */
    public static RawGetResult performRawGet(String baseUrl, OpenSearchAuth auth) {
        OpenSearchAuth resolvedAuth = auth == null ? OpenSearchAuth.none() : auth;
        String normalized = baseUrl == null ? "" : baseUrl.replaceFirst("^\\s+", "").trim().replaceAll("/+$", "");
        String authForLog = resolvedAuth.redactedAuthorizationForLog();
        if (normalized.isEmpty()) {
            String reqLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", "/", null, authForLog);
            return new RawGetResult(0, null, "Invalid base URL", "", reqLog, java.util.List.of());
        }
        if (!resolvedAuth.isComplete()) {
            String reqLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", normalized + "/", null, authForLog);
            return new RawGetResult(0, null, resolvedAuth.validationMessage(), "", reqLog, java.util.List.of());
        }
        String requestUri = normalized + "/";
        boolean insecure = OpenSearchConnector.isInsecureEnabled();
        try {
            URI uri = URI.create(requestUri);
            HttpHost host = new HttpHost(uri.getScheme(), uri.getHost(), uri.getPort());
            if ("https".equalsIgnoreCase(uri.getScheme())
                    && OpenSearchTlsSupport.isPinnedMode()
                    && !OpenSearchTlsSupport.hasPinnedCertificate()) {
                Logger.logErrorPanelOnly("[OpenSearch] TLS mode requires a pinned certificate, but none is imported.");
                String reqLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", requestUri, null, authForLog);
                return new RawGetResult(0, null, "Pinned TLS certificate not imported.", "", reqLog, java.util.List.of());
            }
            try (CloseableHttpAsyncClient client = buildAsyncClient(host, resolvedAuth, insecure)) {
                client.start();
                SimpleHttpRequest request = SimpleRequestBuilder.get(requestUri).build();
                resolvedAuth.applyTo(request);
                Future<SimpleHttpResponse> future = client.execute(request, null);
                SimpleHttpResponse response = future.get();
                String protocol = response.getVersion() != null ? response.getVersion().toString() : null;
                int code = response.getCode();
                String reason = response.getReasonPhrase();
                String body = response.getBodyText() != null ? response.getBodyText() : "";
                String reqForLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", requestUri, protocol, authForLog);
                java.util.List<String> respHeaderLines = new java.util.ArrayList<>();
                for (Header h : response.getHeaders()) {
                    String name = h.getName();
                    String value = OpenSearchLogFormat.shouldRedactHeader(name) ? "***" : (h.getValue() != null ? h.getValue() : "");
                    respHeaderLines.add(name + ": " + value);
                }
                return new RawGetResult(code, protocol, reason, body, reqForLog, respHeaderLines);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            String protocol = OpenSearchLogFormat.parseProtocolFromException(e);
            String reqForLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", requestUri, protocol, authForLog);
            return new RawGetResult(0, null, msg, "", reqForLog, java.util.List.of());
        } catch (java.security.GeneralSecurityException | java.io.IOException
                | java.util.concurrent.ExecutionException | IllegalArgumentException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            String protocol = OpenSearchLogFormat.parseProtocolFromException(e);
            String reqForLog = OpenSearchLogFormat.formatRequestForLog("GET", "/", requestUri, protocol, authForLog);
            return new RawGetResult(0, null, msg, "", reqForLog, java.util.List.of());
        }
    }

    private static final Timeout RAW_GET_RESPONSE_TIMEOUT = Timeout.ofSeconds(5);
    private static final Timeout BULK_RESPONSE_TIMEOUT = Timeout.ofMinutes(2);

    static CloseableHttpAsyncClient buildAsyncClientForBulk(
            HttpHost host,
            OpenSearchAuth auth,
            boolean insecure,
            ConfigState.SearchDestination destination) throws java.security.GeneralSecurityException {
        return buildAsyncClient(host, auth, insecure, BULK_RESPONSE_TIMEOUT, destination);
    }

    private static CloseableHttpAsyncClient buildAsyncClient(HttpHost host, OpenSearchAuth auth, boolean insecure)
            throws java.security.GeneralSecurityException {
        return buildAsyncClient(host, auth, insecure, RAW_GET_RESPONSE_TIMEOUT);
    }

    private static CloseableHttpAsyncClient buildAsyncClient(
            HttpHost host, OpenSearchAuth auth, boolean insecure, Timeout responseTimeout)
            throws java.security.GeneralSecurityException {
        return buildAsyncClient(
                host, auth, insecure, responseTimeout, ConfigState.SearchDestination.OPEN_SEARCH);
    }

    private static CloseableHttpAsyncClient buildAsyncClient(
            HttpHost host,
            OpenSearchAuth auth,
            boolean insecure,
            Timeout responseTimeout,
            ConfigState.SearchDestination destination)
            throws java.security.GeneralSecurityException {
        var clientBuilder = HttpAsyncClients.custom();
        PoolingAsyncClientConnectionManagerBuilder connManagerBuilder =
                PoolingAsyncClientConnectionManagerBuilder.create();
        clientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                .setResponseTimeout(responseTimeout)
                .build());
        if ("https".equalsIgnoreCase(host.getSchemeName())) {
            try {
                OpenSearchHttpTlsSupport.configureAsyncTls(connManagerBuilder, auth, insecure, destination);
            } catch (java.io.IOException e) {
                throw new java.security.GeneralSecurityException("Failed to load OpenSearch client certificate.", e);
            }
        } else {
            connManagerBuilder.setDefaultTlsConfig(TlsConfig.custom()
                    .setVersionPolicy(HttpVersionPolicy.NEGOTIATE)
                    .build());
        }
        AsyncClientConnectionManager connManager = connManagerBuilder.build();
        clientBuilder.setConnectionManager(connManager);
        return clientBuilder.build();
    }
}
