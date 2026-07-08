package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.ssl.SSLContextBuilder;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

/**
 * Shared TLS configuration for OpenSearch HTTP clients so async test-connection, Java SDK
 * transport, and classic bulk paths present the same trust and client-certificate material.
 */
final class OpenSearchHttpTlsSupport {

    private OpenSearchHttpTlsSupport() {
        throw new AssertionError("No instances");
    }

    /**
     * Applies negotiated TLS settings to an async connection manager builder for one destination.
     */
    static void configureAsyncTls(
            PoolingAsyncClientConnectionManagerBuilder connManagerBuilder,
            OpenSearchAuth auth,
            boolean insecure,
            ConfigState.SearchDestination destination) throws GeneralSecurityException, IOException {
        applyNegotiatedTlsDefaults(connManagerBuilder);
        OpenSearchAuth resolvedAuth = auth == null ? OpenSearchAuth.none() : auth;
        SSLContextBuilder sslBuilder = SSLContextBuilder.create();
        resolvedAuth.loadClientKeyMaterial(sslBuilder);
        if (insecure) {
            SSLContext sslContext = sslBuilder
                    .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                    .build();
            connManagerBuilder.setTlsStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .buildAsync());
        } else if (OpenSearchTlsSupport.isPinnedMode(destination)) {
            SSLContextBuilder pinnedBuilder = OpenSearchTlsSupport.pinnedSslContextBuilder(destination);
            resolvedAuth.loadClientKeyMaterial(pinnedBuilder);
            SSLContext sslContext = pinnedBuilder.build();
            connManagerBuilder.setTlsStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .buildAsync());
        } else if (resolvedAuth.mode() == OpenSearchAuth.Mode.CERTIFICATE) {
            SSLContext sslContext = sslBuilder.build();
            connManagerBuilder.setTlsStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .buildAsync());
        }
    }

    /**
     * Applies negotiated TLS settings to a classic connection manager builder for one destination.
     */
    static void configureClassicTls(
            PoolingHttpClientConnectionManagerBuilder connManagerBuilder,
            OpenSearchAuth auth,
            boolean insecure,
            ConfigState.SearchDestination destination) throws GeneralSecurityException, IOException {
        applyNegotiatedTlsDefaults(connManagerBuilder);
        OpenSearchAuth resolvedAuth = auth == null ? OpenSearchAuth.none() : auth;
        SSLContextBuilder sslBuilder = SSLContextBuilder.create();
        resolvedAuth.loadClientKeyMaterial(sslBuilder);
        if (insecure) {
            SSLContext sslContext = sslBuilder
                    .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                    .build();
            connManagerBuilder.setTlsSocketStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .buildClassic());
        } else if (OpenSearchTlsSupport.isPinnedMode(destination)) {
            SSLContextBuilder pinnedBuilder = OpenSearchTlsSupport.pinnedSslContextBuilder(destination);
            resolvedAuth.loadClientKeyMaterial(pinnedBuilder);
            SSLContext sslContext = pinnedBuilder.build();
            connManagerBuilder.setTlsSocketStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .buildClassic());
        } else if (resolvedAuth.mode() == OpenSearchAuth.Mode.CERTIFICATE) {
            SSLContext sslContext = sslBuilder.build();
            connManagerBuilder.setTlsSocketStrategy(ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .buildClassic());
        }
    }

    private static void applyNegotiatedTlsDefaults(PoolingAsyncClientConnectionManagerBuilder connManagerBuilder) {
        connManagerBuilder.setDefaultTlsConfig(TlsConfig.custom()
                .setVersionPolicy(HttpVersionPolicy.NEGOTIATE)
                .build());
    }

    private static void applyNegotiatedTlsDefaults(PoolingHttpClientConnectionManagerBuilder connManagerBuilder) {
        connManagerBuilder.setDefaultTlsConfig(TlsConfig.custom()
                .setVersionPolicy(HttpVersionPolicy.NEGOTIATE)
                .build());
    }
}
