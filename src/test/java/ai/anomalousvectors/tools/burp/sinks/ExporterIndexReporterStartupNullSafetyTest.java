package ai.anomalousvectors.tools.burp.sinks;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import burp.api.montoya.MontoyaApi;

class ExporterIndexReporterStartupNullSafetyTest {

    @AfterEach
    public void clearApiProvider() {
        MontoyaApiProvider.set(null);
    }

    @Test
    void settingsBurpContextHelpers_fallBackSafely_whenBurpSubApisThrowDuringStartup() {
        MontoyaApi api = throwingMontoyaApi();
        MontoyaApiProvider.set(api);

        assertThat(callStatic(SettingsIndexReporter.class, "safeBurpVersion", api)).isNull();
        assertThat(callStatic(SettingsIndexReporter.class, "safeProjectId", api))
                .isEqualTo(BurpRuntimeMetadata.UNKNOWN_PROJECT_ID);
        clearApiProvider();
    }

    @Test
    void sitemapAndWebsocketHelpers_noop_whenMontoyaSubApisThrowDuringStartup() {
        MontoyaApi api = throwingMontoyaApi();

        assertThat(callStatic(SitemapIndexReporter.class, "safeSiteMapItems", api)).isNull();

        Object wsHistoryObj = callStatic(ProxyWebSocketIndexReporter.class, "safeWebSocketHistory", api);
        assertThat(wsHistoryObj).isInstanceOf(List.class);
        List<?> wsHistory = (List<?>) wsHistoryObj;
        assertThat(wsHistory).isEmpty();

        boolean inScope = WebSocketTrafficDocumentBuilder.safeBurpInScope(api, "https://example.com");
        assertThat(inScope).isFalse();
        clearApiProvider();
    }

    @Test
    void sitemapHelper_doesNotSwallowErrors() {
        AssertionError failure = new AssertionError("fatal host failure");
        MontoyaApi api = throwingMontoyaApi(failure);

        assertThatThrownBy(() -> callStatic(SitemapIndexReporter.class, "safeSiteMapItems", api))
                .isSameAs(failure);
    }

    private static MontoyaApi throwingMontoyaApi() {
        return throwingMontoyaApi(null);
    }

    private static MontoyaApi throwingMontoyaApi(Throwable failure) {
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(),
                new Class<?>[] { MontoyaApi.class },
                (proxy, method, args) -> {
                    if (failure != null) {
                        throw failure;
                    }
                    throw new NullPointerException("startup race: " + method.getName());
                });
    }
}
