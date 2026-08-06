package ai.anomalousvectors.tools.burp;

import static ai.anomalousvectors.tools.burp.testutils.LazySchedulers.peek;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStaticList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.awt.Component;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.PopupFactory;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.sinks.FindingsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.ProxyHistoryIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.ProxyWebSocketIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.SettingsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.SitemapIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.ExporterIndexStatsReporter;
import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.ui.ConfigPanel;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.ProductInfo;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.Version;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.project.Project;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.websocket.WebSockets;

class ExporterLifecycleTest {

    private static final Class<?> TRAFFIC_HTTP_HANDLER_SUPPORT = loadTrafficHttpHandlerSupport();

    private static Class<?> loadTrafficHttpHandlerSupport() {
        try {
            return Class.forName("ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandlerSupport");
        } catch (ClassNotFoundException e) {
            throw new AssertionError("TrafficHttpHandlerSupport must be loadable for lifecycle tests.", e);
        }
    }

    @Test
    void initialize_registersUnloadHook_and_leavesRecurringReportersStopped_untilStart() {
        try {
            ApiFixture fixture = new ApiFixture();

            new Exporter().initialize(fixture.api);

            assertThat(fixture.unloadHandler.get()).isNotNull();
            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(MontoyaApiProvider.get()).isSameAs(fixture.api);
            assertThat(peek(ExporterIndexStatsReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(SettingsIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(FindingsIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(SitemapIndexReporter.class, "SCHEDULER")).isNull();
            assertThat(peek(ProxyWebSocketIndexReporter.class, "SCHEDULER")).isNull();

            verify(fixture.extension).setName(ProductInfo.EXTENSION_NAME);
            verify(fixture.extension).registerUnloadingHandler(any(ExtensionUnloadingHandler.class));
            verify(fixture.userInterface).registerSuiteTab(eq(ProductInfo.SUITE_TAB_TITLE), any(Component.class));
            verify(fixture.http).registerHttpHandler(any());
            verify(fixture.proxy).registerRequestHandler(any());
            verify(fixture.proxy).registerResponseHandler(any());
            verify(fixture.webSockets).registerWebSocketCreatedHandler(any());
            verify(fixture.logging).logToOutput(argThat(msg ->
                    msg.contains("initialized successfully") && !msg.startsWith("[")));
        } finally {
            Tooltips.restoreSharedPopupFactory();
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void initialize_failureLogsOneConciseBurpErrorAndCleansPartialState() {
        try {
            ApiFixture fixture = new ApiFixture();
            when(fixture.userInterface.registerSuiteTab(
                    eq(ProductInfo.SUITE_TAB_TITLE), any(Component.class)))
                    .thenThrow(new IllegalStateException("boom"));

            new Exporter().initialize(fixture.api);

            verify(fixture.logging).logToError(argThat((String message) ->
                    message.contains("initialization failed")
                            && message.contains("IllegalStateException: boom")
                            && message.indexOf("boom") == message.lastIndexOf("boom")));
            verify(fixture.logging, never()).logToOutput(
                    argThat(message -> message.contains("initialized successfully")));
            verify(fixture.unloadRegistration).deregister();
            assertThat(MontoyaApiProvider.get()).isNull();
            assertThat(getStaticList(Logger.class, "LISTENERS")).isEmpty();
        } finally {
            Tooltips.restoreSharedPopupFactory();
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void initialize_proxyResponseRegistrationFailure_deregistersPartialProxyRegistration() {
        try {
            ApiFixture fixture = new ApiFixture();
            when(fixture.proxy.registerResponseHandler(any()))
                    .thenThrow(new IllegalStateException("response registration failed"));

            new Exporter().initialize(fixture.api);

            verify(fixture.httpRegistration).deregister();
            verify(fixture.proxyRequestRegistration).deregister();
            verify(fixture.logging, never()).logToOutput(
                    argThat(message -> message.contains("initialized successfully")));
            assertThatCode(() -> fixture.unloadHandler.get().extensionUnloaded())
                    .doesNotThrowAnyException();
            verify(fixture.httpRegistration, times(1)).deregister();
            verify(fixture.proxyRequestRegistration, times(1)).deregister();
        } finally {
            Tooltips.restoreSharedPopupFactory();
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void unloadingHandler_deregistersResources_and_stopsBackgroundWork() {
        Tooltips.restoreSharedPopupFactory();
        PopupFactory popupFactoryBeforeInitialize = PopupFactory.getSharedInstance();
        try {
            ApiFixture fixture = new ApiFixture();
            new Exporter().initialize(fixture.api);

            RuntimeConfig.setExportRunning(true);
            ExporterIndexStatsReporter.start();
            SettingsIndexReporter.start();
            FindingsIndexReporter.start();
            SitemapIndexReporter.start();
            ProxyWebSocketIndexReporter.startLivePoll();

            ExecutorService startupExecutorBeforeUnload =
                    getStatic(ConfigPanel.class, "startupExecutor", ExecutorService.class);
            fixture.unloadHandler.get().extensionUnloaded();

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(MontoyaApiProvider.get()).isNull();
            assertThat(BurpRuntimeMetadata.burpVersion()).isNull();
            assertThat(BurpRuntimeMetadata.projectId()).isNull();
            assertThat(PopupFactory.getSharedInstance()).isSameAs(popupFactoryBeforeInitialize);
            assertAllWorkersTerminated(startupExecutorBeforeUnload);
            assertThat(getStaticList(Logger.class, "LISTENERS")).isEmpty();

            verify(fixture.httpRegistration).deregister();
            verify(fixture.proxyRequestRegistration).deregister();
            verify(fixture.proxyResponseRegistration).deregister();
            verify(fixture.suiteTabRegistration).deregister();
            verify(fixture.unloadRegistration, atLeastOnce()).deregister();
            verify(fixture.logging).logToOutput(argThat(msg ->
                    msg.contains("unloaded") && !msg.startsWith("[")));
        } finally {
            Tooltips.restoreSharedPopupFactory();
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    @Test
    void unloadingHandler_isSafeToInvokeMoreThanOnce() {
        try {
            ApiFixture fixture = new ApiFixture();
            new Exporter().initialize(fixture.api);

            ExecutorService startupExecutorBeforeUnload =
                    getStatic(ConfigPanel.class, "startupExecutor", ExecutorService.class);
            assertThatCode(() -> {
                fixture.unloadHandler.get().extensionUnloaded();
                fixture.unloadHandler.get().extensionUnloaded();
            }).doesNotThrowAnyException();

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(MontoyaApiProvider.get()).isNull();
            assertThat(BurpRuntimeMetadata.burpVersion()).isNull();
            assertThat(BurpRuntimeMetadata.projectId()).isNull();
            assertAllWorkersTerminated(startupExecutorBeforeUnload);
            verify(fixture.logging, times(1)).logToOutput(
                    argThat(message -> message.contains("unloaded")));
            verify(fixture.logging, never()).logToError(any(String.class));
        } finally {
            Tooltips.restoreSharedPopupFactory();
            ExportReporterLifecycle.resetForTests();
            Logger.resetState();
        }
    }

    /**
     * Asserts that every extension-owned background worker is either null or terminated after
     * extension unload, and that {@link ConfigPanel}'s startup executor has been replaced with
     * a fresh instance so subsequent Start actions in the same JVM still work.
     *
     * @param startupExecutorBeforeUnload the {@code startupExecutor} reference captured before
     *                                    {@code extensionUnloaded()} was invoked
     */
    private static void assertAllWorkersTerminated(ExecutorService startupExecutorBeforeUnload) {
        assertThat(peek(ExporterIndexStatsReporter.class, "SCHEDULER")).isNull();
        assertThat(peek(SettingsIndexReporter.class, "SCHEDULER")).isNull();
        assertThat(peek(FindingsIndexReporter.class, "SCHEDULER")).isNull();
        assertThat(peek(SitemapIndexReporter.class, "SCHEDULER")).isNull();
        assertThat(peek(ProxyWebSocketIndexReporter.class, "SCHEDULER")).isNull();
        assertThat(peek(ProxyHistoryIndexReporter.class, "SCHEDULER")).isNull();
        assertThat(peek(TRAFFIC_HTTP_HANDLER_SUPPORT, "ORPHAN_SCHEDULER")).isNull();
        assertThat(getStatic(TrafficExportQueue.class, "drainWorker", Thread.class)).isNull();
        assertThat(IndexingRetryCoordinator.getInstance().isDrainThreadAlive()).isFalse();
        assertThat(startupExecutorBeforeUnload.isShutdown()).isTrue();
        assertThat(getStatic(ConfigPanel.class, "startupExecutor", ExecutorService.class))
                .isNotSameAs(startupExecutorBeforeUnload);
    }

    private static final class ApiFixture {
        final MontoyaApi api = mock(MontoyaApi.class);
        final Extension extension = mock(Extension.class);
        final UserInterface userInterface = mock(UserInterface.class);
        final Http http = mock(Http.class);
        final Proxy proxy = mock(Proxy.class);
        final Logging logging = mock(Logging.class);
        final BurpSuite burpSuite = mock(BurpSuite.class);
        final Version version = mock(Version.class);
        final Project project = mock(Project.class);
        final Registration unloadRegistration = mock(Registration.class);
        final Registration suiteTabRegistration = mock(Registration.class);
        final Registration httpRegistration = mock(Registration.class);
        final Registration proxyRequestRegistration = mock(Registration.class);
        final Registration proxyResponseRegistration = mock(Registration.class);
        final Registration webSocketRegistration = mock(Registration.class);
        final WebSockets webSockets = mock(WebSockets.class);
        final AtomicReference<ExtensionUnloadingHandler> unloadHandler = new AtomicReference<>();

        ApiFixture() {
            when(api.extension()).thenReturn(extension);
            when(api.userInterface()).thenReturn(userInterface);
            when(api.http()).thenReturn(http);
            when(api.proxy()).thenReturn(proxy);
            when(api.websockets()).thenReturn(webSockets);
            when(api.logging()).thenReturn(logging);
            when(api.burpSuite()).thenReturn(burpSuite);
            when(api.project()).thenReturn(project);
            when(burpSuite.version()).thenReturn(version);
            when(version.edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL);
            when(project.id()).thenReturn("project-123");
            when(extension.registerUnloadingHandler(any())).thenAnswer(invocation -> {
                unloadHandler.set(invocation.getArgument(0));
                return unloadRegistration;
            });
            when(userInterface.registerSuiteTab(eq(ProductInfo.SUITE_TAB_TITLE), any(Component.class)))
                    .thenReturn(suiteTabRegistration);
            when(http.registerHttpHandler(any())).thenReturn(httpRegistration);
            when(proxy.registerRequestHandler(any())).thenReturn(proxyRequestRegistration);
            when(proxy.registerResponseHandler(any())).thenReturn(proxyResponseRegistration);
            when(webSockets.registerWebSocketCreatedHandler(any())).thenReturn(webSocketRegistration);
        }
    }
}
