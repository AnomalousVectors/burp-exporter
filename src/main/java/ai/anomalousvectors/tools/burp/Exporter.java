package ai.anomalousvectors.tools.burp;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.sinks.ExporterIndexLogForwarder;
import ai.anomalousvectors.tools.burp.sinks.ExporterIndexStatsReporter;
import ai.anomalousvectors.tools.burp.sinks.ParameterIntegritySessionLog;
import ai.anomalousvectors.tools.burp.sinks.ProxyLiveMetadataCorrelator;
import ai.anomalousvectors.tools.burp.sinks.RepeaterTabsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.ToolWebSocketLiveHandler;
import ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler;
import ai.anomalousvectors.tools.burp.ui.BurpExporterPanel;
import ai.anomalousvectors.tools.burp.ui.ConfigPanel;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.BurpRuntimeMetadata;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.ProductInfo;
import ai.anomalousvectors.tools.burp.utils.Version;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchConnector;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

/**
 * Burp extension entry point for the exporter.
 *
 * <p>This type wires lifecycle hooks, logging, runtime metadata, and the suite-tab UI. Swing UI
 * registration is delegated to the EDT during {@link #initialize(MontoyaApi)} when Burp invokes
 * startup from a background thread.</p>
 */
public class Exporter implements BurpExtension {
    private volatile Registration unloadRegistration;
    private volatile Registration suiteTabRegistration;
    private volatile Registration httpHandlerRegistration;
    private volatile Registration proxyRequestHandlerRegistration;
    private volatile Registration proxyResponseHandlerRegistration;
    private volatile Registration requestEditorRegistration;
    private volatile Registration responseEditorRegistration;
    private volatile Registration contextMenuRegistration;
    private volatile Registration webSocketCreatedRegistration;
    private volatile ExporterIndexLogForwarder logForwarder;
    private volatile boolean initialized;

    /**
     * Registers the extension with Burp, wiring logging and UI composition.
     *
     * <p>Suite tab UI is created on the EDT so Swing components are never built on a
     * background thread (Burp may call {@code initialize} from a non-EDT thread when
     * the extension is loaded at startup). Log panel message delivery is handled by
     * {@link ai.anomalousvectors.tools.burp.ui.LogPanel} addNotify/removeNotify and
     * {@link ai.anomalousvectors.tools.burp.utils.Logger} replay buffer.</p>
     *
     * @param api Montoya API handle provided by Burp
     */
    @Override
    public void initialize(MontoyaApi api) {
        String version = Version.get();

        try {
            api.extension().setName(ProductInfo.EXTENSION_NAME);
            unloadRegistration = api.extension().registerUnloadingHandler(this::cleanupExtensionState);
            Logger.initialize(api.logging());

            MontoyaApiProvider.set(api);
            BurpRuntimeMetadata.prime(api);
            Tooltips.configureSharedToolTipManager();
            logForwarder = new ExporterIndexLogForwarder();
            Logger.registerListener(logForwarder);
            BatchSizeController.getInstance().setOnChangeListener(
                    size -> Logger.logDebug("[BatchSize] Shared batch size: " + size));
            requestEditorRegistration = api.userInterface().registerHttpRequestEditorProvider(
                    RepeaterTabsIndexReporter.requestEditorProvider());
            responseEditorRegistration = api.userInterface().registerHttpResponseEditorProvider(
                    RepeaterTabsIndexReporter.responseEditorProvider());
            contextMenuRegistration = api.userInterface().registerContextMenuItemsProvider(
                    RepeaterTabsIndexReporter.contextMenuItemsProvider());

            if (SwingUtilities.isEventDispatchThread()) {
                registerUi(api, ProductInfo.SUITE_TAB_TITLE);
            } else {
                try {
                    SwingUtilities.invokeAndWait(() -> registerUi(api, ProductInfo.SUITE_TAB_TITLE));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Extension UI registration interrupted", e);
                } catch (InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof RuntimeException re) throw re;
                    if (cause instanceof Error err) throw err;
                    throw new RuntimeException(cause != null ? cause : e);
                }
            }

            httpHandlerRegistration = api.http().registerHttpHandler(new TrafficHttpHandler());
            // Proxy annotations carry a private token that deterministically joins live documents
            // to their exact History rows; messageId and History id are separate namespaces.
            ProxyLiveMetadataCorrelator proxyLiveCorrelator = ProxyLiveMetadataCorrelator.instance();
            proxyRequestHandlerRegistration = api.proxy().registerRequestHandler(proxyLiveCorrelator);
            proxyResponseHandlerRegistration = api.proxy().registerResponseHandler(proxyLiveCorrelator);
            webSocketCreatedRegistration =
                    api.websockets().registerWebSocketCreatedHandler(ToolWebSocketLiveHandler.instance());

            String initLine = ProductInfo.EXTENSION_NAME + " v" + version + " initialized successfully.";
            initialized = true;
            Logger.logInfoPanelAndBurp("[Exporter] " + initLine, initLine);
        } catch (RuntimeException e) {
            String failureLine = ProductInfo.EXTENSION_NAME + " v" + version
                    + " initialization failed.";
            Logger.logErrorPanelAndBurp("[Exporter] " + failureLine, failureLine, e);
            cleanupExtensionState();
        }
    }

    private void cleanupExtensionState() {
        ExporterIndexLogForwarder forwarder = logForwarder;
        if (forwarder != null) {
            Logger.unregisterListener(forwarder);
            forwarder.stop();
            logForwarder = null;
        }

        safeDeregister(webSocketCreatedRegistration);
        webSocketCreatedRegistration = null;
        safeDeregister(proxyResponseHandlerRegistration);
        proxyResponseHandlerRegistration = null;
        safeDeregister(proxyRequestHandlerRegistration);
        proxyRequestHandlerRegistration = null;
        ProxyLiveMetadataCorrelator.closeAndDrainRun();
        if (!ProxyLiveMetadataCorrelator.awaitPendingPersistence(5_000L)) {
            Logger.logWarnPanelOnly(
                    "[ProxyCorrelation] Extension unload persistence exceeded its 5-second budget.");
        }
        safeDeregister(httpHandlerRegistration);
        httpHandlerRegistration = null;
        safeDeregister(requestEditorRegistration);
        requestEditorRegistration = null;
        safeDeregister(responseEditorRegistration);
        responseEditorRegistration = null;
        safeDeregister(contextMenuRegistration);
        contextMenuRegistration = null;
        safeDeregister(suiteTabRegistration);
        suiteTabRegistration = null;
        Tooltips.restoreSharedPopupFactory();

        BatchSizeController.getInstance().setOnChangeListener(null);
        if (ExporterIndexStatsReporter.shouldAttemptFinalPushOnUnload()) {
            ParameterIntegritySessionLog.logFinalExporterStatsPush(
                    ExporterIndexStatsReporter.pushFinalSnapshotNow());
        }
        ExportReporterLifecycle.stopAndClearSessionState();
        // Cleanup after unload or failed initialization must release pooled connections, TLS
        // session caches, and transport-owned reactor/scheduler threads. Run synchronously so the
        // classloader can be GC'd cleanly; closeAll() is idempotent if a Stop-triggered async
        // closeAll() already ran.
        OpenSearchConnector.closeAll();
        ConfigPanel.shutdownStartupExecutor();
        if (initialized) {
            initialized = false;
            String unloadLine = ProductInfo.EXTENSION_NAME + " unloaded.";
            Logger.logInfoPanelAndBurp("[Exporter] " + unloadLine, unloadLine);
        }
        Logger.resetState();

        safeDeregister(unloadRegistration);
        unloadRegistration = null;
    }

    private void registerUi(MontoyaApi api, String tabTitle) {
        suiteTabRegistration = api.userInterface().registerSuiteTab(tabTitle, new BurpExporterPanel());
    }

    private static void safeDeregister(Registration registration) {
        if (registration == null) {
            return;
        }
        try {
            registration.deregister();
        } catch (RuntimeException ignored) {
            // Burp may already be tearing the object down during unload.
        }
    }
}
