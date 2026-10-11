package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.sinks.RepeaterTabMetadataHeuristics.InferenceResult;
import ai.anomalousvectors.tools.burp.sinks.RepeaterTabMetadataHeuristics.SelectedTabSnapshot;
import java.awt.Component;
import java.awt.Frame;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkByteBudget;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

/**
 * Best-effort Repeater tab snapshot capture for historic request/response pairs.
 *
 * <p>Montoya does not currently expose a first-class Repeater tabs API, so this reporter uses
 * extension editor hooks plus a manual context-menu fallback to observe request/response pairs
 * currently bound into Repeater tabs. Captured items use a top-level tab-slot identity when the
 * Repeater tree exposes one and otherwise fall back to a request/response content hash. They are
 * retained only for the active export run and exported to the traffic index with {@code tool=Repeater
 * Tabs} when that traffic option is enabled.</p>
 */
public final class RepeaterTabsIndexReporter {

    private static final String CAPTION = "AF Repeater Tabs Capture";
    private static final String REPEATER_TOOL_TITLE = "Repeater";
    private static final String TOOL_LABEL = "Repeater Tabs";
    private static final String TOOL_TYPE = "REPEATER_TABS";
    private static final String TOOL_TYPE_KEY = "repeater_tabs";
    private static final int STARTUP_TAB_WALK_DELAY_MS = 350;
    private static final int STARTUP_TAB_WALK_SECOND_PASS_DELAY_MS = 1_600;
    private static final int STARTUP_TAB_WALK_STEP_DELAY_MS = 25;
    private static final int STARTUP_EXPORT_SUMMARY_WAIT_MS = 5_000;
    private static final int STARTUP_DUPLICATE_SLOT_TRACE_LIMIT = 3;
    private static final Map<String, CapturedRepeaterItem> CAPTURED = new ConcurrentHashMap<>();
    private static final Set<String> QUEUED_FOR_EXPORT = ConcurrentHashMap.newKeySet();
    private static final Set<String> SCOPE_FILTERED_FOR_EXPORT = ConcurrentHashMap.newKeySet();
    private static final Set<String> STARTUP_TRACE_LOGGED = ConcurrentHashMap.newKeySet();
    private static final Map<String, String> STARTUP_SLOT_TO_FINGERPRINT = new ConcurrentHashMap<>();
    private static final Map<String, AtomicInteger> STARTUP_DUPLICATE_SLOT_TRACE_COUNTS = new ConcurrentHashMap<>();
    private static final RepeaterTabsStartupMetadataSummary STARTUP_METADATA_SUMMARY =
            new RepeaterTabsStartupMetadataSummary();
    private static final AtomicInteger RUN_GENERATION = new AtomicInteger(0);
    private static final AtomicInteger STARTUP_SESSION_SEQUENCE = new AtomicInteger(0);
    private static final AtomicInteger CAPTURE_WINDOW_GENERATION = new AtomicInteger(-1);
    private static volatile RepeaterTabMetadata currentStartupSelectionMetadata;
    private static volatile String currentStartupSessionId = RepeaterMetadataTraceLabels.NONE;
    private static volatile StartupExportStatsSnapshot startupExportStatsSnapshot =
            StartupExportStatsSnapshot.empty();
    private static final RepeaterSwingTabWalker<RepeaterTabMetadata> STARTUP_TAB_WALKER =
            new RepeaterSwingTabWalker<>(
                    REPEATER_TOOL_TITLE,
                    STARTUP_TAB_WALK_DELAY_MS,
                    STARTUP_TAB_WALK_SECOND_PASS_DELAY_MS,
                    STARTUP_TAB_WALK_STEP_DELAY_MS,
                    () -> List.of(Frame.getFrames()),
                    new StartupTabWalkDelegate());

    private RepeaterTabsIndexReporter() {}

    /** Provider registered with Burp to observe request-side Repeater editor bindings. */
    public static HttpRequestEditorProvider requestEditorProvider() {
        return CaptureRequestEditor::new;
    }

    /** Provider registered with Burp to observe response-side Repeater editor bindings. */
    public static HttpResponseEditorProvider responseEditorProvider() {
        return CaptureResponseEditor::new;
    }

    /** Returns the Repeater-only context-menu provider used for manual fallback capture. */
    public static ContextMenuItemsProvider contextMenuItemsProvider() {
        return new RepeaterTabsContextMenuItemsProvider();
    }

    /** Queues all captured Repeater-tab items for the current export run when enabled. */
    public static void pushSnapshotNow() {
        if (!RuntimeConfig.isExportRunning()
                || !RuntimeConfig.isAnyTrafficExportEnabled()
                || !RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY)) {
            Logger.logDebug("[RepeaterTabs] pushSnapshotNow skipped: running=" + RuntimeConfig.isExportRunning()
                    + ", anyTraffic=" + RuntimeConfig.isAnyTrafficExportEnabled()
                    + ", repeaterTabsEnabled=" + RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY)
                    + ", trafficToolTypes=" + describeRuntimeTrafficToolTypes());
            return;
        }
        CAPTURED.values().stream()
                .sorted(Comparator.comparingLong(item -> item.firstSeenAtMs))
                .forEach(RepeaterTabsIndexReporter::queueForCurrentRun);
    }

    /**
     * Replays cached Repeater snapshots directly to the recovering search destination.
     *
     * <p>This method is synchronous and bypasses {@link TrafficExportQueue}. The recovery flag
     * suppresses Files while each prepared chunk uses the normal search bulk path. Existing live
     * traffic remains queued until authorization recovery clears its pause.</p>
     */
    static boolean replaySearchRecoverySnapshot(ExportRunToken token) {
        return replaySearchRecoverySnapshot(
                token,
                (baseUrl, indexName, indexKey, documents) ->
                        OpenSearchClientWrapper.pushPreparedBulk(baseUrl, indexName, indexKey, documents));
    }

    /** Runs the direct replay with a replaceable sender for focused queue/file isolation tests. */
    static boolean replaySearchRecoverySnapshot(
            ExportRunToken token,
            RecoveryBulkSender sender) {
        if (!RuntimeConfig.isExportRunActive(token) || !RuntimeConfig.isSearchRecoveryReplay()) {
            return false;
        }
        if (!RuntimeConfig.isSearchTrafficEnabled()
                || !RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY)) {
            return true;
        }
        if (sender == null) {
            return false;
        }

        String indexName = TrafficRouteBucket.trafficIndexName();
        String baseUrl = RuntimeConfig.searchBaseUrl();
        int maxBatch = SnapshotBatchTuning.initialTarget();
        long maxBytes = Math.max(1L, BulkByteBudget.currentMaxBytes());
        List<PreparedExportDocument> batch = new ArrayList<>(maxBatch);
        long batchBytes = 0L;
        List<CapturedRepeaterItem> captured = CAPTURED.values().stream()
                .sorted(Comparator.comparingLong(item -> item.firstSeenAtMs))
                .toList();
        for (CapturedRepeaterItem item : captured) {
            if (!RuntimeConfig.isExportRunActive(token)) {
                return false;
            }
            Map<String, Object> document =
                    buildDocument(item.requestResponse, item.repeaterTabName, item.repeaterGroupName);
            if (document == null) {
                continue;
            }
            PreparedExportDocument prepared =
                    ExportDocumentIdentity.prepare(indexName, TrafficRouteBucket.INDEX_KEY, document);
            long documentBytes = prepared.resolvedBulkBytes();
            if (!batch.isEmpty()
                    && (batch.size() >= maxBatch || batchBytes + documentBytes > maxBytes)) {
                sendRecoveryBatch(sender, baseUrl, indexName, batch);
                batch = new ArrayList<>(maxBatch);
                batchBytes = 0L;
            }
            batch.add(prepared);
            batchBytes += documentBytes;
        }
        if (!batch.isEmpty() && RuntimeConfig.isExportRunActive(token)) {
            sendRecoveryBatch(sender, baseUrl, indexName, batch);
        }
        return RuntimeConfig.isExportRunActive(token);
    }

    private static void sendRecoveryBatch(
            RecoveryBulkSender sender,
            String baseUrl,
            String indexName,
            List<PreparedExportDocument> batch) {
        BulkPushOutcome outcome =
                sender.push(baseUrl, indexName, TrafficRouteBucket.INDEX_KEY, List.copyOf(batch));
        TrafficRouteBucket.recordBulkOutcome(
                new TrafficRouteBucket.Route(TrafficRouteBucket.Kind.TOOL_TYPE, TOOL_TYPE),
                outcome,
                true,
                "Repeater recovery replay");
    }

    /** Synchronously sends one prepared Repeater replay chunk to the search bulk path. */
    @FunctionalInterface
    interface RecoveryBulkSender {
        BulkPushOutcome push(
                String baseUrl,
                String indexName,
                String indexKey,
                List<PreparedExportDocument> documents);
    }

    /**
     * Cancels the owned Swing walk, requests selection restoration on the EDT, and clears all
     * Repeater state owned by the current export run.
     */
    public static void clearRunState() {
        RUN_GENERATION.incrementAndGet();
        STARTUP_TAB_WALKER.cancelAndRestore();
        CAPTURE_WINDOW_GENERATION.set(-1);
        CAPTURED.clear();
        STARTUP_TRACE_LOGGED.clear();
        STARTUP_METADATA_SUMMARY.clear();
        STARTUP_SLOT_TO_FINGERPRINT.clear();
        STARTUP_DUPLICATE_SLOT_TRACE_COUNTS.clear();
        QUEUED_FOR_EXPORT.clear();
        SCOPE_FILTERED_FOR_EXPORT.clear();
        currentStartupSelectionMetadata = null;
        currentStartupSessionId = RepeaterMetadataTraceLabels.NONE;
        startupExportStatsSnapshot = StartupExportStatsSnapshot.empty();
    }

    /** Clears all cached Repeater-tab session state. */
    public static void clearSessionState() {
        clearRunState();
    }

    /**
     * Captures a Repeater tab binding observed through an extension-provided editor.
     *
     * <p>Only Repeater-origin editor contexts are accepted. Other Burp tool editors are ignored so
     * this helper does not mislabel unrelated traffic as historic Repeater content.</p>
     */
    static void captureFromEditorContext(
            EditorCreationContext creationContext,
            HttpRequestResponse requestResponse,
            String capturePath,
            Component uiAnchor) {
        if (!isRepeaterToolSource(creationContext == null ? null : creationContext.toolSource())) {
            return;
        }
        boolean exportRunning = RuntimeConfig.isExportRunning();
        if (!exportRunning) {
            return;
        }
        RepeaterTabMetadata metadata = currentRepeaterTabMetadata(uiAnchor);
        RepeaterLiveMetadataTracker.observe(requestResponse, metadata.asSharedMetadata());
        // Historic Repeater Tabs capture only while that source is enabled for the run.
        if (!RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY)) {
            return;
        }
        capture(requestResponse, capturePath, metadata);
    }

    /**
     * Captures the current Repeater tab from a Repeater-scoped context-menu invocation.
     *
     * <p>This is a manual fallback for cases where Burp has not rebound the current tab through the
     * extension-provided editor hooks yet.</p>
     *
     * @return {@code true} when a request/response pair was available to capture
     */
    static boolean captureCurrentRepeaterTab(ContextMenuEvent event) {
        if (!isRepeaterContextMenuEvent(event)) {
            return false;
        }
        Optional<MessageEditorHttpRequestResponse> current = event.messageEditorRequestResponse();
        if (current.isPresent()) {
            return capture(current.get().requestResponse(), "context_menu", currentRepeaterTabMetadata(null));
        }
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) {
            return false;
        }
        return capture(selected.getFirst(), "context_menu", currentRepeaterTabMetadata(null));
    }

    static int capturedItemCount() {
        return CAPTURED.size();
    }

    static boolean markStartupSlotForCurrentRun(String slotKey, String fingerprint) {
        return rememberStartupSlotFingerprint(slotKey, fingerprint) == null;
    }

    private static String rememberStartupSlotFingerprint(String slotKey, String fingerprint) {
        if (slotKey == null) {
            return null;
        }
        // During startup we only want one historic capture per logical tab slot.
        // Burp can rebind the same slot through nested editors with a different
        // fingerprint, which should not produce a second export document.
        String storedFingerprint = safeLogValue(fingerprint);
        return STARTUP_SLOT_TO_FINGERPRINT.putIfAbsent(slotKey, storedFingerprint);
    }

    private static String replaceStartupSlotFingerprint(String slotKey, String fingerprint) {
        if (slotKey == null) {
            return null;
        }
        return STARTUP_SLOT_TO_FINGERPRINT.put(slotKey, safeLogValue(fingerprint));
    }

    /** Opens the startup-only Repeater-tab capture window for the current run generation. */
    static void openCaptureWindowForCurrentRun() {
        int generation = RUN_GENERATION.get();
        CAPTURE_WINDOW_GENERATION.set(generation);
        startupExportStatsSnapshot = StartupExportStatsSnapshot.capture(CAPTURED.size());
        currentStartupSessionId = RepeaterMetadataTraceLabels.startupSessionId(
                generation,
                STARTUP_SESSION_SEQUENCE.incrementAndGet());
    }

    /** Closes the startup-only Repeater-tab capture window for the current run. */
    static void closeCaptureWindowForCurrentRun() {
        CAPTURE_WINDOW_GENERATION.set(-1);
        currentStartupSessionId = RepeaterMetadataTraceLabels.NONE;
    }

    /**
     * Schedules delayed unsupported Swing walks that try to visit existing Repeater tabs on Start.
     *
     * <p>This method is thread-safe to call from either the EDT or a background thread. The actual
     * tab walking is always deferred onto the EDT because Swing tab selection must happen there.</p>
     */
    public static void scheduleStartupTabWalk() {
        boolean exportRunning = RuntimeConfig.isExportRunning();
        boolean anyTrafficEnabled = RuntimeConfig.isAnyTrafficExportEnabled();
        boolean repeaterTabsEnabled = RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY);
        if (!exportRunning || !anyTrafficEnabled || !repeaterTabsEnabled) {
            Logger.logDebug("[RepeaterTabs] Startup tab walk skipped: running=" + exportRunning
                    + ", anyTraffic=" + anyTrafficEnabled
                    + ", repeaterTabsEnabled=" + repeaterTabsEnabled
                    + ", trafficToolTypes=" + describeRuntimeTrafficToolTypes());
            return;
        }
        int generation = RUN_GENERATION.get();
        openCaptureWindowForCurrentRun();
        Logger.logInfoPanelOnly("[StartupExport] Repeater Tabs: export starting startupSession="
                + currentStartupSessionId() + ".");
        Logger.logDebug("[RepeaterTabs] Scheduling startup tab walk for generation "
                + generation
                + " startupSession=" + currentStartupSessionId()
                + " with trafficToolTypes=" + describeRuntimeTrafficToolTypes() + ".");
        STARTUP_TAB_WALKER.schedule(generation);
    }

    /**
     * Performs one synchronous Repeater startup tab walk over the provided Swing roots.
     *
     * <p>Caller must invoke on the EDT. This helper temporarily selects Burp's Repeater tool tab,
     * visits only the shallowest eligible request-tab pane in each subtree branch, and restores the
     * original selections before returning. Descendant request/response editor panes are never
     * cycled.</p>
     *
     * @param roots top-level Swing roots to search
     * @return summary of whether Repeater was found and how many selections changed
     */
    static StartupTabWalkResult performStartupTabWalk(Iterable<? extends Component> roots) {
        RepeaterSwingTabWalker.SynchronousWalkResult result =
                RepeaterSwingTabWalker.performSynchronously(
                        roots,
                        REPEATER_TOOL_TITLE,
                        CAPTURED::size,
                        RepeaterTabsIndexReporter::topLevelRepeaterTabMetadata,
                        metadata -> currentStartupSelectionMetadata = metadata);
        if (result.failure() != null) {
            logStartupTabWalkFailure(0, 0, result.failure());
        }
        return new StartupTabWalkResult(
                result.locatedRepeaterToolTab(),
                result.tabbedPaneCount(),
                result.selectionChangeCount(),
                result.captureCountBefore(),
                result.captureCountAfter());
    }

    private static boolean capture(
            HttpRequestResponse requestResponse,
            String capturePath,
            RepeaterTabMetadata repeaterTabMetadata) {
        if (requestResponse == null || !shouldCaptureForCurrentRun(capturePath)) {
            return false;
        }
        if (requestResponse.response() == null) {
            return false;
        }
        String fingerprint = fingerprintFor(requestResponse);
        boolean startupCaptureWindowOpen = isStartupCaptureWindowOpen();
        RepeaterTabsCapturePolicy.CaptureDecision captureDecision =
                RepeaterTabsCapturePolicy.decide(fingerprint, repeaterTabMetadata, startupCaptureWindowOpen);
        String previousStartupSlotFingerprint = startupCaptureWindowOpen
                ? replaceStartupSlotFingerprint(captureDecision.startupSlotKey(), fingerprint)
                : null;
        boolean repeatedStartupFingerprint = previousStartupSlotFingerprint != null
                && previousStartupSlotFingerprint.equals(fingerprint);
        boolean replacedStartupBinding = previousStartupSlotFingerprint != null
                && !previousStartupSlotFingerprint.equals(fingerprint);
        if (captureDecision.startupSlotKey() != null && repeatedStartupFingerprint) {
            STARTUP_METADATA_SUMMARY.recordDuplicateSlotSuppression(
                    capturePath,
                    captureDecision.startupSlotKey());
            int duplicateTraceCount = incrementDuplicateSlotTraceCount(
                    captureDecision.startupSlotKey(),
                    capturePath);
            if (duplicateTraceCount <= STARTUP_DUPLICATE_SLOT_TRACE_LIMIT) {
                Logger.logTrace("[RepeaterTabs] Skipped additional startup editor observation for logical slot already captured "
                        + "startupSession=" + currentStartupSessionId()
                        + " metadataSource=" + RepeaterMetadataTraceLabels.STARTUP_SLOT
                        + " capturePath=" + safeLogValue(capturePath)
                        + " captureKey=" + safeLogValue(captureDecision.captureKey())
                        + " fingerprint=" + safeLogValue(fingerprint)
                        + " existingFingerprint=" + previousStartupSlotFingerprint
                        + " slot=" + safeLogValue(captureDecision.startupSlotKey())
                        + " duplicateSlotObservation=" + duplicateTraceCount
                        + " metadata={" + RepeaterTabsCapturePolicy.describeMetadata(repeaterTabMetadata) + "}");
            } else if (duplicateTraceCount == STARTUP_DUPLICATE_SLOT_TRACE_LIMIT + 1) {
                Logger.logTrace("[RepeaterTabs] Further duplicate startup editor observations for this logical slot "
                        + "will be summarized instead of logged individually "
                        + "startupSession=" + currentStartupSessionId()
                        + " metadataSource=" + RepeaterMetadataTraceLabels.STARTUP_SLOT
                        + " capturePath=" + safeLogValue(capturePath)
                        + " captureKey=" + safeLogValue(captureDecision.captureKey())
                        + " existingFingerprint=" + previousStartupSlotFingerprint
                        + " slot=" + safeLogValue(captureDecision.startupSlotKey())
                        + " duplicateSlotObservation=" + duplicateTraceCount);
            }
            return false;
        }
        recordStartupMetadataObservation(
                capturePath,
                captureDecision.captureKey(),
                fingerprint,
                repeaterTabMetadata);
        if (captureDecision.ignoreAnonymousStartupBinding()) {
            STARTUP_METADATA_SUMMARY.recordIgnoredAnonymousBinding(capturePath);
            Logger.logTrace("[RepeaterTabs] Skipped startup editor observation because no logical tab identity was available "
                    + "startupSession=" + currentStartupSessionId()
                    + " metadataSource=" + RepeaterMetadataTraceLabels.NONE
                    + " capturePath=" + safeLogValue(capturePath)
                    + " captureKey=" + safeLogValue(captureDecision.captureKey())
                    + " fingerprint=" + safeLogValue(fingerprint)
                    + " metadata={" + RepeaterTabsCapturePolicy.describeMetadata(repeaterTabMetadata) + "}");
            return false;
        }
        if (captureDecision.ignoreAuxiliaryTabNameBinding()) {
            Logger.logTrace("[RepeaterTabs] Skipped Repeater Tabs capture because tab name refers to a right-rail message view "
                    + "startupSession=" + currentStartupSessionId()
                    + " metadataSource=" + RepeaterMetadataTraceLabels.NONE
                    + " capturePath=" + safeLogValue(capturePath)
                    + " captureKey=" + safeLogValue(captureDecision.captureKey())
                    + " fingerprint=" + safeLogValue(fingerprint)
                    + " metadata={" + RepeaterTabsCapturePolicy.describeMetadata(repeaterTabMetadata) + "}");
            return false;
        }
        long now = System.currentTimeMillis();
        boolean[] newCapture = { false };
        boolean[] metadataUpgraded = { false };
        boolean[] existingCaptureReused = { false };
        RepeaterTabMetadata[] previousMetadata = { null };
        String captureKey = captureDecision.captureKey();
        CAPTURED.compute(captureKey, (ignored, existing) -> {
            if (existing != null) {
                previousMetadata[0] = existing.asMetadata();
                if (replacedStartupBinding) {
                    return new CapturedRepeaterItem(
                            existing.captureKey,
                            fingerprint,
                            persistentCopy(requestResponse),
                            existing.firstSeenAtMs,
                            repeaterTabMetadata.tabName(),
                            repeaterTabMetadata.groupName());
                }
                if (existing.hasEquivalentOrBetterMetadataThan(repeaterTabMetadata)) {
                    existingCaptureReused[0] = true;
                    return existing;
                }
                metadataUpgraded[0] = true;
                return new CapturedRepeaterItem(
                        existing.captureKey,
                        existing.fingerprint,
                        existing.requestResponse,
                        existing.firstSeenAtMs,
                        repeaterTabMetadata.tabName(),
                        repeaterTabMetadata.groupName());
            }
            newCapture[0] = true;
            return new CapturedRepeaterItem(
                    captureKey,
                    fingerprint,
                    persistentCopy(requestResponse),
                    now,
                    repeaterTabMetadata.tabName(),
                    repeaterTabMetadata.groupName());
        });
        if (metadataUpgraded[0]) {
            STARTUP_METADATA_SUMMARY.recordMetadataUpgrade(capturePath);
            Logger.logTrace("[RepeaterTabs] Enriched captured Repeater metadata with a more descriptive observation "
                    + "startupSession=" + currentStartupSessionId()
                    + " metadataSource=" + historyMetadataSource(captureKey)
                    + " capturePath=" + safeLogValue(capturePath)
                    + " captureKey=" + safeLogValue(captureKey)
                    + " fingerprint=" + safeLogValue(fingerprint)
                    + " previous={" + RepeaterTabsCapturePolicy.describeMetadata(previousMetadata[0]) + "}"
                    + " incoming={" + RepeaterTabsCapturePolicy.describeMetadata(repeaterTabMetadata) + "}");
        } else if (existingCaptureReused[0]) {
            Logger.logTrace("[RepeaterTabs] Kept existing captured Repeater metadata because the new observation added no extra detail "
                    + "startupSession=" + currentStartupSessionId()
                    + " metadataSource=" + historyMetadataSource(captureKey)
                    + " capturePath=" + safeLogValue(capturePath)
                    + " captureKey=" + safeLogValue(captureKey)
                    + " fingerprint=" + safeLogValue(fingerprint)
                    + " existing={" + RepeaterTabsCapturePolicy.describeMetadata(previousMetadata[0]) + "}"
                    + " incoming={" + RepeaterTabsCapturePolicy.describeMetadata(repeaterTabMetadata) + "}");
        } else if (replacedStartupBinding) {
            Logger.logTrace("[RepeaterTabs] Replaced a stale startup slot candidate with the latest complete editor binding "
                    + "startupSession=" + currentStartupSessionId()
                    + " capturePath=" + safeLogValue(capturePath)
                    + " captureKey=" + safeLogValue(captureKey)
                    + " previousFingerprint=" + safeLogValue(previousStartupSlotFingerprint)
                    + " fingerprint=" + safeLogValue(fingerprint)
                    + " metadata={" + RepeaterTabsCapturePolicy.describeMetadata(repeaterTabMetadata) + "}");
        }
        if (newCapture[0] && !isStartupCaptureWindowOpen()) {
            Logger.logDebug("[RepeaterTabs] Captured Repeater tab via " + capturePath + ".");
        }
        if (!startupCaptureWindowOpen
                && (newCapture[0] || metadataUpgraded[0] || replacedStartupBinding)) {
            queueForCurrentRun(CAPTURED.get(captureKey));
        }
        return true;
    }

    private static RepeaterTabMetadata currentRepeaterTabMetadata(Component uiAnchor) {
        if (!SwingUtilities.isEventDispatchThread()) {
            return RepeaterTabMetadata.empty(null);
        }
        if (isStartupCaptureWindowOpen()) {
            RepeaterTabMetadata startupMetadata = currentStartupSelectionMetadata;
            return startupMetadata == null
                    ? RepeaterTabMetadata.empty(uiAnchor == null ? null : uiAnchor.getClass().getName())
                    : startupMetadata;
        }
        RepeaterTabMetadata anchored = inferRepeaterTabMetadataFromAnchor(uiAnchor);
        if (anchored != null) {
            return anchored;
        }
        RepeaterSwingTabWalker.ToolTabLocation repeaterLocation =
                RepeaterSwingTabWalker.findToolTabLocation(
                        List.of(Frame.getFrames()), REPEATER_TOOL_TITLE);
        if (repeaterLocation == null) {
            return RepeaterTabMetadata.empty(null);
        }
        Component repeaterRoot = repeaterLocation.tabbedPane().getComponentAt(repeaterLocation.index());
        return currentTopLevelRepeaterTabMetadata(repeaterRoot);
    }

    /**
     * Returns best-effort live Repeater metadata when tracker correlation has no match.
     *
     * <p>If the startup capture window is still open, the current startup-selection metadata wins
     * because it reflects the tab the startup walker is actively binding. Otherwise the current
     * Repeater UI selection is inferred on the EDT. This helper never throws; failures return
     * {@link RepeaterMetadataFields.Metadata#empty()} so live export prefers a missing label over a
     * guessed one.</p>
     */
    static RepeaterMetadataFields.Metadata currentRepeaterSharedMetadataForLiveFallback() {
        RepeaterTabMetadata startupMetadata = currentStartupSelectionMetadata;
        if (isStartupCaptureWindowOpen() && startupMetadata != null) {
            return startupMetadata.asSharedMetadata();
        }
        if (SwingUtilities.isEventDispatchThread()) {
            return currentRepeaterTabMetadata(null).asSharedMetadata();
        }
        AtomicReference<RepeaterMetadataFields.Metadata> metadataRef =
                new AtomicReference<>(RepeaterMetadataFields.Metadata.empty());
        try {
            SwingUtilities.invokeAndWait(() ->
                    metadataRef.set(currentRepeaterTabMetadata(null).asSharedMetadata()));
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            return RepeaterMetadataFields.Metadata.empty();
        } catch (InvocationTargetException ignored) {
            return RepeaterMetadataFields.Metadata.empty();
        }
        return metadataRef.get();
    }

    private static RepeaterTabMetadata inferRepeaterTabMetadataFromAnchor(Component uiAnchor) {
        RepeaterTabMetadata topLevelMetadata = topLevelRepeaterTabMetadataFromAnchor(uiAnchor);
        if (topLevelMetadata != null) {
            return topLevelMetadata;
        }
        List<SelectedTabSnapshot> selectedTabs =
                RepeaterTabMetadataHeuristics.collectSelectedTabSnapshotsFromAnchor(uiAnchor);
        if (selectedTabs.isEmpty()) {
            return null;
        }
        return inferRepeaterTabMetadata(
                selectedTabs,
                uiAnchor == null ? null : uiAnchor.getClass().getName());
    }

    private static RepeaterTabMetadata topLevelRepeaterTabMetadataFromAnchor(Component uiAnchor) {
        if (uiAnchor == null) {
            return null;
        }
        RepeaterSwingTabWalker.ToolTabLocation repeaterLocation =
                RepeaterSwingTabWalker.findAncestorToolTabLocation(uiAnchor, REPEATER_TOOL_TITLE);
        if (repeaterLocation == null) {
            return null;
        }
        Component repeaterRoot = repeaterLocation.tabbedPane().getComponentAt(repeaterLocation.index());
        List<JTabbedPane> topLevelPanes =
                RepeaterSwingTabWalker.collectTopLevelRepeaterTabPanes(repeaterRoot);
        for (int paneOrdinal = 0; paneOrdinal < topLevelPanes.size(); paneOrdinal++) {
            JTabbedPane pane = topLevelPanes.get(paneOrdinal);
            int selectedIndex = RepeaterSwingTabWalker.indexContainingDescendant(pane, uiAnchor);
            if (selectedIndex >= 0) {
                return topLevelRepeaterTabMetadata(pane, selectedIndex, paneOrdinal);
            }
        }
        return null;
    }

    private static RepeaterTabMetadata currentTopLevelRepeaterTabMetadata(Component repeaterRoot) {
        List<JTabbedPane> topLevelPanes =
                RepeaterSwingTabWalker.collectTopLevelRepeaterTabPanes(repeaterRoot);
        for (int paneOrdinal = 0; paneOrdinal < topLevelPanes.size(); paneOrdinal++) {
            JTabbedPane pane = topLevelPanes.get(paneOrdinal);
            int selectedIndex = pane.getSelectedIndex();
            if (selectedIndex >= 0) {
                return topLevelRepeaterTabMetadata(pane, selectedIndex, paneOrdinal);
            }
        }
        return RepeaterTabMetadata.empty(repeaterRoot == null ? null : repeaterRoot.getClass().getName());
    }

    static RepeaterTabMetadata topLevelRepeaterTabMetadata(
            JTabbedPane pane,
            int selectedIndex,
            int paneOrdinal) {
        SelectedTabSnapshot snapshot = RepeaterTabMetadataHeuristics.selectedTabSnapshot(pane, selectedIndex);
        InferenceResult inferred = RepeaterTabMetadataHeuristics.infer(List.of(snapshot));
        String paneClass = pane == null ? null : pane.getClass().getName();
        return new RepeaterTabMetadata(
                inferred.tabName(),
                inferred.groupName(),
                paneClass,
                RepeaterTabsCapturePolicy.topLevelSlotIdentity(paneOrdinal, paneClass, selectedIndex));
    }

    static String inferRepeaterTabName(Component root) {
        return inferRepeaterTabMetadata(root).tabName();
    }

    static String inferRepeaterGroupName(Component root) {
        return inferRepeaterTabMetadata(root).groupName();
    }

    private static RepeaterTabMetadata inferRepeaterTabMetadata(Component root) {
        List<SelectedTabSnapshot> selectedTabs =
                RepeaterTabMetadataHeuristics.collectSelectedTabSnapshots(root);
        if (selectedTabs.isEmpty()) {
            return RepeaterTabMetadata.empty(root == null ? null : root.getClass().getName());
        }
        return inferRepeaterTabMetadata(selectedTabs, root == null ? null : root.getClass().getName());
    }

    private static RepeaterTabMetadata inferRepeaterTabMetadata(
            List<SelectedTabSnapshot> selectedTabs,
            String rootComponentClass) {
        InferenceResult inferred = RepeaterTabMetadataHeuristics.infer(selectedTabs);
        return new RepeaterTabMetadata(
                inferred.tabName(),
                inferred.groupName(),
                rootComponentClass,
                RepeaterTabMetadataHeuristics.buildSlotIdentityKey(selectedTabs));
    }

    private static String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static void recordStartupMetadataObservation(
            String capturePath,
            String captureKey,
            String fingerprint,
            RepeaterTabMetadata metadata) {
        if (!isStartupCaptureWindowOpen() || metadata == null) {
            return;
        }
        STARTUP_METADATA_SUMMARY.recordObservation(capturePath, metadata);
        String logKey = currentStartupSessionId()
                + "|" + safeLogValue(fingerprint)
                + "|" + safeLogValue(capturePath);
        if (!STARTUP_TRACE_LOGGED.add(logKey)) {
            return;
        }
        Logger.logTrace("[RepeaterTabs] Startup metadata via " + capturePath
                + " startupSession=" + currentStartupSessionId()
                + " metadataSource=" + historyMetadataSource(captureKey)
                + " captureKey=" + safeLogValue(captureKey)
                + " fingerprint=" + safeLogValue(fingerprint)
                + " " + RepeaterTabsCapturePolicy.describeMetadata(metadata));
    }

    static String describeStartupMetadataSummary() {
        return STARTUP_METADATA_SUMMARY.describe();
    }

    private static int incrementDuplicateSlotTraceCount(String startupSlotKey, String capturePath) {
        String counterKey = safeLogValue(startupSlotKey) + "|" + safeLogValue(capturePath);
        return STARTUP_DUPLICATE_SLOT_TRACE_COUNTS
                .computeIfAbsent(counterKey, ignored -> new AtomicInteger(0))
                .incrementAndGet();
    }

    private static boolean isStartupCaptureWindowOpen() {
        return RuntimeConfig.isExportRunning()
                && CAPTURE_WINDOW_GENERATION.get() == RUN_GENERATION.get();
    }

    private static String safeLogValue(String value) {
        return RepeaterTabsCapturePolicy.safeLogValue(value);
    }

    private static String currentStartupSessionId() {
        return RepeaterMetadataTraceLabels.safeValue(currentStartupSessionId);
    }

    private static String historyMetadataSource(String captureKey) {
        return RepeaterMetadataTraceLabels.historyMetadataSource(captureKey);
    }

    private static void logStartupExportCompletionSummary(String startupSession, boolean deliveryComplete) {
        StartupExportStatsSnapshot snapshot = startupExportStatsSnapshot;
        int newCaptures = Math.max(0, CAPTURED.size() - snapshot.captureCountBefore());
        String body = SnapshotSummary.formatCompletionBody(snapshot.baseline(), true, true);
        SnapshotSummary.CompletionDeltas deltas = SnapshotSummary.completionDeltas(snapshot.baseline());
        long pending = startupDeliveryPending(newCaptures, deltas);
        Logger.logInfoPanelOnly("[StartupExport] Repeater Tabs: "
                + (deliveryComplete ? "export complete" : "capture complete")
                + " startupSession="
                + RepeaterMetadataTraceLabels.safeValue(startupSession)
                + " captured " + newCaptures + " tab(s)"
                + (body.isEmpty() ? "" : "; " + body)
                + (deliveryComplete ? "" : "; delivery_pending=" + pending)
                + "; " + describeStartupMetadataSummary() + ".");
        TrafficStartupBacklogSummary.complete(
                TrafficStartupBacklogSummary.Component.REPEATER_TABS,
                newCaptures,
                snapshot.baseline());
    }

    private static void scheduleStartupExportCompletionSummary() {
        pushSnapshotNow();
        int generation = RUN_GENERATION.get();
        String startupSession = currentStartupSessionId();
        Thread summaryThread = new Thread(() -> {
            boolean idle = TrafficExportQueue.awaitIdle(STARTUP_EXPORT_SUMMARY_WAIT_MS);
            if (generation != RUN_GENERATION.get()) {
                return;
            }
            boolean deliveryComplete = startupExportCountersComplete();
            if (!idle && !deliveryComplete) {
                Logger.logDebug("[RepeaterTabs] Startup export summary proceeding before traffic queue idle "
                        + "startupSession=" + startupSession
                        + " timeoutMs=" + STARTUP_EXPORT_SUMMARY_WAIT_MS);
            }
            logStartupExportCompletionSummary(startupSession, deliveryComplete);
        }, "burp-exporter-repeater-startup-summary");
        summaryThread.setDaemon(true);
        summaryThread.start();
    }

    private static boolean startupExportCountersComplete() {
        StartupExportStatsSnapshot snapshot = startupExportStatsSnapshot;
        int newCaptures = Math.max(0, CAPTURED.size() - snapshot.captureCountBefore());
        if (newCaptures <= 0) {
            return true;
        }
        SnapshotSummary.CompletionDeltas deltas = SnapshotSummary.completionDeltas(snapshot.baseline());
        boolean fileComplete = !RuntimeConfig.isAnyFileExportEnabled()
                || deltas.fileSuccess() + deltas.fileFailure() >= newCaptures;
        boolean openSearchComplete = !RuntimeConfig.isSearchActive()
                || deltas.openSearchSuccess() + deltas.openSearchFailure() >= newCaptures;
        return fileComplete && openSearchComplete;
    }

    private static long startupDeliveryPending(
            int captured,
            SnapshotSummary.CompletionDeltas deltas) {
        long filePending = RuntimeConfig.isAnyFileExportEnabled()
                ? Math.max(0L, captured - deltas.fileSuccess() - deltas.fileFailure())
                : 0L;
        long openSearchPending = RuntimeConfig.isSearchActive()
                ? Math.max(0L, captured - deltas.openSearchSuccess() - deltas.openSearchFailure())
                : 0L;
        return Math.max(filePending, openSearchPending);
    }

    private static record StartupExportStatsSnapshot(
            int captureCountBefore,
            SnapshotSummary.Baseline baseline) {

        private static StartupExportStatsSnapshot empty() {
            return new StartupExportStatsSnapshot(0, null);
        }

        private static StartupExportStatsSnapshot capture(int captureCountBefore) {
            SnapshotSummary.Baseline baseline = SnapshotSummary.forRoute(
                    new TrafficRouteBucket.Route(TrafficRouteBucket.Kind.TOOL_TYPE, TOOL_TYPE));
            return new StartupExportStatsSnapshot(captureCountBefore, baseline);
        }
    }

    private static void logStartupTabWalkResult(
            int passNumber,
            int delayMs,
            RepeaterSwingTabWalker.PassResult result) {
        int newCaptures = result.captureCountAfter() - result.captureCountBefore();
        String metadataSummary = describeStartupMetadataSummary();
        if (newCaptures > 0) {
            Logger.logInfoPanelOnly("[StartupExport] Repeater Tabs: startup tab walk pass "
                    + passNumber + " startupSession=" + currentStartupSessionId()
                    + " captured " + newCaptures + " tab(s); "
                    + metadataSummary + ".");
        }
        Logger.logDebug("[RepeaterTabs] Startup tab walk pass " + passNumber
                + " startupSession=" + currentStartupSessionId()
                + " (" + delayMs + " ms) visited "
                + result.tabbedPaneCount() + " Repeater tab container(s) across "
                + result.selectionChangeCount() + " selection change(s). "
                + "Capture count before=" + result.captureCountBefore()
                + ", after=" + result.captureCountAfter()
                + ", newly captured=" + newCaptures
                + ", startup metadata summary=" + metadataSummary
                + ".");
    }

    private static void logStartupTabWalkFailure(
            int passNumber,
            int delayMs,
            RepeaterSwingTabWalker.WalkFailure failure) {
        String restoration = failure.restorationFailureCount() <= 0
                ? ""
                : "; restorationFailures=" + failure.restorationFailureCount()
                        + ", firstRestorationFailure="
                        + summarizeThrowable(failure.firstRestorationFailure());
        Logger.logErrorPanelOnly("[RepeaterTabs] Startup tab walk pass " + passNumber
                + " startupSession=" + currentStartupSessionId()
                + " (" + delayMs + " ms) stopped safely during " + failure.phase()
                + ": " + summarizeThrowable(failure.primaryFailure())
                + restoration + ".");
    }

    /**
     * Queues one captured Repeater-tab item for export when runtime gates allow it.
     *
     */
    private static void queueForCurrentRun(CapturedRepeaterItem item) {
        boolean exportRunning = RuntimeConfig.isExportRunning();
        boolean anyTrafficEnabled = RuntimeConfig.isAnyTrafficExportEnabled();
        boolean repeaterTabsEnabled = RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY);
        if (item == null
                || item.captureKey == null
                || !exportRunning
                || !anyTrafficEnabled
                || !repeaterTabsEnabled
                || QUEUED_FOR_EXPORT.contains(item.captureKey)) {
            return;
        }
        Map<String, Object> document;
        try {
            document = buildDocument(
                    item.requestResponse,
                    item.repeaterTabName,
                    item.repeaterGroupName);
        } catch (RuntimeException e) {
            Logger.logErrorPanelOnly("[RepeaterTabs] Failed to build traffic document for captured tab: "
                    + summarizeThrowable(e));
            return;
        }
        if (document == null) {
            recordScopeSkipIfFiltered(item);
            return;
        }
        if (!QUEUED_FOR_EXPORT.add(item.captureKey)) {
            return;
        }
        Logger.logTrace("[RepeaterTabs] Queued captured tab for export captureKey="
                + safeLogValue(item.captureKey)
                + " metadataSource=" + historyMetadataSource(item.captureKey)
                + " fingerprint=" + safeLogValue(item.fingerprint)
                + " tab=" + safeLogValue(item.repeaterTabName)
                + " group=" + safeLogValue(item.repeaterGroupName)
                + " path=" + safeLogValue(document.get("path") == null ? null : String.valueOf(document.get("path"))));
        TrafficExportQueue.offer(document);
    }

    private static boolean shouldCaptureForCurrentRun(String capturePath) {
        if (!RuntimeConfig.isExportRunning()
                || !RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY)) {
            return false;
        }
        return CAPTURE_WINDOW_GENERATION.get() == RUN_GENERATION.get()
                || "context_menu".equals(capturePath);
    }

    private static String describeRuntimeTrafficToolTypes() {
        var current = RuntimeConfig.getState();
        return current == null || current.trafficToolTypes() == null
                ? "[]"
                : current.trafficToolTypes().toString();
    }

    private static String summarizeThrowable(Throwable throwable) {
        if (throwable == null) {
            return "<null>";
        }
        StringBuilder out = new StringBuilder(throwable.getClass().getName());
        if (throwable.getMessage() != null && !throwable.getMessage().isBlank()) {
            out.append(": ").append(throwable.getMessage());
        }
        StackTraceElement[] stack = throwable.getStackTrace();
        if (stack == null) {
            stack = new StackTraceElement[0];
        }
        int frames = Math.min(stack.length, 5);
        if (frames > 0) {
            out.append(" @ ");
            for (int i = 0; i < frames; i++) {
                if (i > 0) {
                    out.append(" <- ");
                }
                StackTraceElement frame = stack[i];
                out.append(frame.getClassName())
                        .append('.')
                        .append(frame.getMethodName())
                        .append(':')
                        .append(frame.getLineNumber());
            }
        }
        Throwable cause = throwable.getCause();
        if (cause != null && cause != throwable) {
            out.append(" | cause=").append(cause.getClass().getName());
            if (cause.getMessage() != null && !cause.getMessage().isBlank()) {
                out.append(": ").append(cause.getMessage());
            }
        }
        return out.toString();
    }

    /**
     * Creates a temp-file-backed copy when Montoya offers one for longer-lived caching.
     *
     * <p>When temp-file materialization fails, this method falls back to the original
     * {@link HttpRequestResponse} so capture still succeeds for the current Burp session.</p>
     */
    private static HttpRequestResponse persistentCopy(HttpRequestResponse requestResponse) {
        try {
            HttpRequestResponse tempFileCopy = requestResponse.copyToTempFile();
            return tempFileCopy != null ? tempFileCopy : requestResponse;
        } catch (RuntimeException e) {
            Logger.logDebug("[RepeaterTabs] Failed to create temp-file copy: " + e.getMessage());
            return requestResponse;
        }
    }

    /**
     * Computes the stable request/response fingerprint used for Repeater-tab correlation.
     *
     * <p>The digest includes request bytes, response bytes when present, and Burp annotations so
     * edited or annotated tabs do not collapse onto unrelated request/response pairs. Startup
     * startup capture may layer a slot-specific key on top of this fingerprint when distinct
     * Repeater tabs share identical traffic.</p>
     */
    private static String fingerprintFor(HttpRequestResponse requestResponse) {
        return SnapshotExportFingerprints.sitemapEntryFingerprint(requestResponse);
    }

    private static boolean isRepeaterToolSource(ToolSource toolSource) {
        return toolSource != null && toolSource.toolType() == ToolType.REPEATER;
    }

    private static boolean isRepeaterContextMenuEvent(ContextMenuEvent event) {
        if (event == null || event.toolType() != ToolType.REPEATER) {
            return false;
        }
        InvocationType invocationType = event.invocationType();
        return invocationType == InvocationType.MESSAGE_EDITOR_REQUEST
                || invocationType == InvocationType.MESSAGE_EDITOR_RESPONSE
                || invocationType == InvocationType.MESSAGE_VIEWER_REQUEST
                || invocationType == InvocationType.MESSAGE_VIEWER_RESPONSE;
    }

    private static Map<String, Object> buildDocument(
            HttpRequestResponse requestResponse,
            String repeaterTabName,
            String repeaterGroupName) {
        if (requestResponse == null) {
            return null;
        }
        HttpRequest request = requestResponse.request();
        if (request == null) {
            return null;
        }
        HttpResponse response = requestResponse.response();
        HttpService service = requestResponse.httpService();
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        String url = RequestResponseDocBuilder.buildBestEffortUrl(
                request,
                service,
                requestDoc,
                "RepeaterTabs");
        boolean burpInScope = isInScope(url);
        if (!ScopeFilter.shouldExport(RuntimeConfig.getState(), url, burpInScope)) {
            return null;
        }
        requestDoc.put("url", HttpMessageDocSupport.urlObject(url, service));
        requestDoc.put("protocol", TrafficProtocolFields.requestProtocol(
                RequestResponseDocBuilder.safeRequestHttpVersion(request)));

        Map<String, Object> document = new LinkedHashMap<>();
        Map<String, Object> burp = new LinkedHashMap<>();
        burp.put("reporting_tool", TOOL_LABEL);
        burp.put("is_in_scope", burpInScope);
        burp.put("message_id", null);
        burp.put("timing", BurpTimingFields.from(requestResponse));
        BurpAnnotationFields.put(burp, requestResponse.annotations());
        burp.put("proxy", BurpProxyFields.withoutProxyHistoryEditMetadata(null));
        document.put("burp", burp);
        RepeaterMetadataFields.put(document, repeaterTabName, repeaterGroupName);
        document.put("request", requestDoc);

        if (response != null) {
            document.put("response", RequestResponseDocBuilder.buildTrafficResponseDoc(response));
        } else {
            document.put("response", RequestResponseDocBuilder.emptyTrafficResponseDoc());
        }
        document.put("websocket", WebSocketTrafficDocumentBuilder.notWebSocket());

        document.put("meta", ExportMetaFields.meta("1"));

        return document;
    }

    private static void recordScopeSkipIfFiltered(CapturedRepeaterItem item) {
        if (item == null || item.captureKey == null || item.requestResponse == null) {
            return;
        }
        HttpRequest request = item.requestResponse.request();
        if (request == null) {
            return;
        }
        HttpService service = item.requestResponse.httpService();
        Map<String, Object> requestDoc = RequestResponseDocBuilder.buildTrafficRequestDoc(request);
        String url = RequestResponseDocBuilder.buildBestEffortUrl(
                request,
                service,
                requestDoc,
                "RepeaterTabs");
        boolean burpInScope = isInScope(url);
        if (!ScopeFilter.shouldExport(RuntimeConfig.getState(), url, burpInScope)
                && SCOPE_FILTERED_FOR_EXPORT.add(item.captureKey)) {
            ExportStats.recordSkipReason(ExportStats.SKIP_REASON_SCOPE, 1);
        }
    }

    private static boolean isInScope(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        MontoyaApi api = MontoyaApiProvider.get();
        if (api == null || api.scope() == null) {
            return false;
        }
        try {
            return api.scope().isInScope(url);
        } catch (RuntimeException e) {
            Logger.logDebug("[RepeaterTabs] Scope lookup failed: " + e.getMessage());
            return false;
        }
    }

    private static final class CapturedRepeaterItem {
        private final String captureKey;
        private final String fingerprint;
        private final HttpRequestResponse requestResponse;
        private final long firstSeenAtMs;
        private final String repeaterTabName;
        private final String repeaterGroupName;

        private CapturedRepeaterItem(
                String captureKey,
                String fingerprint,
                HttpRequestResponse requestResponse,
                long firstSeenAtMs,
                String repeaterTabName,
                String repeaterGroupName) {
            this.captureKey = captureKey;
            this.fingerprint = fingerprint;
            this.requestResponse = requestResponse;
            this.firstSeenAtMs = firstSeenAtMs;
            this.repeaterTabName = normalizeBlank(repeaterTabName);
            this.repeaterGroupName = normalizeBlank(repeaterGroupName);
        }

        private boolean hasEquivalentOrBetterMetadataThan(RepeaterTabMetadata metadata) {
            if (metadata == null) {
                return true;
            }
            boolean tabNameCovered = repeaterTabName != null || metadata.tabName() == null;
            boolean groupNameCovered = repeaterGroupName != null || metadata.groupName() == null;
            return tabNameCovered && groupNameCovered;
        }

        private RepeaterTabMetadata asMetadata() {
            return new RepeaterTabMetadata(repeaterTabName, repeaterGroupName, null, null);
        }
    }

    static record RepeaterTabMetadata(
            String tabName,
            String groupName,
            String rootComponentClass,
            String slotIdentityKey) {
        RepeaterTabMetadata {
            tabName = normalizeBlank(tabName);
            groupName = normalizeBlank(groupName);
            rootComponentClass = normalizeBlank(rootComponentClass);
            slotIdentityKey = normalizeBlank(slotIdentityKey);
        }

        private static RepeaterTabMetadata empty(String rootComponentClass) {
            return new RepeaterTabMetadata(null, null, rootComponentClass, null);
        }

        private RepeaterMetadataFields.Metadata asSharedMetadata() {
            return new RepeaterMetadataFields.Metadata(tabName, groupName);
        }

    }

    private static abstract class AbstractCaptureEditor {
        private final EditorCreationContext creationContext;
        private final JPanel hiddenComponent = new JPanel();
        private HttpRequestResponse requestResponse;

        private AbstractCaptureEditor(EditorCreationContext creationContext) {
            this.creationContext = creationContext;
        }

        public String caption() {
            return CAPTION;
        }

        public Component uiComponent() {
            return hiddenComponent;
        }

        public Selection selectedData() {
            return null;
        }

        public boolean isModified() {
            return false;
        }

        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            captureFromEditorContext(creationContext, requestResponse, capturePath(), hiddenComponent);
        }

        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            captureFromEditorContext(creationContext, requestResponse, capturePath(), hiddenComponent);
            return false;
        }

        protected HttpRequestResponse currentRequestResponse() {
            return requestResponse;
        }

        protected abstract String capturePath();
    }

    private static final class CaptureRequestEditor extends AbstractCaptureEditor implements ExtensionProvidedHttpRequestEditor {
        private CaptureRequestEditor(EditorCreationContext creationContext) {
            super(creationContext);
        }

        @Override
        public HttpRequest getRequest() {
            HttpRequestResponse current = currentRequestResponse();
            return current == null ? null : current.request();
        }

        @Override
        protected String capturePath() {
            return "request_editor";
        }
    }

    private static final class CaptureResponseEditor extends AbstractCaptureEditor implements ExtensionProvidedHttpResponseEditor {
        private CaptureResponseEditor(EditorCreationContext creationContext) {
            super(creationContext);
        }

        @Override
        public HttpResponse getResponse() {
            HttpRequestResponse current = currentRequestResponse();
            return current == null ? null : current.response();
        }

        @Override
        protected String capturePath() {
            return "response_editor";
        }
    }

    private static final class RepeaterTabsContextMenuItemsProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            if (!isRepeaterContextMenuEvent(event)) {
                return List.of();
            }
            JMenuItem item = new JMenuItem("Capture current Repeater tab for history export");
            item.addActionListener(ignored -> {
                boolean captured = captureCurrentRepeaterTab(event);
                if (captured) {
                    Logger.logInfoPanelOnly("[RepeaterTabs] Captured current tab for export.");
                } else {
                    Logger.logWarnPanelOnly("[RepeaterTabs] Unable to capture current tab from context menu.");
                }
            });
            return List.of(item);
        }
    }

    static record StartupTabWalkResult(
            boolean locatedRepeaterToolTab,
            int tabbedPaneCount,
            int selectionChangeCount,
            int captureCountBefore,
            int captureCountAfter) { }

    private static final class StartupTabWalkDelegate
            implements RepeaterSwingTabWalker.Delegate<RepeaterTabMetadata> {

        @Override
        public boolean isWalkValid(int generation) {
            return isStartupWalkStillValid(generation);
        }

        @Override
        public int captureCount() {
            return CAPTURED.size();
        }

        @Override
        public RepeaterTabMetadata metadataFor(
                JTabbedPane pane,
                int selectedIndex,
                int paneOrdinal) {
            return topLevelRepeaterTabMetadata(pane, selectedIndex, paneOrdinal);
        }

        @Override
        public void setActiveMetadata(RepeaterTabMetadata metadata) {
            currentStartupSelectionMetadata = metadata;
        }

        @Override
        public void onPassUnavailable(int passNumber, int delayMs) {
            Logger.logDebug("[RepeaterTabs] Startup tab walk pass " + passNumber
                    + " startupSession=" + currentStartupSessionId()
                    + " (" + delayMs + " ms) could not locate Burp's Repeater tool tab.");
        }

        @Override
        public void onPassCompleted(
                int passNumber,
                int delayMs,
                RepeaterSwingTabWalker.PassResult result) {
            logStartupTabWalkResult(passNumber, delayMs, result);
        }

        @Override
        public void onPassFailed(
                int passNumber,
                int delayMs,
                RepeaterSwingTabWalker.WalkFailure failure) {
            logStartupTabWalkFailure(passNumber, delayMs, failure);
        }

        @Override
        public void onWalkCompleted() {
            scheduleStartupExportCompletionSummary();
            closeCaptureWindowForCurrentRun();
        }
    }

    private static boolean isStartupWalkStillValid(int generation) {
        return generation == RUN_GENERATION.get()
                && RuntimeConfig.isExportRunning()
                && RuntimeConfig.isAnyTrafficExportEnabled()
                && RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY);
    }
}
