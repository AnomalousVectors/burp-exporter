package ai.anomalousvectors.tools.burp.sinks;

import ai.anomalousvectors.tools.burp.sinks.RepeaterTabMetadataHeuristics.InferenceResult;
import ai.anomalousvectors.tools.burp.sinks.RepeaterTabMetadataHeuristics.SelectedTabSnapshot;
import java.awt.Component;
import java.awt.Container;
import java.awt.Frame;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
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
import javax.swing.Timer;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.ScopeFilter;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
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
 * currently bound into Repeater tabs. Captured items are de-duplicated by request/response content
 * hash, cached in memory for the extension session, and exported to the traffic index with
 * {@code tool=Repeater Tabs} when that traffic option is enabled.</p>
 */
public final class RepeaterTabsIndexReporter {

    private static final String CAPTION = "AF Repeater Tabs Capture";
    private static final String REPEATER_TOOL_TITLE = "Repeater";
    private static final String TOOL_LABEL = "Repeater Tabs";
    private static final String TOOL_TYPE = "REPEATER_TABS";
    private static final String TOOL_TYPE_KEY = "repeater_tabs";
    private static final int STARTUP_TAB_WALK_DELAY_MS = 350;
    private static final int STARTUP_TAB_WALK_SECOND_PASS_DELAY_MS = 1_600;
    private static final int STARTUP_TAB_WALK_STEP_DELAY_MS = 5;
    private static final int STARTUP_TAB_WALK_STEPS_PER_TICK = 12;
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

    /** Queues all cached Repeater-tab items for the current export run when enabled. */
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

    /** Clears per-run capture state so the next Start can export cached history again. */
    public static void clearRunState() {
        RUN_GENERATION.incrementAndGet();
        CAPTURE_WINDOW_GENERATION.set(-1);
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
        CAPTURED.clear();
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
        RepeaterTabMetadata metadata = currentRepeaterTabMetadata(uiAnchor);
        if (RuntimeConfig.isExportRunning()) {
            RepeaterLiveMetadataTracker.observe(requestResponse, metadata.asSharedMetadata());
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
        Runnable schedule = () -> {
            scheduleStartupTabWalkPass(generation, 1, STARTUP_TAB_WALK_DELAY_MS);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            schedule.run();
        } else {
            SwingUtilities.invokeLater(schedule);
        }
    }

    /**
     * Performs one synchronous Repeater startup tab walk over the provided Swing roots.
     *
     * <p>Caller must invoke on the EDT. This helper temporarily selects Burp's Repeater tool tab,
     * recursively visits nested tab panes under that subtree, and restores the original selections
     * before returning.</p>
     *
     * @param roots top-level Swing roots to search
     * @return summary of whether Repeater was found and how many selections changed
     */
    static StartupTabWalkResult performStartupTabWalk(Iterable<? extends Component> roots) {
        ToolTabLocation repeaterLocation = findToolTabLocation(roots, REPEATER_TOOL_TITLE);
        if (repeaterLocation == null) {
            return new StartupTabWalkResult(false, 0, 0, 0, 0);
        }

        JTabbedPane toolTabs = repeaterLocation.tabbedPane();
        int repeaterIndex = repeaterLocation.index();
        int originalToolIndex = toolTabs.getSelectedIndex();
        int captureCountBefore = CAPTURED.size();
        int toolSelectionChanges = 0;

        try {
            if (originalToolIndex != repeaterIndex) {
                toolTabs.setSelectedIndex(repeaterIndex);
                toolSelectionChanges++;
            }
            Component repeaterRoot = toolTabs.getComponentAt(repeaterIndex);
            SelectionCycleResult cycle = cycleAllTabSelections(repeaterRoot);
            return new StartupTabWalkResult(
                    true,
                    cycle.tabbedPaneCount(),
                    toolSelectionChanges + cycle.selectionChangeCount(),
                    captureCountBefore,
                    CAPTURED.size());
        } finally {
            if (toolTabs.getSelectedIndex() != originalToolIndex
                    && originalToolIndex >= 0
                    && originalToolIndex < toolTabs.getTabCount()) {
                toolTabs.setSelectedIndex(originalToolIndex);
            }
        }
    }

    private static boolean capture(
            HttpRequestResponse requestResponse,
            String capturePath,
            RepeaterTabMetadata repeaterTabMetadata) {
        if (requestResponse == null || !shouldCaptureForCurrentRun()) {
            return false;
        }
        if (requestResponse.response() == null) {
            return false;
        }
        String fingerprint = fingerprintFor(requestResponse);
        boolean startupCaptureWindowOpen = isStartupCaptureWindowOpen();
        RepeaterTabsCapturePolicy.CaptureDecision captureDecision =
                RepeaterTabsCapturePolicy.decide(fingerprint, repeaterTabMetadata, startupCaptureWindowOpen);
        String previousStartupSlotFingerprint =
                startupCaptureWindowOpen
                        ? rememberStartupSlotFingerprint(captureDecision.startupSlotKey(), fingerprint)
                        : null;
        if (captureDecision.startupSlotKey() != null && previousStartupSlotFingerprint != null) {
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
        }
        if (newCapture[0] && !isStartupCaptureWindowOpen()) {
            Logger.logDebug("[RepeaterTabs] Captured Repeater tab via " + capturePath + ".");
        }
        if (newCapture[0] || metadataUpgraded[0]) {
            queueForCurrentRun(CAPTURED.get(captureKey));
        }
        return true;
    }

    private static RepeaterTabMetadata currentRepeaterTabMetadata(Component uiAnchor) {
        if (!SwingUtilities.isEventDispatchThread()) {
            return RepeaterTabMetadata.empty(null);
        }
        RepeaterTabMetadata anchored = inferRepeaterTabMetadataFromAnchor(uiAnchor);
        if (anchored != null) {
            return anchored;
        }
        if (isStartupCaptureWindowOpen() && currentStartupSelectionMetadata != null) {
            return currentStartupSelectionMetadata;
        }
        ToolTabLocation repeaterLocation = findToolTabLocation(List.of(Frame.getFrames()), REPEATER_TOOL_TITLE);
        if (repeaterLocation == null) {
            return RepeaterTabMetadata.empty(null);
        }
        Component repeaterRoot = repeaterLocation.tabbedPane().getComponentAt(repeaterLocation.index());
        return inferRepeaterTabMetadata(repeaterRoot);
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
        List<SelectedTabSnapshot> selectedTabs =
                RepeaterTabMetadataHeuristics.collectSelectedTabSnapshotsFromAnchor(uiAnchor);
        if (selectedTabs.isEmpty()) {
            return null;
        }
        return inferRepeaterTabMetadata(
                selectedTabs,
                uiAnchor == null ? null : uiAnchor.getClass().getName());
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

    private static void logStartupExportCompletionSummary(String startupSession) {
        StartupExportStatsSnapshot snapshot = startupExportStatsSnapshot;
        int newCaptures = Math.max(0, CAPTURED.size() - snapshot.captureCountBefore());
        String body = SnapshotSummary.formatCompletionBody(snapshot.baseline(), true, true);
        Logger.logInfoPanelOnly("[StartupExport] Repeater Tabs: export complete startupSession="
                + RepeaterMetadataTraceLabels.safeValue(startupSession)
                + " captured " + newCaptures + " tab(s)"
                + (body.isEmpty() ? "" : "; " + body)
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
            if (!idle && !startupExportCountersComplete()) {
                Logger.logDebug("[RepeaterTabs] Startup export summary proceeding before traffic queue idle "
                        + "startupSession=" + startupSession
                        + " timeoutMs=" + STARTUP_EXPORT_SUMMARY_WAIT_MS);
            }
            logStartupExportCompletionSummary(startupSession);
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
        return deltas.fileSuccess() >= newCaptures && deltas.openSearchSuccess() >= newCaptures;
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

    /** Schedules one delayed EDT pass of the unsupported Repeater startup tab walk. */
    private static void scheduleStartupTabWalkPass(int generation, int passNumber, int delayMs) {
        Timer timer = new Timer(delayMs, ignored -> runStartupTabWalk(generation, passNumber, delayMs));
        timer.setRepeats(false);
        timer.start();
    }

    /** Runs one delayed Repeater startup tab-walk pass on the EDT. */
    private static void runStartupTabWalk(int generation, int passNumber, int delayMs) {
        boolean generationMatches = generation == RUN_GENERATION.get();
        boolean exportRunning = RuntimeConfig.isExportRunning();
        boolean anyTrafficEnabled = RuntimeConfig.isAnyTrafficExportEnabled();
        boolean repeaterTabsEnabled = RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY);
        if (!generationMatches || !exportRunning || !anyTrafficEnabled || !repeaterTabsEnabled) {
            Logger.logDebug("[RepeaterTabs] Startup tab walk pass " + passNumber
                    + " startupSession=" + currentStartupSessionId()
                    + " skipped: generationMatches=" + generationMatches
                    + ", running=" + exportRunning
                    + ", anyTraffic=" + anyTrafficEnabled
                    + ", repeaterTabsEnabled=" + repeaterTabsEnabled
                    + ", trafficToolTypes=" + describeRuntimeTrafficToolTypes());
            return;
        }
        try {
            startIncrementalStartupTabWalk(generation, passNumber, delayMs);
        } catch (Throwable t) {
            Logger.logErrorPanelOnly("[RepeaterTabs] Startup tab walk pass " + passNumber
                    + " startupSession=" + currentStartupSessionId()
                    + " failed: " + summarizeThrowable(t));
        }
    }

    private static void startIncrementalStartupTabWalk(int generation, int passNumber, int delayMs) {
        ToolTabLocation repeaterLocation = findToolTabLocation(List.of(Frame.getFrames()), REPEATER_TOOL_TITLE);
        if (repeaterLocation == null) {
            Logger.logDebug("[RepeaterTabs] Startup tab walk pass " + passNumber
                    + " startupSession=" + currentStartupSessionId()
                    + " (" + delayMs + " ms) could not locate Burp's Repeater tool tab.");
            scheduleFollowUpStartupTabWalkPass(generation, passNumber);
            return;
        }
        StartupTabWalkPlan plan = buildStartupTabWalkPlan(repeaterLocation);
        new IncrementalStartupTabWalkSession(generation, passNumber, delayMs, plan).start();
    }

    private static void scheduleFollowUpStartupTabWalkPass(int generation, int completedPassNumber) {
        if (generation != RUN_GENERATION.get()) {
            return;
        }
        if (completedPassNumber < 2) {
            scheduleStartupTabWalkPass(generation, completedPassNumber + 1, STARTUP_TAB_WALK_SECOND_PASS_DELAY_MS);
        } else {
            scheduleStartupExportCompletionSummary();
            closeCaptureWindowForCurrentRun();
        }
    }

    /**
     * Cycles every nested tab selection under {@code root} and restores the prior state afterward.
     *
     * <p>Caller must invoke on the EDT. Restoration runs in reverse visitation order so nested tabs
     * return to the same visible state the user had before the walk.</p>
     */
    private static SelectionCycleResult cycleAllTabSelections(Component root) {
        IdentityHashMap<JTabbedPane, Integer> originalSelections = new IdentityHashMap<>();
        List<JTabbedPane> visitedOrder = new ArrayList<>();
        int selectionChanges = cycleSelectionsRecursive(root, originalSelections, visitedOrder, List.of());
        for (int i = visitedOrder.size() - 1; i >= 0; i--) {
            JTabbedPane pane = visitedOrder.get(i);
            Integer originalIndex = originalSelections.get(pane);
            if (originalIndex != null && originalIndex >= 0 && originalIndex < pane.getTabCount()) {
                pane.setSelectedIndex(originalIndex);
            }
        }
        return new SelectionCycleResult(visitedOrder.size(), selectionChanges);
    }

    private static StartupTabWalkPlan buildStartupTabWalkPlan(ToolTabLocation repeaterLocation) {
        JTabbedPane toolTabs = repeaterLocation.tabbedPane();
        int repeaterIndex = repeaterLocation.index();
        Component repeaterRoot = toolTabs.getComponentAt(repeaterIndex);
        IdentityHashMap<JTabbedPane, Integer> originalSelections = new IdentityHashMap<>();
        List<JTabbedPane> visitedOrder = new ArrayList<>();
        List<StartupTabSelectionStep> steps = new ArrayList<>();
        collectStartupTabWalkSteps(repeaterRoot, originalSelections, visitedOrder, List.of(), steps);
        return new StartupTabWalkPlan(
                toolTabs,
                toolTabs.getSelectedIndex(),
                repeaterIndex,
                visitedOrder,
                originalSelections,
                List.copyOf(steps),
                CAPTURED.size());
    }

    private static void collectStartupTabWalkSteps(
            Component root,
            IdentityHashMap<JTabbedPane, Integer> originalSelections,
            List<JTabbedPane> visitedOrder,
            List<SelectedTabSnapshot> selectedPath,
            List<StartupTabSelectionStep> steps) {
        if (root instanceof JTabbedPane pane) {
            if (RepeaterTabMetadataHeuristics.shouldCycleTabPane(pane)) {
                if (originalSelections.containsKey(pane)) {
                    return;
                }
                originalSelections.put(pane, pane.getSelectedIndex());
                visitedOrder.add(pane);
                for (int i = 0; i < pane.getTabCount(); i++) {
                    List<SelectedTabSnapshot> nextPath = RepeaterTabMetadataHeuristics.appendSelectedPath(
                            selectedPath,
                            RepeaterTabMetadataHeuristics.selectedTabSnapshot(pane, i));
                    steps.add(new StartupTabSelectionStep(
                            pane,
                            i,
                            inferRepeaterTabMetadata(nextPath, root.getClass().getName())));
                    collectStartupTabWalkSteps(
                            pane.getComponentAt(i),
                            originalSelections,
                            visitedOrder,
                            nextPath,
                            steps);
                }
                return;
            }
            Component selected = pane.getSelectedComponent();
            if (selected != null) {
                collectStartupTabWalkSteps(selected, originalSelections, visitedOrder, selectedPath, steps);
            }
            return;
        }
        if (!(root instanceof Container container)) {
            return;
        }
        for (Component child : container.getComponents()) {
            collectStartupTabWalkSteps(child, originalSelections, visitedOrder, selectedPath, steps);
        }
    }

    private static int cycleSelectionsRecursive(
            Component root,
            IdentityHashMap<JTabbedPane, Integer> originalSelections,
            List<JTabbedPane> visitedOrder,
            List<SelectedTabSnapshot> selectedPath) {
        if (root instanceof JTabbedPane pane) {
            if (RepeaterTabMetadataHeuristics.shouldCycleTabPane(pane)) {
                if (originalSelections.containsKey(pane)) {
                    return 0;
                }
                originalSelections.put(pane, pane.getSelectedIndex());
                visitedOrder.add(pane);

                int selectionChanges = 0;
                for (int i = 0; i < pane.getTabCount(); i++) {
                    List<SelectedTabSnapshot> nextPath = RepeaterTabMetadataHeuristics.appendSelectedPath(
                            selectedPath,
                            RepeaterTabMetadataHeuristics.selectedTabSnapshot(pane, i));
                    RepeaterTabMetadata previousMetadata = currentStartupSelectionMetadata;
                    currentStartupSelectionMetadata = inferRepeaterTabMetadata(nextPath, root.getClass().getName());
                    try {
                        if (pane.getSelectedIndex() != i) {
                            pane.setSelectedIndex(i);
                            selectionChanges++;
                        }
                        selectionChanges += cycleSelectionsRecursive(
                                pane.getComponentAt(i),
                                originalSelections,
                                visitedOrder,
                                nextPath);
                    } finally {
                        currentStartupSelectionMetadata = previousMetadata;
                    }
                }
                return selectionChanges;
            }
            Component selected = pane.getSelectedComponent();
            return selected == null ? 0 : cycleSelectionsRecursive(selected, originalSelections, visitedOrder, selectedPath);
        }

        if (!(root instanceof Container container)) {
            return 0;
        }

        int selectionChanges = 0;
        for (Component child : container.getComponents()) {
            selectionChanges += cycleSelectionsRecursive(child, originalSelections, visitedOrder, selectedPath);
        }
        return selectionChanges;
    }

    /**
     * Searches the provided Swing roots for a tabbed pane entry whose visible title matches
     * {@code title}, ignoring case.
     */
    private static ToolTabLocation findToolTabLocation(Iterable<? extends Component> roots, String title) {
        if (roots == null || title == null || title.isBlank()) {
            return null;
        }
        for (Component root : roots) {
            ToolTabLocation location = findToolTabLocation(root, title);
            if (location != null) {
                return location;
            }
        }
        return null;
    }

    private static ToolTabLocation findToolTabLocation(Component root, String title) {
        if (root == null) {
            return null;
        }
        if (root instanceof JTabbedPane pane) {
            for (int i = 0; i < pane.getTabCount(); i++) {
                String tabTitle = pane.getTitleAt(i);
                if (title.equalsIgnoreCase(tabTitle)) {
                    return new ToolTabLocation(pane, i);
                }
            }
        }
        if (!(root instanceof Container container)) {
            return null;
        }
        for (Component child : container.getComponents()) {
            ToolTabLocation location = findToolTabLocation(child, title);
            if (location != null) {
                return location;
            }
        }
        return null;
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

    private static boolean shouldCaptureForCurrentRun() {
        if (!RuntimeConfig.isExportRunning()) {
            return true;
        }
        return CAPTURE_WINDOW_GENERATION.get() == RUN_GENERATION.get();
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

    private static record SelectionCycleResult(int tabbedPaneCount, int selectionChangeCount) { }

    private static record StartupTabSelectionStep(
            JTabbedPane pane,
            int selectedIndex,
            RepeaterTabMetadata metadata) { }

    private static record StartupTabWalkPlan(
            JTabbedPane toolTabs,
            int originalToolIndex,
            int repeaterIndex,
            List<JTabbedPane> visitedOrder,
            IdentityHashMap<JTabbedPane, Integer> originalSelections,
            List<StartupTabSelectionStep> steps,
            int captureCountBefore) { }

    private static record ToolTabLocation(JTabbedPane tabbedPane, int index) { }

    private static final class IncrementalStartupTabWalkSession {
        private final int generation;
        private final int passNumber;
        private final int delayMs;
        private final StartupTabWalkPlan plan;
        private final Timer timer;
        private int nextStepIndex;
        private int selectionChanges;

        private IncrementalStartupTabWalkSession(
                int generation,
                int passNumber,
                int delayMs,
                StartupTabWalkPlan plan) {
            this.generation = generation;
            this.passNumber = passNumber;
            this.delayMs = delayMs;
            this.plan = plan;
            this.timer = new Timer(STARTUP_TAB_WALK_STEP_DELAY_MS, ignored -> processNextStep());
            this.timer.setRepeats(true);
        }

        private void start() {
            if (plan.steps().isEmpty()) {
                finish();
                return;
            }
            timer.start();
        }

        private void processNextStep() {
            if (!isStartupWalkStillValid(generation)) {
                cancelAndRestore();
                return;
            }
            if (nextStepIndex >= plan.steps().size()) {
                finish();
                return;
            }
            boolean restoreOuterToolSelection = plan.toolTabs().getSelectedIndex() != plan.repeaterIndex();
            if (restoreOuterToolSelection) {
                plan.toolTabs().setSelectedIndex(plan.repeaterIndex());
                selectionChanges++;
            }
            try {
                int stepsThisTick = 0;
                while (nextStepIndex < plan.steps().size() && stepsThisTick < STARTUP_TAB_WALK_STEPS_PER_TICK) {
                    StartupTabSelectionStep step = plan.steps().get(nextStepIndex++);
                    currentStartupSelectionMetadata = step.metadata();
                    if (step.pane().getSelectedIndex() != step.selectedIndex()) {
                        step.pane().setSelectedIndex(step.selectedIndex());
                        selectionChanges++;
                    }
                    stepsThisTick++;
                }
            } finally {
                currentStartupSelectionMetadata = null;
                if (restoreOuterToolSelection
                        && plan.originalToolIndex() >= 0
                        && plan.originalToolIndex() < plan.toolTabs().getTabCount()
                        && plan.toolTabs().getSelectedIndex() != plan.originalToolIndex()) {
                    plan.toolTabs().setSelectedIndex(plan.originalToolIndex());
                }
            }
            if (nextStepIndex >= plan.steps().size()) {
                finish();
            }
        }

        private void finish() {
            timer.stop();
            currentStartupSelectionMetadata = null;
            restoreSelections();
            StartupTabWalkResult result = new StartupTabWalkResult(
                    true,
                    plan.visitedOrder().size(),
                    selectionChanges,
                    plan.captureCountBefore(),
                    CAPTURED.size());
            logStartupTabWalkResult(result);
            scheduleFollowUpStartupTabWalkPass(generation, passNumber);
        }

        private void cancelAndRestore() {
            timer.stop();
            currentStartupSelectionMetadata = null;
            restoreSelections();
        }

        private void restoreSelections() {
            for (int i = plan.visitedOrder().size() - 1; i >= 0; i--) {
                JTabbedPane pane = plan.visitedOrder().get(i);
                Integer originalIndex = plan.originalSelections().get(pane);
                if (originalIndex != null
                        && originalIndex >= 0
                        && originalIndex < pane.getTabCount()
                        && pane.getSelectedIndex() != originalIndex) {
                    pane.setSelectedIndex(originalIndex);
                }
            }
            if (plan.originalToolIndex() >= 0
                    && plan.originalToolIndex() < plan.toolTabs().getTabCount()
                    && plan.toolTabs().getSelectedIndex() != plan.originalToolIndex()) {
                plan.toolTabs().setSelectedIndex(plan.originalToolIndex());
            }
        }

        private void logStartupTabWalkResult(StartupTabWalkResult result) {
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
    }

    private static boolean isStartupWalkStillValid(int generation) {
        return generation == RUN_GENERATION.get()
                && RuntimeConfig.isExportRunning()
                && RuntimeConfig.isAnyTrafficExportEnabled()
                && RuntimeConfig.isTrafficToolTypeEnabled(TOOL_TYPE_KEY);
    }
}
