package ai.anomalousvectors.tools.burp.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.prefs.Preferences;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.JViewport;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter.HighlightPainter;

import ai.anomalousvectors.tools.burp.ui.log.LogRenderer;
import ai.anomalousvectors.tools.burp.ui.log.LogStore;
import ai.anomalousvectors.tools.burp.ui.primitives.AutoSizingTextField;
import ai.anomalousvectors.tools.burp.ui.primitives.ButtonStyles;
import ai.anomalousvectors.tools.burp.ui.primitives.ScrollPanes;
import ai.anomalousvectors.tools.burp.ui.primitives.TextFieldUndo;
import ai.anomalousvectors.tools.burp.ui.text.Doc;
import ai.anomalousvectors.tools.burp.ui.text.HighlighterManager;
import ai.anomalousvectors.tools.burp.ui.text.IndentedWrappedTextAreaUI;
import ai.anomalousvectors.tools.burp.ui.text.RegexIndicatorBinder;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.FileUtil;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.text.TextQuery;
import ai.anomalousvectors.tools.burp.utils.text.TextSearchEngine;
import net.miginfocom.swing.MigLayout;

/**
 * Log view with level filter, pause autoscroll, clear/copy/save, text filter (case/regex,
 * optional exclude via ! toggle), search (case/regex, highlight all, match count), and duplicate compaction.
 *
 * <p><strong>Design:</strong> Coordinates a {@link LogStore} (model) with a {@link LogRenderer} (view).
 * Keeps regex compilation and flag rules centralized via {@link ai.anomalousvectors.tools.burp.utils.Regex}.</p>
 *
 * <p><strong>Threading:</strong> All UI mutations occur on the EDT. Logger callbacks are marshaled with
 * {@code invokeLater} to preserve ordering and avoid contention with highlight recomputation.</p>
 */
public class LogPanel extends JPanel implements Logger.ReplayableLogListener {

    @Serial
    private static final long serialVersionUID = 1L;

    // Toolbar layout snippets for consistency across rebuilds.
    private static final String MIG_TOOLBAR_INSETS = "insets 6 8 6 8, fillx, novisualpadding, gapx 0";
    private static final String MIG_TOOLBAR_SECTION = "insets 0, gapx 6, novisualpadding";
    private static final String MIG_SECTION_GAP = "pushx, growx";
    private static final String GAP0               = "gapx 0";
    private static final String GAP4               = "gapx 4";
    private static final String GAP6               = "gapx 6";

    // Actions / defaults
    private static final String ACTION_SEARCH_NEXT = "log.search.next";
    /** Label for the exclude (invert) filter toggle. */
    private static final String FILTER_NEGATIVE_TOGGLE_LABEL = "!";
    private static final String PAUSE_BTN_LABEL = "Pause";
    private static final String UNPAUSE_BTN_LABEL = "Unpause";
    private static final String GAP2               = "gapx 2";
    private static final String DEFAULT_MIN_LEVEL  = ConfigState.DEFAULT_LOG_MIN_LEVEL;
    private static final String[] LEVEL_LABELS = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"};
    private static final int MAX_MODEL_ENTRIES     = 5000;

    /** Debounce window for search highlight recomputation under high-rate ingest. */
    private static final int SEARCH_RECOMPUTE_DEBOUNCE_MS = 150;

    // Editor and renderer (JTextArea for reliable line wrap; no horizontal scroll)
    private final JTextArea logTextPane;
    private final transient LogRenderer renderer;

    // Controls
    private final JComboBox<String> levelCombo;
    private final JButton pauseAutoscrollBtn;
    private boolean autoscrollPaused;

    // Filter controls
    private final AutoSizingTextField filterField;
    private final JCheckBox filterCaseToggle;
    private final JCheckBox filterRegexToggle;
    private final JCheckBox filterNegativeToggle;

    // Search controls
    private final AutoSizingTextField searchField;
    private final JCheckBox searchCaseToggle;
    private final JCheckBox searchRegexToggle;
    private final JLabel searchCountLabel;

    // Search state and highlighting
    private final transient HighlighterManager highlighterManager;
    private List<int[]> matches = List.of(); // [start, end]
    private int matchIndex = -1;

    // Persistence
    private static final Preferences PREFS = Preferences.userRoot().node("ai.anomalousvectors.tools.burp.ui.LogPanel");
    private static final String PREF_MIN_LEVEL     = "minLevel";
    private static final String PREF_PAUSE         = "pauseAutoscroll";
    private static final String PREF_LAST_SEARCH   = "lastSearch";
    private static final String PREF_FILTER_TEXT   = "filterText";
    private static final String PREF_FILTER_CASE   = "filterCase";
    private static final String PREF_FILTER_REGEX  = "filterRegex";
    private static final String PREF_FILTER_NEGATIVE = "filterNegative";
    private static final String PREF_SEARCH_CASE   = "searchCase";
    private static final String PREF_SEARCH_REGEX  = "searchRegex";

    // Indicator bindings (kept so removeNotify can unbind explicitly)
    private final transient AutoCloseable searchIndicatorBinding;
    private final transient AutoCloseable filterIndicatorBinding;
    private final transient RuntimeConfig.StateListener runtimeStateListener;

    // Model
    private final transient LogStore store;
    private transient boolean applyingUiPreferences;

    /**
     * Mirror of the visible aggregates currently rendered into the document. Maintained in
     * lockstep with {@link LogRenderer#append}/{@link LogRenderer#replaceLast}/incremental
     * trim so that {@link #applyIncrementalTrim} can compute a suffix-diff against the
     * canonical {@link LogStore#buildVisibleAggregated()} without paying for a full rebuild.
     */
    private transient List<LogStore.Aggregate> renderedAggregates = new ArrayList<>();

    /**
     * Visibility gate driving whether ingest performs view work.
     *
     * <p>Defaults to {@code true} so that:</p>
     * <ul>
     *   <li>Construction-time {@link #rebuildView()} runs.</li>
     *   <li>Headless tests that never call {@link #addNotify()} still see ingests render
     *       into the document.</li>
     * </ul>
     *
     * <p>Real Burp use re-evaluates this in {@link #addNotify()} and through a
     * {@link HierarchyListener} on {@link HierarchyEvent#SHOWING_CHANGED}. While
     * {@code viewActive == false}, ingest still feeds {@link LogStore} so the model stays
     * authoritative; document edits and search recomputes are deferred. When the panel
     * becomes visible again {@link #rebuildView()} resyncs the document in one pass.</p>
     */
    private transient boolean viewActive = true;

    /** Set whenever an ingest or trim is processed while {@link #viewActive} is {@code false}. */
    private transient boolean viewDirty;

    private final transient HierarchyListener visibilityListener = this::onHierarchyChanged;

    /**
     * Coalesces search match recomputation during high-throughput ingest. Empty-query and
     * user-initiated paths bypass the timer ({@link #recomputeMatchesNow()}).
     */
    private final transient Timer searchRecomputeTimer;

    /** Constructs and wires the UI (EDT). */
    public LogPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(1200, 600));

        // Editor + renderer (JTextArea for reliable line wrap; no horizontal scroll bar; continuation indent on wrap)
        logTextPane = new JTextArea();
        logTextPane.setLineWrap(true);
        logTextPane.setWrapStyleWord(true);
        logTextPane.setUI(new IndentedWrappedTextAreaUI());
        logTextPane.setEditable(false);
        logTextPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logTextPane.setBackground(UIManager.getColor("TextArea.background"));
        logTextPane.setForeground(UIManager.getColor("TextArea.foreground"));
        renderer = new LogRenderer(logTextPane);

        // Highlight painter uses LAF color to integrate visually with theme.
        Color sel = UIManager.getColor("TextField.selectionBackground");
        if (sel == null) sel = UIManager.getColor("TextArea.selectionBackground");
        if (sel == null) sel = new Color(180, 200, 255);
        HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(sel);
        highlighterManager = new HighlighterManager(logTextPane, painter);

        // Toolbar
        JPanel toolbar = new JPanel(new MigLayout(MIG_TOOLBAR_INSETS, "", "[]"));
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")));

        levelCombo = new Tooltips.HtmlComboBox<>(LEVEL_LABELS);
        levelCombo.setName("log.filter.level");
        levelCombo.setSelectedItem(displayLogMinLevel(ConfigState.normalizeLogMinLevel(PREFS.get(PREF_MIN_LEVEL, DEFAULT_MIN_LEVEL))));

        autoscrollPaused = PREFS.getBoolean(PREF_PAUSE, false);
        pauseAutoscrollBtn = new Tooltips.HtmlButton(autoscrollPaused ? UNPAUSE_BTN_LABEL : PAUSE_BTN_LABEL);
        pauseAutoscrollBtn.setName("log.pause");

        // Filter group (restore persisted)
        filterField = new AutoSizingTextField(PREFS.get(PREF_FILTER_TEXT, ""));
        filterField.setName("log.filter.text");
        filterCaseToggle = new Tooltips.HtmlCheckBox("Aa");
        filterCaseToggle.setName("log.filter.case");
        filterCaseToggle.setSelected(PREFS.getBoolean(PREF_FILTER_CASE, false));
        filterRegexToggle = new Tooltips.HtmlCheckBox(".*");
        filterRegexToggle.setName("log.filter.regex");
        filterNegativeToggle = new Tooltips.HtmlCheckBox(FILTER_NEGATIVE_TOGGLE_LABEL);
        filterNegativeToggle.setName("log.filter.negative");
        filterNegativeToggle.setSelected(PREFS.getBoolean(PREF_FILTER_NEGATIVE, false));
        final JLabel filterRegexIndicator = new Tooltips.HtmlLabel("");
        filterRegexIndicator.setName("log.filter.regex.indicator");

        // Search group (restore last search text only)
        searchField = new AutoSizingTextField(PREFS.get(PREF_LAST_SEARCH, ""));
        searchField.setName("log.search.field");
        searchCaseToggle = new Tooltips.HtmlCheckBox("Aa");
        searchCaseToggle.setName("log.search.case");
        searchCaseToggle.setSelected(PREFS.getBoolean(PREF_SEARCH_CASE, false));
        searchRegexToggle = new Tooltips.HtmlCheckBox(".*");
        searchRegexToggle.setName("log.search.regex");
        searchRegexToggle.setSelected(PREFS.getBoolean(PREF_SEARCH_REGEX, false));
        JButton searchPrevBtn = new Tooltips.HtmlButton("Prev");
        searchPrevBtn.setName("log.search.prev");
        JButton searchNextBtn = new Tooltips.HtmlButton("Next");
        searchNextBtn.setName(ACTION_SEARCH_NEXT);
        searchCountLabel = new Tooltips.HtmlLabel("0/0");
        searchCountLabel.setName("log.search.count");
        Tooltips.apply(searchCountLabel, Tooltips.html("Current match and total matches for the active Find query."));
        final JLabel searchRegexIndicator = new Tooltips.HtmlLabel("");
        searchRegexIndicator.setName("log.search.regex.indicator");

        JButton clearBtn = new Tooltips.HtmlButton("Clear");
        clearBtn.setName("log.clear");
        JButton copyBtn = new Tooltips.HtmlButton("Copy");
        copyBtn.setName("log.copy");
        JButton saveBtn = new Tooltips.HtmlButton("Save");
        saveBtn.setName("log.save");
        ButtonStyles.normalize(searchPrevBtn);
        ButtonStyles.normalize(searchNextBtn);
        ButtonStyles.normalize(clearBtn);
        ButtonStyles.normalize(copyBtn);
        ButtonStyles.normalize(saveBtn);
        ButtonStyles.normalize(pauseAutoscrollBtn);
        pinPauseButtonWidth();

        assignToolTips(
                searchPrevBtn,
                searchNextBtn,
                pauseAutoscrollBtn,
                clearBtn,
                copyBtn,
                saveBtn
        );

        // Build toolbar: five compact sections with equal flex gaps between them.
        JLabel minLevelLabel = Tooltips.label("Min level:",
                Tooltips.html("Choose the minimum log level shown in the pane."));
        JPanel minLevelSection = new JPanel(new MigLayout(MIG_TOOLBAR_SECTION, "", "[]"));
        minLevelSection.add(minLevelLabel);
        minLevelSection.add(levelCombo, "w 110!");

        JLabel filterLabel = Tooltips.label("Filter:",
                Tooltips.html("Filter visible log entries by plain text or regex."));
        JPanel filterSection = new JPanel(new MigLayout(MIG_TOOLBAR_SECTION, "", "[]"));
        filterSection.add(filterLabel, GAP0);
        filterSection.add(filterField, GAP0);
        filterSection.add(filterCaseToggle, GAP4);
        filterSection.add(filterRegexToggle, GAP4);
        filterSection.add(filterNegativeToggle, GAP4);
        filterSection.add(filterRegexIndicator, GAP6);

        JLabel findLabel = Tooltips.label("Find:",
                Tooltips.html("Search within the visible log entries."));
        JPanel findSection = new JPanel(new MigLayout(MIG_TOOLBAR_SECTION, "", "[]"));
        findSection.add(findLabel, GAP0);
        findSection.add(searchField, GAP0);
        findSection.add(searchCaseToggle, GAP4);
        findSection.add(searchRegexToggle, GAP4);
        findSection.add(searchRegexIndicator, GAP4);
        findSection.add(searchPrevBtn, GAP2);
        findSection.add(searchNextBtn, GAP4);
        findSection.add(searchCountLabel, GAP6);

        JPanel actionSection = new JPanel(new MigLayout(MIG_TOOLBAR_SECTION, "", "[]"));
        actionSection.add(copyBtn);
        actionSection.add(saveBtn, GAP4);

        JPanel trailingSection = new JPanel(new MigLayout(MIG_TOOLBAR_SECTION + ", fillx", "", "[]"));
        trailingSection.add(pauseAutoscrollBtn);
        trailingSection.add(new JLabel(), "pushx, growx");
        trailingSection.add(clearBtn, GAP0);

        toolbar.add(minLevelSection);
        toolbar.add(new JLabel(), MIG_SECTION_GAP);
        toolbar.add(filterSection);
        toolbar.add(new JLabel(), MIG_SECTION_GAP);
        toolbar.add(findSection);
        toolbar.add(new JLabel(), MIG_SECTION_GAP);
        toolbar.add(actionSection);
        toolbar.add(new JLabel(), MIG_SECTION_GAP);
        toolbar.add(trailingSection, "growx");

        add(toolbar, BorderLayout.NORTH);

        add(ScrollPanes.wrapNoHorizontalScroll(logTextPane), BorderLayout.CENTER);

        // Model created before listeners capture it; filter supplied via visible().
        store = new LogStore(MAX_MODEL_ENTRIES, this::visible);

        // Context menu (right-click on the log area)
        JPopupMenu menu = buildContextMenu();
        logTextPane.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { maybeShow(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShow(e); }
            private void maybeShow(MouseEvent e) {
                if (e.isPopupTrigger()) menu.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        // Wiring
        levelCombo.addActionListener(e -> {
            PREFS.put(PREF_MIN_LEVEL, selectedLogMinLevel());
            rebuildView();
            syncRuntimePreferencesFromUi();
        });

        pauseAutoscrollBtn.addActionListener(e -> setAutoscrollPaused(!autoscrollPaused));

        DocumentListener filterChange = Doc.onChange(() -> {
            PREFS.put(PREF_FILTER_TEXT, filterField.getText());
            rebuildView();
            syncRuntimePreferencesFromUi();
        });
        filterField.getDocument().addDocumentListener(filterChange);
        filterCaseToggle.addActionListener(e -> {
            PREFS.putBoolean(PREF_FILTER_CASE, filterCaseToggle.isSelected());
            rebuildView();
            syncRuntimePreferencesFromUi();
        });
        filterRegexToggle.addActionListener(e -> {
            PREFS.putBoolean(PREF_FILTER_REGEX, filterRegexToggle.isSelected());
            rebuildView();
            syncRuntimePreferencesFromUi();
        });
        filterNegativeToggle.addActionListener(e -> {
            PREFS.putBoolean(PREF_FILTER_NEGATIVE, filterNegativeToggle.isSelected());
            rebuildView();
            syncRuntimePreferencesFromUi();
        });

        DocumentListener searchChange = Doc.onChange(() -> {
            PREFS.put(PREF_LAST_SEARCH, searchField.getText());
            computeMatchesAndJumpFirst();
            syncRuntimePreferencesFromUi();
        });
        searchField.getDocument().addDocumentListener(searchChange);
        searchField.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke("ENTER"), ACTION_SEARCH_NEXT
        );
        searchField.getActionMap().put(ACTION_SEARCH_NEXT, new AbstractAction() {
            @Override public void actionPerformed(ActionEvent e) { jumpMatch(+1); }
        });

        searchPrevBtn.addActionListener(e -> jumpMatch(-1));
        searchNextBtn.addActionListener(e -> jumpMatch(+1));
        searchCaseToggle.addActionListener(e -> {
            PREFS.putBoolean(PREF_SEARCH_CASE, searchCaseToggle.isSelected());
            computeMatchesAndJumpFirst();
            syncRuntimePreferencesFromUi();
        });
        searchRegexToggle.addActionListener(e -> {
            PREFS.putBoolean(PREF_SEARCH_REGEX, searchRegexToggle.isSelected());
            computeMatchesAndJumpFirst();
            syncRuntimePreferencesFromUi();
        });

        clearBtn.addActionListener(e -> {
            Logger.internalDebug("LogPanel: clear requested");
            store.clear();
            renderer.clear();
            renderedAggregates.clear();
            viewDirty = false;
            clearSearchHighlights();
            matches = List.of();
            matchIndex = -1;
            updateMatchCount();
            Logger.internalTrace("LogPanel: cleared, matches reset");
        });

        copyBtn.addActionListener(e -> copySelectionOrAll());
        saveBtn.addActionListener(e -> saveVisible());

        // Regex indicators (✓/✖). Binder enforces fixed width and glyph-safe font.
        searchIndicatorBinding = RegexIndicatorBinder.bind(
                searchField, searchRegexToggle, searchCaseToggle, true, searchRegexIndicator
        );
        filterIndicatorBinding = RegexIndicatorBinder.bind(
                filterField, filterRegexToggle, filterCaseToggle, false, filterRegexIndicator
        );

        TextFieldUndo.install(filterField);
        TextFieldUndo.install(searchField);

        runtimeStateListener = this::onRuntimeStateChanged;

        searchRecomputeTimer = new Timer(SEARCH_RECOMPUTE_DEBOUNCE_MS, e -> doRecomputeMatches());
        searchRecomputeTimer.setRepeats(false);
        searchRecomputeTimer.setCoalesce(true);

        applyAutoscrollPauseState();
        rebuildView();
        computeMatchesAndJumpFirst();
        syncRuntimePreferencesFromUi();
    }

    /**
     * Registers with Logger when this panel is added to the display hierarchy.
     * Burp may remove our tab content when another top-level tab is selected and re-add when
     * the user switches back; we only receive log messages while registered, so we register
     * here and unregister in removeNotify. Logger replays recent messages to newly registered
     * listeners so the Log tab shows full history after a tab switch.
     */
    @Override
    public void addNotify() {
        super.addNotify();
        // Reset visibility gating to a clean baseline. removeNotify() may have flipped
        // viewActive=false in response to a SHOWING_CHANGED event fired during teardown;
        // on re-add we want a fresh evaluation rather than carrying forward stale state.
        viewActive = true;
        viewDirty = false;
        Logger.registerListener(this);
        RuntimeConfig.registerStateListener(runtimeStateListener);
        addHierarchyListener(visibilityListener);
        // Re-evaluate visibility only when there is a real parent hierarchy. Headless tests
        // call addNotify() without attaching the panel to a frame; isShowing() is false in
        // that case but it does not represent the "user on another tab" scenario the gating
        // is designed for. We therefore key off the presence of a parent and rely on
        // SHOWING_CHANGED to toggle once the panel is actually attached to a visible frame.
        if (getParent() != null && !isShowing()) {
            viewActive = false;
            viewDirty = true;
        }
    }

    /**
     * Updates pause state, button label, persistence, and runtime config.
     *
     * @param paused {@code true} when autoscroll should stay at the current viewport position
     */
    private void setAutoscrollPaused(boolean paused) {
        autoscrollPaused = paused;
        updatePauseButtonLabel();
        applyAutoscrollPauseState();
        PREFS.putBoolean(PREF_PAUSE, paused);
        if (!paused) {
            renderer.autoscrollIfNeeded(false);
        }
        syncRuntimePreferencesFromUi();
    }

    /** Syncs the pause button label with {@link #autoscrollPaused}. */
    private void updatePauseButtonLabel() {
        pauseAutoscrollBtn.setText(autoscrollPaused ? UNPAUSE_BTN_LABEL : PAUSE_BTN_LABEL);
    }

    /**
     * Keeps the log caret from following document inserts.
     *
     * <p>{@link DefaultCaret#ALWAYS_UPDATE} (and {@code setCaretPosition} during appends) can steal
     * keyboard focus from the toolbar while logs stream. Autoscroll instead moves the viewport via
     * {@link ai.anomalousvectors.tools.burp.ui.log.LogRenderer#autoscrollIfNeeded(boolean)}.</p>
     */
    private void applyAutoscrollPauseState() {
        if (logTextPane.getCaret() instanceof DefaultCaret caret) {
            caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
        }
    }

    /**
     * Pins pause-button width to the wider toggle label so trailing toolbar layout does not shift.
     */
    private void pinPauseButtonWidth() {
        FontMetrics fm = pauseAutoscrollBtn.getFontMetrics(pauseAutoscrollBtn.getFont());
        int textWidth = Math.max(fm.stringWidth(PAUSE_BTN_LABEL), fm.stringWidth(UNPAUSE_BTN_LABEL));
        Insets insets = pauseAutoscrollBtn.getInsets();
        int width = textWidth + insets.left + insets.right;
        Dimension fixed = new Dimension(width, pauseAutoscrollBtn.getPreferredSize().height);
        pauseAutoscrollBtn.setMinimumSize(fixed);
        pauseAutoscrollBtn.setPreferredSize(fixed);
    }

    /**
     * Assigns tooltips for all toolbar controls in one place.
     *
     * @param searchPrevBtn jump-to-previous button
     * @param searchNextBtn jump-to-next button
     * @param pauseAutoscrollBtn pause/unpause autoscroll button
     * @param clearBtn      clear action button
     * @param copyBtn       copy action button
     * @param saveBtn       save action button
     */
    private void assignToolTips(
            JButton searchPrevBtn,
            JButton searchNextBtn,
            JButton pauseAutoscrollBtn,
            JButton clearBtn,
            JButton copyBtn,
            JButton saveBtn
    ) {
        Tooltips.apply(levelCombo, Tooltips.html("Minimum level to display."));
        Tooltips.apply(pauseAutoscrollBtn, Tooltips.html(
                "Pause autoscroll while reviewing the log. Click again (Unpause) to follow new entries."));

        Tooltips.apply(filterField, Tooltips.html("Filter by string or regex."));
        Tooltips.apply(filterCaseToggle, Tooltips.html("Case-sensitive filter."));
        Tooltips.apply(filterRegexToggle, Tooltips.html("Regex filter."));
        Tooltips.apply(filterNegativeToggle, Tooltips.html(
                "Exclude (!): show only lines that do not match the filter."));

        Tooltips.apply(searchField, Tooltips.html("Find string or regex."));
        Tooltips.apply(searchCaseToggle, Tooltips.html("Case-sensitive search."));
        Tooltips.apply(searchRegexToggle, Tooltips.html("Regex search."));

        Tooltips.apply(searchPrevBtn, Tooltips.html("Jump to previous match."));
        Tooltips.apply(searchNextBtn, Tooltips.html("Jump to next match."));

        Tooltips.apply(clearBtn, Tooltips.html("Clear log pane."));
        Tooltips.apply(copyBtn, Tooltips.html("Copy log to clipboard."));
        Tooltips.apply(saveBtn, Tooltips.html("Save log to file."));
    }

    /**
     * Lifecycle hook: unregisters from Logger (so we stop receiving while not in the hierarchy)
     * and closes regex bindings when removed. Re-registration happens in addNotify when shown again.
     */
    @Override
    public void removeNotify() {
        // Detach the hierarchy listener before super.removeNotify() so the SHOWING_CHANGED
        // event fired during teardown does not flip our visibility gating to "hidden" (which
        // would persist into the next addNotify() and silently defer log replay).
        removeHierarchyListener(visibilityListener);
        super.removeNotify();
        Logger.unregisterListener(this);
        RuntimeConfig.unregisterStateListener(runtimeStateListener);
        searchRecomputeTimer.stop();
        try { if (filterIndicatorBinding != null) filterIndicatorBinding.close(); }
        catch (Exception ex) { Logger.internalDebug("regex filter binder close skipped: " + ex); }
        try { if (searchIndicatorBinding != null) searchIndicatorBinding.close(); }
        catch (Exception ex) { Logger.internalDebug("regex search binder close skipped: " + ex); }
    }

    /**
     * Listens for hierarchy changes so we can pause document edits while the panel is hidden
     * (the user is on another sub-tab). When the panel becomes visible again, we resync via a
     * single {@link #rebuildView()} so the user sees exactly what they would have seen had we
     * been rendering live.
     */
    private void onHierarchyChanged(HierarchyEvent e) {
        if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) == 0) return;
        boolean showing = isShowing();
        if (showing == viewActive) return;
        viewActive = showing;
        if (showing && viewDirty) {
            viewDirty = false;
            rebuildView();
            recomputeMatchesNow();
        }
    }

    private void onRuntimeStateChanged(ConfigState.State state) {
        Runnable apply = () -> applyUiPreferences(state == null ? null : state.uiPreferences());
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            javax.swing.SwingUtilities.invokeLater(apply);
        }
    }

    private void applyUiPreferences(ConfigState.UiPreferences uiPreferences) {
        ConfigState.LogPanelPreferences preferences = uiPreferences == null
                ? ConfigState.defaultLogPanelPreferences()
                : uiPreferences.logPanel();
        ConfigState.LogPanelPreferences current = currentUiPreferences();
        if (current.equals(preferences)) {
            return;
        }
        applyingUiPreferences = true;
        try {
            levelCombo.setSelectedItem(displayLogMinLevel(preferences.minLevel()));
            autoscrollPaused = preferences.pauseAutoscroll();
            updatePauseButtonLabel();
            applyAutoscrollPauseState();
            filterField.setText(preferences.filterText());
            filterCaseToggle.setSelected(preferences.filterCase());
            filterRegexToggle.setSelected(preferences.filterRegex());
            filterNegativeToggle.setSelected(preferences.filterNegative());
            searchField.setText(preferences.searchText());
            searchCaseToggle.setSelected(preferences.searchCase());
            searchRegexToggle.setSelected(preferences.searchRegex());
            persistUiPreferencesToPreferences(preferences);
            rebuildView();
            if (autoscrollPaused) {
                recomputeMatchesNow();
            } else {
                computeMatchesAndJumpFirst();
            }
        } finally {
            applyingUiPreferences = false;
        }
    }

    private void syncRuntimePreferencesFromUi() {
        if (!applyingUiPreferences) {
            RuntimeConfig.updateLogPanelPreferences(currentUiPreferences());
        }
    }

    private ConfigState.LogPanelPreferences currentUiPreferences() {
        return new ConfigState.LogPanelPreferences(
                selectedLogMinLevel(),
                autoscrollPaused,
                filterField.getText(),
                filterCaseToggle.isSelected(),
                filterRegexToggle.isSelected(),
                filterNegativeToggle.isSelected(),
                searchField.getText(),
                searchCaseToggle.isSelected(),
                searchRegexToggle.isSelected());
    }

    private String selectedLogMinLevel() {
        return ConfigState.normalizeLogMinLevel(Objects.toString(levelCombo.getSelectedItem(), DEFAULT_MIN_LEVEL));
    }

    private static String displayLogMinLevel(String normalizedLevel) {
        return switch (ConfigState.normalizeLogMinLevel(normalizedLevel)) {
            case "trace" -> "TRACE";
            case "debug" -> "DEBUG";
            case "info" -> "INFO";
            case "warn" -> "WARN";
            case "error" -> "ERROR";
            default -> "TRACE";
        };
    }

    private static void persistUiPreferencesToPreferences(ConfigState.LogPanelPreferences preferences) {
        PREFS.put(PREF_MIN_LEVEL, preferences.minLevel());
        PREFS.putBoolean(PREF_PAUSE, preferences.pauseAutoscroll());
        PREFS.put(PREF_FILTER_TEXT, preferences.filterText());
        PREFS.putBoolean(PREF_FILTER_CASE, preferences.filterCase());
        PREFS.putBoolean(PREF_FILTER_REGEX, preferences.filterRegex());
        PREFS.putBoolean(PREF_FILTER_NEGATIVE, preferences.filterNegative());
        PREFS.put(PREF_LAST_SEARCH, preferences.searchText());
        PREFS.putBoolean(PREF_SEARCH_CASE, preferences.searchCase());
        PREFS.putBoolean(PREF_SEARCH_REGEX, preferences.searchRegex());
    }

    // ---- Logger.LogListener ----

    /**
     * Logger callback; invoked on the EDT by Logger so ingestion runs on the UI thread.
     *
     * @param level   level string from Logger
     * @param message log message (nullable)
     */
    @Override
    public void onLog(String level, String message) {
        ingest(level, message);
    }

    // ---- Ingest and rendering ----

    /**
     * Ingests a log event, rendering incrementally when visible.
     *
     * @param levelStr level string (parsed via {@link LogStore.Level#fromString(String)})
     * @param message  log message (nullable)
     */
    private void ingest(String levelStr, String message) {
        LogStore.Level lvl = LogStore.Level.fromString(levelStr);
        if (Logger.isInternalTraceEnabled()) {
            Logger.internalTrace("LogPanel ingest -> level=" + lvl + " msg=" + (message == null ? "" : message));
        }
        LocalDateTime now = LocalDateTime.now();

        LogStore.Decision d = store.ingest(lvl, message, now);

        if (!viewActive) {
            // Defer document edits while hidden. The store is now authoritative; a single
            // rebuildView() runs on re-show. Trim still runs so the cap is enforced
            // while hidden; whether it changed the visible window is folded into viewDirty.
            LogStore.TrimResult trimHidden = store.trimIfNeeded();
            boolean visibleChange =
                    d.kind() != LogStore.Decision.Kind.NONE
                            || trimHidden.removedVisible() > 0;
            if (visibleChange) viewDirty = true;
            return;
        }

        switch (d.kind()) {
            case APPEND -> {
                LogStore.Entry e = d.entry();
                String line = renderer.formatLine(e.ts, e.level, e.message, e.repeats());
                runPreservingViewportWhenPaused(() -> {
                    renderer.append(line, e.level);
                    renderedAggregates.add(new LogStore.Aggregate(e.ts, e.level, e.message, e.repeats()));
                    renderer.autoscrollIfNeeded(autoscrollPaused);
                });
                if (Logger.isInternalTraceEnabled()) Logger.internalTrace("LogPanel render=APPEND");
                recomputeMatchesAfterDocChange();
            }
            case REPLACE -> {
                LogStore.Entry e = d.entry();
                String line = renderer.formatLine(e.ts, e.level, e.message, e.repeats());
                runPreservingViewportWhenPaused(() -> {
                    renderer.replaceLast(line, e.level);
                    if (!renderedAggregates.isEmpty()) {
                        LogStore.Aggregate prev = renderedAggregates.getLast();
                        renderedAggregates.set(renderedAggregates.size() - 1,
                                new LogStore.Aggregate(e.ts, e.level, e.message, prev.count() + 1));
                    }
                    renderer.autoscrollIfNeeded(autoscrollPaused);
                });
                if (Logger.isInternalTraceEnabled()) Logger.internalTrace("LogPanel render=REPLACE");
                recomputeMatchesAfterDocChange();
            }
            default -> {
                if (Logger.isInternalTraceEnabled()) Logger.internalTrace("LogPanel render=NONE (filtered)");
            }
        }

        // Only run the suffix-diff when something visible was actually trimmed; a filter-only
        // trim (e.g. all dropped entries were filter-rejected) leaves the document untouched
        // and avoids paying for store.buildVisibleAggregated() on every cap-driven trim.
        LogStore.TrimResult trim = store.trimIfNeeded();
        if (trim.removedVisible() > 0) {
            applyIncrementalTrim();
        }
    }

    /**
     * Applies a suffix-diff between the currently rendered aggregates and the canonical
     * {@link LogStore#buildVisibleAggregated()} so the document edits are minimal but the
     * resulting state is byte-identical to a full {@link #rebuildView()}.
     *
     * <p>Mechanism:</p>
     * <ol>
     *   <li>Walk both lists from the tail while elements are equal. Everything past the walk
     *       point is bit-for-bit unchanged in the document and stays put.</li>
     *   <li>Remove the differing-old prefix from the document with a single
     *       {@link LogRenderer#removeLeadingLines} call.</li>
     *   <li>Concatenate the differing-new prefix lines into one string and prepend with a
     *       single {@link LogRenderer#prependLines} call.</li>
     * </ol>
     *
     * <p>In the common case (no aggregation merge across the trim boundary) the differing-old
     * prefix is just the K trimmed visible aggregates and the differing-new prefix is empty,
     * so this collapses to a single {@code remove}. In the merge case (a filter caused two
     * non-adjacent equal entries to become adjacent after trim) the diff is at most a couple
     * of aggregates on each side and still resolves with one {@code remove} + one
     * {@code insertString}.</p>
     *
     * <p>Sanity guard: if we ever observe that {@link #renderedAggregates} is shorter than
     * the canonical visible aggregation by more than the diff window can explain, fall back
     * to a full {@link #rebuildView()}. The property tests cover the suffix-diff invariant,
     * so this branch should be unreachable in production -- it exists as a self-correcting
     * safety net should a future change introduce drift.</p>
     */
    private void applyIncrementalTrim() {
        List<LogStore.Aggregate> oldVisible = renderedAggregates;
        List<LogStore.Aggregate> newVisible = store.buildVisibleAggregated();

        // Sanity: if the rendered mirror is shorter than the canonical visible aggregation,
        // suffix-diff cannot explain it (trim only ever removes from the head). Resync via
        // rebuildView() and return; we lose this iteration's micro-optimisation but stay
        // byte-identical to the canonical state.
        if (oldVisible.size() < newVisible.size()) {
            Logger.internalWarn("LogPanel incremental-trim drift detected: rendered="
                    + oldVisible.size() + " visible=" + newVisible.size() + "; resyncing via rebuildView()");
            rebuildView();
            return;
        }

        int oldEnd = oldVisible.size();
        int newEnd = newVisible.size();
        while (oldEnd > 0 && newEnd > 0
                && oldVisible.get(oldEnd - 1).equals(newVisible.get(newEnd - 1))) {
            oldEnd--;
            newEnd--;
        }

        final int oldEndFinal = oldEnd;
        final int newEndFinal = newEnd;
        runPreservingViewportWhenPaused(() -> {
            if (oldEndFinal > 0) {
                renderer.removeLeadingLines(oldEndFinal);
            }
            if (newEndFinal > 0) {
                StringBuilder sb = new StringBuilder(newEndFinal * 80);
                for (int i = 0; i < newEndFinal; i++) {
                    LogStore.Aggregate a = newVisible.get(i);
                    sb.append(renderer.formatLine(a.ts(), a.level(), a.message(), a.count()));
                }
                renderer.prependLines(sb.toString());
            }
        });

        renderedAggregates = newVisible;
        if (Logger.isInternalTraceEnabled()) {
            Logger.internalTrace("LogPanel incremental-trim removedOld=" + oldEnd + " addedNew=" + newEnd
                    + " visibleNow=" + newVisible.size());
        }
        recomputeMatchesAfterDocChange();
    }

    /**
     * Applies current filters to determine whether a log should render.
     *
     * @param lvl     level to evaluate
     * @param message log message
     * @return {@code true} when the entry passes level and text filters
     */
    private boolean visible(LogStore.Level lvl, String message) {
        return passesLevel(lvl) && passesTextFilter(message);
    }

    /**
     * Checks whether a level meets or exceeds the selected minimum.
     *
     * @param lvl level to evaluate
     * @return {@code true} when the level is visible
     */
    private boolean passesLevel(LogStore.Level lvl) {
        LogStore.Level min = LogStore.Level.fromString(selectedLogMinLevel());
        return lvl.ordinal() >= min.ordinal();
    }

    /**
     * Text filter (regex or substring). Invalid regex results in WARN and non-match.
     *
     * Regex flag rules (case/UNICODE) are centralized; substring matching lowers both
     * sides when case-insensitive to avoid locale pitfalls.
     *
     * @param msg message to test
     * @return {@code true} when the message passes the text filter
     */
    private boolean passesTextFilter(String msg) {
        String f = filterField.getText();
        if (f == null || f.isEmpty()) {
            return true;
        }
        try {
            boolean filterMatches;
            if (filterRegexToggle.isSelected()) {
                int flags = filterCaseToggle.isSelected()
                        ? 0
                        : (java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.UNICODE_CASE);
                filterMatches = java.util.regex.Pattern.compile(f, flags)
                        .matcher(msg == null ? "" : msg)
                        .find();
            } else {
                String m = msg == null ? "" : msg;
                filterMatches = filterCaseToggle.isSelected()
                        ? m.contains(f)
                        : m.toLowerCase(Locale.ROOT).contains(f.toLowerCase(Locale.ROOT));
            }
            return filterNegativeToggle.isSelected() ? !filterMatches : filterMatches;
        } catch (RuntimeException ex) {
            Logger.internalWarn("LogPanel invalid regex: " + ex.getMessage());
            return false;
        }
    }

    /**
     * Full rebuild from the store using the current filter.
     */
    private void rebuildView() {
        store.setFilter(this::visible);
        runPreservingViewportWhenPaused(() -> {
            renderer.clear();
            List<LogStore.Aggregate> visible = store.buildVisibleAggregated();
            for (LogStore.Aggregate a : visible) {
                String line = renderer.formatLine(a.ts(), a.level(), a.message(), a.count());
                renderer.append(line, a.level());
            }
            renderedAggregates = new ArrayList<>(visible);
            renderer.autoscrollIfNeeded(autoscrollPaused);
        });
        recomputeMatchesAfterDocChange();
        if (Logger.isInternalTraceEnabled()) {
            Logger.internalTrace("LogPanel rebuild done, lines=" + renderedAggregates.size());
        }
    }

    /**
     * Runs a visible document mutation without moving the viewport while autoscroll is paused.
     */
    private void runPreservingViewportWhenPaused(Runnable mutation) {
        ViewportSnapshot snapshot = captureViewportSnapshot();
        try {
            mutation.run();
        } finally {
            if (snapshot != null) {
                snapshot.restore();
            }
        }
    }

    private ViewportSnapshot captureViewportSnapshot() {
        if (!autoscrollPaused || !(logTextPane.getParent() instanceof JViewport viewport)) {
            return null;
        }
        return new ViewportSnapshot(viewport, viewport.getViewPosition());
    }

    private record ViewportSnapshot(JViewport viewport, Point position) {
        void restore() {
            viewport.setViewPosition(position);
        }
    }

    // ---- Search / highlight ----

    /**
     * Recomputes search matches and jumps to the first result when present.
     */
    private void computeMatchesAndJumpFirst() {
        recomputeMatchesNow();
        if (!matches.isEmpty()) {
            matchIndex = 0;
            revealMatch(matchIndex);
        } else {
            matchIndex = -1;
        }
        updateMatchCount();
    }

    /**
     * Schedules a coalesced search recompute. Cheap when the query is empty (we clear
     * highlights immediately and skip the timer altogether). For non-empty queries we kick
     * the {@link #searchRecomputeTimer}; multiple ingest events within the debounce window
     * collapse into a single {@link TextSearchEngine#findAll} pass.
     */
    private void recomputeMatchesAfterDocChange() {
        final String q = searchField.getText();
        if (q == null || q.isEmpty()) {
            searchRecomputeTimer.stop();
            clearSearchHighlights();
            matches = List.of();
            updateMatchCount();
            return;
        }
        if (!searchRecomputeTimer.isRunning()) {
            searchRecomputeTimer.start();
        }
    }

    /**
     * Synchronous recompute used by user-initiated paths (search field edit, toggle change,
     * filter/level change, re-show). Cancels any pending debounced recompute.
     */
    private void recomputeMatchesNow() {
        searchRecomputeTimer.stop();
        doRecomputeMatches();
    }

    private void doRecomputeMatches() {
        clearSearchHighlights();

        final String q = searchField.getText();
        if (q == null || q.isEmpty()) {
            matches = List.of();
            updateMatchCount();
            return;
        }

        try {
            final String hay = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            final TextQuery tq = new TextQuery(
                    q, searchCaseToggle.isSelected(), searchRegexToggle.isSelected(), true
            );
            matches = TextSearchEngine.findAll(hay, tq);
            highlighterManager.apply(matches);
            Logger.internalTrace(
                    "LogPanel highlight recompute, matches=" + (matches == null ? 0 : matches.size())
            );
        } catch (BadLocationException | RuntimeException ex) {
            matches = List.of();
            Logger.internalDebug("LogPanel highlight recompute failed: " + ex);
        }
        updateMatchCount();
    }

    /**
     * Clears all applied search highlights.
     */
    private void clearSearchHighlights() { highlighterManager.clear(); }

    /**
     * Moves the current match index by the provided delta, wrapping around.
     *
     * @param delta offset to apply (positive for next, negative for previous)
     */
    private void jumpMatch(int delta) {
        if (matches.isEmpty()) return;
        matchIndex = (matchIndex + delta) % matches.size();
        if (matchIndex < 0) matchIndex += matches.size();
        revealMatch(matchIndex);
        updateMatchCount();
    }

    /**
     * Ensures the indexed match is visible in the viewport.
     *
     * @param i match index to reveal
     */
    private void revealMatch(int i) {
        if (i < 0 || i >= matches.size()) return;
        int[] m = matches.get(i);
        ensureVisible(m[0]);
    }

    /**
     * Scrolls the viewport to the given document offset.
     *
     * @param offset document offset to reveal
     */
    private void ensureVisible(int offset) {
        try {
            var r2d = logTextPane.modelToView2D(offset);
            if (r2d != null) logTextPane.scrollRectToVisible(r2d.getBounds());
        } catch (BadLocationException | RuntimeException ex) {
            Logger.internalDebug("LogPanel ensureVisible failed: " + ex);
        }
    }

    /**
     * Updates the match count label based on current search state.
     */
    private void updateMatchCount() {
        int total = matches == null ? 0 : matches.size();
        int idx1 = (matchIndex >= 0 && total > 0) ? (matchIndex + 1) : 0;
        searchCountLabel.setText(idx1 + "/" + total);
    }

    // ---- Copy/Save ----

    /**
     * Copies the current selection when present; otherwise copies the entire log.
     */
    private void copySelectionOrAll() {
        String sel = logTextPane.getSelectedText();
        if (sel != null && !sel.isEmpty()) {
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(sel), null);
            return;
        }
        copyAll();
    }

    /**
     * Copies only the current selection to the system clipboard.
     */
    private void copySelection() {
        String sel = logTextPane.getSelectedText();
        if (sel == null || sel.isEmpty()) return;
        Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(new StringSelection(sel), null);
    }

    /**
     * Copies the line at the caret position to the system clipboard.
     */
    private void copyCurrentLine() {
        try {
            int caret = logTextPane.getCaretPosition();
            String text = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            int start = text.lastIndexOf('\n', Math.max(0, caret - 1)) + 1;
            int end = text.indexOf('\n', caret);
            if (end < 0) end = text.length();
            String line = text.substring(start, end);
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(line), null);
        } catch (BadLocationException | IllegalStateException | SecurityException | HeadlessException ex) {
            Logger.internalDebug("LogPanel copy current line failed: " + ex);
        }
    }

    /**
     * Copies the entire log contents to the system clipboard.
     */
    private void copyAll() {
        try {
            String all = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(all), null);
        } catch (BadLocationException | IllegalStateException | SecurityException | HeadlessException ex) {
            Logger.internalDebug("LogPanel copy all failed: " + ex);
        }
    }

    /**
     * Saves the currently visible log to a user-selected file.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    private void saveVisible() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Log");
        String ts = java.time.format.DateTimeFormatter
                .ofPattern("yyyyMMdd-HHmmss")
                .format(java.time.LocalDateTime.now());
        chooser.setSelectedFile(new File("burp-exporter-" + ts + ".log"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File out = chooser.getSelectedFile();
        try {
            String text = logTextPane.getDocument().getText(0, logTextPane.getDocument().getLength());
            FileUtil.writeStringCreateDirs(out.toPath(), text);
        } catch (DiskSpaceGuard.LowDiskSpaceException ex) {
            Logger.logError("[LogPanel] Save failed: " + ex.userMessage());
        } catch (IOException | javax.swing.text.BadLocationException ex) {
            Logger.logError("[LogPanel] Save failed: " + ex.getMessage());
        }
    }

    private JPopupMenu buildContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copySel = new JMenuItem("Copy selection");
        JMenuItem copyLine = new JMenuItem("Copy current line");
        JMenuItem copyAll = new JMenuItem("Copy all");
        JMenuItem saveVisible = new JMenuItem("Save visible");
        copySel.addActionListener(e -> copySelection());
        copyLine.addActionListener(e -> copyCurrentLine());
        copyAll.addActionListener(e -> copyAll());
        menu.add(copySel);
        menu.add(copyLine);
        menu.add(copyAll);
        menu.addSeparator();
        menu.add(saveVisible);
        return menu;
    }
}
