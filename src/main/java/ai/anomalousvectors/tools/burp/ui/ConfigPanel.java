package ai.anomalousvectors.tools.burp.ui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import javax.swing.AbstractAction;
import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;

import ai.anomalousvectors.tools.burp.sinks.BodyEnumerationSkippedLog;
import ai.anomalousvectors.tools.burp.sinks.BodyParameterTruncationLog;
import ai.anomalousvectors.tools.burp.sinks.CompressedWireBodyParamsLog;
import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.sinks.ExporterIndexConfigReporter;
import ai.anomalousvectors.tools.burp.sinks.ExporterIndexStatsReporter;
import ai.anomalousvectors.tools.burp.sinks.ExporterStatsPushOutcome;
import ai.anomalousvectors.tools.burp.sinks.FileExportService;
import ai.anomalousvectors.tools.burp.sinks.FindingsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.OpenSearchSink;
import ai.anomalousvectors.tools.burp.sinks.ParameterIntegritySessionLog;
import ai.anomalousvectors.tools.burp.sinks.ProxyHistoryIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.ProxyWebSocketIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.RepeaterTabsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.SettingsIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.SitemapIndexReporter;
import ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue;
import ai.anomalousvectors.tools.burp.sinks.TrafficLiveAttributionSummary;
import ai.anomalousvectors.tools.burp.sinks.TrafficStartupBacklogSummary;
import ai.anomalousvectors.tools.burp.sinks.UrlParameterTruncationLog;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.ui.primitives.AutoSizingPasswordField;
import ai.anomalousvectors.tools.burp.ui.primitives.AutoSizingTextField;
import ai.anomalousvectors.tools.burp.ui.primitives.ButtonStyles;
import ai.anomalousvectors.tools.burp.ui.primitives.ScopeGrid;
import ai.anomalousvectors.tools.burp.ui.primitives.StatusViews;
import ai.anomalousvectors.tools.burp.ui.primitives.TextFieldUndo;
import ai.anomalousvectors.tools.burp.ui.primitives.ThickSeparator;
import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox;
import ai.anomalousvectors.tools.burp.ui.text.Doc;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.ui.text.ValidationIndicator;
import ai.anomalousvectors.tools.burp.utils.ControlStatusBridge;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileUtil;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.MontoyaApiProvider;
import ai.anomalousvectors.tools.burp.utils.concurrent.Workers;
import ai.anomalousvectors.tools.burp.utils.config.ConfigJsonMapper;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchTlsSupport;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import net.miginfocom.swing.MigLayout;

/**
 * Main configuration panel for data sources, scope, destination, and control actions.
 *
 * <p><strong>Responsibilities:</strong> render the UI, compose/parse {@link ConfigState.State},
 * and delegate long-running work to {@link ConfigController}.</p>
 *
 * <p><strong>Threading:</strong> callers construct and interact with this panel on the EDT.</p>
 */
public class ConfigPanel extends JPanel implements ConfigController.Ui {

    @Serial private static final long serialVersionUID = 1L;

    private static final int INDENT = 30;
    private static final int ROW_GAP = 15;
    private static final String MIG_STATUS_INSETS = "insets 5, novisualpadding";
    private static final String MIG_PREF_COL = "[pref!]";
    private static final String MIG_FILL_WRAP = "growx, wrap";
    /** ActionMap key: Enter on the OpenSearch TLS mode combo runs Test Connection. */
    private static final String TLS_MODE_ENTER_TEST_CONNECTION = "os.tlsMode.enterTestConnection";
    private static final int STATUS_MIN_COLS = 20;
    private static final int STATUS_MAX_COLS = 200;
    /** Background executor for Start-path OpenSearch bootstrap work. */
    private static volatile ExecutorService startupExecutor = newStartupExecutor();

    private static ExecutorService newStartupExecutor() {
        return Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "burp-exporter-startup");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Cancels queued Start-path work, waits briefly for the executor to terminate, and installs
     * a fresh executor so subsequent Start actions in the same JVM still function.
     *
     * <p>Called from {@link ai.anomalousvectors.tools.burp.Exporter}'s unload cleanup so the
     * extension leaves no background worker alive after Burp deregisters it. Safe to call more
     * than once. Delegates termination to {@link Workers} so shutdown semantics match every
     * other extension-owned worker; if the executor does not terminate within
     * {@link Workers#DEFAULT_SHUTDOWN_TIMEOUT_MS} milliseconds, the current thread's interrupt
     * flag is restored and the replacement executor is still installed.</p>
     */
    public static synchronized void shutdownStartupExecutor() {
        ExecutorService current = startupExecutor;
        Workers.awaitExecutorShutdown(current, Workers.DEFAULT_SHUTDOWN_TIMEOUT_MS);
        startupExecutor = newStartupExecutor();
    }

    private final TriStateCheckBox settingsCheckbox = new TriStateCheckBox("Settings", TriStateCheckBox.State.SELECTED);
    private final JCheckBox sitemapCheckbox  = new Tooltips.HtmlCheckBox("Sitemap",  true);
    private final TriStateCheckBox issuesCheckbox   = new TriStateCheckBox("Issues",   TriStateCheckBox.State.SELECTED);
    private final TriStateCheckBox trafficCheckbox  = new TriStateCheckBox("Traffic",  TriStateCheckBox.State.SELECTED);
    private final TriStateCheckBox exporterCheckbox = new TriStateCheckBox("Exporter", TriStateCheckBox.State.SELECTED);

    private final JCheckBox settingsProjectCheckbox = new Tooltips.HtmlCheckBox("Project", true);
    private final JCheckBox settingsUserCheckbox    = new Tooltips.HtmlCheckBox("User", true);

    private final JCheckBox trafficBurpAiCheckbox       = new Tooltips.HtmlCheckBox("Burp AI", true);
    private final JCheckBox trafficExtensionsCheckbox   = new Tooltips.HtmlCheckBox("Extensions", true);
    private final JCheckBox trafficIntruderCheckbox    = new Tooltips.HtmlCheckBox("Intruder", true);
    private final JCheckBox trafficProxyCheckbox        = new Tooltips.HtmlCheckBox("Proxy", true);
    private final JCheckBox trafficProxyHistoryCheckbox  = new Tooltips.HtmlCheckBox("Proxy History", true);
    private final JCheckBox trafficRepeaterCheckbox    = new Tooltips.HtmlCheckBox("Repeater", true);
    private final JCheckBox trafficRepeaterTabsCheckbox = new Tooltips.HtmlCheckBox("Repeater Tabs", true);
    private final JCheckBox trafficScannerCheckbox      = new Tooltips.HtmlCheckBox("Scanner", true);
    private final JCheckBox trafficSequencerCheckbox     = new Tooltips.HtmlCheckBox("Sequencer", true);

    private final JCheckBox issuesCriticalCheckbox      = new Tooltips.HtmlCheckBox("Critical", true);
    private final JCheckBox issuesHighCheckbox          = new Tooltips.HtmlCheckBox("High", true);
    private final JCheckBox issuesMediumCheckbox        = new Tooltips.HtmlCheckBox("Medium", true);
    private final JCheckBox issuesLowCheckbox           = new Tooltips.HtmlCheckBox("Low", true);
    private final JCheckBox issuesInformationalCheckbox = new Tooltips.HtmlCheckBox("Informational", true);

    private final JCheckBox exporterTraceCheckbox  = new Tooltips.HtmlCheckBox("Trace", true);
    private final JCheckBox exporterDebugCheckbox  = new Tooltips.HtmlCheckBox("Debug", true);
    private final JCheckBox exporterInfoCheckbox   = new Tooltips.HtmlCheckBox("Info", true);
    private final JCheckBox exporterWarnCheckbox   = new Tooltips.HtmlCheckBox("Warn", true);
    private final JCheckBox exporterErrorCheckbox  = new Tooltips.HtmlCheckBox("Error", true);
    private final JCheckBox exporterStatsCheckbox  = new Tooltips.HtmlCheckBox("Stats", true);
    private final JCheckBox exporterConfigCheckbox = new Tooltips.HtmlCheckBox("Config", true);
    private final JTextField exporterStatsIntervalField = new AutoSizingTextField(
            String.valueOf(ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS));
    private final JTextField indexNameBaseTemplateField = new AutoSizingTextField(
            ConfigState.DEFAULT_INDEX_NAME_BASE_TEMPLATE);
    private final JLabel indexNameBaseValidationIndicator = new Tooltips.HtmlLabel("");

    private static final String EXPAND_COLLAPSED = "+";
    private static final String EXPAND_EXPANDED = "−";
    private final JButton settingsExpandButton = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton issuesExpandButton   = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton trafficExpandButton  = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JButton exporterExpandButton = new Tooltips.HtmlButton(EXPAND_COLLAPSED);
    private final JPanel issuesCommunityIndicator = ConfigSourcesPanel.buildCommunityEditionIndicator(
            "src.issues.communityNotice",
            "src.issues.communityNotice.icon");
    private final JPanel trafficBurpAiCommunityIndicator = ConfigSourcesPanel.buildCommunityEditionIndicator(
            "src.traffic.burp_ai.communityNotice",
            "src.traffic.burp_ai.communityNotice.icon");
    private final JPanel trafficScannerCommunityIndicator = ConfigSourcesPanel.buildCommunityEditionIndicator(
            "src.traffic.scanner.communityNotice",
            "src.traffic.scanner.communityNotice.icon");

    private final JRadioButton allRadio       = new Tooltips.HtmlRadioButton("All");
    private final JRadioButton burpSuiteRadio = new Tooltips.HtmlRadioButton("Burp Suite's", true);
    private final JRadioButton customRadio    = new Tooltips.HtmlRadioButton("Custom");

    /** Pure grid of custom rows (field, regex toggle+indicator, add/delete). */
    private final ScopeGrid scopeGrid = new ScopeGrid(
            List.of(new ScopeGrid.ScopeEntryInit("^.*acme\\.com$", true))
    );

    private final JCheckBox fileSinkCheckbox = new Tooltips.HtmlCheckBox("Files", false);
    private final JTextField filePathField   = new AutoSizingTextField("/path/to/directory");
    private final JRadioButton fileJsonlCheckbox = new Tooltips.HtmlRadioButton("JSONL");
    private final JRadioButton fileBulkNdjsonCheckbox = new Tooltips.HtmlRadioButton("NDJSON", true);
    private final ButtonGroup fileFormatGroup = new ButtonGroup();
    private final JCheckBox fileTotalCapCheckbox = new Tooltips.HtmlCheckBox("", true);
    private final JTextField fileTotalCapField = new AutoSizingTextField("10");
    private final JCheckBox fileDiskUsagePercentCheckbox = new Tooltips.HtmlCheckBox("", true);
    private final JTextField fileDiskUsagePercentField = new AutoSizingTextField("95");

    private static final String DESTINATION_OPENSEARCH = "OpenSearch";
    private static final String DESTINATION_OPENSEARCH_AMAZON = "Amazon OpenSearch";
    private static final String DESTINATION_ELASTICSEARCH = "Elasticsearch";
    private static final String OPENSEARCH_DEFAULT_URL = "https://opensearch.url:9200";
    private static final String OPENSEARCH_AMAZON_PLACEHOLDER_URL = OPENSEARCH_DEFAULT_URL;
    private static final String ELASTICSEARCH_DEFAULT_URL = "https://elasticsearch.url:443";
    private static final String[] OPENSEARCH_AMAZON_AUTH_TYPES = {
            "IAM (sigV4)", "Basic", "None" };
    private static final String[] ELASTICSEARCH_AUTH_TYPES = {
            "API key", "Bearer token", "Certificate", "Basic", "None" };
    private static final String[] OPENSEARCH_TLS_MODES = {
            "Verify", "Trust pinned certificate", "Trust all certificates" };

    private static Map<String, String> openSearchAmazonAuthTooltips() {
        return Map.of(
                "IAM (sigV4)", Tooltips.htmlRaw(
                        "Recommended for Amazon OpenSearch Service.",
                        "Use AWS Signature Version 4 when the domain access policy uses IAM users or roles, or when you want AWS-native credential handling through profiles, instance roles, ECS/EKS roles, or temporary credentials.",
                        "Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-signing-service-requests.html"),
                "Basic", Tooltips.htmlRaw(
                        "Use a username and password when the Amazon OpenSearch Service domain uses fine-grained access control with the internal user database.",
                        "This is common for direct OpenSearch API access when an internal master user or internal users are configured.",
                        "References:",
                        "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/dashboards.html"),
                "None", Tooltips.htmlRaw(
                        "Send unsigned requests without authentication headers.",
                        "Use only for domains that intentionally allow unsigned OpenSearch API requests, such as permissive lab domains, VPC-only domains with network-based trust, or deployments protected by an upstream proxy.",
                        "AWS service configuration API requests still require signing.",
                        "Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-signing-service-requests.html"));
    }

    private static Map<String, String> elasticSearchAuthTooltips() {
        return Map.of(
                "API key", Tooltips.htmlRaw(
                        "Recommended for programmatic access.",
                        "Use a scoped Elasticsearch API key for export/indexing operations.",
                        "This is the preferred option for most application and automation integrations.",
                        "Reference: https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys"),
                "Bearer token", Tooltips.htmlRaw(
                        "Use when Elasticsearch is configured to accept token-based authentication.",
                        "This is useful for environments that issue access tokens through Elastic token services or another supported token workflow.",
                        "Reference: https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/token-based-authentication-services"),
                "Certificate", Tooltips.htmlRaw(
                        "Use client certificate authentication when Elasticsearch requires mutual TLS or PKI-based authentication.",
                        "This is strong, but usually requires more setup because users must provide a client certificate, private key, and trust material.",
                        "Reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/pki-realm.html"),
                "Basic", Tooltips.htmlRaw(
                        "Use a username and password for Elasticsearch users.",
                        "This is common and simple, but API keys are usually better for service-style integrations because they can be scoped, rotated, and revoked independently.",
                        "Reference: https://www.elastic.co/docs/deploy-manage/security/httprest-clients-security"),
                "None", Tooltips.htmlRaw(
                        "Send requests without authentication headers.",
                        "Use only for local testing, isolated self-managed clusters, or deployments where Elasticsearch security is disabled or access is enforced outside Elasticsearch."));
    }

    private static Map<String, String> openSearchTlsModeTooltips() {
        return Map.of(
                "Verify", Tooltips.htmlRaw(
                        "Use the system trust store to verify the OpenSearch server certificate.",
                        "Recommended for production clusters with a certificate chain trusted by the host JVM."),
                "Trust pinned certificate", Tooltips.htmlRaw(
                        "Trust only the imported OpenSearch server certificate for this Burp session.",
                        "Use when the cluster has a self-signed or private-CA certificate that is not in the system trust store."),
                "Trust all certificates", Tooltips.htmlRaw(
                        "Disable OpenSearch server certificate verification.",
                        "Use only for temporary testing or isolated lab clusters because this allows man-in-the-middle interception."));
    }

    private final JCheckBox databaseSinkCheckbox = new Tooltips.HtmlCheckBox("Database", true);
    private final JRadioButton openSearchSinkCheckbox = new Tooltips.HtmlRadioButton(DESTINATION_OPENSEARCH, true);
    private final ButtonGroup searchDestinationGroup = new ButtonGroup();
    private final JRadioButton openSearchAmazonDestinationRadio = new Tooltips.HtmlRadioButton(DESTINATION_OPENSEARCH_AMAZON);
    private final JRadioButton elasticSearchDestinationRadio = new Tooltips.HtmlRadioButton(DESTINATION_ELASTICSEARCH);
    private final JTextField openSearchUrlField     = new AutoSizingTextField(OPENSEARCH_DEFAULT_URL);
    private final JTextField openSearchAmazonUrlField  = new AutoSizingTextField(OPENSEARCH_AMAZON_PLACEHOLDER_URL);
    private final JTextField elasticSearchUrlField  = new AutoSizingTextField(ELASTICSEARCH_DEFAULT_URL);
    private final JTextField openSearchAmazonUserField = new AutoSizingTextField("");
    private final JPasswordField openSearchAmazonPasswordField = new AutoSizingPasswordField();
    private final JTextField openSearchAmazonRegionField = new AutoSizingTextField("");
    private final JTextField openSearchAmazonProfileField = new AutoSizingTextField("");
    private final JTextField elasticSearchUserField = new AutoSizingTextField("");
    private final JPasswordField elasticSearchPasswordField = new AutoSizingPasswordField();
    private final JPasswordField elasticSearchApiKeyTokenField = new AutoSizingPasswordField();
    private final JPasswordField elasticSearchBearerTokenField = new AutoSizingPasswordField();
    private final JTextField elasticSearchCertPathField = new AutoSizingTextField("");
    private final JTextField elasticSearchCertKeyPathField = new AutoSizingTextField("");
    private final JPasswordField elasticSearchCertPassphraseField = new AutoSizingPasswordField();
    private final JComboBox<String> openSearchAmazonAuthTypeCombo =
            new Tooltips.ItemTooltipComboBox<>(OPENSEARCH_AMAZON_AUTH_TYPES, openSearchAmazonAuthTooltips());
    private final JComboBox<String> elasticSearchAuthTypeCombo =
            new Tooltips.ItemTooltipComboBox<>(ELASTICSEARCH_AUTH_TYPES, elasticSearchAuthTooltips());
    private final JComboBox<String> openSearchTlsModeCombo =
            new Tooltips.ItemTooltipComboBox<>(OPENSEARCH_TLS_MODES, openSearchTlsModeTooltips());
    private final JComboBox<String> openSearchAmazonTlsModeCombo =
            new Tooltips.ItemTooltipComboBox<>(OPENSEARCH_TLS_MODES, openSearchTlsModeTooltips());
    private final JComboBox<String> elasticSearchTlsModeCombo =
            new Tooltips.ItemTooltipComboBox<>(OPENSEARCH_TLS_MODES, openSearchTlsModeTooltips());
    private final JButton    importPinnedCertificateButton = new Tooltips.HtmlButton("Import Certificate");
    private final JButton    importOpenSearchAmazonPinnedCertificateButton = new Tooltips.HtmlButton("Import Certificate");
    private final JButton    importElasticsearchPinnedCertificateButton = new Tooltips.HtmlButton("Import Certificate");
    private final JButton    testConnectionButton   = new Tooltips.HtmlButton("Test Connection");
    /** OpenSearch auth controls panel (inline on the OpenSearch row). Built in {@link #buildAuthFormPanel()}. */
    private JPanel           openSearchAuthFormPanel;
    /** TLS controls panel (inline on the OpenSearch row). Built in {@link #buildTlsPanel()}. */
    private JPanel           openSearchTlsPanel;
    /** Last TLS mode logged to avoid duplicate mode-change messages during no-op selections. */
    private String           lastLoggedTlsMode = ConfigState.OPEN_SEARCH_TLS_VERIFY;
    /** Auth type dropdown (used in buildCurrentState to clear creds when None). Set in buildAuthFormPanel. */
    private JComboBox<String> openSearchAuthTypeCombo;
    /** Basic auth fields (used in auth form and buildCurrentState). */
    private final JTextField openSearchUserField   = new AutoSizingTextField("");
    private final JPasswordField openSearchPasswordField = new AutoSizingPasswordField();
    /** API key auth field. */
    private final JPasswordField openSearchApiKeyTokenField = new AutoSizingPasswordField();
    /** Bearer-token auth field. */
    private final JTextField openSearchJwtTokenField = new AutoSizingTextField("");
    /** Certificate auth fields. */
    private final JTextField openSearchCertPathField = new AutoSizingTextField("");
    private final JTextField openSearchCertKeyPathField = new AutoSizingTextField("");
    private final JPasswordField openSearchCertPassphraseField = new AutoSizingPasswordField();
    private final JTextArea  databaseStatus       = new JTextArea();
    private final JPanel     databaseStatusWrapper
            = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));

    private final JTextArea controlStatus = new JTextArea();
    private final JPanel    controlStatusWrapper
            = new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL));
    private transient boolean scopeGridListenerRegistered;
    private transient boolean buttonStylesNormalized;
    private transient boolean suppressAuthSync;

    /** Action controller (transient; rebuilt on deserialization). */
    private transient ConfigController controller;

    /** Fields panel: index -> (fieldKey -> checkbox). Populated in constructor when building Fields section. */
    private java.util.Map<String, java.util.Map<String, JCheckBox>> fieldCheckboxesByIndex;
    /**
     * Required-field display labels per index, kept so {@link #refreshFieldsSectionsEnabled()}
     * can re-disable them after the per-section recursive enable/disable pass; they are visual
     * indicators of always-included fields and must remain non-interactive regardless of whether
     * the parent section is currently enabled.
     */
    private java.util.Map<String, java.util.List<JLabel>> requiredFieldLabelsByIndex;
    /** Fields panel: index -> expand button; used for enable/disable when Data Source is toggled. */
    private java.util.Map<String, JButton> fieldsExpandButtons;
    /** Fields panel: index -> sub-panel of checkboxes; used for enable/disable when Data Source is toggled. */
    private java.util.Map<String, JPanel> fieldsSubPanels;
    /** Fields panel: index -> header row panel (label + expand button); used for enable/disable when Data Source is toggled. */
    private java.util.Map<String, JPanel> fieldsSectionHeaderRows;
    /** Creates the panel with its default controller. Caller must invoke on the EDT. */
    public ConfigPanel() { this(null); }

    /** Dependency-injected constructor (tests). */
    public ConfigPanel(ConfigController injectedController) {
        this.controller = injectedController;
        ControlStatusBridge.register(this::onControlStatus);

        setLayout(new MigLayout("fillx, insets 12", "[fill]"));

        assignToolTips();
        configureFileFormatButtons();
        configureSearchDestinationButtons();
        configureIndexNameBaseValidationUi();

        ButtonStyles.configureExpandButton(settingsExpandButton);
        ButtonStyles.configureExpandButton(issuesExpandButton);
        ButtonStyles.configureExpandButton(trafficExpandButton);
        ButtonStyles.configureExpandButton(exporterExpandButton);

        JPanel settingsSubPanel = buildSettingsSubPanel();
        JPanel issuesSubPanel = buildIssuesSubPanel();
        JPanel trafficSubPanel = buildTrafficSubPanel();
        JPanel exporterSubPanel = buildExporterSubPanel();
        settingsSubPanel.setOpaque(false);
        issuesSubPanel.setOpaque(false);
        trafficSubPanel.setOpaque(false);
        exporterSubPanel.setOpaque(false);
        settingsSubPanel.setVisible(false);
        issuesSubPanel.setVisible(false);
        trafficSubPanel.setVisible(false);
        exporterSubPanel.setVisible(false);
        wireSourcesExpandCollapse(settingsExpandButton, settingsSubPanel);
        wireSourcesExpandCollapse(issuesExpandButton, issuesSubPanel);
        wireSourcesExpandCollapse(trafficExpandButton, trafficSubPanel);
        wireSourcesExpandCollapse(exporterExpandButton, exporterSubPanel);

        FieldSectionSelectionWiring.wireTriStateParentChild(settingsCheckbox, java.util.List.of(settingsProjectCheckbox, settingsUserCheckbox));
        FieldSectionSelectionWiring.wireTriStateParentChild(issuesCheckbox, java.util.List.of(
                issuesCriticalCheckbox, issuesHighCheckbox, issuesMediumCheckbox, issuesLowCheckbox, issuesInformationalCheckbox));
        FieldSectionSelectionWiring.wireTriStateParentChild(trafficCheckbox, java.util.List.of(
                trafficBurpAiCheckbox, trafficExtensionsCheckbox, trafficIntruderCheckbox, trafficProxyCheckbox,
                trafficProxyHistoryCheckbox, trafficRepeaterCheckbox, trafficRepeaterTabsCheckbox,
                trafficScannerCheckbox, trafficSequencerCheckbox));
        FieldSectionSelectionWiring.wireTriStateParentChild(exporterCheckbox, java.util.List.of(
                exporterTraceCheckbox, exporterDebugCheckbox, exporterInfoCheckbox, exporterWarnCheckbox,
                exporterErrorCheckbox, exporterStatsCheckbox, exporterConfigCheckbox));

        add(new ConfigSourcesPanel(settingsCheckbox, sitemapCheckbox, issuesCheckbox, trafficCheckbox, exporterCheckbox,
                settingsExpandButton, settingsSubPanel, issuesExpandButton, issuesSubPanel,
                trafficExpandButton, trafficSubPanel, exporterExpandButton, exporterSubPanel,
                issuesCommunityIndicator, INDENT).build(),
                "gaptop 5, gapbottom 5, wrap");
        add(panelSeparator(), MIG_FILL_WRAP);

        ActionListener fieldsRuntimeUpdater = e -> updateRuntimeConfig();
        ConfigFieldsSectionBuilder.FieldsSectionState fieldsSection =
                ConfigFieldsSectionBuilder.build(
                        INDENT,
                        ConfigPanel::checkboxTextStartInset,
                        this::wireSourcesExpandCollapse,
                        fieldsRuntimeUpdater);
        fieldCheckboxesByIndex = fieldsSection.fieldCheckboxesByIndex();
        requiredFieldLabelsByIndex = fieldsSection.requiredFieldLabelsByIndex();
        fieldsExpandButtons = fieldsSection.expandButtonsByIndex();
        fieldsSubPanels = fieldsSection.subPanelsByIndex();
        fieldsSectionHeaderRows = fieldsSection.sectionHeaderRows();
        JPanel fieldsPanel = new ConfigFieldsPanel(
                fieldsExpandButtons,
                fieldsSubPanels,
                buildGlobalIndexNamingPanel(),
                INDENT).build(fieldsSectionHeaderRows);

        add(new ConfigScopePanel(allRadio, burpSuiteRadio, customRadio, scopeGrid, INDENT).build(),
                "gaptop 10, gapbottom 5, wrap");
        add(panelSeparator(), MIG_FILL_WRAP);

        add(fieldsPanel, "growx, gaptop 10, gapbottom 5, wrap");
        refreshFieldsSectionsEnabled();
        add(panelSeparator(), MIG_FILL_WRAP);

        openSearchAuthFormPanel = buildAuthFormPanel();
        openSearchTlsPanel = buildTlsPanel();
        add(new ConfigDestinationPanel(
                fileSinkCheckbox,
                filePathField,
                fileJsonlCheckbox,
                fileBulkNdjsonCheckbox,
                buildFileLimitsPanel(),
                databaseSinkCheckbox,
                openSearchSinkCheckbox,
                openSearchUrlField,
                openSearchAmazonDestinationRadio,
                openSearchAmazonUrlField,
                buildOpenSearchAmazonOptionsPanel(),
                buildDestinationTlsPanel(
                        openSearchAmazonTlsModeCombo,
                        importOpenSearchAmazonPinnedCertificateButton,
                        "os.amazon.tlsMode",
                        "os.amazon.tls.import",
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON),
                elasticSearchDestinationRadio,
                elasticSearchUrlField,
                buildElasticsearchOptionsPanel(),
                buildDestinationTlsPanel(
                        elasticSearchTlsModeCombo,
                        importElasticsearchPinnedCertificateButton,
                        "os.elasticsearch.tlsMode",
                        "os.elasticsearch.tls.import",
                        ConfigState.SearchDestination.ELASTICSEARCH),
                openSearchTlsPanel,
                testConnectionButton,
                openSearchAuthFormPanel,
                databaseStatus,
                databaseStatusWrapper,
                INDENT,
                ROW_GAP,
                StatusViews::configureTextArea
        ).build(), "gaptop 10, gapbottom 5, wrap");

        wireButtonActions();
        add(panelSeparator(), MIG_FILL_WRAP);

        add(new ConfigControlPanel(
                new JTextArea(),
                new JPanel(new MigLayout(MIG_STATUS_INSETS, MIG_PREF_COL)),
                controlStatus,
                controlStatusWrapper,
                INDENT,
                ROW_GAP,
                StatusViews::configureTextArea,
                this::importConfig,
                this::exportConfig,
                this::startExportAsync,
                this::runExportStopAsync
        ).build(), MIG_FILL_WRAP);

        add(Box.createVerticalGlue(), "growy, wrap");

        assignToolTips();
        assignComponentNames();
        wireTextFieldEnhancements();
        loadSessionOpenSearchCredentials();
        refreshEnabledStates();
        applyEditionRestrictions();
        refreshIndexNameBaseValidationState();
    }

    @Override
    public void addNotify() {
        super.addNotify();
        if (!scopeGridListenerRegistered) {
            scopeGrid.setOnContentChange(this::updateRuntimeConfig);
            scopeGridListenerRegistered = true;
        }
        if (!buttonStylesNormalized) {
            ButtonStyles.normalizeTree(this);
            buttonStylesNormalized = true;
        }
    }

    /** Loads in-memory auth values for the current Burp session. */
    private void loadSessionOpenSearchCredentials() {
        if (openSearchAuthTypeCombo == null) {
            return;
        }
        String selectedType = SecureCredentialStore.loadSelectedAuthType();
        if (selectedType == null || selectedType.isBlank() || "none".equalsIgnoreCase(selectedType)) {
            selectedType = "Basic";
        }
        suppressAuthSync = true;
        try {
            openSearchAuthTypeCombo.setSelectedItem(selectedType);
            openSearchAmazonAuthTypeCombo.setSelectedItem(loadDestinationAuthType(
                    ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(), "IAM (sigV4)"));
            elasticSearchAuthTypeCombo.setSelectedItem(loadDestinationAuthType(
                    ConfigState.SearchDestination.ELASTICSEARCH.configKey(), ConfigState.DEFAULT_OPEN_SEARCH_AUTH_TYPE));
            loadSessionAuthFields();
        } finally {
            suppressAuthSync = false;
        }
        syncSelectedAuthStateFromUi();
    }

    private static String loadDestinationAuthType(String destination, String defaultAuthType) {
        if (!SecureCredentialStore.hasSelectedAuthType(destination)) {
            return defaultAuthType;
        }
        String stored = SecureCredentialStore.loadSelectedAuthType(destination);
        return stored == null || stored.isBlank() ? defaultAuthType : stored;
    }

    /** Groups file-format radios and keeps one selection active for the UI/runtime state. */
    private void configureFileFormatButtons() {
        fileFormatGroup.add(fileJsonlCheckbox);
        fileFormatGroup.add(fileBulkNdjsonCheckbox);
        if (!fileJsonlCheckbox.isSelected() && !fileBulkNdjsonCheckbox.isSelected()) {
            fileBulkNdjsonCheckbox.setSelected(true);
        }
    }

    /** Groups search-destination radios so at most one search backend is selected. */
    private void configureSearchDestinationButtons() {
        searchDestinationGroup.add(openSearchSinkCheckbox);
        searchDestinationGroup.add(openSearchAmazonDestinationRadio);
        searchDestinationGroup.add(elasticSearchDestinationRadio);
        if (!openSearchSinkCheckbox.isSelected()
                && !openSearchAmazonDestinationRadio.isSelected()
                && !elasticSearchDestinationRadio.isSelected()) {
            openSearchSinkCheckbox.setSelected(true);
        }
    }

    private void loadSessionAuthFields() {
        SecureCredentialStore.BasicCredentials basic = SecureCredentialStore.loadOpenSearchCredentials();
        openSearchUserField.setText(basic.username());
        openSearchPasswordField.setText(basic.password());

        SecureCredentialStore.ApiKeyCredentials apiKey = SecureCredentialStore.loadApiKeyCredentials();
        openSearchApiKeyTokenField.setText(apiKey.token());

        SecureCredentialStore.JwtCredentials jwt = SecureCredentialStore.loadJwtCredentials();
        openSearchJwtTokenField.setText(jwt.token());

        SecureCredentialStore.CertificateCredentials cert = SecureCredentialStore.loadCertificateCredentials();
        openSearchCertPathField.setText(cert.certPath());
        openSearchCertKeyPathField.setText(cert.keyPath());
        openSearchCertPassphraseField.setText(cert.passphrase());

        SecureCredentialStore.BasicCredentials awsBasic =
                SecureCredentialStore.loadBasicCredentials(ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
        openSearchAmazonUserField.setText(awsBasic.username());
        openSearchAmazonPasswordField.setText(awsBasic.password());

        String elasticDestination = ConfigState.SearchDestination.ELASTICSEARCH.configKey();
        SecureCredentialStore.BasicCredentials elasticBasic = SecureCredentialStore.loadBasicCredentials(elasticDestination);
        elasticSearchUserField.setText(elasticBasic.username());
        elasticSearchPasswordField.setText(elasticBasic.password());
        elasticSearchApiKeyTokenField.setText(SecureCredentialStore.loadApiKeyCredentials(elasticDestination).token());
        elasticSearchBearerTokenField.setText(SecureCredentialStore.loadJwtCredentials(elasticDestination).token());
        SecureCredentialStore.CertificateCredentials elasticCert =
                SecureCredentialStore.loadCertificateCredentials(elasticDestination);
        elasticSearchCertPathField.setText(elasticCert.certPath());
        elasticSearchCertKeyPathField.setText(elasticCert.keyPath());
        elasticSearchCertPassphraseField.setText(elasticCert.passphrase());
    }

    /**
     * Runs cooperative export shutdown off the EDT and posts phased status to the control panel.
     *
     * @param callbacks stop UI hooks from {@link ConfigControlPanel}
     */
    private void runExportStopAsync(ConfigControlPanel.StopUiCallbacks callbacks) {
        ExportShutdownStatus.Snapshot snapshot = callbacks.snapshot();
        startupExecutor.execute(() -> {
            postStopProgress(callbacks, ExportShutdownStatus.waitingForBatchMessage());
            ParameterIntegritySessionLog.flushStopDebugValidation();
            ExportReporterLifecycle.stopBackgroundReporters();
            TrafficExportQueue.stopWorker();
            TrafficLiveAttributionSummary.logAndClearForCurrentRun();
            postStopProgress(callbacks, ExportShutdownStatus.clearingQueuedTrafficMessage(snapshot));
            ExportReporterLifecycle.clearRepeaterRunState();
            TrafficExportQueue.clearPendingWork();
            FileExportService.resetForRuntime();
            postStopProgress(callbacks, ExportShutdownStatus.pushingFinalStatsMessage());
            ExporterStatsPushOutcome finalPush = ExporterIndexStatsReporter.pushFinalSnapshotNow();
            ParameterIntegritySessionLog.logFinalExporterStatsPush(finalPush);
            if (RuntimeConfig.isOpenSearchActive()) {
                postStopProgress(callbacks, ExportShutdownStatus.collectingOpenSearchCountsMessage());
            }
            StatsClipboardSnapshot.logSessionStopSummaryWithOpenSearchCounts();
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            IndexingRetryCoordinator.getInstance().stopDrainThread();
            postStopProgress(callbacks, ExportShutdownStatus.closingConnectionsMessage());
            ExportReporterLifecycle.releaseRunResourcesAsync();
            ExportReporterLifecycle.awaitStopReclaim(ExportReporterLifecycle.STOP_UI_RECLAIM_TIMEOUT_MS);
            Logger.logInfoPanelOnly("[Export] Stopped.");
            SwingUtilities.invokeLater(() -> {
                callbacks.onStopProgress().accept(ExportShutdownStatus.stoppedMessage());
                callbacks.onStopComplete().run();
            });
        });
    }

    private static void postStopProgress(ConfigControlPanel.StopUiCallbacks callbacks, String message) {
        Logger.logInfoPanelOnly("[Export] " + message);
        SwingUtilities.invokeLater(() -> {
            if (RuntimeConfig.isExportStopping()) {
                callbacks.onStopProgress().accept(message);
            }
        });
    }

    private static void postStartProgress(ConfigControlPanel.StartUiCallbacks callbacks, String message) {
        SwingUtilities.invokeLater(() -> {
            if (RuntimeConfig.isExportStarting()) {
                callbacks.onStartProgress().accept(message);
            }
        });
    }

    /**
     * Starts export without blocking the EDT.
     *
     * <p>Caller must invoke on the EDT. This method captures UI state, marks export running
     * immediately, then performs OpenSearch bootstrap and initial snapshot pushes on a background
     * executor. If bootstrap fails, runtime state and UI start/stop controls are reverted on EDT.</p>
     *
     * @param uiCallbacks callbacks from {@link ConfigControlPanel} to revert or complete Start UI state
     */
    private void startExportAsync(ConfigControlPanel.StartUiCallbacks uiCallbacks) {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        syncSelectedAuthStateFromUi();
        ai.anomalousvectors.tools.burp.utils.IndexNaming.ResolutionResult indexNamingResolution =
                RuntimeConfig.prepareIndexNamesForCurrentRun();
        if (!indexNamingResolution.valid()) {
            abortStartOnEdt("fix index naming before Start: " + String.join(" ", indexNamingResolution.errors()), uiCallbacks);
            return;
        }
        boolean filesSelected = fileSinkCheckbox.isSelected();
        boolean openSearchSelected = isOpenSearchExportSelected();
        if (fileSinkCheckbox.isSelected() && !hasSelectedFileFormat()) {
            abortStartOnEdt(
                    "select at least one file format when Files export is enabled.",
                    uiCallbacks);
            return;
        }
        List<String> startupIssues = validateSelectedDestinationConfiguration();
        if (!RuntimeConfig.isAnyFileExportEnabled() && !openSearchSelected) {
            String reason = startupIssues.isEmpty()
                    ? "configure at least one destination."
                    : String.join(" ", startupIssues);
            abortStartOnEdt(reason, uiCallbacks);
            return;
        }
        String url = selectedSearchUrlField().getText().trim();
        List<String> sources = List.copyOf(getSelectedSources());
        ExportStartupStatus.Snapshot startupSnapshot =
                new ExportStartupStatus.Snapshot(filesSelected, openSearchSelected);
        postStartProgress(uiCallbacks, ExportStartupStatus.initialStartingMessage(startupSnapshot));
        Logger.logDebug("[Export] Runtime traffic tool types at Start: "
                + (RuntimeConfig.getState() == null || RuntimeConfig.getState().trafficToolTypes() == null
                        ? "[]"
                        : RuntimeConfig.getState().trafficToolTypes()));
        ExportStats.recordExportStartRequested();
        Logger.logInfoPanelOnly("[Export] Starting. Selected destinations: "
                + summarizeSelectedDestinations(filesSelected, openSearchSelected) + ".");
        RuntimeConfig.setExportRunning(true);
        RepeaterTabsIndexReporter.clearRunState();
        TrafficStartupBacklogSummary.startForCurrentRun();
        UrlParameterTruncationLog.startForCurrentRun();
        BodyParameterTruncationLog.startForCurrentRun();
        BodyEnumerationSkippedLog.startForCurrentRun();
        CompressedWireBodyParamsLog.startForCurrentRun();
        TrafficLiveAttributionSummary.startForCurrentRun();
        startupExecutor.execute(() -> runStartupPipeline(
                url, sources, uiCallbacks, startupIssues, filesSelected, openSearchSelected));
    }

    /** Returns whether at least one file-export format checkbox is selected. */
    private boolean hasSelectedFileFormat() {
        return fileJsonlCheckbox.isSelected() || fileBulkNdjsonCheckbox.isSelected();
    }

    /**
     * Runs OpenSearch bootstrap and initial reporter startup on a background thread.
     *
     * <p>Not EDT-only. On bootstrap failure, this method posts revert work to EDT so UI state
     * remains consistent with runtime state.</p>
     *
     * @param url OpenSearch base URL from UI
     * @param sources selected source keys at Start time
     * @param uiCallbacks callbacks to revert or complete Start button/indicator state
     */
    private void runStartupPipeline(
            String url,
            List<String> sources,
            ConfigControlPanel.StartUiCallbacks uiCallbacks,
            List<String> startupIssues,
            boolean filesSelected,
            boolean openSearchSelected
    ) {
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        List<String> runtimeStartIssues = new ArrayList<>(startupIssues);
        if (!openSearchSelected && RuntimeConfig.getState() != null && RuntimeConfig.getState().sinks() != null
                && RuntimeConfig.getState().sinks().osEnabled()) {
            RuntimeConfig.disableOpenSearchDestination();
        }
        if (filesSelected) {
            postStartProgress(uiCallbacks, ExportStartupStatus.initializingFilesMessage());
        }
        boolean openSearchEnabled = RuntimeConfig.getState() != null
                && RuntimeConfig.getState().sinks() != null
                && openSearchSelected
                && !url.isEmpty();
        if (RuntimeConfig.isAnyFileExportEnabled()) {
            try {
                String fileRoot = RuntimeConfig.fileExportRoot();
                Logger.logDebug("[Files] Preflight check for " + fileRoot);
                Path fileRootPath = FileUtil.requireAbsoluteDirectoryPath(fileRoot);
                FileUtil.ensureDirectoryWritable(fileRootPath, "file export root");
                Logger.logInfoPanelOnly("[Files] Initializing files for selected sources.");
                Logger.logDebug("[Files] Ensuring files for sources: " + sources);
                List<FileExportService.FileInitResult> fileResults =
                        FileExportService.createSelectedExportFiles(sources, RuntimeConfig::isExportRunning);
                for (FileExportService.FileInitResult result : fileResults) {
                    Logger.logDebug("[Files] File "
                            + (result.path() != null ? result.path().getFileName() : result.shortName())
                            + ": " + result.status()
                            + (result.error() != null ? " (" + result.error() + ")" : ""));
                }
                if (fileResults.stream().anyMatch(r -> r.status() == FileUtil.Status.FAILED)) {
                    String reason = "one or more export files failed to initialize.";
                    logFileInitializationFailures(fileResults);
                    if (!openSearchEnabled) {
                        ExportReporterLifecycle.stopAndClearPendingExportWork();
                        abortStartFromWorker(reason, uiCallbacks);
                        return;
                    }
                    recordStartIssue(runtimeStartIssues, "Files failed during start: " + reason);
                    FileExportService.disableCurrentRoot("File export initialization failed. OpenSearch export will continue.");
                }
            } catch (IOException | RuntimeException e) {
                String reason = e.getMessage() == null || e.getMessage().isBlank()
                        ? "File export preflight failed."
                        : "File export preflight failed: " + e.getMessage();
                if (!openSearchEnabled) {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    abortStartFromWorker(reason, uiCallbacks);
                    return;
                }
                recordStartIssue(runtimeStartIssues, "Files failed during start: " + reason);
                FileExportService.disableCurrentRoot(reason + " OpenSearch export will continue.");
            }
        }
        if (openSearchEnabled && !url.isEmpty()) {
            ConfigState.SearchDestination databaseDestination = RuntimeConfig.searchDestinationKind();
            String databaseName = databaseDestination.displayName();
            OpenSearchAuth openSearchAuth = OpenSearchAuth.fromRuntime(databaseDestination);
            if (!openSearchAuth.isComplete()) {
                String reason = openSearchAuth.validationMessage();
                if (!RuntimeConfig.isAnyFileExportEnabled()) {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    abortStartFromWorker(reason, uiCallbacks);
                    return;
                }
                recordStartIssue(runtimeStartIssues, databaseName + " failed during start: " + reason);
                disableOpenSearchForCurrentRun(reason + " Files export will continue.");
                openSearchEnabled = false;
            }
        }
        if (openSearchEnabled && !url.isEmpty()) {
            ConfigState.SearchDestination databaseDestination = RuntimeConfig.searchDestinationKind();
            String databaseName = databaseDestination.displayName();
            OpenSearchAuth openSearchAuth = OpenSearchAuth.fromRuntime(databaseDestination);
            postStartProgress(uiCallbacks, "Starting: testing " + databaseName + " connection …");
            Logger.logDebug("[" + databaseName + "] Preflight connection test for " + url);
            var preflight = ai.anomalousvectors.tools.burp.utils.search.SearchConnectionTester.safeTestConnection(
                    databaseDestination, url);
            Logger.logDebug("[" + databaseName + "] Preflight result: success=" + preflight.success()
                    + ", message=" + preflight.message());
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            if (!preflight.success()) {
                String reason = preflight.message() == null || preflight.message().isBlank()
                        ? databaseName + " preflight failed."
                        : databaseName + " preflight failed: " + preflight.message();
                if (!RuntimeConfig.isAnyFileExportEnabled()) {
                    ExportReporterLifecycle.stopAndClearPendingExportWork();
                    abortStartFromWorker(reason, uiCallbacks);
                    return;
                }
                recordStartIssue(runtimeStartIssues, databaseName + " failed during start: " + reason);
                disableOpenSearchForCurrentRun(reason + " Files export will continue.");
                openSearchEnabled = false;
            }

            if (openSearchEnabled) {
                postStartProgress(uiCallbacks, "Starting: creating " + databaseName + " indexes …");
                Logger.logInfoPanelOnly("[" + databaseName + "] Initializing indexes for selected sources.");
                Logger.logDebug("[" + databaseName + "] Ensuring indexes for sources: " + sources);
                List<OpenSearchSink.IndexResult> results = OpenSearchSink.createSelectedIndexes(url, sources,
                        openSearchAuth, RuntimeConfig::isExportRunning);
                for (OpenSearchSink.IndexResult r : results) {
                    Logger.logDebug("[" + databaseName + "] Index " + r.fullName() + ": " + r.status()
                            + (r.error() != null ? " (" + r.error() + ")" : ""));
                }
                if (!RuntimeConfig.isExportRunning()) {
                    return;
                }
                if (results.stream().anyMatch(r -> r.status() == OpenSearchSink.IndexResult.Status.FAILED)) {
                    String reason = "one or more OpenSearch indexes failed to initialize.";
                    logOpenSearchIndexInitializationFailures(results);
                    if (!RuntimeConfig.isAnyFileExportEnabled()) {
                        ExportReporterLifecycle.stopAndClearPendingExportWork();
                        abortStartFromWorker(reason, uiCallbacks);
                        return;
                    }
                    recordStartIssue(
                            runtimeStartIssues,
                            databaseName + " failed during start: " + reason);
                    disableOpenSearchForCurrentRun(databaseName
                            + " index initialization failed. Files export will continue.");
                }
            }
        }

        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        postStartProgress(uiCallbacks, ExportStartupStatus.startingBackgroundReportersMessage());
        if (!TrafficStartupBacklogSummary.hasExpectedStartupComponents()) {
            UrlParameterTruncationLog.flushStartupSummary();
            BodyParameterTruncationLog.flushStartupSummary();
            BodyEnumerationSkippedLog.flushStartupSummary();
            CompressedWireBodyParamsLog.flushStartupSummary();
        }
        RuntimeConfig.setExportStarting(false);
        String runningStatus = buildRunningStatusMessage(runtimeStartIssues, filesSelected, openSearchSelected);
        SwingUtilities.invokeLater(() -> {
            uiCallbacks.onStartSuccess().run();
            onControlStatus(runningStatus);
            RepeaterTabsIndexReporter.scheduleStartupTabWalk();
        });
        if (RuntimeConfig.isAnySinkEnabled()) {
            ExporterIndexConfigReporter.pushConfigSnapshot();
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
            ExporterIndexStatsReporter.start();
            BodyEnumerationSkippedLog.startPeriodicFlusher();
            CompressedWireBodyParamsLog.startPeriodicFlusher();
        }
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SettingsIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SettingsIndexReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        FindingsIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        FindingsIndexReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SitemapIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        SitemapIndexReporter.start();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        ProxyHistoryIndexReporter.pushSnapshotNow();
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        if (isTrafficToolSelected("proxy_history")) {
            ProxyWebSocketIndexReporter.pushHistoricSnapshotNow();
            if (!RuntimeConfig.isExportRunning()) {
                return;
            }
        }
        if (isTrafficToolSelected("proxy")) {
            if (!isTrafficToolSelected("proxy_history")) {
                ProxyWebSocketIndexReporter.startLivePollAfterCurrentHistorySeed(false);
            } else {
                ProxyWebSocketIndexReporter.startLivePoll();
            }
        }
        if (!RuntimeConfig.isExportRunning()) {
            return;
        }
        Logger.logInfoPanelOnly("[Export] Started. Destinations: " + RuntimeConfig.activeSinkSummary() + ".");
    }

    private boolean isTrafficToolSelected(String toolTypeKey) {
        if (toolTypeKey == null || toolTypeKey.isBlank()) {
            return false;
        }
        List<String> trafficTypes = RuntimeConfig.getState() == null
                ? null
                : RuntimeConfig.getState().trafficToolTypes();
        return trafficTypes != null && trafficTypes.contains(toolTypeKey);
    }

    private void disableOpenSearchForCurrentRun(String reason) {
        if (RuntimeConfig.disableOpenSearchDestination()) {
            IndexingRetryCoordinator.getInstance().clearPendingWork();
            Logger.logErrorPanelOnly("[OpenSearch] " + reason);
        }
    }

    private List<String> validateSelectedDestinationConfiguration() {
        List<String> startupIssues = new ArrayList<>();
        if (fileSinkCheckbox.isSelected() && filePathField.getText().trim().isEmpty()) {
            recordStartIssue(startupIssues, "Files not started: root directory is blank.");
        }
        if (!databaseSinkCheckbox.isSelected()) {
            return startupIssues;
        }
        if (selectedSearchUrlField().getText().trim().isEmpty()) {
            recordStartIssue(startupIssues, selectedSearchDestination() + " not started: base URL is blank.");
        }
        if (!RuntimeConfig.isSearchDestinationExportWired(selectedSearchDestinationKind())) {
            recordStartIssue(startupIssues,
                    selectedSearchDestination() + " is not wired for Start/export yet.");
        }
        return startupIssues;
    }

    private void recordStartIssue(List<String> startupIssues, String issue) {
        startupIssues.add(issue);
        Logger.logErrorPanelOnly("[Export] " + issue);
    }

    private void abortStartOnEdt(String reason, ConfigControlPanel.StartUiCallbacks uiCallbacks) {
        Logger.logErrorPanelOnly("[Export] Start aborted: " + reason);
        UrlParameterTruncationLog.flushStartupSummary();
        BodyParameterTruncationLog.flushStartupSummary();
        BodyEnumerationSkippedLog.flushStartupSummary();
        RuntimeConfig.setExportStarting(false);
        onControlStatus("Start aborted: " + reason);
        uiCallbacks.onStartFailure().run();
    }

    private void abortStartFromWorker(String reason, ConfigControlPanel.StartUiCallbacks uiCallbacks) {
        Logger.logErrorPanelOnly("[Export] Start aborted: " + reason);
        UrlParameterTruncationLog.flushStartupSummary();
        BodyParameterTruncationLog.flushStartupSummary();
        BodyEnumerationSkippedLog.flushStartupSummary();
        RuntimeConfig.setExportStarting(false);
        SwingUtilities.invokeLater(() -> {
            onControlStatus("Start aborted: " + reason);
            uiCallbacks.onStartFailure().run();
        });
    }

    private static String summarizeSelectedDestinations(boolean filesSelected, boolean openSearchSelected) {
        String databaseName = RuntimeConfig.searchDestinationDisplayName();
        if (filesSelected && openSearchSelected) {
            return "Files and " + databaseName;
        }
        if (filesSelected) {
            return "Files";
        }
        if (openSearchSelected) {
            return databaseName;
        }
        return "none";
    }

    private static void logOpenSearchIndexInitializationFailures(List<OpenSearchSink.IndexResult> results) {
        Logger.logErrorPanelOnly("[OpenSearch] Index initialization failed for one or more selected indexes.");
        if (results == null) {
            return;
        }
        for (OpenSearchSink.IndexResult result : results) {
            if (result == null || result.status() != OpenSearchSink.IndexResult.Status.FAILED) {
                continue;
            }
            String detail = result.error() == null || result.error().isBlank() ? "unknown error" : result.error();
            Logger.logErrorPanelOnly("[OpenSearch] Index initialization failed for "
                    + result.fullName() + ": " + detail);
        }
    }

    private static void logFileInitializationFailures(List<FileExportService.FileInitResult> results) {
        Logger.logErrorPanelOnly("[Files] Export file initialization failed for one or more selected files.");
        if (results == null) {
            return;
        }
        for (FileExportService.FileInitResult result : results) {
            if (result == null || result.status() != FileUtil.Status.FAILED) {
                continue;
            }
            String detail = result.error() == null || result.error().isBlank() ? "unknown error" : result.error();
            String path = result.path() == null ? result.shortName() + result.format() : result.path().toString();
            Logger.logErrorPanelOnly("[Files] Export file initialization failed for " + path + ": " + detail);
        }
    }

    private static String buildRunningStatusMessage(
            List<String> startupIssues,
            boolean filesSelected,
            boolean openSearchSelected
    ) {
        String filesStatus = filesSelected
                ? (RuntimeConfig.isAnyFileExportEnabled()
                ? "Running -> " + activeFilesDestination()
                : "Not running")
                : null;
        String databaseStatus = openSearchSelected
                ? (RuntimeConfig.isOpenSearchExportEnabled()
                ? "Running -> " + activeOpenSearchDestination()
                : "Not running")
                : null;
        if (startupIssues != null) {
            for (String issue : startupIssues) {
                if (issue == null || issue.isBlank()) {
                    continue;
                }
        String databaseName = RuntimeConfig.searchDestinationDisplayName();
        String databaseNotStartedPrefix = databaseName + " not started: ";
        String databaseFailedPrefix = databaseName + " failed during start: ";
        if (issue.startsWith("Files not started: ")) {
                    filesStatus = "Not started (" + shortStatusDetail(issue.substring("Files not started: ".length())) + ")";
        } else if (issue.startsWith(databaseNotStartedPrefix)) {
            databaseStatus = "Not started (" + shortStatusDetail(issue.substring(databaseNotStartedPrefix.length())) + ")";
                } else if (issue.startsWith("Files failed during start: ")) {
                    filesStatus = "Start failed (" + shortStatusDetail(issue.substring("Files failed during start: ".length())) + ")";
        } else if (issue.startsWith(databaseFailedPrefix)) {
            databaseStatus = "Start failed (" + shortStatusDetail(issue.substring(databaseFailedPrefix.length())) + ")";
                }
            }
        }
        return buildDestinationStatusMessage(filesStatus, databaseStatus);
    }

    private static String formatControlStatusMessage(String message) {
        if (message == null || message.isBlank()) {
            return message;
        }
        if (message.startsWith("OpenSearch export disabled after repeated ")
                && message.endsWith(" Files export will continue.")) {
            String detail = message.substring(
                    "OpenSearch export disabled after repeated ".length(),
                    message.length() - " Files export will continue.".length());
            return buildDestinationStatusMessage("Running", "Stopped (" + shortStatusDetail(detail) + ")");
        }
        if (message.startsWith("File export stopped: ")
                && message.endsWith(" OpenSearch export continues.")) {
            String detail = message.substring(
                    "File export stopped: ".length(),
                    message.length() - " OpenSearch export continues.".length());
            return buildDestinationStatusMessage("Stopped (" + shortStatusDetail(detail) + ")", "Running");
        }
        if (message.startsWith("Local disk writes stopped")
                && message.endsWith("OpenSearch export continues.")) {
            return buildDestinationStatusMessage("Stopped (" + shortStatusDetail(message) + ")", "Running");
        }
        return message;
    }

    private static String buildDestinationStatusMessage(String filesStatus, String databaseStatus) {
        List<String> lines = new ArrayList<>(2);
        if (filesStatus != null && !filesStatus.isBlank()) {
            lines.add("Files: " + filesStatus);
        }
        if (databaseStatus != null && !databaseStatus.isBlank()) {
            lines.add("OpenSearch: " + databaseStatus);
        }
        return lines.isEmpty() ? "Running" : String.join("\n", lines);
    }

    private static String shortStatusDetail(String detail) {
        if (detail == null || detail.isBlank()) {
            return "unknown error";
        }
        String shortened = detail.trim();
        shortened = shortened.replaceFirst("^OpenSearch preflight failed:\\s*", "");
        shortened = shortened.replaceFirst("^File export preflight failed:\\s*", "");
        shortened = shortened.replaceFirst("^OpenSearch index initialization failed\\.\\s*", "");
        shortened = shortened.replaceFirst("^(?:(?:[a-zA-Z_$][\\w$]*\\.)+[A-Za-z_$][\\w$]*Exception:\\s*)+", "");
        if (shortened.length() > 180) {
            shortened = shortened.substring(0, 177) + "...";
        }
        return shortened;
    }

    private static String activeFilesDestination() {
        String fileRoot = RuntimeConfig.fileExportRoot();
        if (fileRoot == null || fileRoot.isBlank()) {
            return "(path unavailable)";
        }
        try {
            return FileUtil.requireAbsoluteDirectoryPath(fileRoot).toString();
        } catch (IOException e) {
            return fileRoot.trim();
        }
    }

    private static String activeOpenSearchDestination() {
        String url = RuntimeConfig.searchBaseUrl();
        return (url == null || url.isBlank()) ? "(url unavailable)" : url.trim();
    }

    /**
     * Applies Burp edition-specific source availability and Community-only tooltip overrides.
     *
     * <p>Community edition forces Findings off and disables the Burp AI and Scanner traffic
     * tool-type checkboxes. Professional re-enables those controls and hides the inline Community
     * notices.</p>
     */
    private void applyEditionRestrictions() {
        boolean communityEdition = isCommunityEdition();

        issuesCheckbox.setEnabled(!communityEdition);
        issuesExpandButton.setEnabled(!communityEdition);
        Tooltips.apply(issuesCheckbox, communityEdition
                ? Tooltips.html("Unsupported in Community Edition.")
                : Tooltips.html("All findings (aka issues)."));
        issuesCommunityIndicator.setVisible(communityEdition);
        if (communityEdition) {
            issuesCheckbox.setSelected(false);
            for (JCheckBox checkbox : issueSeverityCheckboxes()) {
                checkbox.setSelected(false);
                checkbox.setEnabled(false);
            }
            for (JCheckBox checkbox : findingsFieldCheckboxes()) {
                checkbox.setSelected(false);
                checkbox.setEnabled(false);
            }
        } else {
            for (JCheckBox checkbox : issueSeverityCheckboxes()) {
                checkbox.setEnabled(true);
            }
            for (JCheckBox checkbox : findingsFieldCheckboxes()) {
                checkbox.setEnabled(true);
            }
        }

        for (JCheckBox checkbox : communityLimitedTrafficCheckboxes()) {
            checkbox.setEnabled(!communityEdition);
            if (communityEdition) {
                checkbox.setSelected(false);
            }
        }
        for (JPanel indicator : communityLimitedTrafficIndicators()) {
            indicator.setVisible(communityEdition);
        }

        refreshFieldsSectionsEnabled();
        updateRuntimeConfig();
    }

    private boolean isCommunityEdition() {
        try {
            MontoyaApi api = MontoyaApiProvider.get();
            if (api == null || api.burpSuite() == null) {
                return false;
            }
            var version = api.burpSuite().version();
            return version != null && version.edition() == BurpSuiteEdition.COMMUNITY_EDITION;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private List<JCheckBox> issueSeverityCheckboxes() {
        return List.of(
                issuesCriticalCheckbox,
                issuesHighCheckbox,
                issuesMediumCheckbox,
                issuesLowCheckbox,
                issuesInformationalCheckbox);
    }

    private List<JCheckBox> findingsFieldCheckboxes() {
        if (fieldCheckboxesByIndex == null) {
            return List.of();
        }
        java.util.Map<String, JCheckBox> findings = fieldCheckboxesByIndex.get("findings");
        return findings == null ? List.of() : List.copyOf(findings.values());
    }

    private List<JCheckBox> communityLimitedTrafficCheckboxes() {
        return List.of(trafficBurpAiCheckbox, trafficScannerCheckbox);
    }

    private List<JPanel> communityLimitedTrafficIndicators() {
        return List.of(trafficBurpAiCommunityIndicator, trafficScannerCommunityIndicator);
    }

    /**
     * Creates a separator used between major configuration blocks.
     *
     * @return new separator component
     */
    private JComponent panelSeparator() { return new ThickSeparator(); }

    /* ----------------------- ConfigController.Ui ----------------------- */

    /** File-export runtime messages are routed through Config Control instead. */
    @Override public void onFileStatus(String message) { }

    /**
     * Updates the database-destination status area on the EDT with the provided message.
     *
     * @param message status text to display (nullable)
     */
    @Override public void onDatabaseStatus(String message) {
        StatusViews.setStatus(
                databaseStatus, databaseStatusWrapper, message, STATUS_MIN_COLS, STATUS_MAX_COLS);
    }

    /**
     * Updates the Control status area on the EDT.
     *
     * @param message status text to display (nullable)
     */
    @Override public void onControlStatus(String message) {
        if (RuntimeConfig.isExportStopping() || RuntimeConfig.isExportStarting()) {
            return;
        }
        String formattedMessage = formatControlStatusMessage(message);
        Runnable r = () -> {
            StatusViews.setStatus(
                    controlStatus, controlStatusWrapper, formattedMessage, STATUS_MIN_COLS, STATUS_MAX_COLS);
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else {
            try { SwingUtilities.invokeAndWait(r); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); SwingUtilities.invokeLater(r); }
            catch (InvocationTargetException ex) { SwingUtilities.invokeLater(r); }
        }
    }

    /* ----------------------- Import plumbing (not Ui) ----------------------- */

    /**
     * Applies an imported state to the UI.
     *
     * <p>For custom scope, rows are applied first and then the Custom radio is selected to ensure
     * enablement is updated on the final state.</p>
     */
    public void onImportResult(ConfigState.State state) {
        Runnable r = () -> {
            settingsCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SETTINGS));
            sitemapCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_SITEMAP));
            issuesCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_FINDINGS));
            trafficCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_TRAFFIC));
            exporterCheckbox.setSelected(state.dataSources().contains(ConfigKeys.SRC_EXPORTER));

            List<String> settingsSub = state.settingsSub() != null ? state.settingsSub() : List.of();
            settingsProjectCheckbox.setSelected(settingsSub.contains(ConfigKeys.SRC_SETTINGS_PROJECT));
            settingsUserCheckbox.setSelected(settingsSub.contains(ConfigKeys.SRC_SETTINGS_USER));

            List<String> trafficTools = state.trafficToolTypes() != null ? state.trafficToolTypes() : List.of();
            trafficBurpAiCheckbox.setSelected(trafficTools.contains("burp_ai"));
            trafficExtensionsCheckbox.setSelected(trafficTools.contains("extensions"));
            trafficIntruderCheckbox.setSelected(trafficTools.contains("intruder"));
            trafficProxyCheckbox.setSelected(trafficTools.contains("proxy"));
            trafficProxyHistoryCheckbox.setSelected(trafficTools.contains("proxy_history"));
            trafficRepeaterCheckbox.setSelected(trafficTools.contains("repeater"));
            trafficRepeaterTabsCheckbox.setSelected(trafficTools.contains("repeater_tabs"));
            trafficScannerCheckbox.setSelected(trafficTools.contains("scanner"));
            trafficSequencerCheckbox.setSelected(trafficTools.contains("sequencer"));

            List<String> severities = state.findingsSeverities() != null ? state.findingsSeverities() : List.of();
            issuesCriticalCheckbox.setSelected(severities.contains("critical"));
            issuesHighCheckbox.setSelected(severities.contains("high"));
            issuesMediumCheckbox.setSelected(severities.contains("medium"));
            issuesLowCheckbox.setSelected(severities.contains("low"));
            issuesInformationalCheckbox.setSelected(severities.contains("informational"));

            List<String> exporterOptions = state.exporterSubOptions() != null ? state.exporterSubOptions() : List.of();
            exporterTraceCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_TRACE));
            exporterDebugCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_DEBUG));
            exporterInfoCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_INFO));
            exporterWarnCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_WARN));
            exporterErrorCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_ERROR));
            exporterStatsCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_STATS));
            exporterConfigCheckbox.setSelected(exporterOptions.contains(ConfigKeys.SRC_EXPORTER_CONFIG));
            exporterStatsIntervalField.setText(String.valueOf(state.exporterStatsIntervalSeconds()));
            refreshExporterStatsIntervalEnabledState();
            indexNameBaseTemplateField.setText(state.indexNameBaseTemplate());
            refreshIndexNameBaseValidationState();

            ConfigState.Sinks sinks = state.sinks();
            if (sinks != null) {
                fileSinkCheckbox.setSelected(sinks.filesEnabled());
                filePathField.setText(sinks.filesPath() != null ? sinks.filesPath() : "");
                applyFileFormatSelection(sinks.fileJsonlEnabled(), sinks.fileBulkNdjsonEnabled());
                fileTotalCapCheckbox.setSelected(sinks.fileTotalCapEnabled());
                fileTotalCapField.setText(formatGiBLimit(sinks.fileTotalCapGb()));
                fileDiskUsagePercentCheckbox.setSelected(sinks.fileDiskUsagePercentEnabled());
                fileDiskUsagePercentField.setText(String.valueOf(sinks.fileDiskUsagePercent()));
                databaseSinkCheckbox.setSelected(sinks.osEnabled());
                switch (sinks.searchDestinationKind()) {
                    case OPEN_SEARCH_AMAZON -> openSearchAmazonDestinationRadio.setSelected(true);
                    case ELASTICSEARCH -> elasticSearchDestinationRadio.setSelected(true);
                    default -> openSearchSinkCheckbox.setSelected(true);
                }
                openSearchUrlField.setText(sinks.openSearchUrl() != null ? sinks.openSearchUrl() : "");
                openSearchAmazonUrlField.setText(sinks.openSearchAmazonUrl() != null ? sinks.openSearchAmazonUrl() : "");
                elasticSearchUrlField.setText(sinks.elasticSearchUrl() != null ? sinks.elasticSearchUrl() : "");
                ConfigState.OpenSearchAmazonOptions awsOptions = sinks.openSearchAmazonOptions() == null
                        ? ConfigState.defaultOpenSearchAmazonOptions()
                        : sinks.openSearchAmazonOptions();
                openSearchAmazonAuthTypeCombo.setSelectedItem(awsOptions.authType());
                openSearchAmazonUserField.setText(awsOptions.username());
                openSearchAmazonRegionField.setText(awsOptions.region());
                openSearchAmazonProfileField.setText(awsOptions.profile());
                openSearchAmazonTlsModeCombo.setSelectedItem(labelForTlsMode(awsOptions.tlsMode()));
                applyImportedPinnedTlsCertificate(awsOptions);
                ConfigState.ElasticsearchOptions elasticOptions = sinks.elasticSearchOptions() == null
                        ? ConfigState.defaultElasticsearchOptions()
                        : sinks.elasticSearchOptions();
                elasticSearchAuthTypeCombo.setSelectedItem(elasticOptions.authType());
                elasticSearchUserField.setText(elasticOptions.username());
                elasticSearchCertPathField.setText(elasticOptions.certPath());
                elasticSearchCertKeyPathField.setText(elasticOptions.certKeyPath());
                elasticSearchTlsModeCombo.setSelectedItem(labelForTlsMode(elasticOptions.tlsMode()));
                applyImportedPinnedTlsCertificate(elasticOptions);
                boolean previousSuppressAuthSync = suppressAuthSync;
                suppressAuthSync = true;
                try {
                    openSearchTlsModeCombo.setSelectedItem(labelForTlsMode(sinks.openSearchTlsMode()));
                    openSearchUserField.setText(sinks.openSearchUser() != null ? sinks.openSearchUser() : "");
                    ConfigState.OpenSearchOptions openSearchOptions = sinks.openSearchOptions() == null
                            ? ConfigState.defaultOpenSearchOptions()
                            : sinks.openSearchOptions();
                    if (openSearchAuthTypeCombo != null) {
                        openSearchAuthTypeCombo.setSelectedItem(openSearchOptions.authType());
                    }
                    openSearchCertPathField.setText(openSearchOptions.certPath());
                    openSearchCertKeyPathField.setText(openSearchOptions.certKeyPath());
                    applyImportedPinnedTlsCertificate(openSearchOptions);
                } finally {
                    suppressAuthSync = previousSuppressAuthSync;
                }
            }

            switch (state.scopeType()) {
                case ConfigKeys.SCOPE_CUSTOM -> {
                    List<ScopeGrid.ScopeEntryInit> init = new ArrayList<>();
                    for (ConfigState.ScopeEntry ce : state.customEntries()) {
                        boolean isRegex = ce.kind() == ConfigState.Kind.REGEX;
                        init.add(new ScopeGrid.ScopeEntryInit(ce.value(), isRegex));
                    }
                    if (init.isEmpty()) init.add(new ScopeGrid.ScopeEntryInit("", true));
                    scopeGrid.setEntries(init);
                    customRadio.setSelected(true);
                }
                case ConfigKeys.SCOPE_BURP -> burpSuiteRadio.setSelected(true);
                default -> allRadio.setSelected(true);
            }

            applyExportFieldsState(state.enabledExportFieldsByIndex());
            refreshFieldsSectionsEnabled();
            refreshEnabledStates();
            applyEditionRestrictions();
            syncSelectedAuthStateFromUi(state.uiPreferences());
        };
        runOnEdt(r);
    }

    /**
     * Applies one normalized file-format selection to the UI.
     *
     * <p>If both or neither are requested, {@code NDJSON} wins as the default selection.</p>
     */
    private void applyFileFormatSelection(boolean jsonlSelected, boolean bulkNdjsonSelected) {
        if (jsonlSelected == bulkNdjsonSelected) {
            fileBulkNdjsonCheckbox.setSelected(true);
            return;
        }
        fileJsonlCheckbox.setSelected(jsonlSelected);
        fileBulkNdjsonCheckbox.setSelected(bulkNdjsonSelected);
    }

    /** Applies imported enabled-export-fields state to Fields panel checkboxes; null = all selected. */
    private void applyExportFieldsState(java.util.Map<String, java.util.Set<String>> enabledByIndex) {
        if (fieldCheckboxesByIndex == null) return;
        for (String indexName : ai.anomalousvectors.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER) {
            java.util.Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex.get(indexName);
            if (checkboxes == null) continue;
            java.util.Set<String> enabled = enabledByIndex != null ? enabledByIndex.get(indexName) : null;
            for (java.util.Map.Entry<String, JCheckBox> e : checkboxes.entrySet()) {
                boolean select = enabled == null || enabled.contains(e.getKey());
                e.getValue().setSelected(select);
            }
        }
    }

    private void updateRuntimeConfig() {
        updateRuntimeConfig(null);
    }

    private void updateRuntimeConfig(ConfigState.UiPreferences uiPreferences) {
        RuntimeConfig.TrafficExportGate previousTrafficGate = RuntimeConfig.trafficExportGate();
        RuntimeConfig.updateState(uiPreferences == null ? buildCurrentState() : buildCurrentState(uiPreferences));
        RuntimeConfig.TrafficExportGate currentTrafficGate = RuntimeConfig.trafficExportGate();
        if (shouldPurgeQueuedTraffic(previousTrafficGate, currentTrafficGate)) {
            startupExecutor.execute(() -> purgeQueuedTrafficForGate(currentTrafficGate));
        }
        ExporterIndexStatsReporter.refreshScheduleForCurrentState();
        ProxyWebSocketIndexReporter.refreshLivePollScheduleForCurrentState();
        refreshControlStatusIfExportRunning();
    }

    /**
     * Rebuilds the Config Control destination status lines when export is active and the operator
     * changes sink selection or paths live in the panel.
     *
     * <p>Startup and Stop phases keep their own phased status text and are not overwritten.</p>
     */
    private void refreshControlStatusIfExportRunning() {
        if (!RuntimeConfig.isExportRunning()
                || RuntimeConfig.isExportStarting()
                || RuntimeConfig.isExportStopping()) {
            return;
        }
        onControlStatus(buildRunningStatusMessage(
                List.of(),
                fileSinkCheckbox.isSelected(),
                isOpenSearchExportSelected()));
    }

    private static void purgeQueuedTrafficForGate(RuntimeConfig.TrafficExportGate currentTrafficGate) {
        int purged = TrafficExportQueue.purgeDisabledTraffic(currentTrafficGate);
        if (purged > 0) {
            Logger.logInfoPanelOnly("[TrafficExportQueue] Cleared " + purged
                    + " queued document(s) after traffic export deselection.");
        }
    }

    private static boolean shouldPurgeQueuedTraffic(
            RuntimeConfig.TrafficExportGate previous,
            RuntimeConfig.TrafficExportGate current) {
        if (previous == null || current == null || !RuntimeConfig.isExportRunning()) {
            return false;
        }
        if (!previous.anyTrafficExportEnabled()) {
            return false;
        }
        if (!current.anyTrafficExportEnabled()) {
            return true;
        }
        return (current.enabledToolMask() & previous.enabledToolMask()) != previous.enabledToolMask();
    }

    private void syncSelectedAuthStateFromUi() {
        persistSelectedAuthSecrets();
        updateRuntimeConfig();
    }

    private void syncSelectedAuthStateFromUi(ConfigState.UiPreferences uiPreferences) {
        persistSelectedAuthSecrets();
        updateRuntimeConfig(uiPreferences);
    }

    /**
     * Builds the tooltip text for a required (always-enabled) field display label.
     *
     * <p>Appends a note to the field's existing tooltip so the always-on semantics live in
     * the tooltip rather than the visible label text. When the
     * field has no registered tooltip (default fall-through to the bare key), produces a
     * compact tooltip that only conveys the always-enabled note.</p>
     */
    private static int checkboxTextStartInset() {
        Icon icon = UIManager.getIcon("CheckBox.icon");
        int iconWidth = icon == null ? 0 : icon.getIconWidth();
        return iconWidth + new JCheckBox().getIconTextGap();
    }

    private void refreshFieldsSectionsEnabled() {
        if (fieldsSectionHeaderRows == null || fieldsExpandButtons == null || fieldsSubPanels == null || fieldCheckboxesByIndex == null) return;
        for (String indexName : ai.anomalousvectors.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER_FOR_FIELDS_PANEL) {
            boolean enabled = isAnySourceOptionSelectedForFieldsIndex(indexName);
            boolean disableExpandForCommunity = "findings".equals(indexName) && isCommunityEdition();
            JPanel headerRow = fieldsSectionHeaderRows.get(indexName);
            if (headerRow != null) {
                headerRow.setEnabled(enabled);
                for (java.awt.Component c : headerRow.getComponents()) c.setEnabled(enabled);
            }
            JButton expandBtn = fieldsExpandButtons.get(indexName);
            if (expandBtn != null) expandBtn.setEnabled(!disableExpandForCommunity);
            JPanel sub = fieldsSubPanels.get(indexName);
            if (sub != null) setEnabledRecursively(sub, enabled);
            java.util.Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex.get(indexName);
            if (checkboxes != null) {
                for (JCheckBox cb : checkboxes.values()) cb.setEnabled(enabled);
            }
            // Required-field display labels are intentionally non-interactive regardless of the
            // section's enabled state; re-disable them after setEnabledRecursively() restored the
            // sub-panel's children to the section's enabled state.
            java.util.List<JLabel> requiredLabels = requiredFieldLabelsByIndex == null
                    ? null : requiredFieldLabelsByIndex.get(indexName);
            if (requiredLabels != null) {
                for (JLabel label : requiredLabels) {
                    label.setEnabled(false);
                }
            }
        }
    }

    /** True if at least one source option for this index is selected (so the Fields section should be enabled). Handles partial selection and parent-click timing: parent selected OR any child selected. */
    private boolean isAnySourceOptionSelectedForFieldsIndex(String indexName) {
        return switch (indexName) {
            case "settings" -> settingsCheckbox.isSelected() || settingsProjectCheckbox.isSelected() || settingsUserCheckbox.isSelected();
            case "sitemap" -> sitemapCheckbox.isSelected();
            case "findings" -> issuesCheckbox.isSelected() || issuesCriticalCheckbox.isSelected() || issuesHighCheckbox.isSelected()
                    || issuesMediumCheckbox.isSelected() || issuesLowCheckbox.isSelected() || issuesInformationalCheckbox.isSelected();
            case "traffic" -> trafficCheckbox.isSelected() || trafficBurpAiCheckbox.isSelected()
                    || trafficExtensionsCheckbox.isSelected() || trafficIntruderCheckbox.isSelected()
                    || trafficProxyCheckbox.isSelected() || trafficProxyHistoryCheckbox.isSelected() || trafficRepeaterCheckbox.isSelected()
                    || trafficRepeaterTabsCheckbox.isSelected()
                    || trafficScannerCheckbox.isSelected() || trafficSequencerCheckbox.isSelected();
            case "exporter" -> exporterCheckbox.isSelected() || exporterTraceCheckbox.isSelected() || exporterDebugCheckbox.isSelected()
                    || exporterInfoCheckbox.isSelected() || exporterWarnCheckbox.isSelected() || exporterErrorCheckbox.isSelected()
                    || exporterStatsCheckbox.isSelected() || exporterConfigCheckbox.isSelected();
            default -> false;
        };
    }

    /* ----------------------------- Wiring ----------------------------- */

    /**
     * Wires button and checkbox actions for destination and layout relayout hooks.
     *
     * <p>Caller must invoke on the EDT. Validates required fields before delegating to
     * {@link ConfigController} and keeps text fields revalidated as their contents change.</p>
     */
    private void wireButtonActions() {
        ActionListener runtimeUpdater = e -> updateRuntimeConfig();
        ActionListener sinkUpdater = e -> {
            refreshEnabledStates();
            updateRuntimeConfig();
        };

        settingsCheckbox.addActionListener(runtimeUpdater);
        sitemapCheckbox.addActionListener(runtimeUpdater);
        issuesCheckbox.addActionListener(runtimeUpdater);
        trafficCheckbox.addActionListener(runtimeUpdater);
        exporterCheckbox.addActionListener(runtimeUpdater);
        // Defer so checkbox model and other listeners run first, avoiding flakiness when toggling source
        ActionListener refreshFieldsSections = e -> SwingUtilities.invokeLater(this::refreshFieldsSectionsEnabled);
        settingsCheckbox.addActionListener(refreshFieldsSections);
        sitemapCheckbox.addActionListener(refreshFieldsSections);
        issuesCheckbox.addActionListener(refreshFieldsSections);
        trafficCheckbox.addActionListener(refreshFieldsSections);
        exporterCheckbox.addActionListener(refreshFieldsSections);
        settingsProjectCheckbox.addActionListener(runtimeUpdater);
        settingsProjectCheckbox.addActionListener(refreshFieldsSections);
        settingsUserCheckbox.addActionListener(runtimeUpdater);
        settingsUserCheckbox.addActionListener(refreshFieldsSections);
        trafficBurpAiCheckbox.addActionListener(runtimeUpdater);
        trafficBurpAiCheckbox.addActionListener(refreshFieldsSections);
        trafficExtensionsCheckbox.addActionListener(runtimeUpdater);
        trafficExtensionsCheckbox.addActionListener(refreshFieldsSections);
        trafficIntruderCheckbox.addActionListener(runtimeUpdater);
        trafficIntruderCheckbox.addActionListener(refreshFieldsSections);
        trafficProxyCheckbox.addActionListener(runtimeUpdater);
        trafficProxyCheckbox.addActionListener(refreshFieldsSections);
        trafficProxyHistoryCheckbox.addActionListener(runtimeUpdater);
        trafficProxyHistoryCheckbox.addActionListener(refreshFieldsSections);
        trafficRepeaterCheckbox.addActionListener(runtimeUpdater);
        trafficRepeaterCheckbox.addActionListener(refreshFieldsSections);
        trafficRepeaterTabsCheckbox.addActionListener(runtimeUpdater);
        trafficRepeaterTabsCheckbox.addActionListener(refreshFieldsSections);
        trafficScannerCheckbox.addActionListener(runtimeUpdater);
        trafficScannerCheckbox.addActionListener(refreshFieldsSections);
        trafficSequencerCheckbox.addActionListener(runtimeUpdater);
        trafficSequencerCheckbox.addActionListener(refreshFieldsSections);
        issuesCriticalCheckbox.addActionListener(runtimeUpdater);
        issuesCriticalCheckbox.addActionListener(refreshFieldsSections);
        issuesHighCheckbox.addActionListener(runtimeUpdater);
        issuesHighCheckbox.addActionListener(refreshFieldsSections);
        issuesMediumCheckbox.addActionListener(runtimeUpdater);
        issuesMediumCheckbox.addActionListener(refreshFieldsSections);
        issuesLowCheckbox.addActionListener(runtimeUpdater);
        issuesLowCheckbox.addActionListener(refreshFieldsSections);
        issuesInformationalCheckbox.addActionListener(runtimeUpdater);
        issuesInformationalCheckbox.addActionListener(refreshFieldsSections);
        exporterTraceCheckbox.addActionListener(runtimeUpdater);
        exporterTraceCheckbox.addActionListener(refreshFieldsSections);
        exporterDebugCheckbox.addActionListener(runtimeUpdater);
        exporterDebugCheckbox.addActionListener(refreshFieldsSections);
        exporterInfoCheckbox.addActionListener(runtimeUpdater);
        exporterInfoCheckbox.addActionListener(refreshFieldsSections);
        exporterWarnCheckbox.addActionListener(runtimeUpdater);
        exporterWarnCheckbox.addActionListener(refreshFieldsSections);
        exporterErrorCheckbox.addActionListener(runtimeUpdater);
        exporterErrorCheckbox.addActionListener(refreshFieldsSections);
        exporterStatsCheckbox.addActionListener(e -> {
            refreshExporterStatsIntervalEnabledState();
            updateRuntimeConfig();
        });
        exporterStatsCheckbox.addActionListener(refreshFieldsSections);
        exporterConfigCheckbox.addActionListener(runtimeUpdater);
        exporterConfigCheckbox.addActionListener(refreshFieldsSections);

        allRadio.addActionListener(runtimeUpdater);
        burpSuiteRadio.addActionListener(runtimeUpdater);
        customRadio.addActionListener(runtimeUpdater);

        fileSinkCheckbox.addActionListener(sinkUpdater);
        fileJsonlCheckbox.addActionListener(sinkUpdater);
        fileBulkNdjsonCheckbox.addActionListener(sinkUpdater);
        fileTotalCapCheckbox.addActionListener(sinkUpdater);
        fileDiskUsagePercentCheckbox.addActionListener(sinkUpdater);
        databaseSinkCheckbox.addActionListener(sinkUpdater);
        openSearchSinkCheckbox.addActionListener(sinkUpdater);
        openSearchTlsModeCombo.addActionListener(sinkUpdater);
        openSearchAmazonTlsModeCombo.addActionListener(sinkUpdater);
        elasticSearchTlsModeCombo.addActionListener(sinkUpdater);
        ActionListener searchDestinationUpdater = e -> {
            applySearchDestinationSelection();
            sinkUpdater.actionPerformed(e);
        };
        databaseSinkCheckbox.addActionListener(searchDestinationUpdater);
        openSearchSinkCheckbox.addActionListener(searchDestinationUpdater);
        openSearchAmazonDestinationRadio.addActionListener(searchDestinationUpdater);
        elasticSearchDestinationRadio.addActionListener(searchDestinationUpdater);
        openSearchAmazonAuthTypeCombo.addActionListener(sinkUpdater);
        elasticSearchAuthTypeCombo.addActionListener(sinkUpdater);

        testConnectionButton.addActionListener(e -> {
            syncSelectedAuthStateFromUi();
            String url = selectedSearchUrlField().getText().trim();
            if (url.isEmpty()) { onDatabaseStatus("✖ URL required"); return; }
            onDatabaseStatus("Testing ...");
            controller().testConnectionAsync(selectedSearchDestinationKind(), url);
        });
        importPinnedCertificateButton.addActionListener(e -> importPinnedCertificate());
        openSearchPasswordField.addActionListener(e -> {
            String selectedType = openSearchAuthTypeCombo == null
                    ? "None"
                    : String.valueOf(openSearchAuthTypeCombo.getSelectedItem());
            if ("Basic".equals(selectedType) && openSearchPasswordField.isEnabled() && testConnectionButton.isEnabled()) {
                testConnectionButton.doClick();
            }
        });

        DocumentListener relayout = Doc.onChange(() -> {
            filePathField.revalidate();
            openSearchUrlField.revalidate();
            openSearchAmazonUrlField.revalidate();
            elasticSearchUrlField.revalidate();
            openSearchAmazonUserField.revalidate();
            openSearchAmazonPasswordField.revalidate();
            openSearchAmazonRegionField.revalidate();
            openSearchAmazonProfileField.revalidate();
            elasticSearchUserField.revalidate();
            elasticSearchPasswordField.revalidate();
            elasticSearchApiKeyTokenField.revalidate();
            elasticSearchBearerTokenField.revalidate();
            elasticSearchCertPathField.revalidate();
            elasticSearchCertKeyPathField.revalidate();
            elasticSearchCertPassphraseField.revalidate();
            exporterStatsIntervalField.revalidate();
            indexNameBaseTemplateField.revalidate();
            updateRuntimeConfig();
        });
        filePathField.getDocument().addDocumentListener(relayout);
        openSearchUrlField.getDocument().addDocumentListener(relayout);
        openSearchAmazonUrlField.getDocument().addDocumentListener(relayout);
        elasticSearchUrlField.getDocument().addDocumentListener(relayout);
        openSearchAmazonUserField.getDocument().addDocumentListener(relayout);
        openSearchAmazonPasswordField.getDocument().addDocumentListener(relayout);
        openSearchAmazonRegionField.getDocument().addDocumentListener(relayout);
        openSearchAmazonProfileField.getDocument().addDocumentListener(relayout);
        elasticSearchUserField.getDocument().addDocumentListener(relayout);
        elasticSearchPasswordField.getDocument().addDocumentListener(relayout);
        elasticSearchApiKeyTokenField.getDocument().addDocumentListener(relayout);
        elasticSearchBearerTokenField.getDocument().addDocumentListener(relayout);
        elasticSearchCertPathField.getDocument().addDocumentListener(relayout);
        elasticSearchCertKeyPathField.getDocument().addDocumentListener(relayout);
        elasticSearchCertPassphraseField.getDocument().addDocumentListener(relayout);
        fileTotalCapField.getDocument().addDocumentListener(relayout);
        fileDiskUsagePercentField.getDocument().addDocumentListener(relayout);
        exporterStatsIntervalField.getDocument().addDocumentListener(relayout);
        indexNameBaseTemplateField.getDocument().addDocumentListener(relayout);

        DocumentListener authUpdater = Doc.onChange(() -> {
            if (!suppressAuthSync) {
                syncSelectedAuthStateFromUi();
            }
        });
        openSearchUserField.getDocument().addDocumentListener(authUpdater);
        openSearchPasswordField.getDocument().addDocumentListener(authUpdater);
        openSearchApiKeyTokenField.getDocument().addDocumentListener(authUpdater);
        openSearchJwtTokenField.getDocument().addDocumentListener(authUpdater);
        openSearchCertPathField.getDocument().addDocumentListener(authUpdater);
        openSearchCertKeyPathField.getDocument().addDocumentListener(authUpdater);
        openSearchCertPassphraseField.getDocument().addDocumentListener(authUpdater);
        openSearchAmazonUserField.getDocument().addDocumentListener(authUpdater);
        openSearchAmazonPasswordField.getDocument().addDocumentListener(authUpdater);
        elasticSearchUserField.getDocument().addDocumentListener(authUpdater);
        elasticSearchPasswordField.getDocument().addDocumentListener(authUpdater);
        elasticSearchApiKeyTokenField.getDocument().addDocumentListener(authUpdater);
        elasticSearchBearerTokenField.getDocument().addDocumentListener(authUpdater);
        elasticSearchCertPathField.getDocument().addDocumentListener(authUpdater);
        elasticSearchCertKeyPathField.getDocument().addDocumentListener(authUpdater);
        elasticSearchCertPassphraseField.getDocument().addDocumentListener(authUpdater);
    }

    private JPanel buildSettingsSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(settingsProjectCheckbox);
        p.add(settingsUserCheckbox);
        return p;
    }

    private JPanel buildIssuesSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(issuesCriticalCheckbox);
        p.add(issuesHighCheckbox);
        p.add(issuesMediumCheckbox);
        p.add(issuesLowCheckbox);
        p.add(issuesInformationalCheckbox);
        return p;
    }

    private JPanel buildExporterSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(exporterTraceCheckbox);
        p.add(exporterDebugCheckbox);
        p.add(exporterInfoCheckbox);
        p.add(exporterWarnCheckbox);
        p.add(exporterErrorCheckbox);
        p.add(buildExporterStatsRow());
        p.add(exporterConfigCheckbox);
        refreshExporterStatsIntervalEnabledState();
        return p;
    }

    private JPanel buildExporterStatsRow() {
        JPanel row = new JPanel(new MigLayout("insets 0, gapx 8, gapy 0, novisualpadding", "[left][pref][40!][left]", "[]"));
        row.setOpaque(false);
        row.add(exporterStatsCheckbox);
        row.add(Tooltips.label("Interval:",
                Tooltips.html(
                        "Frequency for exporter stats snapshots.",
                        "This controls how often the Exporter index receives stats documents."
                )));
        row.add(exporterStatsIntervalField, "w 40!");
        row.add(new JLabel("sec"));
        return row;
    }

    private void refreshExporterStatsIntervalEnabledState() {
        exporterStatsIntervalField.setEnabled(exporterStatsCheckbox.isSelected());
    }

    /** Builds inline OpenSearch authentication controls (auth type + type-specific credential fields). */
    private JPanel buildAuthFormPanel() {
        ConfigOpenSearchInlinePanels.AuthFormResult result = ConfigOpenSearchInlinePanels.buildAuthFormPanel(
                new ConfigOpenSearchInlinePanels.AuthFormFields(
                        openSearchUserField,
                        openSearchPasswordField,
                        openSearchApiKeyTokenField,
                        openSearchJwtTokenField,
                        openSearchCertPathField,
                        openSearchCertKeyPathField,
                        openSearchCertPassphraseField),
                this::syncSelectedAuthStateFromUi,
                () -> suppressAuthSync);
        openSearchAuthTypeCombo = result.authTypeCombo();
        return result.panel();
    }

    private JPanel buildOpenSearchAmazonOptionsPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0", "[pref][pref][pref]", "[top]"));
        panel.setOpaque(false);

        String authTip = Tooltips.html("Select the Amazon OpenSearch Service authentication type.");
        String usernameTip = Tooltips.html(
                "Amazon OpenSearch Service Basic auth username.",
                "Stored in exported config as a non-secret.");
        String passwordTip = Tooltips.html(
                "Amazon OpenSearch Service Basic auth password.",
                "Stored only within in-process memory.");
        String regionTip = Tooltips.html(
                "AWS region for SigV4 credential resolution.",
                "Required when testing IAM/SigV4 credentials.");
        String profileTip = Tooltips.html(
                "Optional AWS shared-config profile.",
                "Leave blank to use the default AWS SDK credential provider chain.");
        Tooltips.apply(openSearchAmazonUserField, usernameTip);
        Tooltips.apply(openSearchAmazonPasswordField, passwordTip);
        Tooltips.apply(openSearchAmazonRegionField, regionTip);
        Tooltips.apply(openSearchAmazonProfileField, profileTip);

        JPanel contentCards = destinationAuthContentCards("os.amazon.authContent");
        JPanel iamCard = destinationAuthCard("os.amazon.authCard.iam");
        JPanel basicCard = destinationAuthCard("os.amazon.authCard.basic");
        JPanel noneCard = destinationAuthCard("os.amazon.authCard.none");

        addDestinationAuthFieldRow(iamCard, "Region:", openSearchAmazonRegionField, regionTip);
        addDestinationAuthFieldRow(iamCard, "Profile:", openSearchAmazonProfileField, profileTip);
        addDestinationAuthFieldRow(basicCard, "Amazon Username:", openSearchAmazonUserField, usernameTip);
        addDestinationAuthFieldRow(basicCard, "Amazon Password:", openSearchAmazonPasswordField, passwordTip);

        contentCards.add(iamCard, "hidemode 3");
        contentCards.add(basicCard, "hidemode 3");
        contentCards.add(noneCard, "hidemode 3");

        Consumer<String> applyAuthTypeVisibility = selectedType -> {
            iamCard.setVisible("IAM (sigV4)".equals(selectedType));
            basicCard.setVisible("Basic".equals(selectedType));
            noneCard.setVisible("None".equals(selectedType));
            contentCards.revalidate();
            contentCards.repaint();
        };
        openSearchAmazonAuthTypeCombo.addActionListener(e ->
                applyAuthTypeVisibility.accept(String.valueOf(openSearchAmazonAuthTypeCombo.getSelectedItem())));
        applyAuthTypeVisibility.accept(String.valueOf(openSearchAmazonAuthTypeCombo.getSelectedItem()));

        panel.add(Tooltips.label("Auth type:", authTip), "alignx left, top");
        panel.add(openSearchAmazonAuthTypeCombo, "alignx left, top");
        panel.add(contentCards, "gapleft 15, alignx left, top");
        return panel;
    }

    private JPanel buildElasticsearchOptionsPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0", "[pref][pref][pref]", "[top]"));
        panel.setOpaque(false);

        String authTip = Tooltips.html("Select the Elasticsearch authentication type.");
        String usernameTip = Tooltips.html("Elasticsearch Basic auth username.", "Stored in exported config as a non-secret.");
        String passwordTip = Tooltips.html("Elasticsearch Basic auth password.", "Stored only within in-process memory.");
        String apiKeyTokenTip = Tooltips.html("Elasticsearch API key token.", "Stored only within in-process memory.");
        String bearerTokenTip = Tooltips.html("Elasticsearch bearer token.", "Stored only within in-process memory.");
        String certPathTip = Tooltips.html("Path to the Elasticsearch client certificate file.");
        String keyPathTip = Tooltips.html("Path to the Elasticsearch client private key file.");
        String passphraseTip = Tooltips.html("Elasticsearch client key passphrase.", "Stored only within in-process memory.");
        Tooltips.apply(elasticSearchUserField, usernameTip);
        Tooltips.apply(elasticSearchPasswordField, passwordTip);
        Tooltips.apply(elasticSearchApiKeyTokenField, apiKeyTokenTip);
        Tooltips.apply(elasticSearchBearerTokenField, bearerTokenTip);
        Tooltips.apply(elasticSearchCertPathField, certPathTip);
        Tooltips.apply(elasticSearchCertKeyPathField, keyPathTip);
        Tooltips.apply(elasticSearchCertPassphraseField, passphraseTip);

        JPanel contentCards = destinationAuthContentCards("os.elasticsearch.authContent");
        JPanel apiKeyCard = destinationAuthCard("os.elasticsearch.authCard.apikey");
        JPanel bearerCard = destinationAuthCard("os.elasticsearch.authCard.bearer");
        JPanel certCard = destinationAuthCard("os.elasticsearch.authCard.certificate");
        JPanel basicCard = destinationAuthCard("os.elasticsearch.authCard.basic");
        JPanel noneCard = destinationAuthCard("os.elasticsearch.authCard.none");

        addDestinationAuthFieldRow(apiKeyCard, "API Key:", elasticSearchApiKeyTokenField, apiKeyTokenTip);
        addDestinationAuthFieldRow(bearerCard, "Bearer Token:", elasticSearchBearerTokenField, bearerTokenTip);
        addDestinationAuthFieldRow(certCard, "Cert Path:", elasticSearchCertPathField, certPathTip);
        addDestinationAuthFieldRow(certCard, "Key Path:", elasticSearchCertKeyPathField, keyPathTip);
        addDestinationAuthFieldRow(certCard, "Passphrase:", elasticSearchCertPassphraseField, passphraseTip);
        addDestinationAuthFieldRow(basicCard, "Username:", elasticSearchUserField, usernameTip);
        addDestinationAuthFieldRow(basicCard, "Password:", elasticSearchPasswordField, passwordTip);

        contentCards.add(apiKeyCard, "hidemode 3");
        contentCards.add(bearerCard, "hidemode 3");
        contentCards.add(certCard, "hidemode 3");
        contentCards.add(basicCard, "hidemode 3");
        contentCards.add(noneCard, "hidemode 3");

        Consumer<String> applyAuthTypeVisibility = selectedType -> {
            apiKeyCard.setVisible("API key".equals(selectedType));
            bearerCard.setVisible("Bearer token".equals(selectedType));
            certCard.setVisible("Certificate".equals(selectedType));
            basicCard.setVisible("Basic".equals(selectedType));
            noneCard.setVisible("None".equals(selectedType));
            contentCards.revalidate();
            contentCards.repaint();
        };
        elasticSearchAuthTypeCombo.addActionListener(e ->
                applyAuthTypeVisibility.accept(String.valueOf(elasticSearchAuthTypeCombo.getSelectedItem())));
        applyAuthTypeVisibility.accept(String.valueOf(elasticSearchAuthTypeCombo.getSelectedItem()));

        panel.add(Tooltips.label("Auth type:", authTip), "alignx left, top");
        panel.add(elasticSearchAuthTypeCombo, "alignx left, top");
        panel.add(contentCards, "gapleft 15, alignx left, top");
        return panel;
    }

    private static JPanel destinationAuthContentCards(String name) {
        JPanel panel = new JPanel(new MigLayout("insets 0, hidemode 3", "[left]", "[]"));
        panel.setName(name);
        panel.setOpaque(false);
        return panel;
    }

    private static JPanel destinationAuthCard(String name) {
        JPanel panel = new JPanel(new MigLayout("insets 0, wrap 2", "[pref][pref]", "[]"));
        panel.setName(name);
        panel.setOpaque(false);
        return panel;
    }

    private static void addDestinationAuthFieldRow(JPanel panel, String label, Component field, String tooltip) {
        panel.add(Tooltips.label(label, tooltip), "alignx left, top");
        panel.add(field, "alignx left, top");
    }

    private JPanel buildDestinationTlsPanel(
            JComboBox<String> tlsModeCombo,
            JButton importButton,
            String comboName,
            String importButtonName,
            ConfigState.SearchDestination destination) {
        tlsModeCombo.setName(comboName);
        tlsModeCombo.setSelectedItem("Verify");
        importButton.setName(importButtonName);
        String tlsModeTip = Tooltips.html(
                "Select how TLS server certificates are trusted.",
                "- Verify: uses the system trust store.",
                "- Trust pinned certificate: requires an imported X.509 server certificate.",
                "- Trust all certificates: disables verification. Use with caution.");
        String importTip = Tooltips.html(
                "Import a pinned X.509 server certificate for " + destination.displayName() + " TLS trust.",
                "  Common file types: .cer, .crt, .der, .pem.",
                "  The imported certificate bytes and source path are stored only within in-process memory.");
        Tooltips.apply(importButton, importTip);

        JPanel pinnedPanel = new JPanel(new MigLayout("insets 0", "[pref]", "[]"));
        pinnedPanel.setOpaque(false);
        pinnedPanel.add(importButton);
        Consumer<String> applyPinnedVisibility = selectedMode -> {
            boolean pinned = ConfigState.OPEN_SEARCH_TLS_PINNED.equals(normalizeTlsModeLabel(selectedMode));
            pinnedPanel.setVisible(pinned);
            importButton.setVisible(pinned);
        };
        tlsModeCombo.addActionListener(e -> {
            applyPinnedVisibility.accept(String.valueOf(tlsModeCombo.getSelectedItem()));
            pinnedPanel.revalidate();
            pinnedPanel.repaint();
        });
        importButton.addActionListener(e -> importPinnedCertificate(destination));
        applyPinnedVisibility.accept(String.valueOf(tlsModeCombo.getSelectedItem()));

        JPanel panel = new JPanel(new MigLayout("insets 0, hidemode 3", "[pref][pref][pref]", "[]"));
        panel.setOpaque(false);
        panel.add(Tooltips.label("TLS mode:", tlsModeTip), "alignx left, top");
        panel.add(tlsModeCombo, "alignx left, top");
        panel.add(pinnedPanel, "hidemode 3, gapleft 12, alignx left, top");
        return panel;
    }

    /** Builds inline TLS controls (mode selection + optional pinned-certificate import). */
    private JPanel buildTlsPanel() {
        return ConfigOpenSearchInlinePanels.buildTlsPanel(
                new ConfigOpenSearchInlinePanels.TlsFormFields(
                        openSearchTlsModeCombo,
                        importPinnedCertificateButton,
                        openSearchSinkCheckbox),
                selectedMode -> logTlsModeChangeIfNeeded(normalizeTlsModeLabel(selectedMode)));
    }

    private void importPinnedCertificate() {
        importPinnedCertificate(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    private void importPinnedCertificate(ConfigState.SearchDestination destination) {
        ConfigState.SearchDestination selectedDestination = destination == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : destination;
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import " + selectedDestination.displayName() + " TLS Certificate");
        chooser.setAcceptAllFileFilterUsed(true);
        chooser.setFileFilter(new FileNameExtensionFilter(
                "Certificate files (*.cer, *.crt, *.der, *.pem)", "cer", "crt", "der", "pem"));
        int choice = chooser.showOpenDialog(this);
        if (choice != JFileChooser.APPROVE_OPTION) {
            Logger.logDebug("[ConfigPanel] " + selectedDestination.displayName()
                    + " pinned TLS certificate import canceled.");
            return;
        }
        applyPinnedCertificateImport(selectedDestination, chooser.getSelectedFile().toPath());
    }

    private void applyPinnedCertificateImport(ConfigState.SearchDestination destination, Path selectedPath) {
        ConfigState.SearchDestination selectedDestination = destination == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : destination;
        Logger.logDebug("[ConfigPanel] Importing " + selectedDestination.displayName()
                + " pinned TLS certificate from " + selectedPath);
        try {
            SecureCredentialStore.PinnedTlsCertificate certificate =
                    OpenSearchTlsSupport.importPinnedCertificate(selectedPath);
            SecureCredentialStore.savePinnedTlsCertificate(
                    selectedDestination.configKey(),
                    certificate.sourcePath(), certificate.fingerprintSha256(), certificate.encodedBytes());
            Logger.logInfoPanelOnly("[ConfigPanel] Imported " + selectedDestination.displayName()
                    + " pinned TLS certificate: fingerprint="
                    + certificate.fingerprintSha256() + ", source=" + certificate.sourcePath());
            Logger.logTrace("[ConfigPanel] " + selectedDestination.displayName()
                    + " pinned TLS certificate bytes=" + certificate.encodedBytes().length);
            onDatabaseStatus("Pinned TLS certificate imported\nTrust: " + certificate.fingerprintSha256()
                    + "\nSource: " + certificate.sourcePath());
        } catch (IOException | java.security.cert.CertificateException e) {
            Logger.logErrorPanelOnly("[ConfigPanel] " + selectedDestination.displayName()
                    + " pinned TLS certificate import failed for " + selectedPath + ": " + rootMessage(e));
            onDatabaseStatus("Pinned TLS certificate import failed\nDetails: " + rootMessage(e));
        }
    }

    private void applyImportedPinnedTlsCertificate(ConfigState.OpenSearchOptions openSearchOptions) {
        applyImportedPinnedTlsCertificate(
                ConfigState.SearchDestination.OPEN_SEARCH,
                openSearchOptions == null ? "" : openSearchOptions.pinnedTlsCertificateSourcePath(),
                openSearchOptions == null ? "" : openSearchOptions.pinnedTlsCertificateFingerprintSha256(),
                openSearchOptions == null ? "" : openSearchOptions.pinnedTlsCertificateEncodedBase64());
    }

    private void applyImportedPinnedTlsCertificate(ConfigState.OpenSearchAmazonOptions openSearchAmazonOptions) {
        applyImportedPinnedTlsCertificate(
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON,
                openSearchAmazonOptions == null ? "" : openSearchAmazonOptions.pinnedTlsCertificateSourcePath(),
                openSearchAmazonOptions == null ? "" : openSearchAmazonOptions.pinnedTlsCertificateFingerprintSha256(),
                openSearchAmazonOptions == null ? "" : openSearchAmazonOptions.pinnedTlsCertificateEncodedBase64());
    }

    private void applyImportedPinnedTlsCertificate(ConfigState.ElasticsearchOptions elasticsearchOptions) {
        applyImportedPinnedTlsCertificate(
                ConfigState.SearchDestination.ELASTICSEARCH,
                elasticsearchOptions == null ? "" : elasticsearchOptions.pinnedTlsCertificateSourcePath(),
                elasticsearchOptions == null ? "" : elasticsearchOptions.pinnedTlsCertificateFingerprintSha256(),
                elasticsearchOptions == null ? "" : elasticsearchOptions.pinnedTlsCertificateEncodedBase64());
    }

    private void applyImportedPinnedTlsCertificate(
            ConfigState.SearchDestination destination,
            String sourcePath,
            String fingerprintSha256,
            String encodedBase64) {
        ConfigState.SearchDestination selectedDestination = destination == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : destination;
        if (encodedBase64 == null || encodedBase64.isBlank()
                || sourcePath == null || sourcePath.isBlank()
                || fingerprintSha256 == null || fingerprintSha256.isBlank()) {
            SecureCredentialStore.clearPinnedTlsCertificate(selectedDestination.configKey());
            return;
        }
        try {
            byte[] encodedBytes = Base64.getDecoder().decode(encodedBase64);
            SecureCredentialStore.savePinnedTlsCertificate(
                    selectedDestination.configKey(),
                    sourcePath,
                    fingerprintSha256,
                    encodedBytes);
        } catch (IllegalArgumentException e) {
            SecureCredentialStore.clearPinnedTlsCertificate(selectedDestination.configKey());
            Logger.logErrorPanelOnly("[ConfigPanel] Imported config contained an invalid "
                    + selectedDestination.displayName() + " pinned TLS certificate payload.");
        }
    }

    private void logTlsModeChangeIfNeeded(String normalizedMode) {
        if (normalizedMode == null || normalizedMode.equals(lastLoggedTlsMode)) {
            return;
        }
        lastLoggedTlsMode = normalizedMode;
        String label = labelForTlsMode(normalizedMode);
        Logger.logDebug("[ConfigPanel] OpenSearch TLS mode set to " + label + ".");
        if (ConfigState.OPEN_SEARCH_TLS_PINNED.equals(normalizedMode) && !OpenSearchTlsSupport.hasPinnedCertificate()) {
            Logger.logInfoPanelOnly("[ConfigPanel] OpenSearch TLS mode requires an imported pinned certificate before test/start.");
        } else if (ConfigState.OPEN_SEARCH_TLS_INSECURE.equals(normalizedMode)) {
            Logger.logInfoPanelOnly("[ConfigPanel] OpenSearch TLS mode is trusting all certificates insecurely.");
        }
    }

    private static String normalizeTlsModeLabel(String label) {
        return ConfigOpenSearchInlinePanels.normalizeTlsModeLabel(label);
    }

    private static String labelForTlsMode(String mode) {
        return switch (ConfigState.normalizeOpenSearchTlsMode(mode)) {
            case ConfigState.OPEN_SEARCH_TLS_PINNED -> "Trust pinned certificate";
            case ConfigState.OPEN_SEARCH_TLS_INSECURE -> "Trust all certificates";
            default -> "Verify";
        };
    }

    private String selectedTlsMode() {
        return normalizeTlsModeLabel(String.valueOf(openSearchTlsModeCombo.getSelectedItem()));
    }

    private static String selectedTlsMode(JComboBox<String> comboBox) {
        return normalizeTlsModeLabel(String.valueOf(comboBox.getSelectedItem()));
    }

    /**
     * Caches auth values in memory for the current Burp session.
     */
    private void persistSelectedAuthSecrets() {
        String selectedType = openSearchAuthTypeCombo == null
                ? "None"
                : String.valueOf(openSearchAuthTypeCombo.getSelectedItem());
        SecureCredentialStore.saveSelectedAuthType(ConfigState.SearchDestination.OPEN_SEARCH.configKey(), selectedType);
        SecureCredentialStore.saveSelectedAuthType(
                ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                String.valueOf(openSearchAmazonAuthTypeCombo.getSelectedItem()));
        SecureCredentialStore.saveSelectedAuthType(
                ConfigState.SearchDestination.ELASTICSEARCH.configKey(),
                String.valueOf(elasticSearchAuthTypeCombo.getSelectedItem()));
        switch (selectedType) {
            case "Basic" -> SecureCredentialStore.saveBasicCredentials(
                    ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
                    openSearchUserField.getText(),
                    passwordText(openSearchPasswordField));
            case "API key" -> SecureCredentialStore.saveApiKeyCredentials(
                    ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
                    passwordText(openSearchApiKeyTokenField));
            case "Bearer token" -> SecureCredentialStore.saveJwtCredentials(
                    ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
                    openSearchJwtTokenField.getText());
            case "Certificate" -> SecureCredentialStore.saveCertificateCredentials(
                    ConfigState.SearchDestination.OPEN_SEARCH.configKey(),
                    openSearchCertPathField.getText(),
                    openSearchCertKeyPathField.getText(),
                    passwordText(openSearchCertPassphraseField));
            default -> { }
        }
        if ("Basic".equals(String.valueOf(openSearchAmazonAuthTypeCombo.getSelectedItem()))) {
            SecureCredentialStore.saveBasicCredentials(
                    ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey(),
                    openSearchAmazonUserField.getText(),
                    passwordText(openSearchAmazonPasswordField));
        }
        String elasticDestination = ConfigState.SearchDestination.ELASTICSEARCH.configKey();
        switch (String.valueOf(elasticSearchAuthTypeCombo.getSelectedItem())) {
            case "Basic" -> SecureCredentialStore.saveBasicCredentials(
                    elasticDestination,
                    elasticSearchUserField.getText(),
                    passwordText(elasticSearchPasswordField));
            case "API key" -> SecureCredentialStore.saveApiKeyCredentials(
                    elasticDestination,
                    passwordText(elasticSearchApiKeyTokenField));
            case "Bearer token" -> SecureCredentialStore.saveJwtCredentials(
                    elasticDestination,
                    passwordText(elasticSearchBearerTokenField));
            case "Certificate" -> SecureCredentialStore.saveCertificateCredentials(
                    elasticDestination,
                    elasticSearchCertPathField.getText(),
                    elasticSearchCertKeyPathField.getText(),
                    passwordText(elasticSearchCertPassphraseField));
            default -> { }
        }
    }

    private JPanel buildTrafficSubPanel() {
        JPanel p = new JPanel(new MigLayout("insets 0, wrap 1", "[left]"));
        p.add(buildTrafficToolRow(trafficBurpAiCheckbox, trafficBurpAiCommunityIndicator));
        p.add(trafficExtensionsCheckbox);
        p.add(trafficIntruderCheckbox);
        p.add(trafficProxyCheckbox);
        p.add(trafficProxyHistoryCheckbox);
        p.add(trafficRepeaterCheckbox);
        p.add(trafficRepeaterTabsCheckbox);
        p.add(buildTrafficToolRow(trafficScannerCheckbox, trafficScannerCommunityIndicator));
        p.add(trafficSequencerCheckbox);
        return p;
    }

    private static JPanel buildTrafficToolRow(JCheckBox checkbox, JPanel communityIndicator) {
        JPanel row = new JPanel(new MigLayout("insets 0, aligny center, hidemode 3", "[left]8[pref!]"));
        row.setOpaque(false);
        row.add(checkbox, "aligny center");
        row.add(communityIndicator, "aligny center, hidemode 3");
        return row;
    }

    private void wireSourcesExpandCollapse(JButton expandButton, JPanel subPanel) {
        expandButton.addActionListener(e -> {
            boolean show = !subPanel.isVisible();
            subPanel.setVisible(show);
            expandButton.setText(show ? EXPAND_EXPANDED : EXPAND_COLLAPSED);
            subPanel.revalidate();
            subPanel.repaint();
        });
    }

    /**
     * Enables/disables sink controls based on checkbox selections.
     *
     * <p>EDT only. Keeps paired text fields and buttons in sync with their enable toggles.</p>
     */
    private void refreshEnabledStates() {
        refreshExporterStatsIntervalEnabledState();

        boolean files = fileSinkCheckbox.isSelected();
        filePathField.setEnabled(files);
        fileJsonlCheckbox.setEnabled(files);
        fileBulkNdjsonCheckbox.setEnabled(files);
        fileTotalCapCheckbox.setEnabled(files);
        fileTotalCapField.setEnabled(files && fileTotalCapCheckbox.isSelected());
        fileDiskUsagePercentCheckbox.setEnabled(files);
        fileDiskUsagePercentField.setEnabled(files && fileDiskUsagePercentCheckbox.isSelected());

        boolean databaseSelected = databaseSinkCheckbox.isSelected();
        boolean openSearchSelected = databaseSelected && openSearchSinkCheckbox.isSelected();
        boolean amazonSelected = databaseSelected && openSearchAmazonDestinationRadio.isSelected();
        boolean elasticSearchSelected = databaseSelected && elasticSearchDestinationRadio.isSelected();
        openSearchSinkCheckbox.setEnabled(databaseSelected);
        openSearchAmazonDestinationRadio.setEnabled(databaseSelected);
        elasticSearchDestinationRadio.setEnabled(databaseSelected);
        openSearchUrlField.setEnabled(openSearchSelected);
        openSearchAmazonUrlField.setEnabled(amazonSelected);
        openSearchAmazonAuthTypeCombo.setEnabled(amazonSelected);
        openSearchAmazonTlsModeCombo.setEnabled(amazonSelected && isHttpsEndpoint(openSearchAmazonUrlField));
        openSearchAmazonUserField.setEnabled(amazonSelected);
        openSearchAmazonPasswordField.setEnabled(amazonSelected);
        openSearchAmazonRegionField.setEnabled(amazonSelected);
        openSearchAmazonProfileField.setEnabled(amazonSelected);
        elasticSearchUrlField.setEnabled(elasticSearchSelected);
        elasticSearchAuthTypeCombo.setEnabled(elasticSearchSelected);
        elasticSearchTlsModeCombo.setEnabled(elasticSearchSelected && isHttpsEndpoint(elasticSearchUrlField));
        elasticSearchUserField.setEnabled(elasticSearchSelected);
        elasticSearchPasswordField.setEnabled(elasticSearchSelected);
        elasticSearchApiKeyTokenField.setEnabled(elasticSearchSelected);
        elasticSearchBearerTokenField.setEnabled(elasticSearchSelected);
        elasticSearchCertPathField.setEnabled(elasticSearchSelected);
        elasticSearchCertKeyPathField.setEnabled(elasticSearchSelected);
        elasticSearchCertPassphraseField.setEnabled(elasticSearchSelected);
        testConnectionButton.setEnabled(openSearchSelected || amazonSelected || elasticSearchSelected);
        if (openSearchAuthFormPanel != null) {
            setEnabledRecursively(openSearchAuthFormPanel, openSearchSelected);
        }
        if (openSearchTlsPanel != null) {
            setEnabledRecursively(openSearchTlsPanel, openSearchSelected && isHttpsEndpoint(openSearchUrlField));
        }
        importPinnedCertificateButton.setEnabled(openSearchSelected
                && isHttpsEndpoint(openSearchUrlField)
                && ConfigState.OPEN_SEARCH_TLS_PINNED.equals(selectedTlsMode()));
    }

    private void applySearchDestinationSelection() {
        refreshEnabledStates();
    }

    private String selectedSearchDestination() {
        if (openSearchAmazonDestinationRadio.isSelected()) {
            return DESTINATION_OPENSEARCH_AMAZON;
        }
        if (elasticSearchDestinationRadio.isSelected()) {
            return DESTINATION_ELASTICSEARCH;
        }
        return DESTINATION_OPENSEARCH;
    }

    private String selectedSearchDestinationKey() {
        if (openSearchAmazonDestinationRadio.isSelected()) {
            return ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey();
        }
        if (elasticSearchDestinationRadio.isSelected()) {
            return ConfigState.SearchDestination.ELASTICSEARCH.configKey();
        }
        return ConfigState.SearchDestination.OPEN_SEARCH.configKey();
    }

    private ConfigState.SearchDestination selectedSearchDestinationKind() {
        return ConfigState.normalizeSearchDestination(selectedSearchDestinationKey());
    }

    private JTextField selectedSearchUrlField() {
        if (openSearchAmazonDestinationRadio.isSelected()) {
            return openSearchAmazonUrlField;
        }
        if (elasticSearchDestinationRadio.isSelected()) {
            return elasticSearchUrlField;
        }
        return openSearchUrlField;
    }

    private static boolean isHttpsEndpoint(JTextField field) {
        String text = field == null ? "" : field.getText();
        return text != null && text.trim().regionMatches(true, 0, "https://", 0, "https://".length());
    }

    private boolean isOpenSearchExportSelected() {
        return databaseSinkCheckbox.isSelected()
                && RuntimeConfig.isSearchDestinationExportWired(selectedSearchDestinationKind());
    }

    private static void setEnabledRecursively(Component c, boolean enabled) {
        c.setEnabled(enabled);
        if (c instanceof java.awt.Container container) {
            for (Component child : container.getComponents()) {
                setEnabledRecursively(child, enabled);
            }
        }
    }

    /**
     * Collects the currently selected data sources.
     *
     * @return ordered list of source keys suitable for {@link ConfigKeys}
     */
    private List<String> getSelectedSources() {
        List<String> selected = new ArrayList<>();
        if (settingsCheckbox.isSelected()) selected.add(ConfigKeys.SRC_SETTINGS);
        if (sitemapCheckbox.isSelected())  selected.add(ConfigKeys.SRC_SITEMAP);
        if (issuesCheckbox.isSelected())   selected.add(ConfigKeys.SRC_FINDINGS);
        if (trafficCheckbox.isSelected())  selected.add(ConfigKeys.SRC_TRAFFIC);
        if (exporterCheckbox.isSelected()) selected.add(ConfigKeys.SRC_EXPORTER);
        return selected;
    }

    /**
     * Installs undo/redo bindings and enter-key shortcuts on text fields and the TLS mode combo.
     *
     * <p>EDT only. Enter triggers the most relevant action for each field; on the OpenSearch TLS
     * mode dropdown it runs Test Connection when that button is enabled.</p>
     */
    private void wireTextFieldEnhancements() {
        TextFieldUndo.install(filePathField);
        TextFieldUndo.install(openSearchUrlField);
        TextFieldUndo.install(openSearchAmazonUrlField);
        TextFieldUndo.install(elasticSearchUrlField);
        TextFieldUndo.install(fileTotalCapField);
        TextFieldUndo.install(fileDiskUsagePercentField);
        TextFieldUndo.install(exporterStatsIntervalField);
        TextFieldUndo.install(indexNameBaseTemplateField);
        indexNameBaseTemplateField.getDocument().addDocumentListener(Doc.onChange(this::refreshIndexNameBaseValidationState));
        openSearchUrlField.addActionListener(e -> testConnectionButton.doClick());

        openSearchTlsModeCombo.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), TLS_MODE_ENTER_TEST_CONNECTION);
        openSearchTlsModeCombo.getActionMap().put(TLS_MODE_ENTER_TEST_CONNECTION, new AbstractAction() {
            @Serial private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(ActionEvent e) {
                if (testConnectionButton.isEnabled()) {
                    testConnectionButton.doClick();
                }
            }
        });
    }

    private JPanel buildFileLimitsPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, gapx 8, gapy 0, novisualpadding",
                "[left][40!][left][left][40!][left]", "[]"));
        panel.setOpaque(false);
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(fileTotalCapCheckbox);
        panel.add(fileTotalCapField, "w 40!");
        panel.add(new JLabel("GiB"), "gapright 12");
        panel.add(fileDiskUsagePercentCheckbox);
        panel.add(fileDiskUsagePercentField, "w 40!");
        panel.add(new JLabel("%"));
        return panel;
    }

    private JPanel buildGlobalIndexNamingPanel() {
        JPanel panel = new JPanel(new MigLayout("insets 0, hidemode 3, gapx 8", "[pref!][pref][pref!]", "[]"));
        panel.setOpaque(false);

        String tooltip = indexBaseNameTooltip();
        panel.add(Tooltips.label("Index Base Name:", tooltip));
        panel.add(indexNameBaseTemplateField, "aligny center");
        panel.add(indexNameBaseValidationIndicator, "aligny center");
        return panel;
    }

    /** Prepares the inline Index Base Name validation indicator to match regex-style glyph feedback. */
    private void configureIndexNameBaseValidationUi() {
        ValidationIndicator.hide(indexNameBaseValidationIndicator, indexNameBaseTemplateField.getFont());
    }

    /** Revalidates the Index Base Name field against the same OpenSearch rules used at Start. */
    private void refreshIndexNameBaseValidationState() {
        ai.anomalousvectors.tools.burp.utils.IndexNaming.BaseTemplateValidation validation =
                ai.anomalousvectors.tools.burp.utils.IndexNaming.validateBaseTemplateDetailed(
                indexNameBaseTemplateField.getText(),
                Instant.now());
        if (validation.valid()) {
            ValidationIndicator.good(
                    indexNameBaseValidationIndicator,
                    indexNameBaseTemplateField.getFont(),
                    validIndexBaseNameTooltip());
        } else {
            ValidationIndicator.bad(
                    indexNameBaseValidationIndicator,
                    indexNameBaseTemplateField.getFont(),
                    invalidIndexBaseNameTooltip(validation));
        }
        if (indexNameBaseValidationIndicator.getParent() != null) {
            indexNameBaseValidationIndicator.getParent().revalidate();
            indexNameBaseValidationIndicator.getParent().repaint();
        }
    }

    private static String indexBaseNameTooltip() {
        return Tooltips.htmlRaw(
                "<b>Index Base Name</b>",
                "Shared base used to derive all OpenSearch index names and file basenames.",
                "Enter only the shared base. Fixed suffixes are appended automatically:",
                "&nbsp;&nbsp;<code>-exporter</code>, <code>-findings</code>, <code>-settings</code>, <code>-sitemap</code>, <code>-traffic</code>",
                "",
                "Default:",
                "&nbsp;&nbsp;<code>tool-burp</code>",
                "",
                "Examples:",
                "&nbsp;&nbsp;<code>tool-burp</code>",
                "&nbsp;&nbsp;<code>${now:yyyyMMdd}-tool-burp</code>",
                "&nbsp;&nbsp;<code>${now:yyyyMMdd-HHmmss}-tool-burp</code>",
                "",
                "Supported date-time variables:",
                "&nbsp;&nbsp;<code>{NOW}</code> or <code>{DATE-TIME}</code> for the built-in current local date/time value",
                "&nbsp;&nbsp;<code>${now:yyyyMMdd}</code> or <code>${now:yyyyMMdd-HHmmss}</code> for explicit Java date-time formats",
                "",
                "OpenSearch requirements after suffixes are appended:",
                "&nbsp;&nbsp;- lowercase only",
                "&nbsp;&nbsp;- cannot start with <code>-</code>, <code>_</code>, or <code>+</code>",
                "&nbsp;&nbsp;- cannot be <code>.</code> or <code>..</code>",
                "&nbsp;&nbsp;- cannot contain spaces or <code>\\ / * ? \" &lt; &gt; | , # :</code>",
                "&nbsp;&nbsp;- cannot contain unresolved variable syntax",
                "&nbsp;&nbsp;- must stay within 255 UTF-8 bytes",
                "",
                "Resolution timing:",
                "&nbsp;&nbsp;Date-time variables resolve on each <b>Start</b> and remain fixed for that full run."
        );
    }

    private static String validIndexBaseNameTooltip() {
        return Tooltips.htmlRaw(
                "<b>Valid Index Base Name</b>",
                "All resolved index names currently satisfy the OpenSearch naming rules.",
                "Blank is also allowed and falls back to <code>tool-burp</code>."
        );
    }

    private static String invalidIndexBaseNameTooltip(
            ai.anomalousvectors.tools.burp.utils.IndexNaming.BaseTemplateValidation validation) {
        String displayName = Tooltips.escapeHtml(validation.failingDisplayName());
        String resolvedName = Tooltips.escapeHtml(validation.failingResolvedName());
        String error = Tooltips.escapeHtml(validation.error());
        return Tooltips.htmlRaw(
                "<b>Invalid Index Base Name</b>",
                "<b>Error:</b> " + error,
                "<b>Failing resolved index:</b> " + displayName,
                "<b>Resolved name:</b> <code>" + resolvedName + "</code>",
                "",
                "<b>Requirements</b>",
                "All resolved index names must:",
                "&nbsp;&nbsp;- be lowercase",
                "&nbsp;&nbsp;- not start with <code>-</code>, <code>_</code>, or <code>+</code>",
                "&nbsp;&nbsp;- not be <code>.</code> or <code>..</code>",
                "&nbsp;&nbsp;- not contain spaces or <code>\\ / * ? \" &lt; &gt; | , # :</code>",
                "&nbsp;&nbsp;- not contain unsupported or unresolved variable syntax",
                "&nbsp;&nbsp;- stay within 255 UTF-8 bytes after the suffix is appended"
        );
    }

    /** Returns {@code value} if non-null and non-blank, otherwise {@code fallback}. */
    private static String nonBlankOr(String value, String fallback) {
        return (value != null && !value.isBlank()) ? value.trim() : (fallback != null ? fallback : "");
    }

    /**
     * Builds the current UI state into a serializable config object.
     *
     * @return assembled {@link ConfigState.State} reflecting user selections
     */
    private ConfigState.State buildCurrentState() {
        return buildCurrentState(currentUiPreferences());
    }

    private ConfigState.State buildCurrentState(ConfigState.UiPreferences uiPreferences) {
        List<String> selectedSources = getSelectedSources();

        String scopeType;
        List<ConfigState.ScopeEntry> custom = new ArrayList<>();
        if (allRadio.isSelected()) {
            scopeType = ConfigKeys.SCOPE_ALL;
        } else if (burpSuiteRadio.isSelected()) {
            scopeType = ConfigKeys.SCOPE_BURP;
        } else if (customRadio.isSelected()) {
            scopeType = ConfigKeys.SCOPE_CUSTOM;
            List<String> vals  = scopeGrid.values();
            List<Boolean> kinds = scopeGrid.regexKinds();
            int n = Math.min(vals.size(), kinds.size());
            for (int i = 0; i < n; i++) {
                String v = vals.get(i);
                if (v == null || v.trim().isEmpty()) continue;
                boolean isRegex = Boolean.TRUE.equals(kinds.get(i));
                custom.add(new ConfigState.ScopeEntry(
                        v.trim(), isRegex ? ConfigState.Kind.REGEX : ConfigState.Kind.STRING));
            }
        } else {
            scopeType = ConfigKeys.SCOPE_ALL;
        }

        boolean filesEnabled = fileSinkCheckbox.isSelected();
        boolean databaseEnabled = databaseSinkCheckbox.isSelected();
        String  osUrl        = openSearchUrlField.getText();
        String  awsUrl       = openSearchAmazonUrlField.getText();
        String  elasticUrl   = elasticSearchUrlField.getText();
        String  filesRoot    = filePathField.getText();

        List<String> settingsSub = new ArrayList<>();
        if (settingsProjectCheckbox.isSelected()) settingsSub.add(ConfigKeys.SRC_SETTINGS_PROJECT);
        if (settingsUserCheckbox.isSelected()) settingsSub.add(ConfigKeys.SRC_SETTINGS_USER);

        List<String> trafficToolTypes = new ArrayList<>();
        if (trafficBurpAiCheckbox.isSelected()) trafficToolTypes.add("burp_ai");
        if (trafficExtensionsCheckbox.isSelected()) trafficToolTypes.add("extensions");
        if (trafficIntruderCheckbox.isSelected()) trafficToolTypes.add("intruder");
        if (trafficProxyCheckbox.isSelected()) trafficToolTypes.add("proxy");
        if (trafficProxyHistoryCheckbox.isSelected()) trafficToolTypes.add("proxy_history");
        if (trafficRepeaterCheckbox.isSelected()) trafficToolTypes.add("repeater");
        if (trafficRepeaterTabsCheckbox.isSelected()) trafficToolTypes.add("repeater_tabs");
        if (trafficScannerCheckbox.isSelected()) trafficToolTypes.add("scanner");
        if (trafficSequencerCheckbox.isSelected()) trafficToolTypes.add("sequencer");

        List<String> findingsSeverities = new ArrayList<>();
        if (issuesCriticalCheckbox.isSelected()) findingsSeverities.add("critical");
        if (issuesHighCheckbox.isSelected()) findingsSeverities.add("high");
        if (issuesMediumCheckbox.isSelected()) findingsSeverities.add("medium");
        if (issuesLowCheckbox.isSelected()) findingsSeverities.add("low");
        if (issuesInformationalCheckbox.isSelected()) findingsSeverities.add("informational");

        List<String> exporterSubOptions = new ArrayList<>();
        if (exporterTraceCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_TRACE);
        if (exporterDebugCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_DEBUG);
        if (exporterInfoCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_INFO);
        if (exporterWarnCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_WARN);
        if (exporterErrorCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_ERROR);
        if (exporterStatsCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_STATS);
        if (exporterConfigCheckbox.isSelected()) exporterSubOptions.add(ConfigKeys.SRC_EXPORTER_CONFIG);

        String authType = openSearchAuthTypeCombo != null
                ? String.valueOf(openSearchAuthTypeCombo.getSelectedItem())
                : ConfigState.DEFAULT_OPEN_SEARCH_AUTH_TYPE;
        boolean authBasic = "Basic".equals(authType);
        String osUser = nonBlankOr(openSearchUserField.getText(), "");
        String osPass = authBasic ? nonBlankOr(passwordText(openSearchPasswordField), "") : "";
        SecureCredentialStore.PinnedTlsCertificate pinnedTlsCertificate = SecureCredentialStore.loadPinnedTlsCertificate(
                ConfigState.SearchDestination.OPEN_SEARCH.configKey());
        String pinnedTlsCertificateBase64 = pinnedTlsCertificate.encodedBytes().length == 0
                ? ""
                : Base64.getEncoder().encodeToString(pinnedTlsCertificate.encodedBytes());
        SecureCredentialStore.PinnedTlsCertificate amazonPinnedTlsCertificate =
                SecureCredentialStore.loadPinnedTlsCertificate(
                        ConfigState.SearchDestination.OPEN_SEARCH_AMAZON.configKey());
        String amazonPinnedTlsCertificateBase64 = amazonPinnedTlsCertificate.encodedBytes().length == 0
                ? ""
                : Base64.getEncoder().encodeToString(amazonPinnedTlsCertificate.encodedBytes());
        SecureCredentialStore.PinnedTlsCertificate elasticPinnedTlsCertificate =
                SecureCredentialStore.loadPinnedTlsCertificate(
                        ConfigState.SearchDestination.ELASTICSEARCH.configKey());
        String elasticPinnedTlsCertificateBase64 = elasticPinnedTlsCertificate.encodedBytes().length == 0
                ? ""
                : Base64.getEncoder().encodeToString(elasticPinnedTlsCertificate.encodedBytes());
        String searchDestination = selectedSearchDestinationKey();
        String awsAuthType = String.valueOf(openSearchAmazonAuthTypeCombo.getSelectedItem());
        String elasticAuthType = String.valueOf(elasticSearchAuthTypeCombo.getSelectedItem());
        String awsUser = nonBlankOr(openSearchAmazonUserField.getText(), "");
        String awsRegion = nonBlankOr(openSearchAmazonRegionField.getText(), "");
        String awsProfile = nonBlankOr(openSearchAmazonProfileField.getText(), "");
        String elasticUser = nonBlankOr(elasticSearchUserField.getText(), "");
        String elasticCertPath = nonBlankOr(elasticSearchCertPathField.getText(), "");
        String elasticCertKeyPath = nonBlankOr(elasticSearchCertKeyPathField.getText(), "");
        return new ConfigState.State(
                selectedSources,
                scopeType,
                custom,
                new ConfigState.Sinks(filesEnabled, filesRoot, fileJsonlCheckbox.isSelected(),
                        fileBulkNdjsonCheckbox.isSelected(),
                        fileTotalCapCheckbox.isSelected(), parseGiBLimit(fileTotalCapField.getText(),
                                ConfigState.DEFAULT_FILE_TOTAL_CAP_GB),
                        fileDiskUsagePercentCheckbox.isSelected(), parsePercentLimit(fileDiskUsagePercentField.getText(),
                                ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT),
                        databaseEnabled, osUrl,
                        osUser,
                        osPass,
                        selectedTlsMode(),
                        new ConfigState.OpenSearchOptions(
                                authType,
                                "",
                                nonBlankOr(openSearchCertPathField.getText(), ""),
                                nonBlankOr(openSearchCertKeyPathField.getText(), ""),
                                pinnedTlsCertificate.sourcePath(),
                                pinnedTlsCertificate.fingerprintSha256(),
                                pinnedTlsCertificateBase64),
                        searchDestination,
                        awsUrl,
                        new ConfigState.OpenSearchAmazonOptions(
                                awsAuthType,
                                awsUser,
                                awsRegion,
                                awsProfile,
                                selectedTlsMode(openSearchAmazonTlsModeCombo),
                                amazonPinnedTlsCertificate.sourcePath(),
                                amazonPinnedTlsCertificate.fingerprintSha256(),
                                amazonPinnedTlsCertificateBase64),
                        elasticUrl,
                        new ConfigState.ElasticsearchOptions(
                                elasticAuthType,
                                elasticUser,
                                elasticCertPath,
                                elasticCertKeyPath,
                                selectedTlsMode(elasticSearchTlsModeCombo),
                                elasticPinnedTlsCertificate.sourcePath(),
                                elasticPinnedTlsCertificate.fingerprintSha256(),
                                elasticPinnedTlsCertificateBase64)),
                settingsSub,
                trafficToolTypes,
                findingsSeverities,
                exporterSubOptions,
                parsePositiveSeconds(exporterStatsIntervalField.getText(),
                        ConfigState.DEFAULT_EXPORTER_STATS_INTERVAL_SECONDS),
                nonBlankOr(indexNameBaseTemplateField.getText(), ConfigState.DEFAULT_INDEX_NAME_BASE_TEMPLATE),
                buildEnabledExportFieldsByIndex(),
                uiPreferences
        );
    }

    private static ConfigState.UiPreferences currentUiPreferences() {
        ConfigState.State current = RuntimeConfig.getState();
        return current == null || current.uiPreferences() == null
                ? ConfigState.defaultUiPreferences()
                : current.uiPreferences();
    }

    /**
     * Builds enabled export fields from Fields panel checkboxes.
     *
     * <p>{@code null} means every toggleable field is on (omit {@code exportFields} from JSON).
     * When only some indexes differ from all-on, the map lists just those indexes; others are
     * implied all-on on import and at runtime.</p>
     */
    private java.util.Map<String, java.util.Set<String>> buildEnabledExportFieldsByIndex() {
        if (fieldCheckboxesByIndex == null) return null;
        java.util.Map<String, java.util.Set<String>> raw = new java.util.LinkedHashMap<>();
        for (String indexName : ai.anomalousvectors.tools.burp.utils.config.ExportFieldRegistry.INDEX_ORDER) {
            java.util.Map<String, JCheckBox> checkboxes = fieldCheckboxesByIndex.get(indexName);
            if (checkboxes == null) continue;
            java.util.Set<String> enabled = new java.util.LinkedHashSet<>();
            for (java.util.Map.Entry<String, JCheckBox> e : checkboxes.entrySet()) {
                if (e.getValue().isSelected()) {
                    enabled.add(e.getKey());
                }
            }
            raw.put(indexName, java.util.Collections.unmodifiableSet(enabled));
        }
        return ai.anomalousvectors.tools.burp.utils.config.ExportFieldRegistry.compactEnabledFieldsForExport(raw);
    }

    /**
     * Parses a GiB limit from the UI, accepting decimal values such as {@code 0.5}.
     *
     * <p>Invalid, blank, or non-positive input falls back to {@code defaultGb}. Values are rounded
     * to three decimals so import/export remains stable for user-entered values such as
     * {@code 1.25}.</p>
     */
    private static double parseGiBLimit(String raw, double defaultGb) {
        try {
            BigDecimal gib = new BigDecimal(nonBlankOr(raw, "").trim());
            if (gib.compareTo(BigDecimal.ZERO) <= 0) {
                return defaultGb;
            }
            return gib.setScale(3, RoundingMode.HALF_UP).stripTrailingZeros().doubleValue();
        } catch (RuntimeException e) {
            return defaultGb;
        }
    }

    /** Formats a GB limit back to a trimmed string suitable for the UI text fields. */
    private static String formatGiBLimit(double gb) {
        if (gb <= 0) {
            return "1";
        }
        return BigDecimal.valueOf(gb)
                .setScale(3, RoundingMode.HALF_UP)
                .stripTrailingZeros()
                .toPlainString();
    }

    private static int parsePercentLimit(String raw, int defaultPercent) {
        try {
            return Math.clamp(Integer.parseInt(nonBlankOr(raw, "")), 1, 100);
        } catch (NumberFormatException e) {
            return defaultPercent;
        }
    }

    private static int parsePositiveSeconds(String raw, int defaultSeconds) {
        try {
            int seconds = Integer.parseInt(nonBlankOr(raw, ""));
            return seconds > 0 ? seconds : defaultSeconds;
        } catch (NumberFormatException e) {
            return defaultSeconds;
        }
    }

    /**
     * Prompts for a save location and exports the current config to JSON asynchronously.
     *
     * <p>EDT only. Uses {@link FileUtil#ensureJsonExtension(java.io.File)} to normalize the file
     * name before delegating to {@link ConfigController#exportConfigAsync(java.nio.file.Path, String)}.</p>
     */
    private void exportConfig() {
        ConfigState.State currentState = buildCurrentState();
        ai.anomalousvectors.tools.burp.utils.IndexNaming.ResolutionResult indexNamingResolution =
                ai.anomalousvectors.tools.burp.utils.IndexNaming.resolveAllConfiguredNames(
                        currentState,
                        java.time.Instant.now());
        if (!indexNamingResolution.valid()) {
            onControlStatus("Fix index naming before export: " + String.join(" ", indexNamingResolution.errors()));
            return;
        }
        String json = ConfigJsonMapper.build(currentState);
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        chooser.setSelectedFile(new File("burp-exporter-config.json"));
        int result = chooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) { onControlStatus("Export cancelled."); return; }
        Path out = FileUtil.ensureJsonExtension(chooser.getSelectedFile()).toPath();
        controller().exportConfigAsync(out, json);
    }

    /**
     * Prompts for a config file and imports it asynchronously via the controller.
     *
     * <p>EDT only. Delegates parsing and UI application to
     * {@link ConfigController#importConfigAsync(java.nio.file.Path)}.</p>
     */
    private void importConfig() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Config");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files (*.json)", "json"));
        int result = chooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) { onControlStatus("Import cancelled."); return; }
        controller().importConfigAsync(chooser.getSelectedFile().toPath());
    }

    /** Assign stable names used by headless tests. */
    private void assignComponentNames() {
        settingsCheckbox.setName("src.settings");
        sitemapCheckbox.setName("src.sitemap");
        issuesCheckbox.setName("src.issues");
        trafficCheckbox.setName("src.traffic");
        exporterCheckbox.setName("src.exporter");
        settingsProjectCheckbox.setName("src.settings.project");
        settingsUserCheckbox.setName("src.settings.user");
        settingsExpandButton.setName("src.settings.expand");
        issuesCriticalCheckbox.setName("src.issues.critical");
        issuesHighCheckbox.setName("src.issues.high");
        issuesMediumCheckbox.setName("src.issues.medium");
        issuesLowCheckbox.setName("src.issues.low");
        issuesInformationalCheckbox.setName("src.issues.informational");
        issuesExpandButton.setName("src.issues.expand");
        trafficBurpAiCheckbox.setName("src.traffic.burp_ai");
        trafficExtensionsCheckbox.setName("src.traffic.extensions");
        trafficIntruderCheckbox.setName("src.traffic.intruder");
        trafficProxyCheckbox.setName("src.traffic.proxy");
        trafficProxyHistoryCheckbox.setName("src.traffic.proxy_history");
        trafficRepeaterCheckbox.setName("src.traffic.repeater");
        trafficRepeaterTabsCheckbox.setName("src.traffic.repeater_tabs");
        trafficScannerCheckbox.setName("src.traffic.scanner");
        trafficSequencerCheckbox.setName("src.traffic.sequencer");
        trafficExpandButton.setName("src.traffic.expand");
        exporterTraceCheckbox.setName("src.exporter.trace");
        exporterDebugCheckbox.setName("src.exporter.debug");
        exporterInfoCheckbox.setName("src.exporter.info");
        exporterWarnCheckbox.setName("src.exporter.warn");
        exporterErrorCheckbox.setName("src.exporter.error");
        exporterStatsCheckbox.setName("src.exporter.stats");
        exporterStatsIntervalField.setName("src.exporter.stats.intervalSeconds");
        exporterConfigCheckbox.setName("src.exporter.config");
        exporterExpandButton.setName("src.exporter.expand");
        indexNameBaseTemplateField.setName("indexNaming.baseTemplate");
        indexNameBaseValidationIndicator.setName("indexNaming.baseTemplate.indicator");

        allRadio.setName("scope.all");
        burpSuiteRadio.setName("scope.burp");
        customRadio.setName("scope.custom");

        fileSinkCheckbox.setName("files.enable");
        filePathField.setName("files.path");
        fileJsonlCheckbox.setName("files.format.jsonl");
        fileBulkNdjsonCheckbox.setName("files.format.bulkNdjson");
        fileTotalCapCheckbox.setName("files.limit.total.enable");
        fileTotalCapField.setName("files.limit.total.gib");
        fileDiskUsagePercentCheckbox.setName("files.limit.diskPercent.enable");
        fileDiskUsagePercentField.setName("files.limit.diskPercent.value");

        databaseSinkCheckbox.setName("database.enable");
        openSearchSinkCheckbox.setName("os.destination.openSearch");
        openSearchAmazonDestinationRadio.setName("os.destination.amazon");
        elasticSearchDestinationRadio.setName("os.destination.elasticsearch");
        openSearchUrlField.setName("os.url");
        openSearchAmazonUrlField.setName("os.amazon.url");
        elasticSearchUrlField.setName("os.elasticsearch.url");
        openSearchAmazonAuthTypeCombo.setName("os.amazon.authType");
        openSearchAmazonUserField.setName("os.amazon.username");
        openSearchAmazonPasswordField.setName("os.amazon.password");
        openSearchAmazonRegionField.setName("os.amazon.region");
        openSearchAmazonProfileField.setName("os.amazon.profile");
        elasticSearchAuthTypeCombo.setName("os.elasticsearch.authType");
        elasticSearchUserField.setName("os.elasticsearch.username");
        elasticSearchPasswordField.setName("os.elasticsearch.password");
        elasticSearchApiKeyTokenField.setName("os.elasticsearch.apiKey");
        elasticSearchBearerTokenField.setName("os.elasticsearch.bearerToken");
        elasticSearchCertPathField.setName("os.elasticsearch.certPath");
        elasticSearchCertKeyPathField.setName("os.elasticsearch.certKeyPath");
        elasticSearchCertPassphraseField.setName("os.elasticsearch.certPassphrase");
        testConnectionButton.setName("os.test");

        controlStatusWrapper.setName("control.statusWrapper");
        controlStatus.setName("control.status");
    }

    /**
     * Assigns tooltips for all ConfigPanel controls.
     *
     * <p>EDT only. Consolidated here to keep tooltip text consistent and discoverable.</p>
     */
    private void assignToolTips() {
        Tooltips.apply(settingsCheckbox, Tooltips.html("All settings."));
        Tooltips.apply(sitemapCheckbox, Tooltips.html("All in-scope sitemaps."));
        Tooltips.apply(issuesCheckbox, Tooltips.html("All findings (aka issues)."));
        Tooltips.apply(trafficCheckbox, Tooltips.html("All in-scope traffic."));
        Tooltips.apply(exporterCheckbox, Tooltips.html(
                "Burp Exporter runtime logs and metrics.",
                "Controls logs, stats snapshots, and config snapshots exported to the Exporter index."
        ));
        Tooltips.apply(settingsExpandButton, Tooltips.html("Settings sub-options."));
        Tooltips.apply(issuesExpandButton, Tooltips.html("Issues sub-options."));
        Tooltips.apply(trafficExpandButton, Tooltips.html("Traffic sub-options."));
        Tooltips.apply(exporterExpandButton, Tooltips.html("Exporter sub-options."));
        Tooltips.apply(settingsProjectCheckbox, Tooltips.html("Project settings."));
        Tooltips.apply(settingsUserCheckbox, Tooltips.html("User settings."));
        Tooltips.apply(trafficBurpAiCheckbox, Tooltips.html("Traffic sent from Burp AI."));
        Tooltips.apply(trafficExtensionsCheckbox, Tooltips.html("Traffic sent from all other extensions."));
        Tooltips.apply(trafficIntruderCheckbox, Tooltips.html("Traffic sent from Intruder."));
        Tooltips.apply(trafficProxyCheckbox, Tooltips.html(
                "Live traffic from Proxy (HTTP and WebSocket frames).",
                "WebSocket frames are exported from Proxy WebSocket history on a short interval",
                "so Burp conversation and message ids are included.",
                "For historic proxy traffic already in the table when Start is clicked, select Proxy History."));
        Tooltips.apply(trafficProxyHistoryCheckbox, Tooltips.html(
                "Historic traffic from Proxy History (HTTP pairs and WebSocket frames).",
                "This exports a one-time snapshot when Start is clicked.",
                "The export is performed in smart batches to minimize performance impact to Burp. ",
                "For ongoing and future proxy traffic, select Proxy."
        ));
        Tooltips.apply(trafficRepeaterCheckbox, Tooltips.html(
                "Traffic sent from live Repeater requests.",
                "Best-effort Repeater tab and group fields are included when Burp exposes a "
                        + "confident match.",
                "Identical concurrent Repeater tabs can intentionally export null tab/group "
                        + "metadata instead of guessing."
        ));
        Tooltips.apply(trafficRepeaterTabsCheckbox, Tooltips.html(
                "Historic traffic from Repeater tabs.",
                "This exports a one-time snapshot when Start is clicked.",
                "When Burp exposes readable tab headers, the snapshot also writes best-effort "
                        + "Repeater tab and group labels.",
                "For ongoing and future Repeater traffic, select Repeater."
        ));
        Tooltips.apply(trafficScannerCheckbox, Tooltips.html("All in-scope traffic sent from Scanner."));
        Tooltips.apply(trafficSequencerCheckbox, Tooltips.html("All in-scope traffic sent from Sequencer."));
        Tooltips.apply(exporterTraceCheckbox, Tooltips.html("Exporter trace-level log events."));
        Tooltips.apply(exporterDebugCheckbox, Tooltips.html("Exporter debug-level log events."));
        Tooltips.apply(exporterInfoCheckbox, Tooltips.html("Exporter info-level log events."));
        Tooltips.apply(exporterWarnCheckbox, Tooltips.html("Exporter warning log events."));
        Tooltips.apply(exporterErrorCheckbox, Tooltips.html("Exporter error log events."));
        Tooltips.apply(exporterStatsCheckbox, Tooltips.html(
                "Periodic exporter runtime stats snapshots.",
                "These documents include resource usage and exporter counters."
        ));
        Tooltips.apply(exporterStatsIntervalField, Tooltips.html(
                "Stats snapshot interval in seconds.",
                "Default: 30 seconds."
        ));
        Tooltips.apply(exporterConfigCheckbox, Tooltips.html(
                "Exporter config snapshots when Start completes.",
                "Includes the normalized source, scope, and destination selections."
        ));
        Tooltips.apply(indexNameBaseTemplateField, indexBaseNameTooltip());

        Tooltips.apply(allRadio, Tooltips.html("Export all observed."));
        Tooltips.apply(burpSuiteRadio, Tooltips.html("Export Burp Suite's project scope."));
        Tooltips.apply(customRadio, Tooltips.html("Export custom scope."));

        Tooltips.apply(fileSinkCheckbox, Tooltips.html("Enable file-based export."));
        Tooltips.apply(filePathField, Tooltips.htmlRaw(
                "Root directory for generated files. Examples:",
                "&nbsp;&nbsp;/path/to/directory",
                "&nbsp;&nbsp;c:\\path\\to\\directory"
        ));
        Tooltips.apply(fileJsonlCheckbox, Tooltips.html(
                "JSONL (JSON Lines): write one filtered JSON document per line.",
                "Each line is a standalone JSON object; there is no OpenSearch bulk action metadata.",
                "Best for local grep, line-by-line tooling, or simple downstream processing."
        ));
        Tooltips.apply(fileBulkNdjsonCheckbox, Tooltips.html(
                "NDJSON (Newline-Delimited JSON): write OpenSearch bulk-request lines.",
                "Each exported document is written as two lines: bulk action metadata, then the JSON document body.",
                "Best for later re-import with the OpenSearch {@code _bulk} API."
        ));
        Tooltips.apply(fileTotalCapCheckbox, Tooltips.html(
                "Stop all file export under the selected root when exporter-managed files reach the configured combined cap."
        ));
        Tooltips.apply(fileTotalCapField, Tooltips.html(
                "GiB cap across exporter-managed files in the selected root.",
                "OpenSearch export can continue after this cap is hit."
        ));
        Tooltips.apply(fileDiskUsagePercentCheckbox, Tooltips.html(
                "Optional advanced stop condition based on the destination volume's used percent."
        ));
        Tooltips.apply(fileDiskUsagePercentField, Tooltips.html(
                "Stop file export when the destination volume is at or above this used-percent threshold.",
                "This does not replace the built-in low-disk reserve."
        ));

        Tooltips.apply(databaseSinkCheckbox, Tooltips.html(
                "Enable export to one database destination.",
                "Choose one database below, or leave Database unchecked to export to Files only."));
        Tooltips.apply(openSearchSinkCheckbox, Tooltips.html("OpenSearch destination. Wired in this build."));
        Tooltips.apply(openSearchAmazonDestinationRadio, Tooltips.html(
                "Amazon OpenSearch destination.",
                "Connection testing captures AWS auth setup; export wiring is not implemented yet."));
        Tooltips.apply(elasticSearchDestinationRadio, Tooltips.html(
                "Elasticsearch destination.",
                "Connection testing and export are wired in this build."));
        Tooltips.apply(openSearchUrlField, Tooltips.htmlRaw("Base URL of the OpenSearch destination. Examples:",
                "&nbsp;&nbsp;https://opensearch.url:9200",
                "&nbsp;&nbsp;http://10.0.0.1:9200"));
        Tooltips.apply(openSearchAmazonUrlField, Tooltips.htmlRaw("Base URL of the Amazon OpenSearch destination. Examples:",
                "&nbsp;&nbsp;https://opensearch.url:9200",
                "&nbsp;&nbsp;http://10.0.0.1:9200"));
        Tooltips.apply(elasticSearchUrlField, Tooltips.htmlRaw("Base URL of the Elasticsearch destination. Examples:",
                "&nbsp;&nbsp;https://serverless-elasticsearch-project.es.us-east-1.aws.elastic.cloud:443",
                "&nbsp;&nbsp;https://00000000000000000000000000abc123.us-east4.gcp.elastic-cloud.com:443",
                "&nbsp;&nbsp;http://self-hosted-elasticsearch.url:9200"));
        Tooltips.apply(testConnectionButton, Tooltips.html(
                "Test connectivity and authentication against the selected database destination.",
                "Status output includes connection, authentication, trust, and reported version.",
                "Secrets are only stored within in-process memory."
        ));
    }

    /**
     * Runs a task on the EDT, executing immediately when already on the EDT.
     *
     * @param r task to run
     */
    private void runOnEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    private static String passwordText(JPasswordField field) {
        if (field == null || field.getPassword() == null) {
            return "";
        }
        return new String(field.getPassword());
    }

    private static String rootMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return (message == null || message.isBlank()) ? current.getClass().getSimpleName() : message;
    }

    private ConfigController controller() {
        if (controller == null) {
            controller = new ConfigController(this);
        }
        return controller;
    }

    /** Rebuild transient collaborators after deserialization. */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.controller = new ConfigController(this);
        ControlStatusBridge.register(this::onControlStatus);
    }

}
