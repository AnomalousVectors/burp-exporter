package ai.anomalousvectors.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.Paint;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.event.MouseEvent;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.awt.geom.Path2D;
import java.awt.geom.Rectangle2D;
import java.io.Serial;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.JToolTip;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnit;
import org.jfree.chart.axis.DateTickUnitType;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.NumberTickUnit;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.renderer.xy.XYSplineRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.chart.ui.RectangleInsets;
import org.jfree.chart.ui.VerticalAlignment;
import org.jfree.data.RangeType;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.ui.text.Tooltips;
import ai.anomalousvectors.tools.burp.utils.ExportAdmissionController;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.SystemMetrics;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.opensearch.BatchSizeController;
import ai.anomalousvectors.tools.burp.utils.opensearch.BulkRateLimitBackoff;
import ai.anomalousvectors.tools.burp.utils.opensearch.IndexingRetryCoordinator;

/**
 * Panel that displays live export charts and dashboard metrics.
 *
 * <p>Updates every few seconds via a Swing {@link Timer}. The panel shows rolling throughput
 * charts, per-index and per-source traffic tables, and a compact "Misc Stats" card with the
 * current export state. Sink-specific chart/table sections are shown only when that destination is
 * selected at runtime. Caller must construct on the EDT.</p>
 *
 * <p>The runtime-state listener is transient and final and is not rebuilt after deserialization.
 * A deserialized panel must not be attached to a display hierarchy; construct a new panel for
 * continued use.</p>
 */
public class StatsPanel extends JPanel {
    @Serial private static final long serialVersionUID = 1L;

    private static final String[] CHART_STYLE_NAMES = { "Simple", "Smooth", "Accessible" };

    /** Smooth style area-fill alpha (0–255); lower values reduce overlap saturation. */
    private static final int SMOOTH_FILL_TOP_ALPHA_DARK = 132;
    private static final int SMOOTH_FILL_TOP_ALPHA_LIGHT = 122;
    private static final int SMOOTH_FILL_BOTTOM_ALPHA_DARK = 40;
    private static final int SMOOTH_FILL_BOTTOM_ALPHA_LIGHT = 50;
    private static final int SMOOTH_LINE_ALPHA_DARK = 202;
    private static final int SMOOTH_LINE_ALPHA_LIGHT = 187;
    private static final int SMOOTH_LEGEND_BOTTOM_ALPHA_DARK = 62;
    private static final int SMOOTH_LEGEND_BOTTOM_ALPHA_LIGHT = 72;
    /**
     * Spline segments between samples for Smooth style (JFree default is 5). Higher precision
     * keeps Database/Files rate charts as fluid as the JVM heap chart; too low (5) reads as
     * faceted straight segments between 3 s samples.
     */
    private static final int SMOOTH_SPLINE_PRECISION = 12;
    /**
     * Headroom above sample max for Smooth style. Must cover {@link XYSplineRenderer} peak
     * overshoot on spiky docs/sec and KiB/sec series (heap levels overshoot less, but share this).
     */
    private static final double SPLINE_RANGE_HEADROOM_MULTIPLIER = 1.22;
    private static final double LINE_RANGE_HEADROOM_MULTIPLIER = 1.08;
    /** Range max is computed explicitly; do not add JFreeChart margin on top. */
    private static final double RANGE_AXIS_UPPER_MARGIN = 0.0;
    /** {@link ExportStats#getIndexKeys()} order: traffic is series 0, sitemap is series 3. */
    private static final int TRAFFIC_SERIES_STYLE_INDEX = 0;
    private static final int SITEMAP_SERIES_STYLE_INDEX = 3;
    /** Extra transparency for high-volume traffic/sitemap overlays (fills vs lines). */
    private static final double SMOOTH_TRAFFIC_SITEMAP_FILL_ALPHA_FACTOR = 0.56;
    private static final double SMOOTH_TRAFFIC_SITEMAP_LINE_ALPHA_FACTOR = 0.80;

    private static final int PANEL_BASE_WIDTH = 1200;
    private static final int PANEL_BASE_HEIGHT = 900;
    private static final int CONTENT_VERTICAL_PADDING = 56;
    private static final int REFRESH_INTERVAL_MS = 3000;
    /**
     * Skip factor applied to {@link #refreshVisibleStats} when no export is running. With the 3 s
     * base interval and factor 5, idle refreshes happen every 15 s instead of every 3 s. This
     * minimizes allocation and refresh churn while the visible panel is idle after Stop.
     */
    private static final int IDLE_REFRESH_SKIP_FACTOR = 5;
    /** Misc Stats groups toggled with the database destination section. */
    private static final List<String> MISC_DATABASE_SECTIONS = List.of(
            "Database Session", "Parameter Integrity", "Database Traffic",
            "Database Retry", "Database Capacity",
            "Database Run Peaks");
    /** Misc Stats group for live traffic spill (files and/or database traffic export). */
    private static final String MISC_TRAFFIC_SPILL_SECTION = "Traffic Spill";
    private static final long CHART_WINDOW_MAX_MS = 60L * 60L * 1000L;
    private static final int CHART_MAX_POINTS = (int) (CHART_WINDOW_MAX_MS / REFRESH_INTERVAL_MS) + 5;
    private static final int CHART_PANEL_HEIGHT = 360;
    /**
     * Vertical pixels reserved for the standalone memory time-series chart that lives at the
     * bottom of the chart stack. Sized roughly the same as the per-sink Docs/sec or KiB/sec
     * panes so the three chart rows render at a consistent visual rhythm.
     */
    private static final int MEMORY_CHART_PANEL_HEIGHT = CHART_PANEL_HEIGHT / 2;
    /**
     * Visual indent applied to traffic-source sub-rows nested under the {@code Traffic} index
     * row in the merged sink-counts tables. The leading whitespace is the entire mechanism that
     * marks a row as a sub-row, so {@link CardCopySupport#tableToTsv} preserves the indent in
     * clipboard output as well.
     */
    private static final String SUBROW_INDENT = "    ";
    private static final double DEFAULT_RATE_RANGE_MAX = 10.0;
    private static final String DOMAIN_TIME_PATTERN = "HH:mm:ss";
    private static final int DOMAIN_TARGET_LABELS = 14;
    private static final int[] DOMAIN_CANDIDATE_SECONDS = new int[] { 1, 2, 3, 5, 6, 10, 12, 15, 20, 30, 60, 120, 300 };
    private static final Font CARD_KEY_FONT = cardFont();
    private static final Font CARD_VALUE_FONT = cardFont();
    private static final float CHART_LINE_STROKE_WIDTH = 1.5f;
    private static final Color TEXT_FG = uiColor("Label.foreground", new Color(235, 235, 235));
    private static final int LEGEND_ICON_WIDTH = 28;
    private static final int LEGEND_ICON_HEIGHT = 14;
    private static final DecimalFormat DECIMAL_ONE =
            new DecimalFormat("0.0", DecimalFormatSymbols.getInstance(Locale.ROOT));
    /**
     * Maps memory-chart series indexes (0 = Heap Used, 1 = Heap Committed) to the throughput
     * chart's {@link #SERIES_STYLES} slots, so the memory chart picks up the same theme-aware
     * green and yellow that the per-sink charts use for their {@code Traffic} and
     * {@code Sitemap} series respectively.
     */
    private static final int[] MEMORY_SERIES_TO_STYLE = { 0, 3 };

    private static final SeriesStyle[] SERIES_STYLES = new SeriesStyle[] {
            new SeriesStyle(
                    "Traffic",
                    new Color(57, 255, 20),
                    new Color(46, 140, 54),
                    new float[] { 8f, 5f },
                    squareMarker(6f),
                    true),
            new SeriesStyle(
                    "Exporter",
                    new Color(174, 126, 255),
                    new Color(112, 74, 176),
                    new float[] { 8f, 4f, 1.5f, 4f },
                    diamondMarker(7f),
                    true),
            new SeriesStyle(
                    "Settings",
                    new Color(86, 156, 214),
                    new Color(41, 98, 179),
                    null,
                    circleMarker(6f),
                    true),
            new SeriesStyle(
                    "Sitemap",
                    new Color(255, 210, 92),
                    new Color(196, 138, 0),
                    new float[] { 1.5f, 4f },
                    triangleMarker(7f),
                    true),
            new SeriesStyle(
                    "Findings",
                    new Color(244, 71, 71),
                    new Color(191, 52, 52),
                    new float[] { 12f, 6f },
                    crossMarker(7f),
                    false)
    };

    private record SeriesStyle(
            String label,
            Color darkColor,
            Color lightColor,
            float[] dashPattern,
            Shape markerShape,
            boolean markerFilled) {

        private Color paint() {
            return isDarkTheme() ? darkColor : lightColor;
        }

        private BasicStroke stroke(float width) {
            if (dashPattern == null || dashPattern.length == 0) {
                return new BasicStroke(width, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
            }
            return new BasicStroke(
                    width,
                    BasicStroke.CAP_ROUND,
                    BasicStroke.JOIN_ROUND,
                    1f,
                    dashPattern,
                    0f);
        }
    }

    private final class LegendSampleIcon implements Icon {

        private final int seriesIndex;

        private LegendSampleIcon(int seriesIndex) {
            this.seriesIndex = seriesIndex;
        }

        @Override
        public void paintIcon(java.awt.Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int centerY = y + (LEGEND_ICON_HEIGHT / 2);
                int startX = x + 1;
                int endX = x + LEGEND_ICON_WIDTH - 2;
                g2.setPaint(legendPaint(seriesIndex, y, y + LEGEND_ICON_HEIGHT));
                g2.setStroke(seriesStroke(seriesIndex));
                g2.draw(new Line2D.Float(startX, centerY, endX, centerY));

                g2.translate(x + (LEGEND_ICON_WIDTH / 2.0), centerY);
                g2.setStroke(new BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                Shape marker = seriesMarkerShape(seriesIndex);
                if (seriesShapesVisible(seriesIndex) && marker != null) {
                    g2.setPaint(seriesSolidColor(seriesIndex));
                    if (seriesShapesFilled(seriesIndex)) {
                        g2.fill(marker);
                    }
                    g2.draw(marker);
                }
            } finally {
                g2.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return LEGEND_ICON_WIDTH;
        }

        @Override
        public int getIconHeight() {
            return LEGEND_ICON_HEIGHT;
        }
    }

    /**
     * Legend icon for the memory chart. Mirrors {@link LegendSampleIcon}'s styling rhythm
     * (theme-aware paint, chart-style-aware stroke and marker) but reads its style from the
     * throughput-chart slot that {@link #MEMORY_SERIES_TO_STYLE} points the memory series at.
     * Picking up the same dash pattern and shape marker as the chart in Accessible style
     * keeps the legend in lock-step with the rendered series, so heap-used and heap-committed
     * remain distinguishable for color-blind users without relying on color alone.
     */
    private final class MemoryLegendIcon implements Icon {

        private final int memorySeriesIndex;

        private MemoryLegendIcon(int memorySeriesIndex) {
            this.memorySeriesIndex = memorySeriesIndex;
        }

        @Override
        public void paintIcon(java.awt.Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int centerY = y + (LEGEND_ICON_HEIGHT / 2);
                int startX = x + 1;
                int endX = x + LEGEND_ICON_WIDTH - 2;
                int seriesStyleIndex = MEMORY_SERIES_TO_STYLE[memorySeriesIndex];
                g2.setPaint(legendPaint(seriesStyleIndex, y, y + LEGEND_ICON_HEIGHT));
                g2.setStroke(seriesStroke(seriesStyleIndex));
                g2.draw(new Line2D.Float(startX, centerY, endX, centerY));

                g2.translate(x + (LEGEND_ICON_WIDTH / 2.0), centerY);
                g2.setStroke(new BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                Shape marker = seriesMarkerShape(seriesStyleIndex);
                if (seriesShapesVisible(seriesStyleIndex) && marker != null) {
                    g2.setPaint(seriesSolidColor(seriesStyleIndex));
                    if (seriesShapesFilled(seriesStyleIndex)) {
                        g2.fill(marker);
                    }
                    g2.draw(marker);
                }
            } finally {
                g2.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return LEGEND_ICON_WIDTH;
        }

        @Override
        public int getIconHeight() {
            return LEGEND_ICON_HEIGHT;
        }
    }

    private final Timer refreshTimer;
    /** Idle-cadence tick counter for {@link #refreshVisibleStats}; reset whenever export runs. */
    private long idleRefreshSkipCounter;
    private final TimeSeriesCollection docsPerSecondDataset;
    private final TimeSeriesCollection kibPerSecondDataset;
    private final TimeSeriesCollection fileDocsPerSecondDataset;
    private final TimeSeriesCollection fileKibPerSecondDataset;
    private final TimeSeriesCollection memoryDataset;
    private final TimeSeries heapUsedSeries;
    private final TimeSeries heapCommittedSeries;
    private final JFreeChart docsChart;
    private final JFreeChart kibChart;
    private final JFreeChart fileDocsChart;
    private final JFreeChart fileKibChart;
    private final JFreeChart memoryChart;
    private final JPanel chartsPanel;
    private final JPanel chartSectionsPanel;
    private final JPanel fileChartsSectionPanel;
    private final JPanel openSearchChartsSectionPanel;
    private final JLabel fileChartsSectionHeaderLabel;
    private final JLabel openSearchChartsSectionHeaderLabel;
    private final JPanel fileChartsSectionHeader;
    private final JPanel openSearchChartsSectionHeader;
    private final JPanel memoryChartSectionPanel;
    private final JPanel openSearchDocsChartPanel;
    private final JPanel openSearchKibChartPanel;
    private final JPanel fileDocsChartPanel;
    private final JPanel fileKibChartPanel;
    private final JPanel memoryChartPanel;
    private final JPanel sharedLegendPanel;
    private final JPanel memoryLegendPanel;
    private final JButton chartStyleButton;
    private final JLabel exportRunningValue;
    private final JLabel sharedBatchSizeValue;
    private final JLabel proxyHistoryChunkTargetValue;
    private final JLabel trafficQueueValue;
    private final JLabel queueDropsValue;
    private final JLabel repeaterMetadataSourcesValue;
    private final JLabel spillQueueValue;
    private final JLabel spillOldestAgeValue;
    private final JLabel spillFlowValue;
    private final JLabel dropReasonValue;
    private final JLabel throughputValue;
    private final JLabel exportedDocsValue;
    private final JLabel exportedSizeValue;
    private final JLabel exportedFailuresValue;
    private final JLabel fileTotalExportedValue;
    private final JLabel fileTotalDocsPushedValue;
    private final JLabel fileTotalFailuresValue;
    private final JLabel heapUsedMaxValue;
    private final JLabel heapCommittedValue;
    private final JLabel nonHeapUsedValue;
    private final JLabel directBufferUsedValue;
    private final JLabel mappedBufferUsedValue;
    private final JLabel threadsLivePeakValue;
    private final JLabel gcCountTimeValue;
    private final JLabel processCpuLoadValue;
    private final JLabel permanentDropsTotalValue;
    private final JLabel permanentDropReasonsValue;
    private final JLabel countBasisValue;
    private final JLabel bodyTruncationsTotalValue;
    private final JLabel bodyTruncationsByIndexValue;
    private final JLabel recoveredFailuresTotalValue;
    private final JLabel retryAttemptsTotalValue;
    private final JLabel openSearchLastSuccessValue;
    private final JLabel openSearchConsecutiveFailuresValue;
    private final JLabel oldestQueuedAgeValue;
    private final JLabel trafficQueueBytesValue;
    private final JLabel retryQueueDepthValue;
    private final JLabel peakTrafficQueueValue;
    private final JLabel peakSpillQueueValue;
    private final JLabel peakRetryQueueValue;
    private final JLabel peakSnapshotChunkTargetValue;
    private final JLabel peakSnapshotFlushMsValue;
    private final JLabel peakSnapshotBuildAheadValue;
    private final JLabel peakCooldownWaitMsValue;
    private final JLabel peakFlushSlotWaitMsValue;
    private final JLabel pendingOrphansValue;
    private final JLabel bulkInFlightValue;
    private final JLabel softOutageValue;
    private final JLabel authorizationRecoveryValue;
    private final JLabel trafficSpillStatusValue;
    private final JLabel bulkByteBudgetValue;
    private final JLabel snapshotFlushCapValue;
    private final JLabel snapshotBuildAheadValue;
    private final JLabel cooldownRemainingValue;
    private final JLabel pressureStreakValue;
    private final JLabel softOutageEntriesValue;
    private final JLabel capacityEventsValue;
    private final JLabel misgateSuspectsValue;
    private final JLabel skippedBodyEnumerationValue;
    private final JLabel wireBodyReplacedValue;
    private final JLabel skipPathRescuedValue;
    private final JLabel supplementalBodyUsedValue;
    private final JLabel supplementalRejectedValue;
    private final JLabel wireBodyDroppedEntriesValue;
    private final DefaultTableModel byIndexModel;
    private final DefaultTableModel fileByIndexModel;
    private final JTable byIndexTable;
    private final JTable fileByIndexTable;
    private final JPanel openSearchSinkCard;
    private final JPanel fileSinkCard;
    private final JPanel openSearchSinkRow;
    private final JPanel fileSinkRow;
    private final JPanel cardsRow;
    private final JPanel lowerPanel;
    private final JPanel miscStatsCard;
    private final Map<String, List<Component>> miscSectionComponents;
    private final Map<String, TimeSeries> docsSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> kibSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> fileDocsSeriesByIndex = new HashMap<>();
    private final Map<String, TimeSeries> fileKibSeriesByIndex = new HashMap<>();
    private final Map<String, Long> previousSuccessByIndex = new HashMap<>();
    private final Map<String, Long> previousBytesByIndex = new HashMap<>();
    private final Map<String, Long> previousFileSuccessByIndex = new HashMap<>();
    private final Map<String, Long> previousFileBytesByIndex = new HashMap<>();
    private long lastLoggedToolSourceFallbacks = -1;
    private long firstSampleAtMs = -1;
    private long previousSampleAtMs = -1;
    private int chartStyleIndex = 0;
    private final transient RuntimeConfig.StateListener runtimeStateListener;

    /**
     * Creates the Stats panel and starts the refresh timer.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    public StatsPanel() {
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(PANEL_BASE_WIDTH, PANEL_BASE_HEIGHT));

        docsPerSecondDataset = new TimeSeriesCollection();
        kibPerSecondDataset = new TimeSeriesCollection();
        fileDocsPerSecondDataset = new TimeSeriesCollection();
        fileKibPerSecondDataset = new TimeSeriesCollection();
        memoryDataset = new TimeSeriesCollection();
        heapUsedSeries = new TimeSeries("Heap Used");
        heapUsedSeries.setMaximumItemCount(CHART_MAX_POINTS);
        heapCommittedSeries = new TimeSeries("Heap Committed");
        heapCommittedSeries.setMaximumItemCount(CHART_MAX_POINTS);
        memoryDataset.addSeries(heapUsedSeries);
        memoryDataset.addSeries(heapCommittedSeries);
        docsChart = createRateChart("Docs per second", docsPerSecondDataset, false);
        kibChart = createRateChart("KiB per second", kibPerSecondDataset, false);
        fileDocsChart = createRateChart("Docs per second", fileDocsPerSecondDataset, false);
        fileKibChart = createRateChart("KiB per second", fileKibPerSecondDataset, false);
        memoryChart = createMemoryChart(memoryDataset);

        chartsPanel = new JPanel(new BorderLayout(0, 4));
        chartSectionsPanel = new JPanel();
        chartSectionsPanel.setLayout(new javax.swing.BoxLayout(chartSectionsPanel, javax.swing.BoxLayout.Y_AXIS));
        chartSectionsPanel.setOpaque(false);
        fileDocsChartPanel = createRateChartPanel(fileDocsChart);
        fileKibChartPanel = createRateChartPanel(fileKibChart);
        openSearchDocsChartPanel = createRateChartPanel(docsChart);
        openSearchKibChartPanel = createRateChartPanel(kibChart);
        memoryChartPanel = createRateChartPanel(memoryChart);
        memoryLegendPanel = createMemoryLegendPanel();
        String memoryChartTooltip = memoryChartTooltip();
        Tooltips.apply(memoryLegendPanel, memoryChartTooltip);
        fileChartsSectionHeaderLabel = createChartSectionHeaderLabel("File Export", false);
        openSearchChartsSectionHeaderLabel = createChartSectionHeaderLabel("Database Export", false);
        fileChartsSectionHeader = wrapChartSectionHeader(fileChartsSectionHeaderLabel);
        openSearchChartsSectionHeader = wrapChartSectionHeader(openSearchChartsSectionHeaderLabel);
        fileChartsSectionPanel = buildChartSection(
                fileChartsSectionHeader, fileDocsChartPanel, fileKibChartPanel, 12);
        openSearchChartsSectionPanel = buildChartSection(
                openSearchChartsSectionHeader, openSearchDocsChartPanel, openSearchKibChartPanel, 12);
        memoryChartSectionPanel = buildMemoryChartSection(memoryLegendPanel, memoryChartPanel);
        Tooltips.apply(memoryChartSectionPanel, memoryChartTooltip);
        chartSectionsPanel.add(fileChartsSectionPanel);
        chartSectionsPanel.add(openSearchChartsSectionPanel);
        chartSectionsPanel.add(memoryChartSectionPanel);
        chartsPanel.add(chartSectionsPanel, BorderLayout.CENTER);
        sharedLegendPanel = createSharedLegendPanel();
        chartStyleButton = createChartStyleButton();
        fileChartsSectionPanel.add(sharedLegendPanel, 0);
        runtimeStateListener = this::onRuntimeStateChanged;
        chartStyleIndex = Math.clamp(RuntimeConfig.statsChartStyle(), 1, CHART_STYLE_NAMES.length) - 1;
        applyChartStyles();
        refreshSharedLegendPanel();
        JPanel contentPanel = new JPanel(new BorderLayout(0, 10));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));
        contentPanel.setBackground(UIManager.getColor("Panel.background"));
        contentPanel.add(chartsPanel, BorderLayout.NORTH);

        cardsRow = new JPanel(new GridLayout(1, 1, 10, 0));
        cardsRow.setOpaque(false);

        MetricCardState miscState = addGroupedMetricCard(cardsRow, "Misc Stats", List.of(
                new MetricSection("Overview", new String[] {
                        "Export Running",
                        "Soft Outage",
                        "Database Exported Size",
                        "Files Exported Size",
                        "Traffic Spill Status"
                }),
                new MetricSection("Process", new String[] {
                        "Heap Used / Max", "Heap Committed",
                        "Non-Heap Used", "Direct Buffer Used", "Mapped Buffer Used",
                        "Threads (Live / Peak)",
                        "GC (Count / Time)", "Process CPU Load"
                }),
                new MetricSection("Database Session", new String[] {
                        "Throughput (10s)", "Exported Docs", "Exported Failures",
                        "Count Basis", "Authorization Recovery",
                        "Last Success", "Consecutive Failures", "Permanent Drops", "Permanent Drop Reasons",
                        "Body Truncations", "Body Truncations by Index",
                        "Recovered Failures", "Retry Drain Pushes"
                }),
                new MetricSection("Parameter Integrity", new String[] {
                        "Mis-gate Suspects",
                        "Skipped BODY Enumeration",
                        "Wire BODY Replaced",
                        "Skip-path Rescued",
                        "Supplemental BODY Used",
                        "Supplemental Rejected (non-form)",
                        "Wire BODY Dropped (entries)"
                }),
                new MetricSection("Database Traffic", new String[] {
                        "Bulk In-Flight",
                        "Shared Batch Size", "Proxy History Chunk Target",
                        "Traffic Queue Size", "Traffic Queue Bytes (est.)",
                        "Queue Drops", "Pending Orphans", "Repeater Metadata Sources"
                }),
                new MetricSection(MISC_TRAFFIC_SPILL_SECTION, new String[] {
                        "Queue", "Oldest Age (s)", "Enqueued / Dequeued / Dropped", "Drop Reasons"
                }),
                new MetricSection("Database Retry", new String[] {
                        "Queue Depth", "Oldest Queued Age"
                }),
                new MetricSection("Database Capacity", new String[] {
                        "Bulk Byte Budget", "Snapshot Flush Cap", "Snapshot Build-Ahead",
                        "Cooldown Remaining", "Pressure Streak",
                        "Soft Outage Entries", "Capacity Events"
                }),
                new MetricSection("Database Run Peaks", new String[] {
                        "Peak Traffic Queue", "Peak Traffic Spill", "Peak Retry Queue",
                        "Peak Snapshot Chunk Target", "Peak Snapshot Flush (ms)", "Peak Snapshot Build-Ahead",
                        "Peak Cooldown Wait (ms)", "Peak Flush Slot Wait (ms)"
                }),
                new MetricSection("Files", new String[] {
                        "File Total Docs Exported", "File Total Failures"
                })
        ));
        miscStatsCard = miscState.card();
        miscStatsCard.setName("miscStatsCard");
        miscSectionComponents = miscState.sections();
        final Map<String, JLabel> miscValues = miscState.values();
        exportRunningValue = miscValues.get("Export Running");
        softOutageValue = miscValues.get("Soft Outage");
        authorizationRecoveryValue = miscValues.get("Authorization Recovery");
        trafficSpillStatusValue = miscValues.get("Traffic Spill Status");
        sharedBatchSizeValue = miscValues.get("Shared Batch Size");
        proxyHistoryChunkTargetValue = miscValues.get("Proxy History Chunk Target");
        applyMiscStatTooltips(miscSectionComponents);
        trafficQueueValue = miscValues.get("Traffic Queue Size");
        queueDropsValue = miscValues.get("Queue Drops");
        repeaterMetadataSourcesValue = miscValues.get("Repeater Metadata Sources");
        spillQueueValue = miscValues.get("Queue");
        spillOldestAgeValue = miscValues.get("Oldest Age (s)");
        spillFlowValue = miscValues.get("Enqueued / Dequeued / Dropped");
        dropReasonValue = miscValues.get("Drop Reasons");
        throughputValue = miscValues.get("Throughput (10s)");
        exportedDocsValue = miscValues.get("Exported Docs");
        exportedSizeValue = miscValues.get("Database Exported Size");
        exportedFailuresValue = miscValues.get("Exported Failures");
        fileTotalExportedValue = miscValues.get("Files Exported Size");
        fileTotalDocsPushedValue = miscValues.get("File Total Docs Exported");
        fileTotalFailuresValue = miscValues.get("File Total Failures");
        heapUsedMaxValue = miscValues.get("Heap Used / Max");
        heapCommittedValue = miscValues.get("Heap Committed");
        nonHeapUsedValue = miscValues.get("Non-Heap Used");
        directBufferUsedValue = miscValues.get("Direct Buffer Used");
        mappedBufferUsedValue = miscValues.get("Mapped Buffer Used");
        threadsLivePeakValue = miscValues.get("Threads (Live / Peak)");
        gcCountTimeValue = miscValues.get("GC (Count / Time)");
        processCpuLoadValue = miscValues.get("Process CPU Load");
        permanentDropsTotalValue = miscValues.get("Permanent Drops");
        permanentDropReasonsValue = miscValues.get("Permanent Drop Reasons");
        countBasisValue = miscValues.get("Count Basis");
        bodyTruncationsTotalValue = miscValues.get("Body Truncations");
        bodyTruncationsByIndexValue = miscValues.get("Body Truncations by Index");
        recoveredFailuresTotalValue = miscValues.get("Recovered Failures");
        retryAttemptsTotalValue = miscValues.get("Retry Drain Pushes");
        openSearchLastSuccessValue = miscValues.get("Last Success");
        openSearchConsecutiveFailuresValue = miscValues.get("Consecutive Failures");
        oldestQueuedAgeValue = miscValues.get("Oldest Queued Age");
        trafficQueueBytesValue = miscValues.get("Traffic Queue Bytes (est.)");
        retryQueueDepthValue = miscValues.get("Queue Depth");
        peakTrafficQueueValue = miscValues.get("Peak Traffic Queue");
        peakSpillQueueValue = miscValues.get("Peak Traffic Spill");
        peakRetryQueueValue = miscValues.get("Peak Retry Queue");
        peakSnapshotChunkTargetValue = miscValues.get("Peak Snapshot Chunk Target");
        peakSnapshotFlushMsValue = miscValues.get("Peak Snapshot Flush (ms)");
        peakSnapshotBuildAheadValue = miscValues.get("Peak Snapshot Build-Ahead");
        peakCooldownWaitMsValue = miscValues.get("Peak Cooldown Wait (ms)");
        peakFlushSlotWaitMsValue = miscValues.get("Peak Flush Slot Wait (ms)");
        pendingOrphansValue = miscValues.get("Pending Orphans");
        bulkInFlightValue = miscValues.get("Bulk In-Flight");
        bulkByteBudgetValue = miscValues.get("Bulk Byte Budget");
        snapshotFlushCapValue = miscValues.get("Snapshot Flush Cap");
        snapshotBuildAheadValue = miscValues.get("Snapshot Build-Ahead");
        cooldownRemainingValue = miscValues.get("Cooldown Remaining");
        pressureStreakValue = miscValues.get("Pressure Streak");
        softOutageEntriesValue = miscValues.get("Soft Outage Entries");
        capacityEventsValue = miscValues.get("Capacity Events");
        misgateSuspectsValue = miscValues.get("Mis-gate Suspects");
        skippedBodyEnumerationValue = miscValues.get("Skipped BODY Enumeration");
        wireBodyReplacedValue = miscValues.get("Wire BODY Replaced");
        skipPathRescuedValue = miscValues.get("Skip-path Rescued");
        supplementalBodyUsedValue = miscValues.get("Supplemental BODY Used");
        supplementalRejectedValue = miscValues.get("Supplemental Rejected (non-form)");
        wireBodyDroppedEntriesValue = miscValues.get("Wire BODY Dropped (entries)");

        // Merged sink-counts model: index rows on top, traffic-source sub-rows nested directly
        // under the Traffic index row (visually distinguished by SUBROW_INDENT on column 0),
        // followed by a trailing Total row that aggregates only the index rows. The OpenSearch
        // table carries Failures / Queued / Recovered Failures / terminal drops because the sink genuinely
        // queues, retries, permanently drops, and recovers via the retry drain; traffic source sub-rows
        // attribute those counters by route. File writes are synchronous and have bounded immediate
        // retries, but no queue, retry-drain recovery, or terminal-drop concepts.
        byIndexModel = new DefaultTableModel(
                new String[] { "Index", "Exported", "Failures", "Queued",
                        "Recovered Failures", "Retry Drops", "Permanent Drops", "Last Bulk (ms)", "Last Error" }, 0);
        byIndexTable = createStatsTable(byIndexModel);
        fileByIndexModel = new DefaultTableModel(
                new String[] { "Index", "Written", "Failures", "Retry Attempts",
                        "Baseline", "Appended", "Final Size", "Integrity",
                        "Last Append (ms)", "Last Error" }, 0);
        fileByIndexTable = createStatsTable(fileByIndexModel);
        applyColumnHeaderTooltips(byIndexTable, databaseCountsHeaderTooltips());
        applyColumnHeaderTooltips(fileByIndexTable, fileCountsHeaderTooltips());

        // One titled card per sink wrapped in a 1x1 GridLayout row so the card always fills the
        // panel width (matches the cardsRow / Misc Stats pattern). The card's body is a single
        // table because traffic-source rows are now nested directly under the Traffic index row,
        // freeing horizontal room for long Last-Error strings.
        fileSinkCard = createSinkCard("File Counts", "fileSinkCard", fileByIndexTable);
        openSearchSinkCard = createSinkCard("Database Counts", "openSearchSinkCard", byIndexTable);
        fileSinkRow = wrapSinkCardInFullWidthRow(fileSinkCard, "fileSinkRow");
        openSearchSinkRow = wrapSinkCardInFullWidthRow(openSearchSinkCard, "openSearchSinkRow");

        lowerPanel = new JPanel();
        lowerPanel.setName("lowerPanel");
        lowerPanel.setLayout(new javax.swing.BoxLayout(lowerPanel, javax.swing.BoxLayout.Y_AXIS));
        lowerPanel.setOpaque(false);
        JPanel statsCopyToolbar = CardCopySupport.buildCopyOnlyToolbar(
                "Copy File Counts, Database Counts, and Misc Stats to the clipboard",
                this::renderAllStatsForClipboard);
        lowerPanel.add(statsCopyToolbar);
        lowerPanel.add(javax.swing.Box.createVerticalStrut(4));
        lowerPanel.add(fileSinkRow);
        lowerPanel.add(javax.swing.Box.createVerticalStrut(10));
        lowerPanel.add(openSearchSinkRow);
        lowerPanel.add(javax.swing.Box.createVerticalStrut(10));
        lowerPanel.add(cardsRow);
        contentPanel.add(lowerPanel, BorderLayout.CENTER);
        add(contentPanel, BorderLayout.CENTER);

        refreshTimer = new Timer(REFRESH_INTERVAL_MS, e -> timerTick());
        refreshTimer.setRepeats(true);

        refreshVisibleStats();
        updateDashboardSectionSizing();
    }

    private void refreshVisibleStats() {
        sampleRateSeries();
        refreshDashboard();
    }

    /**
     * Timer-tick wrapper around {@link #refreshVisibleStats} that applies the idle-cadence gate.
     *
     * <p>While {@link RuntimeConfig#isExportRunning()} is {@code true} every tick refreshes the
     * dashboard. While idle, only one in {@link #IDLE_REFRESH_SKIP_FACTOR} ticks runs, so the
     * table-model rebuilds, formatters, and chart sampling that dominate the per-tick allocation
     * cost stop running on the 3 s base cadence and effectively drop to one per 15 s. The
     * counter resets to zero whenever a run resumes, so the next idle period starts with a fresh
     * "emit-the-first-tick" sample.</p>
     *
     * <p>Constructor and direct callers (including tests) bypass this gate and always do a full
     * refresh, so unit-test paths that call {@code refreshVisibleStats} reflectively are not
     * affected by the idle counter.</p>
     */
    private void timerTick() {
        if (!RuntimeConfig.isExportRunning()) {
            long tick = idleRefreshSkipCounter++;
            if (tick % IDLE_REFRESH_SKIP_FACTOR != 0) {
                return;
            }
        } else {
            idleRefreshSkipCounter = 0L;
        }
        refreshVisibleStats();
    }

    private void refreshDashboard() {
        boolean exportRunning = RuntimeConfig.isExportRunning();
        long totalSuccess = ExportStats.getTotalSuccessCount();
        long totalFailure = ExportStats.getTotalFailureCount();
        int trafficQueueDocs = ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentSize();
        long trafficQueueBytes = ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentBytesEstimate();
        int spillDocs = ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentSpillSize();
        long spillBytes = ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentSpillBytes();
        int retryDocs = StatsPanelFormatters.totalRetryQueueDocs();
        long retryBytes = StatsPanelFormatters.totalRetryQueueBytes();
        ExportStats.observeExportPressureSamples(
                trafficQueueDocs, trafficQueueBytes, spillDocs, spillBytes, retryDocs, retryBytes);

        exportRunningValue.setText(exportRunning ? "Yes" : "No");
        exportRunningValue.setForeground(exportRunning ? SERIES_STYLES[0].paint() : SERIES_STYLES[4].paint());
        exportRunningValue.setFont(CARD_VALUE_FONT.deriveFont(Font.BOLD));
        long dbExportedBytes = ExportStats.getTotalExportedBytes();
        long fileExportedBytes = FileExportStats.getTotalExportedBytes();
        exportedSizeValue.setForeground(TEXT_FG);
        fileTotalExportedValue.setForeground(TEXT_FG);
        sharedBatchSizeValue.setText(formatWhole(BatchSizeController.getInstance().getCurrentBatchSize()));
        int proxyChunkTarget = ExportStats.getCurrentProxyHistoryChunkTarget();
        if (proxyChunkTarget >= 0) {
            proxyHistoryChunkTargetValue.setText(formatWhole(proxyChunkTarget));
        } else {
            ExportStats.SnapshotLastRunStats proxySnapshot = ExportStats.getLastProxyHistorySnapshot();
            if (proxySnapshot != null) {
                proxyHistoryChunkTargetValue.setText(formatWhole(proxySnapshot.finalChunkTarget()));
            } else {
                proxyHistoryChunkTargetValue.setText("-");
            }
        }
        trafficQueueValue.setText(formatWhole(trafficQueueDocs));
        queueDropsValue.setText(formatWhole(ExportStats.getTrafficQueueDrops()));
        repeaterMetadataSourcesValue.setText(ExportStats.describeRepeaterMetadataSourceCounts());
        spillQueueValue.setText(StatsPanelFormatters.formatSpillQueue(spillDocs, spillBytes));
        spillOldestAgeValue.setText(
                DECIMAL_ONE.format(ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.getCurrentSpillOldestAgeMs() / 1000.0));
        spillFlowValue.setText(
                formatWhole(ExportStats.getTrafficSpillEnqueued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDequeued()) + " / "
                        + formatWhole(ExportStats.getTrafficSpillDrops()));
        long spillRejectNew = ExportStats.getTrafficDropReasonCount("spill_full_reject_new")
                + ExportStats.getTrafficDropReasonCount("spill_low_disk_reject_new")
                + ExportStats.getTrafficDropReasonCount("spill_rejected_drop_oldest")
                + ExportStats.getTrafficDropReasonCount("spill_low_disk_drop_oldest");
        dropReasonValue.setText(
                formatWhole(spillRejectNew) + " / "
                        + formatWhole(ExportStats.getTrafficDropReasonCount("spill_requeue_failed_drop")
                                + ExportStats.getTrafficDropReasonCount("spill_requeue_low_disk_drop")) + " / "
                        + formatWhole(ExportStats.getTrafficSpillExpiredPruned()));
        throughputValue.setText(DECIMAL_ONE.format(ExportStats.getThroughputDocsPerSecLast10s()) + " docs/s");
        exportedDocsValue.setText(formatWhole(totalSuccess) + " docs");
        exportedSizeValue.setText(formatHumanReadableBytes(dbExportedBytes));
        exportedFailuresValue.setText(formatWhole(totalFailure));
        fileTotalExportedValue.setText(formatHumanReadableBytes(fileExportedBytes));
        long fallbackHits = ExportStats.getTrafficToolSourceFallbacks();
        if (RuntimeConfig.isExportRunning()
                && fallbackHits > 0
                && fallbackHits != lastLoggedToolSourceFallbacks) {
            Logger.logError("[StatsPanel] Traffic tool/source fallback hits observed: " + fallbackHits);
            lastLoggedToolSourceFallbacks = fallbackHits;
        }

        fileTotalDocsPushedValue.setText(formatWhole(FileExportStats.getTotalSuccessCount()));
        fileTotalFailuresValue.setText(formatWhole(FileExportStats.getTotalFailureCount()));
        permanentDropsTotalValue.setText(formatWhole(ExportStats.getTotalPermanentDrops()));
        permanentDropReasonsValue.setText(StatsPanelFormatters.formatPermanentDropReasons());
        countBasisValue.setText("Session counters; no Stop readback");
        bodyTruncationsTotalValue.setText(formatWhole(ExportStats.getSearchBodyPrefixTruncations()));
        bodyTruncationsByIndexValue.setText(StatsPanelFormatters.formatBodyTruncationsByIndex());
        recoveredFailuresTotalValue.setText(formatWhole(ExportStats.getTotalRecoveredFailureCount()));
        retryAttemptsTotalValue.setText(formatWhole(ExportStats.getTotalRetryAttempts()));
        openSearchLastSuccessValue.setText(StatsPanelFormatters.formatRelativeTime(ExportStats.getOpenSearchLastSuccessAtMs()));
        openSearchConsecutiveFailuresValue.setText(formatWhole(ExportStats.getOpenSearchConsecutiveFailures()));
        oldestQueuedAgeValue.setText(StatsPanelFormatters.formatOldestQueuedAgeSummary());
        trafficQueueBytesValue.setText(StatsPanelFormatters.formatBytesHuman(trafficQueueBytes));
        retryQueueDepthValue.setText(StatsPanelFormatters.formatRetryQueueDepthSummary());
        peakTrafficQueueValue.setText(StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakTrafficQueueDocs(), ExportStats.getPeakTrafficQueueBytes()));
        peakSpillQueueValue.setText(StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakSpillDocs(), ExportStats.getPeakSpillBytes()));
        peakRetryQueueValue.setText(StatsPanelFormatters.formatPeakQueueDepth(
                ExportStats.getPeakRetryQueueDocs(), ExportStats.getPeakRetryQueueBytes()));
        int peakChunkTarget = ExportStats.getPeakSnapshotChunkTarget();
        peakSnapshotChunkTargetValue.setText(peakChunkTarget > 0 ? formatWhole(peakChunkTarget) : "—");
        long peakFlushMs = ExportStats.getPeakSnapshotFlushMs();
        peakSnapshotFlushMsValue.setText(peakFlushMs > 0 ? formatWhole(peakFlushMs) : "—");
        peakSnapshotBuildAheadValue.setText(StatsPanelFormatters.formatPeakSnapshotBuildAhead());
        long peakCooldownWaitMs = ExportStats.getPeakCooldownWaitMs();
        peakCooldownWaitMsValue.setText(peakCooldownWaitMs > 0 ? formatWhole(peakCooldownWaitMs) : "—");
        long peakFlushSlotWaitMs = ExportStats.getPeakFlushSlotWaitMs();
        peakFlushSlotWaitMsValue.setText(peakFlushSlotWaitMs > 0 ? formatWhole(peakFlushSlotWaitMs) : "—");
        snapshotBuildAheadValue.setText(StatsPanelFormatters.formatSnapshotBuildAhead());
        pendingOrphansValue.setText(formatWhole(
                ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler.pendingOrphansSize()));
        bulkInFlightValue.setText(formatWhole(ExportStats.getBulkInFlight()));
        boolean softOutage = IndexingRetryCoordinator.getInstance().isSoftCapacityOutage();
        softOutageValue.setText(StatsPanelFormatters.formatSoftOutage(softOutage));
        softOutageValue.setForeground(softOutage ? SERIES_STYLES[3].paint() : SERIES_STYLES[0].paint());
        softOutageValue.setFont(CARD_VALUE_FONT.deriveFont(Font.BOLD));
        boolean authorizationPaused =
                IndexingRetryCoordinator.getInstance().isAuthorizationRecoveryPaused();
        authorizationRecoveryValue.setText(StatsPanelFormatters.formatAuthorizationRecovery());
        authorizationRecoveryValue.setForeground(
                authorizationPaused ? SERIES_STYLES[3].paint() : SERIES_STYLES[0].paint());
        authorizationRecoveryValue.setFont(CARD_VALUE_FONT.deriveFont(Font.BOLD));
        ExportAdmissionController.SpillStatus spillStatus =
                ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue.currentSpillStatus();
        trafficSpillStatusValue.setText(StatsPanelFormatters.formatSpillStatus(spillStatus));
        trafficSpillStatusValue.setForeground(spillStatusColor(spillStatus));
        trafficSpillStatusValue.setFont(CARD_VALUE_FONT.deriveFont(Font.BOLD));
        bulkByteBudgetValue.setText(
                StatsPanelFormatters.formatBytesHuman(StatsPanelFormatters.displayedBulkByteBudget()));
        snapshotFlushCapValue.setText(formatWhole(StatsPanelFormatters.displayedSnapshotFlushCap()));
        cooldownRemainingValue.setText(
                StatsPanelFormatters.formatCooldownRemaining(BulkRateLimitBackoff.remainingCooldownMs()));
        pressureStreakValue.setText(formatWhole(BulkRateLimitBackoff.pressureStreak()));
        softOutageEntriesValue.setText(formatWhole(ExportStats.getSoftOutageEntries()));
        capacityEventsValue.setText(formatWhole(ExportStats.getCapacityPressureEvents()));
        misgateSuspectsValue.setText(formatWhole(ExportStats.getDocsBodyEnumerationMisgateSuspect()));
        skippedBodyEnumerationValue.setText(formatWhole(ExportStats.getDocsWithSkippedBodyEnumeration()));
        wireBodyReplacedValue.setText(formatWhole(ExportStats.getDocsWireBodyParamsReplaced()));
        skipPathRescuedValue.setText(formatWhole(ExportStats.getDocsSkipPathBodyRescued()));
        supplementalBodyUsedValue.setText(formatWhole(ExportStats.getDocsSupplementalBodyParamsUsed()));
        supplementalRejectedValue.setText(formatWhole(ExportStats.getDocsSupplementalRejectedNonForm()));
        wireBodyDroppedEntriesValue.setText(formatWhole(ExportStats.getWireBodyParamsDroppedTotal()));
        applySystemMetrics(SystemMetrics.snapshot());
        applyAllChartFonts();

        rebuildByIndexTable();
        rebuildFileByIndexTable();
        updateTablePreferredHeight(byIndexTable);
        updateTablePreferredHeight(fileByIndexTable);
        updateSectionVisibility();
        updateDashboardSectionSizing();
        revalidate();
    }

    /**
     * Rebuilds the merged OpenSearch counts table.
     *
     * <p>Row order is: index rows in alphabetical order, the Traffic row, traffic-source
     * sub-rows directly under it (indented via {@link #SUBROW_INDENT}), then a Total row that
     * aggregates only the index rows. Sub-rows show route-attributed Failures, Queued, Recovered
     * Failures, Retry Drops, and Permanent Drops; Last Bulk / Last Error stay {@code "-"}
     * because those are index-level only.</p>
     */
    private void rebuildByIndexTable() {
        byIndexModel.setRowCount(0);
        List<String> sortedKeys = new ArrayList<>(ExportStats.getIndexKeys());
        sortedKeys.sort((left, right) -> left.compareToIgnoreCase(right));
        long totalSuccess = 0;
        long totalQueued = 0;
        long totalRetryDrops = 0;
        long totalPermanentDrops = 0;
        long totalFailure = 0;
        long totalRecovered = 0;
        for (String indexKey : sortedKeys) {
            long exported = ExportStats.getExportedCount(indexKey);
            int queued = ExportStats.getQueueSize(indexKey);
            long retryDrops = ExportStats.getRetryQueueDrops(indexKey);
            long permanentDrops = ExportStats.getPermanentDrops(indexKey);
            long failure = ExportStats.getFailureCount(indexKey);
            long recovered = ExportStats.getRecoveredFailureCount(indexKey);
            String lastBulkStr = "-";
            if ("traffic".equalsIgnoreCase(indexKey)) {
                long lastBulkMs = ExportStats.getLastLiveBulkDurationMs(indexKey);
                if (lastBulkMs >= 0) {
                    lastBulkStr = String.valueOf(lastBulkMs);
                }
            }
            String lastError = ExportStats.getLastError(indexKey);
            String errStr = lastError != null ? lastError : "-";
            totalSuccess += exported;
            totalQueued += queued;
            totalRetryDrops += retryDrops;
            totalPermanentDrops += permanentDrops;
            totalFailure += failure;
            totalRecovered += recovered;
            byIndexModel.addRow(new Object[] {
                    formatKeyLabel(indexKey), exported, failure, queued,
                    recovered, retryDrops, permanentDrops, lastBulkStr, errStr
            });
            if ("traffic".equalsIgnoreCase(indexKey)) {
                appendOpenSearchTrafficSourceSubRows();
            }
        }
        byIndexModel.addRow(new Object[] {
                "Total", totalSuccess, totalFailure, totalQueued,
                totalRecovered, totalRetryDrops, totalPermanentDrops, "-", "-"
        });
    }

    /** Appends per-source sub-rows for OpenSearch traffic right after the Traffic index row. */
    private void appendOpenSearchTrafficSourceSubRows() {
        for (String sourceKey : ExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            long sourceSuccess = resolveSourceSuccess(sourceKey);
            int sourceQueued = ExportStats.getTrafficDisplaySourceQueueSize(sourceKey);
            long sourceRetryDrops = TrafficRouteBucket.resolveOpenSearchSourceRetryQueueDrops(sourceKey);
            long sourcePermanentDrops = TrafficRouteBucket.resolveOpenSearchSourcePermanentDrops(sourceKey);
            long sourceFailure = resolveSourceFailure(sourceKey);
            long sourceRecovered = TrafficRouteBucket.resolveOpenSearchSourceRecovery(sourceKey);
            byIndexModel.addRow(new Object[] {
                    SUBROW_INDENT + formatKeyLabel(sourceKey),
                    sourceSuccess,
                    sourceFailure,
                    sourceQueued,
                    sourceRecovered,
                    sourceRetryDrops,
                    sourcePermanentDrops,
                    "-",
                    "-"
            });
        }
    }

    /**
     * Rebuilds the merged File counts table; mirrors {@link #rebuildByIndexTable} but uses
     * the trimmed file schema. Queue / retry-drop / permanent-drop columns are omitted because
     * file writes use bounded immediate retries rather than an asynchronous retry queue.
     */
    private void rebuildFileByIndexTable() {
        fileByIndexModel.setRowCount(0);
        List<String> sortedKeys = new ArrayList<>(FileExportStats.getIndexKeys());
        sortedKeys.sort((left, right) -> left.compareToIgnoreCase(right));
        long totalSuccess = 0;
        long totalFailure = 0;
        long totalRetryAttempts = 0;
        long totalBaselineBytes = 0;
        long totalAppendedBytes = 0;
        long totalFinalBytes = 0;
        boolean anyArtifacts = false;
        boolean anyIntegrityFailure = false;
        boolean anyIntegrityPending = false;
        for (String indexKey : sortedKeys) {
            long written = FileExportStats.getWrittenCount(indexKey);
            long failure = FileExportStats.getFailureCount(indexKey);
            long retryAttempts = FileExportStats.getRetryAttemptCount(indexKey);
            long artifactCount = FileExportStats.getArtifactCount(indexKey);
            long baselineBytes = FileExportStats.getArtifactBaselineBytes(indexKey);
            long appendedBytes = FileExportStats.getExportedBytes(indexKey);
            long finalBytes = FileExportStats.getArtifactFinalBytes(indexKey);
            FileExportStats.ArtifactIntegrity integrity =
                    FileExportStats.getArtifactIntegrity(indexKey);
            boolean selected = artifactCount > 0L;
            long lastWriteMs = FileExportStats.getLastWriteDurationMs(indexKey);
            String lastWriteStr = lastWriteMs >= 0 ? String.valueOf(lastWriteMs) : "-";
            String lastError = FileExportStats.getLastError(indexKey);
            String errStr = lastError != null ? lastError : "-";
            totalSuccess += written;
            totalFailure += failure;
            totalRetryAttempts += retryAttempts;
            totalBaselineBytes += baselineBytes;
            totalAppendedBytes += appendedBytes;
            totalFinalBytes += finalBytes;
            anyArtifacts |= selected;
            anyIntegrityFailure |= integrity == FileExportStats.ArtifactIntegrity.FAILED;
            anyIntegrityPending |= integrity == FileExportStats.ArtifactIntegrity.PENDING;
            fileByIndexModel.addRow(new Object[] {
                    formatKeyLabel(indexKey),
                    written,
                    failure,
                    retryAttempts,
                    selected ? StatsPanelFormatters.formatBytesHuman(baselineBytes) : "-",
                    selected ? StatsPanelFormatters.formatBytesHuman(appendedBytes) : "-",
                    integrity == FileExportStats.ArtifactIntegrity.OK
                                    || integrity == FileExportStats.ArtifactIntegrity.FAILED
                            ? StatsPanelFormatters.formatBytesHuman(finalBytes)
                            : "-",
                    fileIntegrityLabel(integrity),
                    lastWriteStr,
                    errStr
            });
            if ("traffic".equalsIgnoreCase(indexKey)) {
                appendFileTrafficSourceSubRows();
            }
        }
        fileByIndexModel.addRow(new Object[] {
                "Total",
                totalSuccess,
                totalFailure,
                totalRetryAttempts,
                anyArtifacts ? StatsPanelFormatters.formatBytesHuman(totalBaselineBytes) : "-",
                anyArtifacts ? StatsPanelFormatters.formatBytesHuman(totalAppendedBytes) : "-",
                !anyArtifacts || anyIntegrityPending
                        ? "-"
                        : StatsPanelFormatters.formatBytesHuman(totalFinalBytes),
                !anyArtifacts
                        ? "Not selected"
                        : anyIntegrityFailure ? "Failed" : anyIntegrityPending ? "Pending" : "OK",
                "-",
                "-"
        });
    }

    private static String fileIntegrityLabel(FileExportStats.ArtifactIntegrity integrity) {
        return switch (integrity) {
            case PENDING -> "Pending";
            case OK -> "OK";
            case FAILED -> "Failed";
            case NOT_SELECTED -> "Not selected";
        };
    }

    /** Appends per-source sub-rows for File traffic right after the Traffic index row. */
    private void appendFileTrafficSourceSubRows() {
        for (String sourceKey : FileExportStats.getTrafficToolTypeKeys()) {
            if ("UNKNOWN".equals(sourceKey)) {
                continue;
            }
            long sourceSuccess = resolveFileSourceSuccess(sourceKey);
            long sourceFailure = resolveFileSourceFailure(sourceKey);
            fileByIndexModel.addRow(new Object[] {
                    SUBROW_INDENT + formatKeyLabel(sourceKey),
                    sourceSuccess, sourceFailure, "-", "-", "-", "-", "-", "-", "-", "-"
            });
        }
    }

    /**
     * Builds a single per-sink card: a titled outer panel containing one merged counts table.
     *
     * <p>The card uses {@link BorderLayout} with the table column header + body in the
     * {@code CENTER} slot. {@link CardCopySupport#attachCopyButton} stacks a Copy header
     * above the column header so a single click captures the full TSV including index rows
     * and indented traffic-source sub-rows.</p>
     */
    private static JPanel createSinkCard(String cardTitle, String cardName, JTable table) {
        JPanel card = new JPanel(new BorderLayout(0, 0));
        card.setName(cardName);
        card.setBorder(BorderFactory.createTitledBorder(cardTitle));
        card.setOpaque(false);

        JPanel tableContainer = new JPanel(new BorderLayout(0, 0));
        tableContainer.setOpaque(false);
        tableContainer.add(table.getTableHeader(), BorderLayout.NORTH);
        tableContainer.add(table, BorderLayout.CENTER);
        card.add(tableContainer, BorderLayout.CENTER);
        return card;
    }

    /**
     * Renders all lower-panel stats cards for the shared Copy toolbar.
     */
    private String renderAllStatsForClipboard() {
        return StatsClipboardSnapshot.buildClipboardText();
    }

    /**
     * Wraps a sink card in a {@code GridLayout(1, 1)} row so it always stretches to the full
     * lower-panel width. Mirrors the {@link #cardsRow} pattern used by the Misc Stats card and
     * eliminates the leading whitespace gap that would otherwise appear when {@link javax.swing.BoxLayout}
     * sized the card to its narrower preferred width.
     */
    private static JPanel wrapSinkCardInFullWidthRow(JPanel sinkCard, String rowName) {
        JPanel row = new JPanel(new GridLayout(1, 1, 10, 0));
        row.setName(rowName);
        row.setOpaque(false);
        row.add(sinkCard);
        return row;
    }

    /**
     * Builds the standalone memory time-series chart that lives at the bottom of the chart
     * stack. The Y axis renders in MiB (the dataset stores MiB directly so axis labels need
     * no extra formatting). Series paints, strokes, and the renderer flavor (line vs. spline)
     * are applied later by {@link #applyMemoryChartStyle(JFreeChart)} so the memory chart
     * picks up the user's currently-selected chart style. The built-in JFreeChart legend is
     * disabled here; a custom JPanel-based legend ({@link #memoryLegendPanel}) is rendered
     * above the chart so the layout matches the per-sink charts' shared legend at the top.
     */
    private static JFreeChart createMemoryChart(TimeSeriesCollection dataset) {
        Color chartBackground = chartBackgroundPaint();
        Color plotBackground = plotBackgroundPaint();
        Color gridForeground = gridPaint();
        JFreeChart chart = ChartFactory.createTimeSeriesChart(
                "JVM Heap (Burp + Extensions)", null, "MiB",
                dataset, false, false, false);
        chart.setBackgroundPaint(chartBackground);
        chart.setPadding(RectangleInsets.ZERO_INSETS);
        TextTitle titleNode = chart.getTitle();
        titleNode.setPaint(TEXT_FG);
        titleNode.setVerticalAlignment(VerticalAlignment.BOTTOM);
        titleNode.setMargin(RectangleInsets.ZERO_INSETS);
        titleNode.setPadding(RectangleInsets.ZERO_INSETS);
        XYPlot plot = chart.getXYPlot();
        plot.setInsets(new RectangleInsets(1, 2, 2, 2));
        plot.setBackgroundPaint(plotBackground);
        plot.setDomainGridlinePaint(gridForeground);
        plot.setRangeGridlinePaint(gridForeground);
        plot.setDomainGridlinesVisible(true);
        plot.setRangeGridlinesVisible(true);
        ValueAxis domain = plot.getDomainAxis();
        configureStatsRangeAxis(plot, "MiB");
        NumberAxis range = (NumberAxis) plot.getRangeAxis();
        range.setRangeType(RangeType.POSITIVE);
        range.setAutoRangeIncludesZero(true);
        range.setAutoRangeStickyZero(true);
        range.setLowerMargin(0.0);
        range.setUpperMargin(RANGE_AXIS_UPPER_MARGIN);
        range.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        range.setLabelPaint(TEXT_FG);
        range.setTickLabelPaint(TEXT_FG);
        if (domain != null) {
            domain.setLabelPaint(TEXT_FG);
            domain.setTickLabelPaint(TEXT_FG);
            domain.setTickLabelsVisible(true);
            domain.setLabel(null);
            if (domain instanceof DateAxis dateAxis) {
                dateAxis.setDateFormatOverride(new SimpleDateFormat(DOMAIN_TIME_PATTERN));
            }
        }
        applyChartFonts(chart, true);
        return chart;
    }

    /**
     * Wraps the memory chart panel in a section panel matching the per-sink chart sections so
     * the Y_AXIS BoxLayout in {@link #chartSectionsPanel} renders three consistently spaced
     * chart blocks. The legend panel is stacked at the top of the section (mirroring the
     * shared legend that sits above the per-sink charts), and the chart panel is forced to
     * {@link #MEMORY_CHART_PANEL_HEIGHT} so the memory section is roughly half the height of
     * a per-sink section (which renders two stacked sub-charts).
     */
    private static JPanel buildMemoryChartSection(JPanel memoryLegendPanel, JPanel memoryChartPanel) {
        memoryChartPanel.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, MEMORY_CHART_PANEL_HEIGHT));
        memoryChartPanel.setMinimumSize(new Dimension(800, MEMORY_CHART_PANEL_HEIGHT));
        memoryChartPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, MEMORY_CHART_PANEL_HEIGHT));
        JPanel section = new Tooltips.HtmlPanel();
        section.setLayout(new javax.swing.BoxLayout(section, javax.swing.BoxLayout.Y_AXIS));
        section.setOpaque(false);
        section.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 0));
        section.add(memoryLegendPanel);
        section.add(memoryChartPanel);
        return section;
    }

    private static JTable createStatsTable(DefaultTableModel model) {
        model.setRowCount(0);
        JTable table = new JTable(model) {
            @Serial private static final long serialVersionUID = 1L;

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(true);
        if (table.getRowSorter() instanceof TableRowSorter<?> sorter) {
            // Every column between the leading label and the trailing free-text "Last Error"
            // holds a numeric or "-" sentinel; use the numeric comparator for all of them so the
            // table stays sortable regardless of how many counters a given table exposes.
            int lastNumericColumn = Math.max(1, table.getColumnCount() - 2);
            for (int columnIndex = 1; columnIndex <= lastNumericColumn; columnIndex++) {
                sorter.setComparator(columnIndex, StatsPanel::compareNumericCell);
            }
        }
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowHeight(22);
        DefaultTableCellRenderer leftAligned = new DefaultTableCellRenderer();
        leftAligned.setHorizontalAlignment(SwingConstants.LEFT);
        for (int columnIndex = 0; columnIndex < table.getColumnCount(); columnIndex++) {
            table.getColumnModel().getColumn(columnIndex).setCellRenderer(leftAligned);
        }
        updateTablePreferredHeight(table);
        return table;
    }

    /**
     * Installs per-column header tooltips on a counts table.
     *
     * <p>Caller must invoke on the EDT. Tips are looked up by the model column name. Uses
     * {@link Tooltips#apply(JComponent, String)} and {@link Tooltips#createHtmlToolTip(JComponent)}
     * so Burp LAF renders {@link Tooltips#htmlRaw(String...)} markup instead of showing tags
     * literally.</p>
     *
     * @param table counts table
     * @param tipsByColumnName HTML tooltips keyed by exact header label
     */
    private static void applyColumnHeaderTooltips(JTable table, Map<String, String> tipsByColumnName) {
        if (table == null || tipsByColumnName == null || tipsByColumnName.isEmpty()) {
            return;
        }
        String registrationTip = tipsByColumnName.values().stream()
                .filter(tip -> tip != null && !tip.isBlank())
                .findFirst()
                .orElse(Tooltips.htmlRaw("Counts column help."));
        TableColumnModel columnModel = table.getColumnModel();
        JTableHeader tipHeader = new JTableHeader(columnModel) {
            @Serial private static final long serialVersionUID = 1L;

            @Override
            public String getToolTipText(MouseEvent event) {
                int viewColumn = columnAtPoint(event.getPoint());
                if (viewColumn < 0) {
                    return null;
                }
                int modelColumn = table.convertColumnIndexToModel(viewColumn);
                Object headerValue = table.getModel().getColumnName(modelColumn);
                String tip = tipsByColumnName.get(String.valueOf(headerValue));
                return tip != null && !tip.isBlank() ? tip : null;
            }

            @Override
            public JToolTip createToolTip() {
                return Tooltips.createHtmlToolTip(this);
            }
        };
        Tooltips.apply(tipHeader, registrationTip);
        tipHeader.setTable(table);
        table.setTableHeader(tipHeader);
    }

    /** Header tooltips for the Database Counts table. */
    private static Map<String, String> databaseCountsHeaderTooltips() {
        Map<String, String> tips = new LinkedHashMap<>();
        tips.put("Index", Tooltips.htmlRaw(
                "Exporter index (or indented traffic source under Traffic).",
                "Total aggregates index rows only."));
        tips.put("Exported", Tooltips.htmlRaw(
                "Documents successfully indexed to the search database for this row this session.",
                "Stop does not read database counts back into Log."));
        tips.put("Queued", Tooltips.htmlRaw(
                "Documents waiting in the indexing retry queue for this index or traffic source.",
                "Traffic source values attribute queued documents by reporting tool / source route."));
        tips.put("Retry Drops", Tooltips.htmlRaw(
                "Documents dropped because the retry queue was at capacity.",
                "These are not retried again. Traffic source rows attribute drops by route."));
        tips.put("Permanent Drops", Tooltips.htmlRaw(
                "Documents removed from retry and not sent again:",
                "non-retryable search errors (mapping/parse/validation), and any remainder discarded",
                "when Stop's bounded retry drain ends (about 20 seconds).",
                "Force-stop aborts the drain early. Traffic source rows attribute drops by route."));
        tips.put("Failures", Tooltips.htmlRaw(
                "Documents counted when a search push reported them failed.",
                "This counter does not decrement when a later retry succeeds — see Recovered Failures.",
                "It is not a count of every retry round (see Retry Drain Pushes in Misc Stats).",
                "Compare with Recovered Failures, Permanent Drops, Retry Drops, and Queued."));
        tips.put("Recovered Failures", Tooltips.htmlRaw(
                "Documents that failed earlier and later succeeded via the retry drain.",
                "Retry-from-queue is the normal path while export is running.",
                "Log recoveries may include <code>evidence=bulk_item_success</code>."));
        tips.put("Last Bulk (ms)", Tooltips.htmlRaw(
                "Duration of the most recent live traffic bulk HTTP request for Traffic.",
                "Other indexes show <code>-</code>."));
        tips.put("Last Error", Tooltips.htmlRaw(
                "Most recent search push error summary for this index, when available."));
        return tips;
    }

    /** Header tooltips for the File Counts table. */
    private static Map<String, String> fileCountsHeaderTooltips() {
        Map<String, String> tips = new LinkedHashMap<>();
        tips.put("Index", Tooltips.htmlRaw(
                "Exporter index (or indented traffic source under Traffic).",
                "Total aggregates index rows only."));
        tips.put("Written", Tooltips.htmlRaw(
                "Documents successfully written to the file export destination this session."));
        tips.put("Failures", Tooltips.htmlRaw(
                "Documents not written after file-export retries were exhausted this session."));
        tips.put("Retry Attempts", Tooltips.htmlRaw(
                "Additional local file-write attempts after transient I/O failures.",
                "A retry is attempted only after any partial append is rolled back safely."));
        tips.put("Baseline", Tooltips.htmlRaw(
                "Bytes already present across this index's selected files when the run started."));
        tips.put("Appended", Tooltips.htmlRaw(
                "Bytes successfully appended across this index's selected files during the run."));
        tips.put("Final Size", Tooltips.htmlRaw(
                "Observed bytes across this index's selected files at final integrity validation."));
        tips.put("Integrity", Tooltips.htmlRaw(
                "Pending while the run is active; OK only after Stop verifies file identity and size.",
                "Failed means an output was deleted, replaced, truncated, or changed externally."));
        tips.put("Last Append (ms)", Tooltips.htmlRaw(
                "Duration of the most recent file append for this index, when available.",
                "This measures append completion, not an explicit disk flush."));
        tips.put("Last Error", Tooltips.htmlRaw(
                "Most recent file-export error summary for this index, when available."));
        return tips;
    }

    private static MetricCardState addGroupedMetricCard(JPanel parent, String title, List<MetricSection> sections) {
        JPanel card = new JPanel(new BorderLayout());
        card.setName("miscStatsCard");
        card.setBorder(BorderFactory.createTitledBorder(title));
        card.setOpaque(false);

        // Probe every section's keys with the card key font so both columns end up with the same
        // key-column width and labels visually line up across the card even though their rows
        // live in separate sub-panels.
        int maxKeyWidth = 0;
        for (MetricSection section : sections) {
            for (String key : section.keys()) {
                JLabel probe = new JLabel(key);
                probe.setFont(CARD_KEY_FONT);
                maxKeyWidth = Math.max(maxKeyWidth, probe.getPreferredSize().width);
            }
        }

        Map<String, JLabel> values = new HashMap<>();
        Map<String, List<Component>> sectionComponents = new HashMap<>();

        // Two-column layout. Sections are distributed across columns so the card uses the full
        // panel width (matching the count tables above) without leaving the right half blank.
        // Splitting by section count rather than row count keeps semantically related sections
        // grouped: general / process info on the left, sink-specific info on the right.
        int splitIndex = (sections.size() + 1) / 2;
        JPanel leftColumn = buildMiscStatsColumn(
                sections.subList(0, splitIndex), maxKeyWidth, values, sectionComponents);
        JPanel rightColumn = buildMiscStatsColumn(
                sections.subList(splitIndex, sections.size()), maxKeyWidth, values, sectionComponents);

        JPanel columnsPanel = new JPanel(new GridLayout(1, 2, 16, 0));
        columnsPanel.setOpaque(false);
        columnsPanel.add(leftColumn);
        columnsPanel.add(rightColumn);
        card.add(columnsPanel, BorderLayout.NORTH);

        parent.add(card);
        return new MetricCardState(card, values, sectionComponents);
    }

    /**
     * Builds one column of the Misc Stats card. Caller distributes sections across columns; this
     * helper just stacks the supplied sections vertically with the same row styling, alternating
     * row backgrounds, and section/row component naming the single-column layout previously used.
     */
    private static JPanel buildMiscStatsColumn(
            List<MetricSection> sections,
            int maxKeyWidth,
            Map<String, JLabel> values,
            Map<String, List<Component>> sectionComponents) {
        JPanel column = new JPanel();
        column.setLayout(new javax.swing.BoxLayout(column, javax.swing.BoxLayout.Y_AXIS));
        column.setOpaque(false);
        int rowIndex = 0;
        for (MetricSection section : sections) {
            JLabel sectionLabel = new JLabel(section.title());
            sectionLabel.setName("miscStats.section." + section.title());
            sectionLabel.setForeground(TEXT_FG);
            sectionLabel.setFont(CARD_KEY_FONT.deriveFont(Font.BOLD));
            sectionLabel.setBorder(BorderFactory.createEmptyBorder(rowIndex == 0 ? 0 : 4, 6, 2, 6));
            sectionLabel.setAlignmentX(LEFT_ALIGNMENT);
            Dimension sectionPref = sectionLabel.getPreferredSize();
            sectionLabel.setMaximumSize(new Dimension(Integer.MAX_VALUE, sectionPref.height));
            column.add(sectionLabel);
            List<Component> components = new ArrayList<>();
            components.add(sectionLabel);
            sectionComponents.put(section.title(), components);
            for (int i = 0; i < section.keys().length; i++) {
                String key = section.keys()[i];
                JComponent row = new Tooltips.HtmlPanel(new BorderLayout(10, 0));
                row.setName("miscStats.row." + section.title() + "." + i);
                row.setOpaque(true);
                row.setBackground(rowBackground(rowIndex));
                row.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
                row.setAlignmentX(LEFT_ALIGNMENT);

                JLabel keyLabel = new Tooltips.HtmlLabel(key);
                keyLabel.setForeground(TEXT_FG);
                keyLabel.setFont(CARD_KEY_FONT);
                keyLabel.setPreferredSize(new Dimension(maxKeyWidth, keyLabel.getPreferredSize().height));

                JLabel valueLabel = new Tooltips.HtmlLabel("-");
                valueLabel.setHorizontalAlignment(SwingConstants.LEFT);
                valueLabel.setForeground(TEXT_FG);
                valueLabel.setFont(CARD_VALUE_FONT);
                values.put(key, valueLabel);

                row.add(keyLabel, BorderLayout.WEST);
                row.add(valueLabel, BorderLayout.CENTER);
                Dimension rowPref = row.getPreferredSize();
                row.setMaximumSize(new Dimension(Integer.MAX_VALUE, rowPref.height));
                column.add(row);
                components.add(row);
                rowIndex++;
            }
        }
        column.add(javax.swing.Box.createVerticalGlue());
        return column;
    }

    private static Color rowBackground(int rowIndex) {
        Color base = UIManager.getColor("Table.background");
        if (base == null) {
            base = UIManager.getColor("Panel.background");
        }
        if (base == null) {
            base = new Color(60, 60, 60);
        }
        Color alternate = UIManager.getColor("Table.alternateRowColor");
        if (alternate == null) {
            int delta = isDark(base) ? 8 : -8;
            alternate = adjust(base, delta);
        }
        return (rowIndex % 2 == 0) ? base : alternate;
    }

    private static boolean isDark(Color color) {
        return ((color.getRed() * 299) + (color.getGreen() * 587) + (color.getBlue() * 114)) / 1000 < 128;
    }

    /**
     * Base UI font for charts and legends — matches {@link #cardFont()} / the counts tables.
     */
    static Font chartBaseFont() {
        return cardFont();
    }

    static Font chartTickFont() {
        return chartBaseFont();
    }

    static Font chartAxisLabelFont() {
        return chartBaseFont();
    }

    static Font chartTitleFont() {
        Font base = chartBaseFont();
        return base.isBold() ? base : base.deriveFont(Font.BOLD);
    }

    static Font chartLegendFont() {
        return chartBaseFont();
    }

    private void applyAllChartFonts() {
        applyChartFonts(docsChart);
        applyChartFonts(kibChart);
        applyChartFonts(fileDocsChart);
        applyChartFonts(fileKibChart);
        applyChartFonts(memoryChart, true);
        if (openSearchChartsSectionHeaderLabel != null) {
            openSearchChartsSectionHeaderLabel.setFont(chartBaseFont());
        }
        if (fileChartsSectionHeaderLabel != null) {
            fileChartsSectionHeaderLabel.setFont(chartBaseFont());
        }
    }

    private static void applyChartFonts(JFreeChart chart) {
        applyChartFonts(chart, false);
    }

    private static void applyChartFonts(JFreeChart chart, boolean plainTitle) {
        if (chart == null) {
            return;
        }
        Font tick = chartTickFont();
        Font axisLabel = chartAxisLabelFont();
        if (chart.getTitle() != null) {
            chart.getTitle().setFont(plainTitle ? chartBaseFont() : chartTitleFont());
        }
        if (chart.getLegend() != null) {
            chart.getLegend().setItemFont(chartLegendFont());
        }
        XYPlot plot = chart.getXYPlot();
        if (plot == null) {
            return;
        }
        ValueAxis domain = plot.getDomainAxis();
        if (domain != null) {
            domain.setLabelFont(axisLabel);
            domain.setTickLabelFont(tick);
        }
        ValueAxis range = plot.getRangeAxis();
        if (range != null) {
            range.setLabelFont(axisLabel);
            range.setTickLabelFont(tick);
        }
    }

    /**
     * Returns the LAF's table-cell font so the Misc Stats card renders at the same point size as
     * the adjacent JTable count cards. Falls back through {@code Table.font} ->
     * {@code Label.font} -> a default {@link JLabel} font so the card never depends on a single
     * UIManager key being populated.
     */
    private static Font cardFont() {
        Font base = UIManager.getFont("Table.font");
        if (base == null) {
            base = UIManager.getFont("Label.font");
        }
        if (base == null) {
            base = new JLabel().getFont();
        }
        if (base == null) {
            base = new Font("SansSerif", Font.PLAIN, 12);
        }
        return base.deriveFont(Font.PLAIN);
    }

    private static Color uiColor(String key, Color fallback) {
        Color color = UIManager.getColor(key);
        return color != null ? color : fallback;
    }

    private static Color adjust(Color color, int delta) {
        return new Color(
                Math.clamp(color.getRed() + delta, 0, 255),
                Math.clamp(color.getGreen() + delta, 0, 255),
                Math.clamp(color.getBlue() + delta, 0, 255)
        );
    }

    private void updateDashboardSectionSizing() {
        // Each per-sink card hosts a single merged counts table. A shared Copy toolbar sits above
        // the cards; {@link #updateTablePreferredHeight} keeps table body height in sync with rows.
        int sinkOuterPadding = 28;

        int openSearchHeight = sinkOuterPadding
                + sinkCardBodyHeight(byIndexTable);
        int fileHeight = sinkOuterPadding
                + sinkCardBodyHeight(fileByIndexTable);

        openSearchSinkCard.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, openSearchHeight));
        openSearchSinkCard.setMinimumSize(new Dimension(800, openSearchHeight));
        openSearchSinkCard.setMaximumSize(new Dimension(Integer.MAX_VALUE, openSearchHeight));
        fileSinkCard.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, fileHeight));
        fileSinkCard.setMinimumSize(new Dimension(800, fileHeight));
        fileSinkCard.setMaximumSize(new Dimension(Integer.MAX_VALUE, fileHeight));
        // The 1x1 GridLayout row eats the full lower-panel width and forces its child card
        // to do the same. Setting matching preferred / max sizes on the row keeps the parent
        // BoxLayout from collapsing the row to its minimum height.
        openSearchSinkRow.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, openSearchHeight));
        openSearchSinkRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, openSearchHeight));
        fileSinkRow.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, fileHeight));
        fileSinkRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, fileHeight));

        int visibleChartCount = visibleChartPanelCount();
        int visibleLegendHeight = sharedLegendPanel.isVisible() ? sharedLegendPanel.getPreferredSize().height + 4 : 0;
        int memoryLegendHeight = memoryLegendPanel.isVisible() ? memoryLegendPanel.getPreferredSize().height + 4 : 0;
        int memoryChartHeight = memoryChartSectionPanel.isVisible()
                ? MEMORY_CHART_PANEL_HEIGHT + memoryLegendHeight + 12
                : 0;
        int sectionHeadersHeight = chartSectionHeadersHeight();
        int chartsHeight = chartsPanel.isVisible()
                ? Math.max(0, visibleChartCount * (CHART_PANEL_HEIGHT / 2))
                        + visibleLegendHeight
                        + sectionHeadersHeight
                        + memoryChartHeight
                : 0;
        chartsPanel.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, chartsHeight));

        int cardsHeight = preferredHeightOf(cardsRow);
        cardsRow.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, cardsHeight));
        cardsRow.setMinimumSize(new Dimension(800, cardsHeight));
        cardsRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, cardsHeight));

        int lowerHeight = preferredHeightOf(lowerPanel);
        lowerPanel.setPreferredSize(new Dimension(PANEL_BASE_WIDTH, lowerHeight));

        int requiredHeight = chartsHeight
                + lowerHeight
                + CONTENT_VERTICAL_PADDING;
        int dynamicPanelHeight = Math.max(PANEL_BASE_HEIGHT, requiredHeight);
        setPreferredSize(new Dimension(PANEL_BASE_WIDTH, dynamicPanelHeight));
    }

    private static int preferredHeightOf(JPanel panel) {
        return Math.max(0, panel.getLayout().preferredLayoutSize(panel).height);
    }

    /**
     * Returns the vertical pixels needed by one merged sink card body: the JTable column-header row
     * plus the JTable preferred body height.
     * {@link #updateTablePreferredHeight} keeps the table's preferred size aligned with row
     * count, so this stays accurate across rebuilds (sub-rows added under the Traffic index
     * row are counted just like any other row).
     */
    private static int sinkCardBodyHeight(JTable table) {
        int header = table.getTableHeader() != null ? table.getTableHeader().getPreferredSize().height : 24;
        int body = Math.max(table.getRowHeight(), table.getPreferredSize().height);
        return header + body + 6;
    }

    /**
     * Shows only the sink-specific chart and table sections enabled by the current runtime config.
     *
     * <p>Files sections appear above OpenSearch sections. One sink is always expected to remain
     * enabled, so the shared legend stays visible whenever at least one chart section is shown.</p>
     */
    private void updateSectionVisibility() {
        boolean fileVisible = isFileSectionEnabled();
        boolean openSearchVisible = isOpenSearchSectionEnabled();
        moveLegendToFirstVisibleSection(fileVisible, openSearchVisible);

        fileChartsSectionPanel.setVisible(fileVisible);
        fileSinkRow.setVisible(fileVisible);

        openSearchChartsSectionPanel.setVisible(openSearchVisible);
        openSearchSinkRow.setVisible(openSearchVisible);
        updateMiscStatsSectionVisibility(fileVisible, openSearchVisible);

        updateChartDomainLabels();
        // The chart container always stays visible because the memory chart at the bottom of
        // the chart stack reflects JVM-wide heap usage and is unrelated to which sink (if any)
        // is currently selected. The shared legend is per-sink, so it follows the per-sink
        // chart visibility.
        chartsPanel.setVisible(true);
        sharedLegendPanel.setVisible(fileVisible || openSearchVisible);
    }

    /**
     * Shows only the Misc Stats groups that apply to the active destinations.
     *
     * <p>Caller must invoke on the EDT because this method mutates Swing component visibility and
     * triggers layout/paint work on {@link #miscStatsCard}. The {@code Overview} group always
     * remains visible. Within Overview, Soft Outage and Database Exported Size follow database
     * enablement, Files Exported Size follows files enablement, and Traffic Spill Status follows
     * live traffic export relevance. The {@code Files} section and OpenSearch-prefixed groups
     * follow the currently visible lower-panel destinations. Traffic Spill detail follows traffic
     * export relevance (files and/or database).</p>
     *
     * @param fileVisible whether the Files metrics group should be visible
     * @param openSearchVisible whether the OpenSearch metrics group should be visible
     */
    private void updateMiscStatsSectionVisibility(boolean fileVisible, boolean openSearchVisible) {
        boolean trafficRelevant = RuntimeConfig.isAnyTrafficExportEnabled();
        setMiscSectionVisible("Overview", true);
        // Overview: Export Running, Soft Outage, Database size, Files size, Traffic Spill Status.
        setMiscRowVisible("Overview", 0, true);
        setMiscRowVisible("Overview", 1, openSearchVisible);
        setMiscRowVisible("Overview", 2, openSearchVisible);
        setMiscRowVisible("Overview", 3, fileVisible);
        setMiscRowVisible("Overview", 4, trafficRelevant);
        setMiscSectionVisible("Process", true);
        for (String section : MISC_DATABASE_SECTIONS) {
            setMiscSectionVisible(section, openSearchVisible);
        }
        setMiscSectionVisible(MISC_TRAFFIC_SPILL_SECTION, trafficRelevant);
        setMiscSectionVisible("Files", fileVisible);
        miscStatsCard.revalidate();
        miscStatsCard.repaint();
    }

    /**
     * Returns Overview Traffic Spill Status foreground color.
     *
     * <p>{@code Ready} and {@code In use} use the default Misc Stats value color; only
     * {@code Full} uses Findings red.</p>
     */
    private Color spillStatusColor(ExportAdmissionController.SpillStatus status) {
        if (status == ExportAdmissionController.SpillStatus.FULL) {
            return SERIES_STYLES[4].paint();
        }
        return TEXT_FG;
    }

    /**
     * Applies visibility to one Misc Stats row within a section.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param title section title used in the row component name
     * @param rowIndex zero-based row index within that section
     * @param visible whether the row should be shown
     */
    private void setMiscRowVisible(String title, int rowIndex, boolean visible) {
        Component row = findMiscRow(title, rowIndex);
        if (row != null) {
            row.setVisible(visible);
        }
    }

    /** Returns the Misc Stats row component for {@code title} at {@code rowIndex}, or {@code null}. */
    private Component findMiscRow(String title, int rowIndex) {
        List<Component> components = miscSectionComponents.get(title);
        if (components == null) {
            return null;
        }
        String name = "miscStats.row." + title + "." + rowIndex;
        for (Component component : components) {
            if (name.equals(component.getName())) {
                return component;
            }
        }
        return null;
    }

    /**
     * Applies visibility to all components that belong to one Misc Stats group.
     *
     * <p>Caller must invoke on the EDT.</p>
     *
     * @param title section title used as the lookup key in {@link #miscSectionComponents}
     * @param visible whether the section label and rows should be shown
     */
    private void setMiscSectionVisible(String title, boolean visible) {
        List<Component> components = miscSectionComponents.get(title);
        if (components == null) {
            return;
        }
        for (Component component : components) {
            component.setVisible(visible);
        }
    }

    private void moveLegendToFirstVisibleSection(boolean fileVisible, boolean openSearchVisible) {
        JPanel target = fileVisible ? fileChartsSectionPanel : (openSearchVisible ? openSearchChartsSectionPanel : null);
        if (target == null) {
            return;
        }
        if (sharedLegendPanel.getParent() == target) {
            return;
        }
        java.awt.Container parent = sharedLegendPanel.getParent();
        if (parent != null) {
            parent.remove(sharedLegendPanel);
        }
        target.add(sharedLegendPanel, 0);
        target.revalidate();
        target.repaint();
    }

    private void updateChartDomainLabels() {
        setChartDomainLabel(fileDocsChart, null);
        setChartDomainLabel(docsChart, null);
        setChartDomainLabel(fileKibChart, null);
        setChartDomainLabel(kibChart, null);
    }

    /** Returns whether the current runtime config has file export selected. */
    private static boolean isFileSectionEnabled() {
        return RuntimeConfig.isAnyFileExportEnabled();
    }

    /** Returns whether the current runtime config has database export selected. */
    private static boolean isOpenSearchSectionEnabled() {
        var current = RuntimeConfig.getState();
        boolean configured = current != null
                && current.sinks() != null
                && current.sinks().databaseEnabled();
        // Keep charts/tables visible after mid-run destination disable until the next Start.
        return configured || RuntimeConfig.shouldRetainSearchStatsVisibility();
    }

    private int visibleChartPanelCount() {
        int count = 0;
        if (fileChartsSectionPanel.isVisible()) {
            count++;
            count++;
        }
        if (openSearchChartsSectionPanel.isVisible()) {
            count++;
            count++;
        }
        return count;
    }

    /**
     * Vertical pixels reserved for the per-pair "File Export" / "Database Export" section
     * headers. Each visible chart-pair contributes its header's preferred height plus the 4px
     * bottom border on the header so the histogram below it does not visually crash into the
     * caption.
     */
    private int chartSectionHeadersHeight() {
        int height = 0;
        if (fileChartsSectionPanel.isVisible()) {
            height += fileChartsSectionHeader.getPreferredSize().height + 4;
        }
        if (openSearchChartsSectionPanel.isVisible()) {
            height += openSearchChartsSectionHeader.getPreferredSize().height + 4;
        }
        return height;
    }

    /**
     * Builds a per-sink chart section containing one shared section header plus a vertical
     * stack of two chart panels. The header sits at the top of the section so each pair of
     * histograms shares a single "File Export" / "Database Export" caption, replacing the
     * legacy per-chart titles that used to repeat the sink name in every header. When the
     * shared legend lives in this section, {@link #moveLegendToFirstVisibleSection} inserts
     * it above the header at index 0; the resulting stack is [legend, header, top chart,
     * strut, bottom chart].
     */
    private static JPanel buildChartSection(JPanel header, JPanel topChartPanel, JPanel bottomChartPanel, int bottomGap) {
        JPanel section = new JPanel();
        section.setLayout(new javax.swing.BoxLayout(section, javax.swing.BoxLayout.Y_AXIS));
        section.setOpaque(false);
        section.setBorder(BorderFactory.createEmptyBorder(0, 0, bottomGap, 0));
        section.add(header);
        section.add(topChartPanel);
        section.add(javax.swing.Box.createVerticalStrut(12));
        section.add(bottomChartPanel);
        return section;
    }

    /**
     * Builds a centered, theme-aware label that captions a per-sink chart pair.
     *
     * @param bold {@code true} for emphasized section titles; {@code false} for plain captions
     *             (File Export, Database Export, JVM heap)
     */
    private static JLabel createChartSectionHeaderLabel(String text, boolean bold) {
        JLabel label = new JLabel(text, SwingConstants.CENTER);
        label.setForeground(TEXT_FG);
        label.setFont(bold ? chartTitleFont() : chartBaseFont());
        return label;
    }

    /**
     * Centers a section caption without letting {@link BoxLayout} stretch the label to the
     * full panel width (which some LAFs render as horizontally scaled text).
     */
    private static JPanel wrapChartSectionHeader(JLabel label) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.CENTER_ALIGNMENT);
        row.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        row.add(label);
        return row;
    }

    private static String formatWhole(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    /**
     * Formats exported-byte totals with a human-readable unit.
     *
     * <p>Uses binary thresholds for readability while keeping familiar unit labels in the UI.
     * Values below 1 KB remain in bytes; larger values are shown in KB, MB, or GB.</p>
     */
    private static String formatHumanReadableBytes(long bytes) {
        long safeBytes = Math.max(0L, bytes);
        double value = safeBytes;
        String unit = "B";
        if (safeBytes >= 1024L * 1024L * 1024L) {
            value = safeBytes / (1024.0 * 1024.0 * 1024.0);
            unit = "GB";
        } else if (safeBytes >= 1024L * 1024L) {
            value = safeBytes / (1024.0 * 1024.0);
            unit = "MB";
        } else if (safeBytes >= 1024L) {
            value = safeBytes / 1024.0;
            unit = "KB";
        }
        if ("B".equals(unit)) {
            return formatWhole(safeBytes) + " " + unit;
        }
        return DECIMAL_ONE.format(value) + " " + unit;
    }

    /**
     * Applies the latest {@link SystemMetrics.Snapshot} to the Misc Stats "Process" rows.
     *
     * <p>Unavailable fields fall back to {@code "n/a"}. Heap rows include a percent of
     * {@code heapMax} so operators can spot saturation at a
     * glance without doing the division themselves.</p>
     */
    private void applySystemMetrics(SystemMetrics.Snapshot snapshot) {
        heapUsedMaxValue.setText(formatBytesPairWithPercent(
                snapshot.heapUsedBytes(), snapshot.heapMaxBytes()));
        heapCommittedValue.setText(formatBytesWithPercentOf(
                snapshot.heapCommittedBytes(), snapshot.heapMaxBytes()));
        nonHeapUsedValue.setText(snapshot.nonHeapUsedBytes() >= 0
                ? formatHumanReadableBytes(snapshot.nonHeapUsedBytes())
                : "n/a");
        directBufferUsedValue.setText(snapshot.directBufferUsedBytes() >= 0
                ? formatHumanReadableBytes(snapshot.directBufferUsedBytes())
                : "n/a");
        mappedBufferUsedValue.setText(snapshot.mappedBufferUsedBytes() >= 0
                ? formatHumanReadableBytes(snapshot.mappedBufferUsedBytes())
                : "n/a");
        threadsLivePeakValue.setText(formatIntPair(snapshot.threadCount(), snapshot.peakThreadCount()));
        gcCountTimeValue.setText(snapshot.gcCollectionCount() >= 0 && snapshot.gcCollectionTimeMs() >= 0
                ? formatWhole(snapshot.gcCollectionCount()) + " / "
                        + formatDurationMsCompact(snapshot.gcCollectionTimeMs())
                : "n/a");
        processCpuLoadValue.setText(Double.isNaN(snapshot.processCpuLoad())
                ? "n/a"
                : DECIMAL_ONE.format(snapshot.processCpuLoad() * 100.0) + "%");
    }

    private static String formatBytesPair(long used, long max) {
        String usedText = used >= 0 ? formatHumanReadableBytes(used) : "n/a";
        String maxText = max > 0 ? formatHumanReadableBytes(max) : "n/a";
        return usedText + " / " + maxText;
    }

    /**
     * Formats {@code used / max} as bytes plus a percent suffix when both values are
     * positive (e.g. {@code "5.2 GB / 10.0 GB (52%)"}). Falls back to plain bytes if the
     * percent cannot be computed.
     */
    private static String formatBytesPairWithPercent(long used, long max) {
        String paired = formatBytesPair(used, max);
        if (used < 0 || max <= 0) {
            return paired;
        }
        return paired + " (" + formatPercentOfMax(used, max) + ")";
    }

    /**
     * Formats a single byte value annotated with its percent of {@code max}. Used for rows
     * that share an implicit denominator already shown elsewhere on the card (Heap Committed
     * lives next to Heap Used / Max, so repeating the cap as bytes would be redundant).
     */
    private static String formatBytesWithPercentOf(long value, long max) {
        if (value < 0) {
            return "n/a";
        }
        if (max <= 0) {
            return formatHumanReadableBytes(value);
        }
        return formatHumanReadableBytes(value) + " (" + formatPercentOfMax(value, max) + ")";
    }

    /**
     * Formats {@code numerator / denominator} as a one-decimal-place percent, e.g.
     * {@code "52.3%"}. Caller guarantees {@code denominator > 0}.
     */
    private static String formatPercentOfMax(long numerator, long denominator) {
        double pct = (numerator * 100.0) / denominator;
        return DECIMAL_ONE.format(pct) + "%";
    }

    private static String formatIntPair(int live, int peak) {
        String liveText = live >= 0 ? formatWhole(live) : "n/a";
        String peakText = peak >= 0 ? formatWhole(peak) : "n/a";
        return liveText + " / " + peakText;
    }

    /**
     * Formats cumulative GC pause time compactly using {@code ms}, {@code s}, or {@code m}
     * depending on magnitude. Small values stay in milliseconds so short sessions do not round to
     * zero.
     */
    private static String formatDurationMsCompact(long millis) {
        long safe = Math.max(0L, millis);
        if (safe < 1_000L) {
            return formatWhole(safe) + " ms";
        }
        if (safe < 60_000L) {
            return DECIMAL_ONE.format(safe / 1_000.0) + " s";
        }
        return DECIMAL_ONE.format(safe / 60_000.0) + " m";
    }

    private static void updateTablePreferredHeight(JTable table) {
        updateAllColumnWidths(table);
        int rows = Math.max(1, table.getRowCount());
        int headerHeight = table.getTableHeader() != null ? table.getTableHeader().getPreferredSize().height : 24;
        int totalHeight = headerHeight + (rows * table.getRowHeight()) + 6;
        int preferredWidth = Math.max(700, table.getPreferredSize().width);
        table.setPreferredScrollableViewportSize(new Dimension(preferredWidth, totalHeight));
        table.setPreferredSize(new Dimension(preferredWidth, Math.max(1, totalHeight - headerHeight)));
    }

    /**
     * Sizes every column to fit its widest visible cell or header text. Column 0 (the label
     * column) gets a comfortable minimum so source/index names like {@code Repeater Tabs}
     * always fit, and every column has a generous max cap so a single long {@code Last Error}
     * cannot blow the table beyond what the panel can render. When a cell still overflows the
     * cap the default {@link DefaultTableCellRenderer} truncates the visible text with an
     * ellipsis; the underlying model keeps the full string so {@link CardCopySupport#tableToTsv}
     * still copies the complete error.
     */
    private static void updateAllColumnWidths(JTable table) {
        if (table == null || table.getColumnCount() == 0) {
            return;
        }
        for (int columnIndex = 0; columnIndex < table.getColumnCount(); columnIndex++) {
            int preferredWidth = preferredColumnWidth(table, columnIndex);
            javax.swing.table.TableColumn column = table.getColumnModel().getColumn(columnIndex);
            column.setPreferredWidth(preferredWidth);
            column.setWidth(preferredWidth);
        }
    }

    /**
     * Vertical pixel cap applied to any auto-fit column. Long error strings beyond this width
     * fall back to ellipsis truncation in the cell, but the model still holds the full text so
     * the per-table Copy button reproduces it verbatim.
     */
    private static final int COLUMN_MAX_AUTO_WIDTH = 800;

    /**
     * Measures the larger of the header text or any visible cell in the column, then adds a
     * small padding buffer so packed labels do not render flush against the divider. Column 0
     * uses a comfortable minimum suited for display labels; trailing columns get a smaller
     * minimum since they hold short numeric values. Every column shares the same upper cap so
     * outliers (one giant error string) cannot dominate the layout.
     */
    private static int preferredColumnWidth(JTable table, int columnIndex) {
        int widest = 0;
        javax.swing.table.TableColumn column = table.getColumnModel().getColumn(columnIndex);
        javax.swing.table.TableCellRenderer headerRenderer = column.getHeaderRenderer();
        if (headerRenderer == null && table.getTableHeader() != null) {
            headerRenderer = table.getTableHeader().getDefaultRenderer();
        }
        if (headerRenderer != null) {
            Component headerComponent = headerRenderer.getTableCellRendererComponent(
                    table,
                    column.getHeaderValue(),
                    false,
                    false,
                    -1,
                    columnIndex);
            widest = Math.max(widest, headerComponent.getPreferredSize().width);
        }
        for (int rowIndex = 0; rowIndex < table.getRowCount(); rowIndex++) {
            javax.swing.table.TableCellRenderer renderer = table.getCellRenderer(rowIndex, columnIndex);
            Component cellComponent = table.prepareRenderer(renderer, rowIndex, columnIndex);
            widest = Math.max(widest, cellComponent.getPreferredSize().width);
        }
        int min = (columnIndex == 0) ? 120 : 60;
        return Math.clamp(widest + 18, min, COLUMN_MAX_AUTO_WIDTH);
    }

    private static int compareNumericCell(Object left, Object right) {
        Long leftValue = toSortableLong(left);
        Long rightValue = toSortableLong(right);
        if (leftValue == null && rightValue == null) {
            return 0;
        }
        if (leftValue == null) {
            return -1;
        }
        if (rightValue == null) {
            return 1;
        }
        return Long.compare(leftValue, rightValue);
    }

    private static Long toSortableLong(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        String text = value instanceof String stringValue
                ? stringValue.trim()
                : value.toString().trim();
        if (text.isEmpty() || "-".equals(text)) {
            return null;
        }
        try {
            return Long.valueOf(text.indexOf(',') >= 0 ? text.replace(",", "") : text);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static void applyMiscStatTooltips(Map<String, List<Component>> sectionComponents) {
        Map<String, String> tooltips = miscStatTooltips();
        for (List<Component> components : sectionComponents.values()) {
            for (Component component : components) {
                if (!(component instanceof JPanel row)) {
                    continue;
                }
                for (Component child : row.getComponents()) {
                    if (child instanceof JLabel keyLabel) {
                        String tooltip = tooltips.get(keyLabel.getText());
                        if (tooltip != null) {
                            Tooltips.applyToRow(row, tooltip);
                        }
                        break;
                    }
                }
            }
        }
    }

    /**
     * Tooltip text for every Misc Stats row (keys match {@link MetricSection} labels).
     * Rows use {@link Tooltips.HtmlPanel} so {@link Tooltips#htmlRaw(String...)} renders as HTML.
     */
    private static Map<String, String> miscStatTooltips() {
        Map<String, String> tooltips = new LinkedHashMap<>();
        tooltips.put("Export Running", Tooltips.htmlRaw(
                "Whether an export session is active.",
                "<b>Yes</b> after Start until Stop; controls whether reporters enqueue new work."));
        tooltips.put("Shared Batch Size", Tooltips.htmlRaw(
                "Doc-count target for the <b>shared</b> batch controller:",
                "live traffic drain, sitemap/findings bulks, and retry drain.",
                "Proxy history uses a <b>separate</b> chunk target (see Proxy History Chunk Target)."));
        tooltips.put("Proxy History Chunk Target", Tooltips.htmlRaw(
                "Proxy-history snapshot chunk doc-count target while a backlog export runs.",
                "After completion, shows the final chunk target from the last run;",
                "full wall-clock duration is under Efficiency / proxy_history_last_run."));
        tooltips.put("Traffic Queue Size", Tooltips.htmlRaw(
                "Live traffic documents waiting in the in-memory drain queue.",
                "Covers Proxy live HTTP and live WebSocket paths; snapshot backlogs do not use this queue."));
        tooltips.put("Traffic Queue Bytes (est.)", Tooltips.htmlRaw(
                "Estimated serialized bulk bytes for documents currently in the in-memory traffic queue.",
                "Computed on refresh; excludes spill-file backlog (see Spill / Queue)."));
        tooltips.put("Queue Drops", Tooltips.htmlRaw(
                "Session total of live traffic documents dropped because the in-memory queue was full.",
                "Distinct from OpenSearch failures and from spill drop counters under Spill."));
        tooltips.put("Pending Orphans", Tooltips.htmlRaw(
                "Live HTTP request/response pairs held until a matching response arrives.",
                "A non-zero value during heavy traffic is normal; sustained growth may indicate pairing pressure."));
        tooltips.put("Repeater Metadata Sources", Tooltips.htmlRaw(
                "How Repeater tab metadata was resolved this session.",
                "<b>id</b> request identity, <b>reqHash</b> / <b>exchHash</b> content hashes,",
                "<b>ui</b> UI fallback, <b>reuse</b> staged request reuse, <b>ambig</b> ambiguous/null."));
        tooltips.put("Heap Used / Max", Tooltips.htmlRaw(
                "JVM heap in use vs configured maximum (percent shown when max is known).",
                "Process-wide for Burp and all extensions, not exporter-only."));
        tooltips.put("Heap Committed", Tooltips.htmlRaw(
                "Heap memory currently reserved by the JVM from the OS.",
                "Percent of max heap shown when available."));
        tooltips.put("Non-Heap Used", Tooltips.htmlRaw(
                "Non-heap JVM memory (metaspace, code cache, and similar)."));
        tooltips.put("Direct Buffer Used", Tooltips.htmlRaw(
                "Direct <code>ByteBuffer</code> memory allocated outside the Java heap (network I/O, NIO)."));
        tooltips.put("Mapped Buffer Used", Tooltips.htmlRaw(
                "Memory-mapped file regions held by the JVM."));
        tooltips.put("Threads (Live / Peak)", Tooltips.htmlRaw(
                "JVM thread count now vs peak since JVM start."));
        tooltips.put("GC (Count / Time)", Tooltips.htmlRaw(
                "Cumulative garbage-collection cycles and total GC wall time for this JVM."));
        tooltips.put("Process CPU Load", Tooltips.htmlRaw(
                "Recent CPU utilization for the Burp JVM process (0&ndash;100%).",
                "Shows <b>n/a</b> when the operating system does not expose a reading."));
        tooltips.put("Throughput (10s)", Tooltips.htmlRaw(
                "Rolling search database export throughput over the last 10 seconds.",
                "Based on successful document acknowledgements across all indexes."));
        tooltips.put("Exported Docs", Tooltips.htmlRaw(
                "Session total of documents successfully indexed to the search database (all indexes)."));
        tooltips.put("Count Basis", Tooltips.htmlRaw(
                "Live Database Counts and clipboard values use in-process session counters.",
                "Stop pushes the final exporter <code>stats_snapshot</code> but does not call",
                "<code>_refresh</code>/<code>_count</code> or duplicate database counts in Log."));
        tooltips.put("Authorization Recovery", Tooltips.htmlRaw(
                "Whether database sends are paused after repeated HTTP 401/403 responses.",
                "Queued retry and live-traffic work is retained while automatic probes use",
                "increasing backoff. Successful probes revalidate selected indexes before resuming.",
                "If the cluster identity changed or indexes were recreated, reproducible snapshots",
                "are replayed to the database without duplicating Files output."));
        tooltips.put("Database Exported Size", Tooltips.htmlRaw(
                "Estimated total bulk bytes successfully indexed to the search database this session."));
        tooltips.put("Files Exported Size", Tooltips.htmlRaw(
                "Session total bytes written to the configured file export destination."));
        tooltips.put("Exported Failures", Tooltips.htmlRaw(
                "<b>Exported Failures</b>",
                "Session total of documents that reported a failed search-database push.",
                "Does not decrement when a later retry succeeds — see Recovered Failures.",
                "Not a count of every retry round. Also check Permanent Drops, Retry Drops,",
                "Queued, and Consecutive Failures."));
        tooltips.put("Recovered Failures", Tooltips.htmlRaw(
                "<b>Recovered Failures</b>",
                "Documents that failed an earlier push and later succeeded via the retry drain.",
                "Retry-from-queue is assumed while export is running.",
                "Log lines for recoveries include <code>evidence=bulk_item_success</code> when the",
                "search database acknowledged those documents in a bulk response.",
                "Misc Stats shows the session total across all indexes; Database Counts shows the same total per index."));
        tooltips.put("Last Success", Tooltips.htmlRaw(
                "How long ago any OpenSearch push last succeeded (any index).",
                "Shows <b>never</b> when no success has been recorded this session."));
        tooltips.put("Consecutive Failures", Tooltips.htmlRaw(
                "OpenSearch push failures since the most recent success.",
                "Resets to zero on any successful push."));
        tooltips.put("Mis-gate Suspects", Tooltips.htmlRaw(
                "Requests whose <code>Content-Type</code> declares a web form",
                "(<code>application/x-www-form-urlencoded</code> or <code>multipart/*</code>) but the exporter",
                "skipped Burp BODY parameter enumeration because the logical body (after",
                "<code>Content-Encoding</code> decompress when applicable) sniffed as binary.",
                "<p>Wire evidence is still exported (<code>body.b64</code>; <code>body.text</code> when",
                "insight rules allow). <code>request.parameters</code> may omit form fields on purpose.",
                "Common on analytics and measurement posts (for example GA4",
                "<code>app-measurement.com</code>). This is <b>not</b> an export failure.</p>",
                "<p>When this host matters to your validation set, use the Wiki Data Integrity",
                "logging guidance and Exporter-index detail events:",
                "<code>event.type=parameter_integrity_detail</code>,",
                "<code>event.data.category=misgate_binary</code>.</p>"));
        tooltips.put("Skipped BODY Enumeration", Tooltips.htmlRaw(
                "All requests where BODY parameter enumeration was not applied to",
                "<code>request.parameters</code> for this session.",
                "<p>Includes mis-gate suspects (declared form/multipart + binary sniff), declared",
                "binary/protobuf/grpc types, empty bodies, and other BODY-skip fast paths.",
                "<b>Mis-gate Suspects</b> is the narrower subset where the declared type looked like a",
                "form but inference said binary.</p>"));
        tooltips.put("Wire BODY Replaced", Tooltips.htmlRaw(
                "Documents where the on-the-wire body was compressed (or otherwise transformed), Burp",
                "returned unusable or missing BODY parameter rows, and the exporter decompressed the",
                "payload and replaced <code>request.parameters</code> BODY rows from parseable",
                "urlencoded logical bytes.",
                "<p>Typical on gzip-wrapped form posts (for example Fiserv ThreatMetrix",
                "<code>clear.png</code>, <code>httpbin.org/post</code>). Distinct from",
                "<b>Supplemental BODY Used</b>, which covers uncompressed wire paths where Burp",
                "enumerated no BODY rows.</p>"));
        tooltips.put("Skip-path Rescued", Tooltips.htmlRaw(
                "Documents where BODY enumeration was skipped (the BODY-skip fast path) but the",
                "declared urlencoded body still contained parseable form fields in logical bytes;",
                "the exporter added supplemental BODY rows to <code>request.parameters</code> anyway.",
                "<p><b>0</b> is normal when every skip-path body is truly non-form binary.",
                "Non-zero is usually a successful correction; use Data Integrity detail events",
                "for URL-level validation if this host matters.</p>"));
        tooltips.put("Supplemental BODY Used", Tooltips.htmlRaw(
                "Documents where the exporter added at least one BODY row to",
                "<code>request.parameters</code> from logical urlencoded bytes when Burp did not",
                "supply usable BODY parameters (uncompressed wire, no wire replace).",
                "<p>This counter uses session skip-reason accounting. The startup DEBUG rollup",
                "<code>supplemental_added=</code> in <code>[ParameterIntegrity]</code> logs can be",
                "higher because it also counts a broader log category for the same family of",
                "fixes. Detail events keep representative sample URLs only.</p>"));
        tooltips.put("Supplemental Rejected (non-form)", Tooltips.htmlRaw(
                "Documents where the exporter refused to invent BODY parameter rows because the",
                "logical body after decompress looked like JSON, protobuf, or another non-form",
                "shape—not a urlencoded field list.",
                "<p>Prevents false-positive <code>request.parameters</code> on compressed JSON APIs",
                "declared as forms. Raw body export is unchanged; review only if this host",
                "and BODY parameter helper matter to your current test.</p>"));
        tooltips.put("Wire BODY Dropped (entries)", Tooltips.htmlRaw(
                "Count of individual <code>request.parameters</code> BODY <b>entries</b> removed,",
                "not failed documents.",
                "<p>Sources include garbage BODY rows on compressed wire (control characters,",
                "bracket-prefixed names) and the 1,000 BODY parameter cap. Pair with",
                "<b>Wire BODY Replaced</b> / <b>Supplemental BODY Used</b> for document-level",
                "fixes. BODY cap hits also log <code>[ParameterIntegrity] BODY parameters truncated",
                "to 1000</code> (live DEBUG) or a startup DEBUG summary. Use Data Integrity detail",
                "events for the URL-level drill-down.</p>"));
        tooltips.put("Bulk In-Flight", Tooltips.htmlRaw(
                "Search database bulk HTTP requests currently executing.",
                "Incremented at bulk start and decremented when the request completes."));
        tooltips.put("Permanent Drops", Tooltips.htmlRaw(
                "Documents permanently removed this session and not retried again:",
                "non-retryable search database errors (mapping/parse/validation), and queued retry",
                "documents discarded when Stop's bounded retry drain ends (about 20 seconds).",
                "Force-stop aborts the drain early.",
                "Stop discards also appear in the Log panel as <code>Discarded N queued retry document(s)</code>."));
        tooltips.put("Permanent Drop Reasons", Tooltips.htmlRaw(
                "Stable reason totals for Permanent Drops in this session.",
                "Examples include maximum-fit rejection, mapping/validation rejection, bounded Stop",
                "discard, and destination unavailable. Values use <code>reason=count</code>."));
        tooltips.put("Body Truncations", Tooltips.htmlRaw(
                "Search/database documents prefix-truncated to fit the live bulk byte budget under",
                "destination pressure (bodies first, then other large strings, then trailing nested",
                "list elements). Indexed docs keep original <code>body.length</code> when bodies shrink",
                "and set <code>truncated=true</code> on affected objects.",
                "File export is not truncated by this path."));
        tooltips.put("Body Truncations by Index", Tooltips.htmlRaw(
                "Unique search/database documents prefix-truncated during this session, grouped by",
                "index. Zero-count indexes are omitted. Stable operation IDs prevent retries and",
                "re-fitting the same document from inflating these totals.",
                "File export is not truncated by this path."));
        tooltips.put("Failures", Tooltips.htmlRaw(
                "<b>Failures</b>",
                "Documents counted when a search push reported them failed.",
                "Does not decrement on later recovery — see Recovered Failures.",
                "Not every retry round — see <b>Retry Drain Pushes</b>. Use Permanent Drops, Retry Drops,",
                "Queued, and Log <code>evidence=bulk_item_success</code> to judge loss vs recovery."));
        tooltips.put("Retry Drain Pushes", Tooltips.htmlRaw(
                "<b>Retry Drain Pushes</b>",
                "Documents pushed again by the retry drain this session (batch sizes summed).",
                "Increments on every drain push, including pushes that fail and re-queue.",
                "Distinct from Failures (first failure) and Recovered Failures (later success).",
                "Log: INFO <code>Retry drain push starting:</code>; WARN on failed push; INFO on recovery."));
        tooltips.put("Queue", Tooltips.htmlRaw(
                "Spill-file backlog when the in-memory traffic queue is full.",
                "Format: <b>N docs (X.X MiB)</b>."));
        tooltips.put("Oldest Age (s)", Tooltips.htmlRaw(
                "Age in seconds of the oldest document in the spill queue.",
                "High values indicate sustained backpressure on live traffic export."));
        tooltips.put("Enqueued / Dequeued / Dropped", Tooltips.htmlRaw(
                "Spill queue lifetime counters: written to spill / drained back to memory / dropped."));
        tooltips.put("Drop Reasons", Tooltips.htmlRaw(
                "Spill and traffic drop breakdown (session totals), in order:",
                "<b>spill full / low-disk reject new</b> / <b>spill requeue failed</b> /",
                "<b>expired prune</b>.",
                "When Traffic Spill is Full, new live traffic is rejected so the earliest backlog is kept."));
        tooltips.put("Traffic Spill Status", Tooltips.htmlRaw(
                "Live traffic overflow valve status for the current run.",
                "<b>Ready</b>: spill empty. <b>In use</b>: spill holds backlog.",
                "<b>Full</b> (red): spill cannot accept more; new live traffic is rejected.",
                "Complements Soft Outage (destination pacing) across all search destinations."));
        tooltips.put("Queue Depth", Tooltips.htmlRaw(
                "Per-index documents waiting in the indexing retry coordinator.",
                "Comma-separated <b>index: N queued</b> pairs; <b>&mdash;</b> when every queue is empty."));
        tooltips.put("Oldest Queued Age", Tooltips.htmlRaw(
                "Per-index age of the oldest document in each retry queue.",
                "Comma-separated <b>index: Ns</b> pairs; <b>&mdash;</b> when nothing is queued."));
        tooltips.put("Soft Outage", Tooltips.htmlRaw(
                "Whether soft capacity outage mode is active.",
                "<b>Yes</b> (yellow) means gateway/timeout/429-class pressure is pacing export via the",
                "shared cooldown and retry drain; the destination stays enabled (unlike auth",
                "failures, which disable the database destination).",
                "<b>No</b> (green) means no soft outage. Clears after meaningful payload recovery,",
                "not from exporter log/stats singles alone."));
        tooltips.put("Database Exported Size", Tooltips.htmlRaw(
                "Total bytes successfully exported to the search database this run."));
        tooltips.put("Files Exported Size", Tooltips.htmlRaw(
                "Total bytes successfully written to the files destination this run."));
        tooltips.put("Bulk Byte Budget", Tooltips.htmlRaw(
                "Adaptive bulk payload byte ceiling for search-database pushes.",
                "Shows the live value during export and preserves the last active value after Stop.",
                "All search destinations share AIMD control (Amazon starts near 1 MiB;",
                "OpenSearch/Elasticsearch start at 5 MiB). Floor 512 KiB; grows toward 5 MiB;",
                "jumps toward last-known-good after soft-outage clear or success streaks."));
        tooltips.put("Snapshot Flush Cap", Tooltips.htmlRaw(
                "How many snapshot bulk flushes may run in parallel.",
                "Shows the live value during export and preserves the last active value after Stop.",
                "Drops to <b>1</b> under hard capacity pressure (429/502/503/504/transport), restores",
                "to <b>2</b> after success or soft-outage clear, and may rise to <b>3</b> when a",
                "healthy success streak shows unused headroom."));
        tooltips.put("Snapshot Build-Ahead", Tooltips.htmlRaw(
                "Current quantized byte and semaphore-permit reservation held by prepared snapshot",
                "documents waiting for chunk assembly, followed by the fixed 64 MiB / 1,024-permit",
                "capacity. One larger document may reserve the full envelope alone.",
                "This measures only prepared queue build-ahead, not active serialization, in-flight",
                "flushes, Burp-owned objects, or other JVM allocations."));
        tooltips.put("Cooldown Remaining", Tooltips.htmlRaw(
                "Longest remaining wait before the next bulk send across hard cluster cooldown",
                "and any per-index mild cooldown. Hard pressure (429/502/503/504, transport, probes)",
                "is cluster-wide (to 60s); mild per-item capacity is per-index (cap 15s) so one hot",
                "index does not freeze others. Stop drain waits at most 2s. <b>&mdash;</b> when idle."));
        tooltips.put("Pressure Streak", Tooltips.htmlRaw(
                "Consecutive hard capacity-pressure events since the last successful bulk.",
                "Drives hard cooldown escalation (5s → 15s → 30s → 60s). Mild item pressure uses a",
                "separate per-index streak. Resets on success."));
        tooltips.put("Soft Outage Entries", Tooltips.htmlRaw(
                "How many times soft capacity outage mode was entered this export run",
                "(false → true transitions). Resets on Start."));
        tooltips.put("Capacity Events", Tooltips.htmlRaw(
                "How many times the shared capacity cooldown was extended this export run.",
                "Counts new/longer deadlines from bulk HTTP pressure, transport pressure, and",
                "capacity probes. Resets on Start."));
        tooltips.put("Peak Traffic Queue", Tooltips.htmlRaw(
                "Highest live traffic queue depth observed during the current export run.",
                "Docs and estimated serialized bulk bytes; resets on Start."));
        tooltips.put("Peak Traffic Spill", Tooltips.htmlRaw(
                "Highest Traffic Spill file backlog depth observed during the current export run.",
                "Docs and bytes; resets on Start."));
        tooltips.put("Peak Retry Queue", Tooltips.htmlRaw(
                "Highest total retry-queue depth observed during the current export run.",
                "Summed across all exporter indexes; resets on Start."));
        tooltips.put("Peak Snapshot Chunk Target", Tooltips.htmlRaw(
                "Highest snapshot chunk doc-count target reached during the current export run.",
                "Includes proxy history and other startup snapshots; resets on Start."));
        tooltips.put("Peak Snapshot Flush (ms)", Tooltips.htmlRaw(
                "Longest single snapshot chunk flush wall time observed during the current export run.",
                "Resets on Start."));
        tooltips.put("Peak Snapshot Build-Ahead", Tooltips.htmlRaw(
                "Highest quantized byte and semaphore-permit reservation held by prepared snapshot",
                "documents waiting for chunk assembly during this export run.",
                "Use with Snapshot Build-Ahead to verify the 64 MiB queue envelope independently of",
                "the JVM heap chart. Resets on Start."));
        tooltips.put("Peak Cooldown Wait (ms)", Tooltips.htmlRaw(
                "Longest shared capacity-cooldown park observed before a bulk send this run.",
                "Includes capped Stop-drain waits. Resets on Start."));
        tooltips.put("Peak Flush Slot Wait (ms)", Tooltips.htmlRaw(
                "Longest wait for an in-flight snapshot flush slot this run.",
                "Snapshot export waits for the transport timeout/retry outcome instead of abandoning a live request.",
                "Stop still cancels active run work. Resets on Start."));
        tooltips.put("File Total Docs Exported", Tooltips.htmlRaw(
                "Session total of documents successfully written to file export."));
        tooltips.put("File Total Failures", Tooltips.htmlRaw(
                "Session total of failed file export write attempts."));
        return tooltips;
    }

    private static String formatKeyLabel(String key) {
        if (key == null || key.isBlank()) {
            return "";
        }
        String[] parts = key.toLowerCase(Locale.ROOT).replace('_', ' ').split("\\s+");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(Character.toUpperCase(part.charAt(0))).append(part.substring(1));
        }
        return sb.toString();
    }

    private void sampleRateSeries() {
        long now = System.currentTimeMillis();
        if (previousSampleAtMs < 0) {
            previousSampleAtMs = now;
            firstSampleAtMs = now;
            for (String indexKey : ExportStats.getIndexKeys()) {
                previousSuccessByIndex.put(indexKey, ExportStats.getSuccessCount(indexKey));
                previousBytesByIndex.put(indexKey, ExportStats.getExportedBytes(indexKey));
                ensureSeries(indexKey);
                previousFileSuccessByIndex.put(indexKey, FileExportStats.getSuccessCount(indexKey));
                previousFileBytesByIndex.put(indexKey, FileExportStats.getExportedBytes(indexKey));
                ensureFileSeries(indexKey);
            }
            updateChartWindow(now);
            return;
        }

        double elapsedSec = Math.max(0.001, (now - previousSampleAtMs) / 1000.0);
        Millisecond tick = new Millisecond(new Date(now));
        for (String indexKey : ExportStats.getIndexKeys()) {
            ensureSeries(indexKey);
            long currentSuccess = ExportStats.getSuccessCount(indexKey);
            long currentBytes = ExportStats.getExportedBytes(indexKey);
            long previousSuccess = previousSuccessByIndex.getOrDefault(indexKey, currentSuccess);
            long previousBytes = previousBytesByIndex.getOrDefault(indexKey, currentBytes);

            double docsPerSec = Math.max(0.0, (currentSuccess - previousSuccess) / elapsedSec);
            double kibPerSec = Math.max(0.0, (currentBytes - previousBytes) / 1024.0 / elapsedSec);
            docsSeriesByIndex.get(indexKey).addOrUpdate(tick, docsPerSec);
            kibSeriesByIndex.get(indexKey).addOrUpdate(tick, kibPerSec);

            previousSuccessByIndex.put(indexKey, currentSuccess);
            previousBytesByIndex.put(indexKey, currentBytes);

            ensureFileSeries(indexKey);
            long currentFileSuccess = FileExportStats.getSuccessCount(indexKey);
            long currentFileBytes = FileExportStats.getExportedBytes(indexKey);
            long previousFileSuccess = previousFileSuccessByIndex.getOrDefault(indexKey, currentFileSuccess);
            long previousFileBytes = previousFileBytesByIndex.getOrDefault(indexKey, currentFileBytes);

            double fileDocsPerSec = Math.max(0.0, (currentFileSuccess - previousFileSuccess) / elapsedSec);
            double fileKibPerSec = Math.max(0.0, (currentFileBytes - previousFileBytes) / 1024.0 / elapsedSec);
            fileDocsSeriesByIndex.get(indexKey).addOrUpdate(tick, fileDocsPerSec);
            fileKibSeriesByIndex.get(indexKey).addOrUpdate(tick, fileKibPerSec);

            previousFileSuccessByIndex.put(indexKey, currentFileSuccess);
            previousFileBytesByIndex.put(indexKey, currentFileBytes);
        }
        sampleMemorySeries(tick);
        previousSampleAtMs = now;
        updateChartWindow(now);
    }

    /**
     * Appends one sample of {@code Heap Used} and {@code Heap Committed} (in MiB) to the
     * memory time-series. Negative readings (rare; only happen if the snapshot is missing
     * data) are skipped rather than charted as zeros so the line doesn't dip artificially.
     */
    private void sampleMemorySeries(Millisecond tick) {
        SystemMetrics.Snapshot snapshot = SystemMetrics.snapshot();
        long heapUsedBytes = snapshot.heapUsedBytes();
        long heapCommittedBytes = snapshot.heapCommittedBytes();
        if (heapUsedBytes >= 0) {
            heapUsedSeries.addOrUpdate(tick, heapUsedBytes / (1024.0 * 1024.0));
        }
        if (heapCommittedBytes >= 0) {
            heapCommittedSeries.addOrUpdate(tick, heapCommittedBytes / (1024.0 * 1024.0));
        }
    }

    private void ensureSeries(String indexKey) {
        docsSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            docsPerSecondDataset.addSeries(s);
            return s;
        });
        kibSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            kibPerSecondDataset.addSeries(s);
            return s;
        });
    }

    private void ensureFileSeries(String indexKey) {
        fileDocsSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            fileDocsPerSecondDataset.addSeries(s);
            return s;
        });
        fileKibSeriesByIndex.computeIfAbsent(indexKey, key -> {
            TimeSeries s = new TimeSeries(displaySeriesLabel(key));
            s.setMaximumItemCount(CHART_MAX_POINTS);
            fileKibPerSecondDataset.addSeries(s);
            return s;
        });
    }

    private static String displaySeriesLabel(String indexKey) {
        if (indexKey == null || indexKey.isBlank()) {
            return "";
        }
        return Character.toUpperCase(indexKey.charAt(0)) + indexKey.substring(1);
    }

    /**
     * Builds a per-sink throughput time-series chart. The chart itself never carries a built-in
     * title -- the merged "File Export" / "Database Export" section headers above each chart
     * pair (see {@link #fileChartsSectionHeader} / {@link #openSearchChartsSectionHeader})
     * provide the sink context, and the Y-axis label disambiguates Docs/sec vs KiB/sec on the
     * left edge of each individual chart.
     */
    private static JFreeChart createRateChart(
            String yLabel,
            TimeSeriesCollection dataset,
            boolean showLegend) {
        Color chartBackground = chartBackgroundPaint();
        Color plotBackground = plotBackgroundPaint();
        Color gridForeground = gridPaint();
        JFreeChart chart = ChartFactory.createTimeSeriesChart(null, null, yLabel, dataset, showLegend, false, false);
        chart.setBackgroundPaint(chartBackground);
        chart.setPadding(RectangleInsets.ZERO_INSETS);
        XYPlot plot = chart.getXYPlot();
        plot.setInsets(new RectangleInsets(1, 2, 2, 2));
        plot.setBackgroundPaint(plotBackground);
        plot.setDomainGridlinePaint(gridForeground);
        plot.setRangeGridlinePaint(gridForeground);
        plot.setDomainGridlinesVisible(true);
        plot.setRangeGridlinesVisible(true);
        ValueAxis domain = plot.getDomainAxis();
        configureStatsRangeAxis(plot, yLabel);
        NumberAxis range = (NumberAxis) plot.getRangeAxis();
        // Throughput charts are non-negative metrics; keep zero anchored at the bottom.
        range.setRangeType(RangeType.POSITIVE);
        range.setAutoRangeIncludesZero(true);
        range.setAutoRangeStickyZero(true);
        range.setLowerMargin(0.0);
        range.setUpperMargin(RANGE_AXIS_UPPER_MARGIN);
        // Keep Y-axis labels/ticks as whole numbers for readability.
        range.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        if (domain != null) {
            domain.setLabelPaint(TEXT_FG);
            domain.setTickLabelPaint(TEXT_FG);
            domain.setTickLabelsVisible(true);
            domain.setLabel(null);
            if (domain instanceof DateAxis dateAxis) {
                // Keep x-axis labels human-readable as local wall-clock time.
                dateAxis.setDateFormatOverride(new SimpleDateFormat(DOMAIN_TIME_PATTERN));
            }
        }
        range.setLabelPaint(TEXT_FG);
        range.setTickLabelPaint(TEXT_FG);
        XYLineAndShapeRenderer renderer = (XYLineAndShapeRenderer) plot.getRenderer();
        renderer.setDefaultStroke(new BasicStroke(CHART_LINE_STROKE_WIDTH, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        if (chart.getLegend() != null) {
            chart.getLegend().setBackgroundPaint(chartBackground);
            chart.getLegend().setItemPaint(TEXT_FG);
        }
        applyChartFonts(chart);
        return chart;
    }

    private static void configureStatsRangeAxis(XYPlot plot, String yLabel) {
        StatsChartRangeAxis rangeAxis = new StatsChartRangeAxis(yLabel);
        plot.setRangeAxis(rangeAxis);
        plot.setFixedRangeAxisSpace(null);
    }

    private void applyChartStyles() {
        applyChartStyle(docsChart);
        applyChartStyle(kibChart);
        applyChartStyle(fileDocsChart);
        applyChartStyle(fileKibChart);
        applyMemoryChartStyle(memoryChart);
        refreshChartRangeAxes();
        applyAllChartFonts();
    }

    /**
     * Applies the currently-selected chart style to the memory chart. Mirrors the
     * paint/stroke/renderer logic of {@link #applyChartStyle(JFreeChart)} but operates on the
     * memory chart's two series, mapped through {@link #MEMORY_SERIES_TO_STYLE} so they
     * inherit the throughput chart's green/yellow palette and the same Accessible-style
     * cues (dashed strokes plus shape markers) so heap-used and heap-committed remain
     * distinguishable for color-blind users when the Accessible style is active.
     */
    private void applyMemoryChartStyle(JFreeChart chart) {
        XYPlot plot = chart.getXYPlot();
        XYLineAndShapeRenderer renderer = rendererForStyle(chart);
        renderer.setDefaultStroke(memoryLineStroke());
        for (int i = 0; i < MEMORY_SERIES_TO_STYLE.length; i++) {
            int styleIndex = MEMORY_SERIES_TO_STYLE[i];
            renderer.setSeriesPaint(i, seriesLinePaint(styleIndex));
            renderer.setSeriesStroke(i, seriesStroke(styleIndex));
            renderer.setSeriesShape(i, seriesMarkerShape(styleIndex));
            renderer.setSeriesShapesVisible(i, seriesShapesVisible(styleIndex));
            renderer.setSeriesShapesFilled(i, seriesShapesFilled(styleIndex));
        }
        if (chartStyleIndex == 1) {
            XYSplineRenderer slickRenderer = (XYSplineRenderer) renderer;
            slickRenderer.setFillType(XYSplineRenderer.FillType.TO_LOWER_BOUND);
            for (int i = 0; i < MEMORY_SERIES_TO_STYLE.length; i++) {
                int styleIndex = MEMORY_SERIES_TO_STYLE[i];
                slickRenderer.setSeriesFillPaint(i, seriesAreaPaint(styleIndex));
            }
        }
        plot.setDataset(1, null);
        plot.setRenderer(1, null);
    }

    /**
     * Default stroke applied to the memory chart's renderer as a fallback for series that
     * have not yet had a per-series stroke installed by {@link #applyMemoryChartStyle}.
     * Held to a single thin {@link #CHART_LINE_STROKE_WIDTH} so any transient un-styled
     * series matches the throughput charts' line weight.
     */
    private BasicStroke memoryLineStroke() {
        return chartStyleIndex == 1 ? smoothChartLineStroke() : chartLineStroke();
    }

    private void applyChartStyle(JFreeChart chart) {
        XYPlot plot = chart.getXYPlot();
        XYLineAndShapeRenderer renderer = rendererForStyle(chart);
        renderer.setDefaultStroke(chartStyleIndex == 1 ? smoothChartLineStroke() : chartLineStroke());
        for (int i = 0; i < SERIES_STYLES.length; i++) {
            renderer.setSeriesPaint(i, seriesLinePaint(i));
            renderer.setSeriesStroke(i, seriesStroke(i));
            renderer.setSeriesShape(i, seriesMarkerShape(i));
            renderer.setSeriesShapesVisible(i, seriesShapesVisible(i));
            renderer.setSeriesShapesFilled(i, seriesShapesFilled(i));
        }
        if (chartStyleIndex == 1) {
            XYSplineRenderer slickRenderer = (XYSplineRenderer) renderer;
            slickRenderer.setFillType(XYSplineRenderer.FillType.TO_LOWER_BOUND);
            for (int i = 0; i < SERIES_STYLES.length; i++) {
                slickRenderer.setSeriesFillPaint(i, seriesAreaPaint(i));
            }
        }
        plot.setDataset(1, null);
        plot.setRenderer(1, null);
    }

    private XYLineAndShapeRenderer rendererForStyle(JFreeChart chart) {
        XYPlot plot = chart.getXYPlot();
        if (chartStyleIndex == 1) {
            if (plot.getRenderer() instanceof XYSplineRenderer splineRenderer) {
                splineRenderer.setPrecision(SMOOTH_SPLINE_PRECISION);
                return splineRenderer;
            }
            XYSplineRenderer splineRenderer = new XYSplineRenderer(SMOOTH_SPLINE_PRECISION);
            plot.setRenderer(splineRenderer);
            return splineRenderer;
        }
        if (plot.getRenderer() instanceof XYLineAndShapeRenderer lineRenderer
                && !(lineRenderer instanceof XYSplineRenderer)) {
            return lineRenderer;
        }
        XYLineAndShapeRenderer lineRenderer = new XYLineAndShapeRenderer();
        plot.setRenderer(lineRenderer);
        return lineRenderer;
    }

    private static void setChartDomainLabel(JFreeChart chart, String label) {
        ValueAxis domain = chart.getXYPlot().getDomainAxis();
        if (domain != null) {
            domain.setLabel(label);
        }
    }

    private static ChartPanel createRateChartPanel(JFreeChart chart) {
        ChartPanel panel = new ChartPanel(chart);
        configureChartPanelDrawing(panel);
        return panel;
    }

    /**
     * Configures {@link ChartPanel} so charts render at the panel's actual size. JFreeChart's
     * defaults cap drawing at 2048×1536 and scale the bitmap to fit, which stretches or
     * compresses axis and title fonts when the Stats tab is resized.
     */
    private static void configureChartPanelDrawing(ChartPanel panel) {
        panel.setFont(chartBaseFont());
        panel.setMouseWheelEnabled(false);
        panel.setPopupMenu(null);
        panel.setMinimumDrawWidth(0);
        panel.setMinimumDrawHeight(0);
        panel.setMaximumDrawWidth(Integer.MAX_VALUE);
        panel.setMaximumDrawHeight(Integer.MAX_VALUE);
    }

    private JPanel createSharedLegendPanel() {
        JPanel legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        legendPanel.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 0));
        legendPanel.setOpaque(false);
        return legendPanel;
    }

    /**
     * Creates the memory chart's standalone legend panel. Uses the same FlowLayout/insets as
     * {@link #createSharedLegendPanel()} so the memory legend visually rhymes with the shared
     * legend at the top of the per-sink charts. Items are populated by
     * {@link #refreshMemoryLegendPanel()}.
     */
    private JPanel createMemoryLegendPanel() {
        JPanel legendPanel = new Tooltips.HtmlPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        legendPanel.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 0));
        legendPanel.setOpaque(false);
        return legendPanel;
    }

    /**
     * Tooltip explaining the JVM-wide scope of the memory chart, so users do not assume the
     * series represent only the exporter extension's allocations.
     */
    private static String memoryChartTooltip() {
        return Tooltips.htmlRaw(
                "<b>JVM Heap (Burp + Extensions)</b>",
                "Process-wide heap usage for the JVM that hosts Burp Suite. The exporter cannot",
                "be isolated from Burp itself or from other loaded extensions, because Java does",
                "not partition heap by classloader.",
                "",
                "Series:",
                "&nbsp;&nbsp;<b>Heap Used</b> &mdash; live heap currently retained by all reachable objects.",
                "&nbsp;&nbsp;<b>Heap Committed</b> &mdash; heap currently reserved by the JVM from the OS.",
                "",
                "Y axis: MiB (mebibytes).",
                "",
                "How to read it:",
                "&nbsp;&nbsp;- A non-zero baseline when the exporter is stopped is normal; that memory",
                "&nbsp;&nbsp;&nbsp;&nbsp;belongs to Burp and other extensions, not this exporter.",
                "&nbsp;&nbsp;- Sustained <b>Heap Used</b> approaching <b>Heap Committed</b> indicates JVM",
                "&nbsp;&nbsp;&nbsp;&nbsp;memory pressure during the run.",
                "&nbsp;&nbsp;- Sawtooth dips reflect garbage collection cycles and are expected."
        );
    }

    private JButton createChartStyleButton() {
        JButton button = new Tooltips.HtmlButton(chartStyleButtonLabel());
        button.setFocusable(false);
        button.setFont(chartBaseFont());
        Tooltips.apply(button, Tooltips.htmlRaw("Cycle chart styles: <b>Smooth</b>, <b>Simple</b>, and <b>Accessible</b>."));
        button.addActionListener(event -> cycleChartStyle());
        return button;
    }

    private void refreshSharedLegendPanel() {
        sharedLegendPanel.removeAll();
        sharedLegendPanel.add(chartStyleButton);
        for (int i = 0; i < SERIES_STYLES.length; i++) {
            JLabel legendItem = new JLabel(SERIES_STYLES[i].label(), new LegendSampleIcon(i), SwingConstants.LEFT);
            legendItem.setForeground(TEXT_FG);
            legendItem.setFont(chartLegendFont());
            legendItem.setIconTextGap(6);
            sharedLegendPanel.add(legendItem);
        }
        chartStyleButton.setText(chartStyleButtonLabel());
        sharedLegendPanel.revalidate();
        sharedLegendPanel.repaint();
        refreshMemoryLegendPanel();
    }

    /**
     * Rebuilds the memory chart's legend so the two heap series ({@code Heap Used} and
     * {@code Heap Committed}) render with the same theme-aware paint (mapped through
     * {@link #MEMORY_SERIES_TO_STYLE}) that the chart itself uses. Called from
     * {@link #refreshSharedLegendPanel()} so style cycles always update both legends in
     * lock-step.
     */
    private void refreshMemoryLegendPanel() {
        memoryLegendPanel.removeAll();
        String[] labels = new String[] { "Heap Used", "Heap Committed" };
        String tooltip = memoryChartTooltip();
        for (int i = 0; i < labels.length; i++) {
            JLabel legendItem = new Tooltips.HtmlLabel(labels[i]);
            legendItem.setIcon(new MemoryLegendIcon(i));
            legendItem.setHorizontalAlignment(SwingConstants.LEFT);
            legendItem.setForeground(TEXT_FG);
            legendItem.setFont(chartLegendFont());
            legendItem.setIconTextGap(6);
            Tooltips.apply(legendItem, tooltip);
            memoryLegendPanel.add(legendItem);
        }
        memoryLegendPanel.revalidate();
        memoryLegendPanel.repaint();
    }

    private void cycleChartStyle() {
        chartStyleIndex = switch (chartStyleIndex) {
            case 1 -> 0;
            case 0 -> 2;
            default -> 1;
        };
        RuntimeConfig.updateStatsChartStyle(chartStyleIndex + 1);
        applyChartStyles();
        refreshSharedLegendPanel();
        refreshDashboard();
    }

    private String chartStyleButtonLabel() {
        return CHART_STYLE_NAMES[chartStyleIndex];
    }

    private static boolean isDarkTheme() {
        return isDark(uiColor("Panel.background", new Color(38, 38, 38)));
    }

    private static Color chartBackgroundPaint() {
        return uiColor("Panel.background", new Color(38, 38, 38));
    }

    private static Color plotBackgroundPaint() {
        Color plotBackground = uiColor("Table.background", chartBackgroundPaint());
        if (plotBackground.equals(chartBackgroundPaint())) {
            return adjust(plotBackground, isDark(plotBackground) ? 6 : -6);
        }
        return plotBackground;
    }

    private static Color gridPaint() {
        Color separator = uiColor("Separator.foreground", adjust(plotBackgroundPaint(), isDarkTheme() ? 28 : -28));
        if (separator.equals(chartBackgroundPaint())) {
            return adjust(separator, isDarkTheme() ? 32 : -32);
        }
        return separator;
    }

    private Color seriesSolidColor(int index) {
        return SERIES_STYLES[index].paint();
    }

    private Paint seriesPaint(int index) {
        SeriesStyle base = SERIES_STYLES[index];
        return switch (chartStyleIndex) {
            case 0 -> withAlpha(base.paint(), smoothSeriesAlpha(index, isDarkTheme() ? 245 : 225, false));
            case 1 -> slickGradientAreaPaint(index, base);
            case 2 -> base.paint();
            default -> base.paint();
        };
    }

    private Paint seriesLinePaint(int index) {
        if (chartStyleIndex == 1) {
            int alpha = smoothSeriesAlpha(
                    index,
                    isDarkTheme() ? SMOOTH_LINE_ALPHA_DARK : SMOOTH_LINE_ALPHA_LIGHT,
                    true);
            return withAlpha(seriesSolidColor(index), alpha);
        }
        return seriesPaint(index);
    }

    private Paint seriesAreaPaint(int index) {
        return chartStyleIndex == 1 ? seriesPaint(index) : seriesLinePaint(index);
    }

    /**
     * Paint for the shared top legend swatches. Uses fully opaque series colors so keys stay
     * readable; chart area fills keep their separate transparency settings.
     */
    private Paint legendPaint(int index, int topY, int bottomY) {
        Color opaque = seriesSolidColor(index);
        if (chartStyleIndex == 1) {
            Color bottom = withAlpha(adjust(opaque, isDarkTheme() ? -34 : -26),
                    isDarkTheme() ? SMOOTH_LEGEND_BOTTOM_ALPHA_DARK : SMOOTH_LEGEND_BOTTOM_ALPHA_LIGHT);
            return new GradientPaint(0f, topY, opaque, 0f, bottomY, bottom);
        }
        return opaque;
    }

    private BasicStroke seriesStroke(int index) {
        // All three styles share the same CHART_LINE_STROKE_WIDTH; only the Accessible style
        // layers per-series dash patterns (carried by SeriesStyle) on top of that width so
        // series remain distinguishable for color-blind users without relying on color.
        return switch (chartStyleIndex) {
            case 0 -> chartLineStroke();
            case 1 -> smoothChartLineStroke();
            case 2 -> SERIES_STYLES[index].stroke(CHART_LINE_STROKE_WIDTH);
            default -> SERIES_STYLES[index].stroke(CHART_LINE_STROKE_WIDTH);
        };
    }

    private static BasicStroke chartLineStroke() {
        return new BasicStroke(CHART_LINE_STROKE_WIDTH, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
    }

    /** Round caps/joins so Smooth splines do not show miter facets at sharp rate peaks. */
    private static BasicStroke smoothChartLineStroke() {
        return new BasicStroke(
                CHART_LINE_STROKE_WIDTH,
                BasicStroke.CAP_ROUND,
                BasicStroke.JOIN_ROUND);
    }

    private Shape seriesMarkerShape(int index) {
        return switch (chartStyleIndex) {
            case 0 -> SERIES_STYLES[index].markerShape();
            case 1 -> SERIES_STYLES[index].markerShape();
            case 2 -> SERIES_STYLES[index].markerShape();
            case 3 -> SERIES_STYLES[index].markerShape();
            default -> SERIES_STYLES[index].markerShape();
        };
    }

    private boolean seriesShapesVisible(int index) {
        return index >= 0 && switch (chartStyleIndex) {
            case 0 -> false;
            case 1 -> false;
            case 2 -> true;
            default -> true;
        };
    }

    private boolean seriesShapesFilled(int index) {
        return switch (chartStyleIndex) {
            case 0 -> false;
            case 1 -> false;
            case 2 -> SERIES_STYLES[index].markerFilled();
            default -> SERIES_STYLES[index].markerFilled();
        };
    }

    private Paint slickGradientAreaPaint(int seriesIndex, SeriesStyle base) {
        Color top = withAlpha(
                base.paint(),
                smoothSeriesAlpha(
                        seriesIndex,
                        isDarkTheme() ? SMOOTH_FILL_TOP_ALPHA_DARK : SMOOTH_FILL_TOP_ALPHA_LIGHT,
                        false));
        Color bottom = withAlpha(
                adjust(base.paint(), isDarkTheme() ? -44 : -34),
                smoothSeriesAlpha(
                        seriesIndex,
                        isDarkTheme() ? SMOOTH_FILL_BOTTOM_ALPHA_DARK : SMOOTH_FILL_BOTTOM_ALPHA_LIGHT,
                        false));
        return new GradientPaint(0f, 0f, top, 0f, CHART_PANEL_HEIGHT / 2f, bottom, true);
    }

    /**
     * Lowers alpha for traffic and sitemap only so their overlays stay readable without
     * washing out exporter/settings/findings. {@code forLine} uses a milder factor.
     */
    private static int smoothSeriesAlpha(int seriesIndex, int baseAlpha, boolean forLine) {
        if (seriesIndex != TRAFFIC_SERIES_STYLE_INDEX && seriesIndex != SITEMAP_SERIES_STYLE_INDEX) {
            return baseAlpha;
        }
        double factor = forLine
                ? SMOOTH_TRAFFIC_SITEMAP_LINE_ALPHA_FACTOR
                : SMOOTH_TRAFFIC_SITEMAP_FILL_ALPHA_FACTOR;
        int scaled = (int) Math.round(baseAlpha * factor);
        int floor = forLine ? 90 : 16;
        return Math.clamp(scaled, floor, 255);
    }

    private static Color withAlpha(Color color, int alpha) {
        return new Color(color.getRed(), color.getGreen(), color.getBlue(), Math.clamp(alpha, 0, 255));
    }

    private static Shape circleMarker(float size) {
        float half = size / 2f;
        return new Ellipse2D.Float(-half, -half, size, size);
    }

    private static Shape squareMarker(float size) {
        float half = size / 2f;
        return new Rectangle2D.Float(-half, -half, size, size);
    }

    private static Shape diamondMarker(float size) {
        float half = size / 2f;
        Path2D.Float path = new Path2D.Float();
        path.moveTo(0, -half);
        path.lineTo(half, 0);
        path.lineTo(0, half);
        path.lineTo(-half, 0);
        path.closePath();
        return path;
    }

    private static Shape triangleMarker(float size) {
        float half = size / 2f;
        Path2D.Float path = new Path2D.Float();
        path.moveTo(0, -half);
        path.lineTo(half, half);
        path.lineTo(-half, half);
        path.closePath();
        return path;
    }

    private static Shape crossMarker(float size) {
        float half = size / 2f;
        Path2D.Float path = new Path2D.Float();
        path.moveTo(-half, -half);
        path.lineTo(half, half);
        path.moveTo(-half, half);
        path.lineTo(half, -half);
        return path;
    }

    private void updateChartWindow(long nowMs) {
        long startMs = ExportStats.getExportStartRequestedAtMs();
        if (startMs <= 0) {
            startMs = firstSampleAtMs > 0 ? firstSampleAtMs : nowMs;
        }
        if (startMs > nowMs) {
            startMs = nowMs;
        }
        long minMs = (nowMs - startMs) < CHART_WINDOW_MAX_MS ? startMs : (nowMs - CHART_WINDOW_MAX_MS);
        updateDomainRange(docsChart, minMs, nowMs);
        updateDomainRange(kibChart, minMs, nowMs);
        updateDomainRange(fileDocsChart, minMs, nowMs);
        updateDomainRange(fileKibChart, minMs, nowMs);
        updateDomainRange(memoryChart, minMs, nowMs);
        refreshChartRangeAxes();
    }

    private void refreshChartRangeAxes() {
        applyDocsPerSecondRange(docsChart, docsPerSecondDataset);
        applyDocsPerSecondRange(fileDocsChart, fileDocsPerSecondDataset);
        applyScaledByteRateRange(kibChart, kibPerSecondDataset);
        applyScaledByteRateRange(fileKibChart, fileKibPerSecondDataset);
        applyScaledMemoryRange(memoryChart, memoryDataset);
    }

    private double rangeHeadroomMultiplier() {
        return chartStyleIndex == 1 ? SPLINE_RANGE_HEADROOM_MULTIPLIER : LINE_RANGE_HEADROOM_MULTIPLIER;
    }

    /**
     * Docs/sec charts: non-negative range from data max plus headroom, rounded to integer ticks.
     */
    private void applyDocsPerSecondRange(JFreeChart chart, TimeSeriesCollection dataset) {
        NumberAxis axis = (NumberAxis) chart.getXYPlot().getRangeAxis();
        long[] domainMs = chartDomainMillis(chart);
        double max = StatsPanelFormatters.maxTimeSeriesValueInDomain(dataset, domainMs[0], domainMs[1]);
        if (max <= 0.0) {
            resetThroughputAxisToIdleRange(axis, "Docs per second");
            return;
        }
        double rangeUpper = StatsPanelFormatters.rangeCeiling(max, rangeHeadroomMultiplier());
        axis.setAutoRange(false);
        axis.setRange(0.0, rangeUpper);
        axis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
    }

    private void applyScaledByteRateRange(JFreeChart chart, TimeSeriesCollection dataset) {
        NumberAxis axis = (NumberAxis) chart.getXYPlot().getRangeAxis();
        long[] domainMs = chartDomainMillis(chart);
        double max = StatsPanelFormatters.maxTimeSeriesValueInDomain(dataset, domainMs[0], domainMs[1]);
        double headroom = rangeHeadroomMultiplier();
        if (max <= 0.0) {
            resetThroughputAxisToIdleRange(axis, "KiB per second");
            return;
        }
        StatsPanelFormatters.ChartAxisScale scale = StatsPanelFormatters.chooseByteRateAxisScale(max, headroom);
        applyScaledPositiveRange(axis, max, headroom, scale);
    }

    private void applyScaledMemoryRange(JFreeChart chart, TimeSeriesCollection dataset) {
        NumberAxis axis = (NumberAxis) chart.getXYPlot().getRangeAxis();
        long[] domainMs = chartDomainMillis(chart);
        double max = StatsPanelFormatters.maxTimeSeriesValueInDomain(dataset, domainMs[0], domainMs[1]);
        double headroom = rangeHeadroomMultiplier();
        if (max <= 0.0) {
            resetThroughputAxisToIdleRange(axis, "MiB");
            return;
        }
        StatsPanelFormatters.ChartAxisScale scale = StatsPanelFormatters.chooseMemoryAxisScale(max, headroom);
        applyScaledPositiveRange(axis, max, headroom, scale);
    }

    /**
     * Restores a throughput chart Y-axis after rates return to zero.
     *
     * <p>Byte-rate charts set an explicit {@link NumberTickUnit} while active; without clearing it,
     * idle refresh keeps a step-1 unit and labels every integer on the 0–10 default range.</p>
     */
    private static void resetThroughputAxisToIdleRange(NumberAxis axis, String yLabel) {
        axis.setLabel(yLabel);
        axis.setNumberFormatOverride(null);
        axis.setAutoTickUnitSelection(true);
        axis.setAutoRange(false);
        axis.setRange(0.0, DEFAULT_RATE_RANGE_MAX);
        axis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
    }

    private static void applyScaledPositiveRange(
            NumberAxis axis,
            double maxInBaseUnits,
            double headroomMultiplier,
            StatsPanelFormatters.ChartAxisScale scale) {
        double rangeUpper = StatsPanelFormatters.rangeUpperInBaseUnits(maxInBaseUnits, headroomMultiplier, scale);
        double niceDisplayUpper = rangeUpper / scale.displayDivisor();
        int tickStepDisplay = StatsPanelFormatters.integerDisplayTickStep(niceDisplayUpper);
        axis.setLabel(scale.label());
        axis.setNumberFormatOverride(StatsPanelFormatters.axisTickNumberFormat(scale.displayDivisor()));
        axis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        axis.setTickUnit(new NumberTickUnit(tickStepDisplay * scale.displayDivisor()));
        axis.setAutoRange(false);
        axis.setRange(0.0, rangeUpper);
    }

    private static long[] chartDomainMillis(JFreeChart chart) {
        ValueAxis domainAxis = chart.getXYPlot().getDomainAxis();
        if (domainAxis instanceof DateAxis dateAxis && !dateAxis.isAutoRange()) {
            return new long[] {
                    dateAxis.getMinimumDate().getTime(),
                    dateAxis.getMaximumDate().getTime()
            };
        }
        return new long[] { Long.MIN_VALUE, Long.MAX_VALUE };
    }

    private static void updateDomainRange(JFreeChart chart, long minMs, long maxMs) {
        if (maxMs <= minMs) {
            maxMs = minMs + 1;
        }
        XYPlot plot = chart.getXYPlot();
        if (plot.getDomainAxis() instanceof DateAxis axis) {
            axis.setAutoRange(false);
            axis.setRange(new Date(minMs), new Date(maxMs));
            configureDomainTickUnit(axis, minMs, maxMs);
        }
    }

    /**
     * Chooses a readable date tick unit from a small "nice" set to keep label count bounded.
     *
     * <p>Without this, date labels can become too dense over long sessions and increase render
     * overhead on repeated refresh. This keeps the chart adaptive while avoiding label crowding.</p>
     */
    private static void configureDomainTickUnit(DateAxis axis, long minMs, long maxMs) {
        long spanMs = Math.max(1L, maxMs - minMs);
        double targetStepSec = Math.max(1.0, (spanMs / 1000.0) / DOMAIN_TARGET_LABELS);
        int chosenSec = DOMAIN_CANDIDATE_SECONDS[DOMAIN_CANDIDATE_SECONDS.length - 1];
        for (int candidate : DOMAIN_CANDIDATE_SECONDS) {
            if (candidate >= targetStepSec) {
                chosenSec = candidate;
                break;
            }
        }
        axis.setTickUnit(new DateTickUnit(DateTickUnitType.SECOND, chosenSec));
    }

    private record MetricSection(String title, String[] keys) { }

    private record MetricCardState(
            JPanel card,
            Map<String, JLabel> values,
            Map<String, List<Component>> sections) { }

    /**
     * Starts periodic refresh while this panel is in the display hierarchy.
     *
     * <p>Burp may remove/add tab content on tab switches. Keeping timer lifecycle tied to
     * add/remove prevents unnecessary refresh work while the panel is not visible. Caller must
     * invoke on the EDT.</p>
     */
    @Override
    public void addNotify() {
        super.addNotify();
        RuntimeConfig.registerStateListener(runtimeStateListener);
        if (!refreshTimer.isRunning()) {
            refreshTimer.start();
        }
        if (isShowing()) {
            refreshVisibleStats();
        }
    }

    /**
     * Stops periodic refresh when panel is removed from the display hierarchy.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    @Override
    public void removeNotify() {
        if (refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
        RuntimeConfig.unregisterStateListener(runtimeStateListener);
        super.removeNotify();
    }

    private void onRuntimeStateChanged(ConfigState.State state) {
        int runtimeStyle = state == null || state.uiPreferences() == null
                ? ConfigState.DEFAULT_STATS_CHART_STYLE
                : state.uiPreferences().statsChartStyle();
        int normalizedStyle = Math.clamp(runtimeStyle, 1, CHART_STYLE_NAMES.length) - 1;
        Runnable apply = () -> {
            if (chartStyleIndex == normalizedStyle) {
                return;
            }
            chartStyleIndex = normalizedStyle;
            applyChartStyles();
            refreshSharedLegendPanel();
            repaint();
        };
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            apply.run();
        } else {
            javax.swing.SwingUtilities.invokeLater(apply);
        }
    }

    /**
     * Resolves "Traffic by source" docs exported count for a source key.
     *
     * <p>Most rows come from live captured tool-type counts. Proxy-history snapshot pushes and
     * proxy WebSocket exports are recorded separately, so include those under the
     * proxy_history row. Delegates to {@link TrafficRouteBucket} so the mapping stays consistent
     * across sinks and stats displays.</p>
     */
    private static long resolveSourceSuccess(String sourceKey) {
        return TrafficRouteBucket.resolveOpenSearchSourceSuccess(sourceKey);
    }

    /** Resolves "Traffic by source" failure count for a source key. */
    private static long resolveSourceFailure(String sourceKey) {
        return TrafficRouteBucket.resolveOpenSearchSourceFailure(sourceKey);
    }

    private static long resolveFileSourceSuccess(String sourceKey) {
        return TrafficRouteBucket.resolveFileSourceSuccess(sourceKey);
    }

    private static long resolveFileSourceFailure(String sourceKey) {
        return TrafficRouteBucket.resolveFileSourceFailure(sourceKey);
    }

}
