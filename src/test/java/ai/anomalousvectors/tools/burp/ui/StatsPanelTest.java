package ai.anomalousvectors.tools.burp.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.GradientPaint;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Shape;
import java.awt.image.BufferedImage;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JButton;
import javax.swing.JToolTip;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import static org.assertj.core.api.Assertions.assertThat;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.DateTickUnitType;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.renderer.xy.XYSplineRenderer;
import org.jfree.data.RangeType;
import org.jfree.data.time.TimeSeries;
import org.junit.jupiter.api.Test;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.call;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.callStatic;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.testutils.Reflect.getStatic;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

class StatsPanelTest {

    @Test
    void docsChart_usesReadableTimeAxis_andPositiveWholeNumberDefaults() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart docsChart = JFreeChart.class.cast(get(panel, "docsChart"));
        XYPlot plot = docsChart.getXYPlot();

        NumberAxis range = (NumberAxis) plot.getRangeAxis();
        assertThat(range.getRangeType()).isEqualTo(RangeType.POSITIVE);
        assertThat(range.getUpperMargin()).isZero();
        assertThat(range.getLowerBound()).isEqualTo(0.0);
        assertThat(range.getUpperBound()).isEqualTo(10.0);

        DateAxis domain = (DateAxis) plot.getDomainAxis();
        assertThat(domain.isTickLabelsVisible()).isTrue();
        assertThat(domain.getDateFormatOverride()).isInstanceOf(SimpleDateFormat.class);
        assertThat(((SimpleDateFormat) domain.getDateFormatOverride()).toPattern()).isEqualTo("HH:mm:ss");
        assertThat(domain.getTickUnit().getUnitType()).isEqualTo(DateTickUnitType.SECOND);

        JFreeChart kibChart = JFreeChart.class.cast(get(panel, "kibChart"));
        NumberAxis kibRange = (NumberAxis) kibChart.getXYPlot().getRangeAxis();
        assertThat(kibRange.getRangeType()).isEqualTo(RangeType.POSITIVE);
        assertThat(kibRange.getLowerBound()).isEqualTo(0.0);
        assertThat(kibRange.getUpperBound()).isEqualTo(10.0);
    }

    @Test
    void refreshVisibleStats_addsSamplesEvenWhenPanelIsNotShowing() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        assertThat(onEdt(panel::isShowing)).isFalse();

        Map<String, TimeSeries> seriesByIndex =
                Reflect.stringKeyedMap(panel, "docsSeriesByIndex", TimeSeries.class);
        int before = onEdt(() -> {
            TimeSeries traffic = seriesByIndex.get("traffic");
            return traffic == null ? 0 : traffic.getItemCount();
        });

        ExportStats.recordSuccess("traffic", 3);
        java.util.concurrent.TimeUnit.MILLISECONDS.sleep(20L);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        int after = onEdt(() -> {
            TimeSeries traffic = seriesByIndex.get("traffic");
            return traffic == null ? 0 : traffic.getItemCount();
        });
        assertThat(after).isGreaterThan(before);
    }

    @Test
    void mergedSinkTables_haveExpectedColumnSchema_andMiscStatsCardSpansFullWidth() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));

        // OpenSearch carries 9 columns including Exported and Recovered Failures counters.
        // File carries 10 columns. Both tables nest source rows under the Traffic index row.
        assertThat(indexModel.getColumnCount()).isEqualTo(9);
        assertThat(indexModel.getColumnName(0)).isEqualTo("Index");
        assertThat(indexModel.getColumnName(1)).isEqualTo("Exported");
        assertThat(indexModel.getColumnName(2)).isEqualTo("Failures");
        assertThat(indexModel.getColumnName(3)).isEqualTo("Queued");
        assertThat(indexModel.getColumnName(4)).isEqualTo("Recovered Failures");
        assertThat(indexModel.getColumnName(5)).isEqualTo("Retry Drops");
        assertThat(indexModel.getColumnName(6)).isEqualTo("Permanent Drops");
        assertThat(fileIndexModel.getColumnCount()).isEqualTo(10);
        assertThat(fileIndexModel.getColumnName(0)).isEqualTo("Index");
        assertThat(fileIndexModel.getColumnName(1)).isEqualTo("Written");
        assertThat(fileIndexModel.getColumnName(2)).isEqualTo("Failures");
        assertThat(fileIndexModel.getColumnName(3)).isEqualTo("Retry Attempts");
        assertThat(fileIndexModel.getColumnName(4)).isEqualTo("Baseline");
        assertThat(fileIndexModel.getColumnName(5)).isEqualTo("Appended");
        assertThat(fileIndexModel.getColumnName(6)).isEqualTo("Final Size");
        assertThat(fileIndexModel.getColumnName(7)).isEqualTo("Integrity");
        assertThat(indexModel.getColumnName(7)).isEqualTo("Last Bulk (ms)");
        assertThat(fileIndexModel.getColumnName(8)).isEqualTo("Last Append (ms)");
        assertThat(fileIndexModel.getColumnName(9)).isEqualTo("Last Error");
        assertThat(cardsRow.getComponentCount()).isEqualTo(1);
    }

    @Test
    void stoppedDashboard_displaysLastActiveCapacityInsteadOfControllerResetDefaults() {
        ExportStats.resetForTests();
        RuntimeConfig.setExportRunning(false);
        try {
            ExportStats.recordLastActiveSearchCapacity(5L * 1024L * 1024L, 3);
            StatsPanel panel = onEdt(StatsPanel::new);

            onEdt(() -> call(panel, "refreshDashboard"));

            JLabel bulkByteBudget = JLabel.class.cast(get(panel, "bulkByteBudgetValue"));
            JLabel snapshotFlushCap = JLabel.class.cast(get(panel, "snapshotFlushCapValue"));
            assertThat(onEdt(bulkByteBudget::getText)).isEqualTo("5.0 MiB");
            assertThat(onEdt(snapshotFlushCap::getText)).isEqualTo("3");
        } finally {
            ExportStats.resetForTests();
        }
    }

    @Test
    void proxyCorrelationCard_displaysCompleteCorrelationContract() {
        StatsPanel panel = onEdt(StatsPanel::new);

        onEdt(() -> call(panel, "refreshDashboard"));

        assertThat(JLabel.class.cast(get(panel, "correlationProxyHttpRequestsValue")).getText())
                .isEqualTo("0 / 0");
        assertThat(JLabel.class.cast(get(panel, "correlationMarkedResponsesValue")).getText())
                .isEqualTo("0 / 0");
        assertThat(JLabel.class.cast(get(panel, "correlationUnmarkedValue")).getText())
                .isEqualTo("0 / 0");
        assertThat(JLabel.class.cast(get(panel, "correlationHistoryLookupsValue")).getText())
                .isEqualTo("0 / 0");
        assertThat(JLabel.class.cast(get(panel, "correlationPendingMemoryValue")).getText())
                .isEqualTo("0 / 0 B");
        assertThat(JLabel.class.cast(get(panel, "correlationPendingDurableValue")).getText())
                .isEqualTo("0 / 0 B");
        assertThat(JLabel.class.cast(get(panel, "correlationBoundEligibleValue")).getText())
                .isEqualTo("0 / 0");
        assertThat(JLabel.class.cast(get(panel, "correlationDurableTotalValue")).getText())
                .isEqualTo("0");
        assertThat(JLabel.class.cast(
                        get(panel, "correlationLookupCleanupFailuresValue")).getText())
                .isEqualTo("0 / 0");
        assertThat(JLabel.class.cast(
                        get(panel, "correlationSpoolExplicitFailuresValue")).getText())
                .isEqualTo("0 / 0");
    }

    @Test
    void mergedSinkTables_packFirstColumnToFitIndentedRepeaterTabsSubRowLabel() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable openSearchTable = JTable.class.cast(get(panel, "byIndexTable"));
        JTable fileTable = JTable.class.cast(get(panel, "fileByIndexTable"));
        String subRowLabel = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT")) + "Repeater Tabs";

        onEdt(() -> call(panel, "refreshDashboard"));

        assertThat(firstColumnPreferredWidth(openSearchTable))
                .isGreaterThanOrEqualTo(requiredLabelColumnWidth(openSearchTable, subRowLabel));
        assertThat(firstColumnPreferredWidth(fileTable))
                .isGreaterThanOrEqualTo(requiredLabelColumnWidth(fileTable, subRowLabel));
    }

    @Test
    void byIndexTable_hasNoDefaultActiveSortKey() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = JTable.class.cast(get(panel, "byIndexTable"));
        RowSorter<? extends javax.swing.table.TableModel> sorter = byIndexTable.getRowSorter();
        assertThat(sorter).isNotNull();
        assertThat(sorter.getSortKeys()).isEmpty();
    }

    @Test
    void countsTableHeaders_useSharedHtmlToolTipPath() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = JTable.class.cast(get(panel, "byIndexTable"));
        JTable fileTable = JTable.class.cast(get(panel, "fileByIndexTable"));

        onEdt(() -> {
            JToolTip openSearchTip = byIndexTable.getTableHeader().createToolTip();
            JToolTip fileTip = fileTable.getTableHeader().createToolTip();
            assertThat(openSearchTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
            assertThat(fileTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
            assertThat(byIndexTable.getTableHeader().getToolTipText()).startsWith("<html>");
            assertThat(fileTable.getTableHeader().getToolTipText()).startsWith("<html>");
        });
    }

    @Test
    void byIndexTable_remainsAlphabeticallySortedAfterRefresh() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable byIndexTable = JTable.class.cast(get(panel, "byIndexTable"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordSuccess("traffic", 11);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        List<String> allRows = onEdt(() -> {
            List<String> rows = new ArrayList<>();
            for (int row = 0; row < byIndexTable.getRowCount(); row++) {
                rows.add(String.valueOf(byIndexTable.getValueAt(row, 0)));
            }
            return rows;
        });
        // The trailing "Total" summary row is appended unconditionally; before it sits a block
        // of indented traffic-source sub-rows that are nested under the Traffic index row but
        // not part of the alphabetical group. Strip the indented block and the Total row, then
        // verify the remaining index rows stay alphabetically sorted across rebuilds.
        assertThat(allRows).isNotEmpty();
        assertThat(allRows.get(allRows.size() - 1)).isEqualTo("Total");
        List<String> indexRows = new ArrayList<>();
        for (String row : allRows.subList(0, allRows.size() - 1)) {
            if (!row.startsWith(indent)) {
                indexRows.add(row);
            }
        }
        List<String> sorted = new ArrayList<>(indexRows);
        Collections.sort(sorted);
        assertThat(indexRows).isEqualTo(sorted);
    }

    @Test
    void refreshVisibleStats_logsFallbackHitsOnlyWhenValueIncreases() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        List<String> seenFallbackErrors = new ArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("ERROR".equals(level) && message.contains("Traffic tool/source fallback hits observed:")) {
                seenFallbackErrors.add(message);
            }
        };
        Logger.registerListener(listener);
        RuntimeConfig.setExportRunning(true);
        try {
            onEdt(() -> call(panel, "refreshVisibleStats"));
            seenFallbackErrors.clear();

            ExportStats.recordTrafficToolSourceFallback();
            onEdt(() -> call(panel, "refreshVisibleStats"));
            int afterIncrease = seenFallbackErrors.size();
            assertThat(afterIncrease).isEqualTo(1);

            onEdt(() -> call(panel, "refreshVisibleStats"));
            assertThat(seenFallbackErrors).hasSize(afterIncrease);

            ExportStats.recordTrafficToolSourceFallback();
            onEdt(() -> call(panel, "refreshVisibleStats"));
            assertThat(seenFallbackErrors).hasSize(afterIncrease + 1);
        } finally {
            Logger.unregisterListener(listener);
            RuntimeConfig.setExportRunning(false);
        }
    }

    @Test
    void sharedLegendPanel_isLeftAlignedWithExpectedSeriesLabels() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(1, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel legendPanel = JPanel.class.cast(get(panel, "sharedLegendPanel"));
            assertThat(legendPanel.getLayout()).isInstanceOf(FlowLayout.class);
            FlowLayout layout = (FlowLayout) legendPanel.getLayout();
            assertThat(layout.getAlignment()).isEqualTo(FlowLayout.LEFT);
            Font expectedLegendFont = StatsPanel.chartLegendFont();
            Color expectedTextColor = Color.class.cast(getStatic(StatsPanel.class, "TEXT_FG"));
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));

            List<String> labels = new ArrayList<>();
            for (Component component : legendPanel.getComponents()) {
                if (component instanceof JLabel label) {
                    labels.add(label.getText());
                    assertThat(label.getHorizontalAlignment()).isEqualTo(SwingConstants.LEFT);
                    assertThat(label.getFont()).isEqualTo(expectedLegendFont);
                    assertThat(label.getForeground()).isEqualTo(expectedTextColor);
                    assertThat(label.getIcon()).isNotNull();
                }
            }
            assertThat(legendPanel.getComponent(0)).isSameAs(styleButton);
            assertThat(styleButton.getText()).isEqualTo("Simple");
            assertThat(styleButton.getFont().isBold()).isFalse();
            JToolTip styleToolTip = onEdt(styleButton::createToolTip);
            assertThat(styleToolTip.getComponent()).isSameAs(styleButton);
            assertThat(styleToolTip.getClientProperty("html.disable")).isEqualTo(Boolean.FALSE);
            assertThat(styleButton.getToolTipText())
                    .isEqualTo("<html>Cycle chart styles: <b>Smooth</b>, <b>Simple</b>, and <b>Accessible</b>.</html>");
            assertThat(labels).containsExactly(
                    "Traffic",
                    "Exporter",
                    "Settings",
                    "Sitemap",
                    "Findings");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void defaultChartStyle_isSmooth() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    ConfigState.defaultUiPreferences()));
            StatsPanel panel = onEdt(StatsPanel::new);
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            JFreeChart chart = JFreeChart.class.cast(get(panel, "docsChart"));

            assertThat(styleButton.getText()).isEqualTo("Smooth");
            assertThat(chart.getXYPlot().getRenderer()).isInstanceOf(XYSplineRenderer.class);
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void sinkCards_nestTrafficSourceSubRowsDirectlyUnderTrafficIndexRow() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordSuccess("traffic", 1);
        FileExportStats.recordSuccess("traffic", 1);
        onEdt(() -> call(panel, "refreshDashboard"));

        // Sub-rows live inline within the merged model; their position is determined entirely
        // by the alphabetical placement of the Traffic index row, with the indent on column 0
        // distinguishing them from index rows. Verify the row immediately following the
        // Traffic index row is an indented sub-row, not the next alphabetical index row.
        assertSubRowsFollowTrafficIndexRow(indexModel, indent);
        assertSubRowsFollowTrafficIndexRow(fileIndexModel, indent);
    }

    private static void assertSubRowsFollowTrafficIndexRow(DefaultTableModel model, String indent) {
        int trafficRow = -1;
        for (int row = 0; row < model.getRowCount(); row++) {
            if ("Traffic".equals(String.valueOf(model.getValueAt(row, 0)))) {
                trafficRow = row;
                break;
            }
        }
        assertThat(trafficRow).as("Traffic index row").isGreaterThanOrEqualTo(0);
        // At least one indented sub-row exists right after the Traffic row.
        assertThat(trafficRow + 1).isLessThan(model.getRowCount());
        String firstSubLabel = String.valueOf(model.getValueAt(trafficRow + 1, 0));
        assertThat(firstSubLabel).startsWith(indent);
    }

    @Test
    void sinkSections_hideAndShowBasedOnSelectedDestinations() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel fileOnlyPanel = onEdt(StatsPanel::new);
            JPanel fileChartsSection = JPanel.class.cast(get(fileOnlyPanel, "fileChartsSectionPanel"));
            JPanel openSearchChartsSection = JPanel.class.cast(get(fileOnlyPanel, "openSearchChartsSectionPanel"));
            JPanel fileSinkRow = JPanel.class.cast(get(fileOnlyPanel, "fileSinkRow"));
            JPanel openSearchSinkRow = JPanel.class.cast(get(fileOnlyPanel, "openSearchSinkRow"));
            onEdt(() -> call(fileOnlyPanel, "refreshDashboard"));
            assertThat(onEdt(fileChartsSection::isVisible)).isTrue();
            assertThat(onEdt(openSearchChartsSection::isVisible)).isFalse();
            assertThat(onEdt(fileSinkRow::isVisible)).isTrue();
            assertThat(onEdt(openSearchSinkRow::isVisible)).isFalse();

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JPanel osFileChartsSection = JPanel.class.cast(get(openSearchOnlyPanel, "fileChartsSectionPanel"));
            JPanel osOpenSearchChartsSection = JPanel.class.cast(get(openSearchOnlyPanel, "openSearchChartsSectionPanel"));
            JPanel osFileSinkRow = JPanel.class.cast(get(openSearchOnlyPanel, "fileSinkRow"));
            JPanel osOpenSearchSinkRow = JPanel.class.cast(get(openSearchOnlyPanel, "openSearchSinkRow"));
            onEdt(() -> call(openSearchOnlyPanel, "refreshDashboard"));
            assertThat(onEdt(osFileChartsSection::isVisible)).isFalse();
            assertThat(onEdt(osOpenSearchChartsSection::isVisible)).isTrue();
            assertThat(onEdt(osFileSinkRow::isVisible)).isFalse();
            assertThat(onEdt(osOpenSearchSinkRow::isVisible)).isTrue();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void fileSections_areOrderedBeforeOpenSearchSections() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel chartSectionsPanel = JPanel.class.cast(get(panel, "chartSectionsPanel"));
        JPanel fileChartsSection = JPanel.class.cast(get(panel, "fileChartsSectionPanel"));
        JPanel openSearchChartsSection = JPanel.class.cast(get(panel, "openSearchChartsSectionPanel"));
        JPanel memoryChartsSection = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));
        JPanel lowerPanel = JPanel.class.cast(get(panel, "lowerPanel"));
        JPanel fileSinkRow = JPanel.class.cast(get(panel, "fileSinkRow"));
        JPanel openSearchSinkRow = JPanel.class.cast(get(panel, "openSearchSinkRow"));

        // Chart ordering: file pair on top, OpenSearch pair in the middle, memory chart at
        // the bottom (heap usage is JVM-wide so it is shared regardless of which sink runs).
        assertThat(chartSectionsPanel.getComponent(0)).isSameAs(fileChartsSection);
        assertThat(chartSectionsPanel.getComponent(1)).isSameAs(openSearchChartsSection);
        assertThat(chartSectionsPanel.getComponent(2)).isSameAs(memoryChartsSection);
        // Per-sink rows mirror the chart ordering: file row precedes OpenSearch row.
        assertThat(indexOfChild(lowerPanel, fileSinkRow))
                .isLessThan(indexOfChild(lowerPanel, openSearchSinkRow));
    }

    @Test
    void byIndexTables_appendTotalRowAfterRefresh() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordSuccess("traffic", 4);
        ExportStats.recordSuccess("findings", 2);
        FileExportStats.recordSuccess("traffic", 3);
        onEdt(() -> call(panel, "refreshDashboard"));

        // Trailing Total row aggregates only the index rows, not the indented traffic-source
        // sub-rows nested under the Traffic index row. The "Last Bulk (ms)" / "Last Error"
        // columns are rendered as "-" because totals do not have a meaningful per-row
        // last-push or last-error attribution.
        assertTotalRowMatchesIndexRowSum(indexModel, indent);
        assertTotalRowMatchesIndexRowSum(fileIndexModel, indent);
    }

    private static void assertTotalRowMatchesIndexRowSum(DefaultTableModel model, String indent) {
        int lastRow = model.getRowCount() - 1;
        assertThat(model.getValueAt(lastRow, 0)).isEqualTo("Total");
        long total = ((Number) model.getValueAt(lastRow, 1)).longValue();
        long sumOfIndexRows = 0L;
        for (int row = 0; row < lastRow; row++) {
            String label = String.valueOf(model.getValueAt(row, 0));
            if (label.startsWith(indent)) {
                continue;
            }
            sumOfIndexRows += ((Number) model.getValueAt(row, 1)).longValue();
        }
        assertThat(total).isEqualTo(sumOfIndexRows);
    }

    @Test
    void lowerPanel_exposesSingleCopyButtonForAllStatsCards() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel lowerPanel = JPanel.class.cast(get(panel, "lowerPanel"));

        assertThat(findByName(lowerPanel, "copy.All Stats", JButton.class))
                .as("shared Stats copy button")
                .isNotNull();
        assertThat(findByName(JPanel.class.cast(get(panel, "openSearchSinkCard")),
                "copy.Database Counts", JButton.class)).isNull();
        assertThat(findByName(JPanel.class.cast(get(panel, "fileSinkCard")),
                "copy.File Counts", JButton.class)).isNull();
        assertThat(findByName(JPanel.class.cast(get(panel, "miscStatsCard")),
                "copy.Misc Stats", JButton.class)).isNull();
    }

    @Test
    void byIndexTable_storesUntruncatedLastErrorTextAfterRefresh() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));

        // 200-char error string is the longest message ExportStats stores verbatim (anything
        // longer is truncated at the storage layer with an ellipsis); blowing past the legacy
        // 50-char cell-truncation cap proves the table cell now holds the full string. The
        // visual width cap is purely a renderer concern - the model yields the full string so
        // per-table TSV copy returns it verbatim.
        String longError = "X".repeat(200);
        ExportStats.recordFailure("traffic", 1);
        ExportStats.recordLastError("traffic", longError);
        try {
            onEdt(() -> call(panel, "refreshDashboard"));

            String stored = null;
            for (int row = 0; row < indexModel.getRowCount(); row++) {
                if ("Traffic".equals(String.valueOf(indexModel.getValueAt(row, 0)))) {
                    // Last Error sits in the last column of the OpenSearch counts table
                    // (last column with the 10-column schema).
                    stored = String.valueOf(indexModel.getValueAt(row, indexModel.getColumnCount() - 1));
                    break;
                }
            }
            assertThat(stored).as("Traffic row Last Error column").isEqualTo(longError);
        } finally {
            ExportStats.recordLastError("traffic", null);
        }
    }

    private static int indexOfChild(Container parent, Component child) {
        for (int i = 0; i < parent.getComponentCount(); i++) {
            if (parent.getComponent(i) == child) {
                return i;
            }
        }
        return -1;
    }

    @Test
    void sharedLegendPanel_movesAboveFirstVisibleHistogramGroup() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel dualPanel = onEdt(StatsPanel::new);
            JPanel dualLegend = JPanel.class.cast(get(dualPanel, "sharedLegendPanel"));
            JPanel dualFileSection = JPanel.class.cast(get(dualPanel, "fileChartsSectionPanel"));
            onEdt(() -> call(dualPanel, "refreshDashboard"));
            assertThat(dualLegend.getParent()).isSameAs(dualFileSection);
            assertThat(dualFileSection.getComponent(0)).isSameAs(dualLegend);

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JPanel osLegend = JPanel.class.cast(get(openSearchOnlyPanel, "sharedLegendPanel"));
            JPanel osSection = JPanel.class.cast(get(openSearchOnlyPanel, "openSearchChartsSectionPanel"));
            onEdt(() -> call(openSearchOnlyPanel, "refreshDashboard"));
            assertThat(osLegend.getParent()).isSameAs(osSection);
            assertThat(osSection.getComponent(0)).isSameAs(osLegend);
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_groupsMetricsByDestination_whenBothDestinationsEnabled() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));
            assertThat(cardsRow.getComponentCount()).isEqualTo(1);
            JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);

            assertThat(miscCard).isNotNull();

            List<String> labels = collectLabelTexts(miscCard);
            JPanel openSearchRow0 = findByName(miscCard, "miscStats.row.Database Session.0", JPanel.class);
            JPanel openSearchRow1 = findByName(miscCard, "miscStats.row.Database Session.1", JPanel.class);
            JPanel openSearchRow2 = findByName(miscCard, "miscStats.row.Database Session.2", JPanel.class);

            assertThat(labels)
                    .contains(
                            "Overview", "Database Session", "Database Traffic",
                            "Traffic Spill", "Proxy Correlation",
                            "Database Retry", "Database Capacity", "Files");
            assertThat(labels).contains(
                    "Export Running", "Shared Batch Size", "Proxy History Chunk Target",
                    "Traffic Queue Size", "Queue Drops");
            assertThat(labels).contains("Throughput (10s)");
            assertThat(labels).contains("Export Running", "Soft Outage", "Authorization Failures",
                    "Traffic Spill Status", "Database Exported Size", "Files Exported Size");
            assertThat(labels).contains("Exported Docs", "Exported Failures", "Count Basis",
                    "Permanent Drops", "Permanent Drop Reasons", "Body Truncations",
                    "Body Truncations by Index",
                    "Recovered Failures", "Retry Drain Pushes");
            assertThat(labels).doesNotContain("Authorization Recovery");
            assertThat(labels).doesNotContain("Exported Size", "File Total Size Exported");
            assertThat(labels).contains("Last Success");
            assertThat(labels).contains("Bulk In-Flight");
            assertThat(labels).contains(
                    "Bulk Byte Budget", "Snapshot Flush Cap", "Snapshot Build-Ahead",
                    "Cooldown Remaining", "Pressure Streak",
                    "Soft Outage Entries", "Capacity Events");
            assertThat(labels).contains("Peak Snapshot Build-Ahead");
            assertThat(findByName(miscCard, "miscStats.section.Traffic Spill", JLabel.class)).isNotNull();
            assertThat(labels).contains("Queue", "Oldest Age (s)", "Enqueued / Dequeued / Dropped", "Drop Reasons");
            assertThat(findByName(miscCard, "miscStats.section.Proxy Correlation", JLabel.class)).isNotNull();
            assertThat(labels).contains(
                    "Pending Memory", "Pending Durable", "Bound / Eligible",
                    "Durable Spool Total", "Lookup / Cleanup Failures", "Spool / Explicit Failures");
            assertThat(labels).contains("Queue Depth", "Oldest Queued Age");
            assertThat(labels).doesNotContain("Spill Directory", "Skips by Reason", "Retry Queue Bytes (per index)");
            assertThat(openSearchRow0.getBackground()).isNotEqualTo(openSearchRow1.getBackground());
            assertThat(openSearchRow1.getBackground()).isNotEqualTo(openSearchRow2.getBackground());
            assertThat(openSearchRow0.getBackground()).isEqualTo(openSearchRow2.getBackground());
            assertThat(labels).contains("File Total Docs Exported");
            assertThat(labels).contains("File Total Failures");
            assertThat(findByName(miscCard, "miscStats.row.Overview.0", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.1", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.2", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.3", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.4", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.5", JPanel.class).isVisible()).isTrue();
            assertThat(labels).doesNotContain("Proxy-History Attempted/Success");

            assertThat(openSearchRow0.getBackground()).isNotEqualTo(openSearchRow1.getBackground());
            assertThat(openSearchRow0.getBackground()).isEqualTo(openSearchRow2.getBackground());
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_parameterIntegrityTooltips_pointToDataIntegrityDrilldown() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel miscCard = findByName(
                    JPanel.class.cast(get(panel, "cardsRow")),
                    "miscStatsCard",
                    JPanel.class);

            JPanel misgateRow = findByName(miscCard, "miscStats.row.Parameter Integrity.0", JPanel.class);
            JPanel supplementalRow = findByName(miscCard, "miscStats.row.Parameter Integrity.4", JPanel.class);
            JPanel rejectedRow = findByName(miscCard, "miscStats.row.Parameter Integrity.5", JPanel.class);

            assertThat(misgateRow.getToolTipText())
                    .contains("Wiki Data Integrity")
                    .contains("event.type=parameter_integrity_detail")
                    .contains("event.data.category=misgate_binary")
                    .contains("validation set")
                    .doesNotContain("INFO line lists sample")
                    .doesNotContain("DEBUG adds more samples");
            assertThat(supplementalRow.getToolTipText())
                    .contains("representative sample URLs only");
            assertThat(rejectedRow.getToolTipText())
                    .contains("review only if this host")
                    .doesNotContain("validate manually");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_hidesOpenSearchSection_whenOpenSearchDestinationDisabled() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel miscCard = findByName(JPanel.class.cast(get(panel, "cardsRow")), "miscStatsCard", JPanel.class);

            assertThat(miscCard).isNotNull();
            assertThat(findByName(miscCard, "miscStats.section.Overview", JLabel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Files", JLabel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.0", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.1", JPanel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Overview.2", JPanel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Overview.3", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.4", JPanel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Overview.5", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Database Session", JLabel.class).isVisible())
                    .isFalse();
            assertThat(findByName(miscCard, "miscStats.section.Database Traffic", JLabel.class).isVisible())
                    .isFalse();
            // Traffic source is still enabled for files-only runs → Traffic Spill remains relevant.
            assertThat(findByName(miscCard, "miscStats.section.Traffic Spill", JLabel.class).isVisible())
                    .isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Proxy Correlation", JLabel.class).isVisible())
                    .isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Database Retry", JLabel.class).isVisible())
                    .isFalse();
            assertThat(findByName(miscCard, "miscStats.section.Database Capacity", JLabel.class).isVisible())
                    .isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Database Session.0", JPanel.class).isVisible())
                    .isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Database Traffic.1", JPanel.class).isVisible())
                    .isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Database Traffic.3", JPanel.class).isVisible())
                    .isFalse();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_hidesFilesSection_whenFilesDestinationDisabled() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel miscCard = findByName(JPanel.class.cast(get(panel, "cardsRow")), "miscStatsCard", JPanel.class);

            assertThat(miscCard).isNotNull();
            assertThat(findByName(miscCard, "miscStats.section.Overview", JLabel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.0", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.1", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.2", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.3", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.4", JPanel.class).isVisible()).isTrue();
            assertThat(findByName(miscCard, "miscStats.row.Overview.5", JPanel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.section.Database Session", JLabel.class).isVisible())
                    .isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Database Traffic", JLabel.class).isVisible())
                    .isTrue();
            assertThat(findByName(miscCard, "miscStats.section.Files", JLabel.class).isVisible()).isFalse();
            assertThat(findByName(miscCard, "miscStats.row.Files.0", JPanel.class).isVisible()).isFalse();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void domainAxisLabel_isNullOnThroughputHistograms_whileTickTimestampsRemain() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(runtimeState(true, true));
            StatsPanel dualPanel = onEdt(StatsPanel::new);
            JFreeChart dualFileKibChart = JFreeChart.class.cast(get(dualPanel, "fileKibChart"));
            JFreeChart dualOpenSearchKibChart = JFreeChart.class.cast(get(dualPanel, "kibChart"));
            onEdt(() -> call(dualPanel, "refreshDashboard"));
            assertThat(((DateAxis) dualFileKibChart.getXYPlot().getDomainAxis()).getLabel()).isNull();
            assertThat(((DateAxis) dualOpenSearchKibChart.getXYPlot().getDomainAxis()).getLabel()).isNull();
            assertThat(((DateAxis) dualOpenSearchKibChart.getXYPlot().getDomainAxis()).isTickLabelsVisible()).isTrue();

            RuntimeConfig.updateState(runtimeState(true, false));
            StatsPanel fileOnlyPanel = onEdt(StatsPanel::new);
            JFreeChart fileOnlyKibChart = JFreeChart.class.cast(get(fileOnlyPanel, "fileKibChart"));
            onEdt(() -> call(fileOnlyPanel, "refreshDashboard"));
            assertThat(((DateAxis) fileOnlyKibChart.getXYPlot().getDomainAxis()).getLabel()).isNull();

            RuntimeConfig.updateState(runtimeState(false, true));
            StatsPanel openSearchOnlyPanel = onEdt(StatsPanel::new);
            JFreeChart openSearchOnlyKibChart = JFreeChart.class.cast(get(openSearchOnlyPanel, "kibChart"));
            onEdt(() -> call(openSearchOnlyPanel, "refreshDashboard"));
            assertThat(((DateAxis) openSearchOnlyKibChart.getXYPlot().getDomainAxis()).getLabel()).isNull();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void formatHumanReadableBytes_usesExpectedUnitsAcrossThresholds() {
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 999L)).isEqualTo("999 B");
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 1024L)).isEqualTo("1.0 KB");
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 1024L * 1024L)).isEqualTo("1.0 MB");
        assertThat(callStatic(StatsPanel.class, "formatHumanReadableBytes", 1024L * 1024L * 1024L)).isEqualTo("1.0 GB");
    }

    @Test
    void formatBytesPairWithPercent_appendsPercentOfMax() {
        assertThat(callStatic(StatsPanel.class, "formatBytesPairWithPercent",
                512L * 1024L * 1024L, 1024L * 1024L * 1024L))
                .isEqualTo("512.0 MB / 1.0 GB (50.0%)");
        assertThat(callStatic(StatsPanel.class, "formatBytesPairWithPercent",
                8L * 1024L * 1024L * 1024L, 32L * 1024L * 1024L * 1024L))
                .isEqualTo("8.0 GB / 32.0 GB (25.0%)");
    }

    @Test
    void formatBytesPairWithPercent_omitsPercent_whenMaxUnknown() {
        String unknownMax = (String) callStatic(
                StatsPanel.class, "formatBytesPairWithPercent", 1024L, -1L);
        assertThat(unknownMax).doesNotContain("%");
        assertThat(callStatic(StatsPanel.class, "formatBytesPairWithPercent", -1L, 1024L * 1024L))
                .isEqualTo("n/a / 1.0 MB");
    }

    @Test
    void formatBytesWithPercentOf_appendsPercent_andHandlesNegatives() {
        assertThat(callStatic(StatsPanel.class, "formatBytesWithPercentOf",
                256L * 1024L * 1024L, 1024L * 1024L * 1024L))
                .isEqualTo("256.0 MB (25.0%)");
        assertThat(callStatic(StatsPanel.class, "formatBytesWithPercentOf", -1L, 1024L))
                .isEqualTo("n/a");
        assertThat(callStatic(StatsPanel.class, "formatBytesWithPercentOf", 1024L, -1L))
                .isEqualTo("1.0 KB");
    }

    @Test
    void miscStatsCard_exposesHeapCommittedAndBufferPoolRows() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel heapUsedMaxValue = JLabel.class.cast(get(panel, "heapUsedMaxValue"));
        JLabel heapCommittedValue = JLabel.class.cast(get(panel, "heapCommittedValue"));
        JLabel directBufferUsedValue = JLabel.class.cast(get(panel, "directBufferUsedValue"));
        JLabel mappedBufferUsedValue = JLabel.class.cast(get(panel, "mappedBufferUsedValue"));

        onEdt(() -> call(panel, "refreshDashboard"));

        // Heap rows are populated from a live SystemMetrics.snapshot(), so we cannot pin exact
        // values - just confirm they contain a percent annotation and a unit suffix.
        assertThat(heapUsedMaxValue.getText()).matches(".+ / .+ \\(\\d+\\.\\d+%\\)");
        assertThat(heapCommittedValue.getText()).matches(".+ \\(\\d+\\.\\d+%\\)");
        assertThat(directBufferUsedValue.getText()).isNotEmpty();
        assertThat(mappedBufferUsedValue.getText()).isNotEmpty();
    }

    @Test
    void memoryChart_isAppendedAfterPerSinkChartSections_andSamplesHeapUsedAndCommitted() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));
        JPanel chartSectionsPanel = JPanel.class.cast(get(panel, "chartSectionsPanel"));
        JPanel memoryChartSectionPanel = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));
        TimeSeries heapUsedSeries = TimeSeries.class.cast(get(panel, "heapUsedSeries"));
        TimeSeries heapCommittedSeries = TimeSeries.class.cast(get(panel, "heapCommittedSeries"));

        // Section ordering: file pair, OpenSearch pair, memory pair last (heap usage is JVM-
        // wide and unrelated to which sink is active).
        assertThat(chartSectionsPanel.getComponent(2)).isSameAs(memoryChartSectionPanel);

        // Memory chart uses MiB on the Y axis and a positive-only range type so the line
        // never dips below zero on transient negative readings.
        NumberAxis range = (NumberAxis) memoryChart.getXYPlot().getRangeAxis();
        assertThat(range.getRangeType()).isEqualTo(RangeType.POSITIVE);

        int beforeUsed = onEdt(heapUsedSeries::getItemCount);
        int beforeCommitted = onEdt(heapCommittedSeries::getItemCount);
        java.util.concurrent.TimeUnit.MILLISECONDS.sleep(20L);
        onEdt(() -> call(panel, "refreshVisibleStats"));
        assertThat(onEdt(heapUsedSeries::getItemCount)).isGreaterThanOrEqualTo(beforeUsed);
        assertThat(onEdt(heapCommittedSeries::getItemCount)).isGreaterThanOrEqualTo(beforeCommitted);
    }

    @Test
    void memoryLegendPanel_sitsAtTopOfMemorySection_andHasHeapUsedAndCommittedItems() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel memoryLegendPanel = JPanel.class.cast(get(panel, "memoryLegendPanel"));
        JPanel memoryChartSectionPanel = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));

        assertThat(memoryChartSectionPanel.getComponent(0)).isSameAs(memoryLegendPanel);
        assertThat(memoryLegendPanel.getLayout()).isInstanceOf(FlowLayout.class);

        List<String> labelTexts = new ArrayList<>();
        for (Component c : memoryLegendPanel.getComponents()) {
            if (c instanceof JLabel label) {
                labelTexts.add(label.getText());
            }
        }
        assertThat(labelTexts).containsExactly("Heap Used", "Heap Committed");
    }

    @Test
    void memoryChart_seriesPaintsTrackThroughputPaletteForGreenAndYellow() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(1, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));
            XYLineAndShapeRenderer renderer =
                    (XYLineAndShapeRenderer) memoryChart.getXYPlot().getRenderer();

            // The memory chart's two series adopt the throughput chart's Traffic (green) and
            // Sitemap (yellow) palette through MEMORY_SERIES_TO_STYLE.
            assertThat(renderer.getSeriesPaint(0)).isEqualTo(call(panel, "seriesLinePaint", 0));
            assertThat(renderer.getSeriesPaint(1)).isEqualTo(call(panel, "seriesLinePaint", 3));
            // Simple style hides shape markers on every chart, including the memory chart; the
            // Accessible-style coverage is verified separately.
            assertThat(renderer.getSeriesShapesVisible(0))
                    .isEqualTo(call(panel, "seriesShapesVisible", 0));
            assertThat(renderer.getSeriesShapesVisible(1))
                    .isEqualTo(call(panel, "seriesShapesVisible", 3));
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void chartStyleButton_alsoSwitchesMemoryChartRenderer() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    ConfigState.defaultUiPreferences()));
            StatsPanel panel = onEdt(StatsPanel::new);
            JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));

            assertThat(memoryChart.getXYPlot().getRenderer()).isInstanceOf(XYSplineRenderer.class);

            onEdt((Runnable) styleButton::doClick); // Simple
            assertThat(memoryChart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);

            onEdt((Runnable) styleButton::doClick); // Accessible
            assertThat(memoryChart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            XYLineAndShapeRenderer renderer =
                    (XYLineAndShapeRenderer) memoryChart.getXYPlot().getRenderer();
            // In Accessible style the memory chart inherits the same dashed strokes and shape
            // markers that SeriesStyle attaches to the throughput chart, so heap-used and
            // heap-committed remain distinguishable for color-blind users without color alone.
            BasicStroke stroke0 = (BasicStroke) renderer.getSeriesStroke(0);
            BasicStroke stroke1 = (BasicStroke) renderer.getSeriesStroke(1);
            assertThat(stroke0.getDashArray()).isNotNull();
            assertThat(stroke1.getDashArray()).isNotNull();
            assertThat(renderer.getSeriesShapesVisible(0)).isTrue();
            assertThat(renderer.getSeriesShapesVisible(1)).isTrue();
            assertThat(renderer.getSeriesShape(0))
                    .isEqualTo(call(panel, "seriesMarkerShape", 0));
            assertThat(renderer.getSeriesShape(1))
                    .isEqualTo(call(panel, "seriesMarkerShape", 3));
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void memoryLegendIcons_paintWithoutErrorAcrossEveryChartStyle() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            StatsPanel panel = onEdt(StatsPanel::new);
            JPanel memoryLegendPanel = JPanel.class.cast(get(panel, "memoryLegendPanel"));
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));

            // Cover Smooth, Simple, and Accessible. The Accessible pass is the regression
            // guard: the icon must paint a shape marker plus dashed stroke without throwing
            // even when no chart pixels have been laid out yet.
            for (int i = 0; i < 3; i++) {
                BufferedImage canvas = new BufferedImage(32, 16, BufferedImage.TYPE_INT_ARGB);
                Graphics2D g2 = canvas.createGraphics();
                try {
                    for (Component c : memoryLegendPanel.getComponents()) {
                        if (c instanceof JLabel label && label.getIcon() != null) {
                            label.getIcon().paintIcon(label, g2, 0, 0);
                        }
                    }
                } finally {
                    g2.dispose();
                }
                onEdt((Runnable) styleButton::doClick);
            }
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void miscStatsCard_processSection_includesNewMemoryRows() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));
        JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);
        assertThat(miscCard).isNotNull();

        List<String> labels = collectLabelTexts(miscCard);
        assertThat(labels).contains("Heap Used / Max", "Heap Committed",
                "Non-Heap Used", "Direct Buffer Used", "Mapped Buffer Used");
    }

    @Test
    void refreshDashboard_updatesTotalExportedValueWithHumanReadableSize() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel exportedSizeValue = JLabel.class.cast(get(panel, "exportedSizeValue"));
        long beforeTotal = ExportStats.getTotalExportedBytes();

        onEdt(() -> call(panel, "refreshDashboard"));
        ExportStats.recordExportedBytes("traffic", 1024L * 1024L);

        onEdt(() -> call(panel, "refreshDashboard"));
        String expectedSize = (String) callStatic(
                StatsPanel.class,
                "formatHumanReadableBytes",
                beforeTotal + (1024L * 1024L));
        assertThat(exportedSizeValue.getText()).isEqualTo(expectedSize);
    }

    @Test
    void refreshDashboard_updatesFileTotalExportedValueWithHumanReadableSize() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel fileTotalExportedValue = JLabel.class.cast(get(panel, "fileTotalExportedValue"));
        long beforeTotal = FileExportStats.getTotalExportedBytes();

        onEdt(() -> call(panel, "refreshDashboard"));
        FileExportStats.recordExportedBytes("traffic", 1024L * 1024L);

        onEdt(() -> call(panel, "refreshDashboard"));
        String expected = (String) callStatic(
                StatsPanel.class,
                "formatHumanReadableBytes",
                beforeTotal + (1024L * 1024L));
        assertThat(fileTotalExportedValue.getText()).isEqualTo(expected);
    }

    @Test
    void totalExportedValue_transitionsAcrossUnits_fromRecordedIndexBytes() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel exportedSizeValue = JLabel.class.cast(get(panel, "exportedSizeValue"));

        long beforeTotal = ExportStats.getTotalExportedBytes();

        ExportStats.recordExportedBytes("traffic", 1536L);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterKb = beforeTotal + 1536L;
        assertThat(exportedSizeValue.getText())
                .isEqualTo((String) callStatic(StatsPanel.class, "formatHumanReadableBytes", afterKb));

        long deltaToMb = Math.max(0L, (1024L * 1024L) - afterKb);
        ExportStats.recordExportedBytes("exporter", deltaToMb);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterMb = afterKb + deltaToMb;
        String afterMbHuman = (String) callStatic(StatsPanel.class, "formatHumanReadableBytes", afterMb);
        assertThat(exportedSizeValue.getText()).isEqualTo(afterMbHuman);
        assertThat(afterMbHuman).endsWith("MB");

        long deltaToGb = Math.max(0L, (1024L * 1024L * 1024L) - afterMb);
        ExportStats.recordExportedBytes("findings", deltaToGb);
        onEdt(() -> call(panel, "refreshDashboard"));
        long afterGb = afterMb + deltaToGb;
        String afterGbHuman = (String) callStatic(StatsPanel.class, "formatHumanReadableBytes", afterGb);
        assertThat(exportedSizeValue.getText()).isEqualTo(afterGbHuman);
        assertThat(afterGbHuman).endsWith("GB");
    }

    @Test
    void mergedTable_recoveredColumnTracksRetryRecovery() {
        ExportStats.resetForTests();
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));

        ExportStats.recordFailure("sitemap", 50);
        onEdt(() -> call(panel, "refreshDashboard"));
        assertThat(sourceTableLong(indexModel, "Sitemap", 2)).isEqualTo(50);
        assertThat(sourceTableLong(indexModel, "Sitemap", 4)).isEqualTo(0);

        ExportStats.recordRetryRecovery("sitemap", 50);
        onEdt(() -> call(panel, "refreshDashboard"));
        assertThat(sourceTableLong(indexModel, "Sitemap", 2)).isEqualTo(50);
        assertThat(sourceTableLong(indexModel, "Sitemap", 4)).isEqualTo(50);
    }

    @Test
    void mergedTable_trafficSubRowShowsRouteAttributedRecoveries() {
        ExportStats.resetForTests();
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordFailure("traffic", 3);
        ExportStats.recordTrafficSourceFailure("proxy_history_snapshot", 3);
        ExportStats.recordRetryRecovery("traffic", 3);
        ExportStats.recordTrafficSourceRecovery("proxy_history_snapshot", 3);
        onEdt(() -> call(panel, "refreshDashboard"));

        assertThat(sourceTableLong(indexModel, "Traffic", 4)).isEqualTo(3);
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 4)).isEqualTo(3);
    }

    @Test
    void mergedTable_trafficSubRowShowsRouteAttributedQueueDropsAndPermanentDrops() {
        ExportStats.resetForTests();
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        ExportStats.recordRetryQueueDrop("traffic", 5);
        ExportStats.recordTrafficSourceRetryQueueDrop("proxy_history_snapshot", 2);
        ExportStats.recordTrafficToolTypeRetryQueueDrop("REPEATER", 3);
        ExportStats.recordPermanentDrop("traffic", 4);
        ExportStats.recordTrafficSourcePermanentDrop("proxy_websocket", 1);
        ExportStats.recordTrafficToolTypePermanentDrop("INTRUDER", 3);
        onEdt(() -> call(panel, "refreshDashboard"));

        assertThat(sourceTableLong(indexModel, "Traffic", 5)).isEqualTo(5);
        assertThat(sourceTableLong(indexModel, "Traffic", 6)).isEqualTo(4);
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 5)).isEqualTo(2);
        assertThat(sourceTableLong(indexModel, indent + "Repeater", 5)).isEqualTo(3);
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 6)).isEqualTo(1);
        assertThat(sourceTableLong(indexModel, indent + "Intruder", 6)).isEqualTo(3);
        // Queued is a live retry-queue snapshot; empty queue shows 0 (not "-").
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 3)).isZero();
    }

    @Test
    void mergedTable_countsProxyWebSocketsUnderProxyHistorySubRowAndTrafficIndex() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        onEdt(() -> call(panel, "refreshDashboard"));

        long proxyHistoryBefore = sourceTableLong(indexModel, indent + "Proxy History", 1);
        long trafficIndexBefore = sourceTableLong(indexModel, "Traffic", 1);
        long proxyHistoryFailuresBefore = sourceTableLong(indexModel, indent + "Proxy History", 2);
        long trafficIndexFailuresBefore = sourceTableLong(indexModel, "Traffic", 2);

        ExportStats.recordSuccess("traffic", 7);
        ExportStats.recordTrafficSourceSuccess("proxy_websocket", 7);
        ExportStats.recordFailure("traffic", 2);
        ExportStats.recordTrafficSourceFailure("proxy_websocket", 2);

        onEdt(() -> call(panel, "refreshDashboard"));

        // Proxy WebSocket success/failure counts roll up into the Proxy History sub-row in
        // the merged table (TrafficRouteBucket.resolveOpenSearchSourceSuccess folds them in)
        // and into the Traffic index row.
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 1) - proxyHistoryBefore).isEqualTo(7);
        assertThat(sourceTableLong(indexModel, "Traffic", 1) - trafficIndexBefore).isEqualTo(7);
        assertThat(sourceTableLong(indexModel, indent + "Proxy History", 2) - proxyHistoryFailuresBefore).isEqualTo(2);
        assertThat(sourceTableLong(indexModel, "Traffic", 2) - trafficIndexFailuresBefore).isEqualTo(2);
    }

    @Test
    void mergedTable_subRowSumMatchesTrafficIndexAfterMixedTrafficSources() {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        onEdt(() -> call(panel, "refreshDashboard"));

        long subRowSumBefore = sumSubRowsForColumn(indexModel, indent, 1);
        long trafficIndexBefore = sourceTableLong(indexModel, "Traffic", 1);
        long subRowFailureSumBefore = sumSubRowsForColumn(indexModel, indent, 2);
        long trafficIndexFailuresBefore = sourceTableLong(indexModel, "Traffic", 2);

        ExportStats.recordSuccess("traffic", 17);
        ExportStats.recordTrafficToolTypeSuccess("PROXY", 5);
        ExportStats.recordTrafficToolTypeSuccess("REPEATER", 3);
        ExportStats.recordTrafficSourceSuccess("proxy_history_snapshot", 4);
        ExportStats.recordTrafficSourceSuccess("proxy_websocket", 5);

        ExportStats.recordFailure("traffic", 4);
        ExportStats.recordTrafficSourceFailure("proxy_history_snapshot", 1);
        ExportStats.recordTrafficSourceFailure("proxy_websocket", 3);

        onEdt(() -> call(panel, "refreshDashboard"));

        // Data integrity: the indented per-source sub-rows must sum to the same number as
        // the parent Traffic index row for both successes and failures. This is the merged
        // table's analog of the old "source-table Total == traffic-index row" invariant.
        long subRowSumAfter = sumSubRowsForColumn(indexModel, indent, 1);
        long trafficIndexAfter = sourceTableLong(indexModel, "Traffic", 1);
        long subRowFailureSumAfter = sumSubRowsForColumn(indexModel, indent, 2);
        long trafficIndexFailuresAfter = sourceTableLong(indexModel, "Traffic", 2);
        assertThat(subRowSumAfter - subRowSumBefore).isEqualTo(trafficIndexAfter - trafficIndexBefore);
        assertThat(subRowFailureSumAfter - subRowFailureSumBefore)
                .isEqualTo(trafficIndexFailuresAfter - trafficIndexFailuresBefore);
    }

    private static long sumSubRowsForColumn(DefaultTableModel model, String indent, int columnIndex) {
        long sum = 0L;
        for (int row = 0; row < model.getRowCount(); row++) {
            String label = String.valueOf(model.getValueAt(row, 0));
            if (!label.startsWith(indent)) {
                continue;
            }
            Object value = model.getValueAt(row, columnIndex);
            if (value instanceof Number number) {
                sum += number.longValue();
            } else if (value != null && !"-".equals(String.valueOf(value))) {
                sum += parseStatsTableLong(String.valueOf(value));
            }
        }
        return sum;
    }

    @Test
    void exportRunningValue_usesGreenForYesAndRedForNo() {
        boolean original = RuntimeConfig.isExportRunning();
        try {
            StatsPanel panel = onEdt(StatsPanel::new);
            JLabel exportRunningValue = JLabel.class.cast(get(panel, "exportRunningValue"));
            JLabel sharedBatchSizeValue = JLabel.class.cast(get(panel, "sharedBatchSizeValue"));

            onEdt(() -> {
                RuntimeConfig.setExportRunning(true);
                call(panel, "refreshDashboard");
            });
            assertThat(exportRunningValue.getText()).isEqualTo("Yes");
            assertThat(exportRunningValue.getForeground()).isEqualTo(seriesBaseColor(panel, 0));
            assertThat(exportRunningValue.getFont().isBold()).isTrue();
            assertThat(sharedBatchSizeValue.getFont().isBold()).isFalse();

            onEdt(() -> {
                RuntimeConfig.setExportRunning(false);
                call(panel, "refreshDashboard");
            });
            assertThat(exportRunningValue.getText()).isEqualTo("No");
            assertThat(exportRunningValue.getForeground()).isEqualTo(seriesBaseColor(panel, 4));
            assertThat(exportRunningValue.getFont().isBold()).isTrue();
            assertThat(exportRunningValue.getFont().getStyle()).isEqualTo(Font.BOLD);
        } finally {
            onEdt(() -> RuntimeConfig.setExportRunning(original));
        }
    }

    @Test
    void chartRenderer_usesAccessibleSeriesPaintsStrokesAndMarkers() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    ConfigState.defaultUiPreferences()));
            StatsPanel panel = onEdt(StatsPanel::new);
            JFreeChart chart = JFreeChart.class.cast(get(panel, "docsChart"));

            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            onEdt((Runnable) styleButton::doClick);
            onEdt((Runnable) styleButton::doClick);
            assertThat(styleButton.getText()).isEqualTo("Accessible");
            XYLineAndShapeRenderer renderer = currentRenderer(chart);

            assertSeriesStyle(panel, renderer, 0, new float[] { 8f, 5f }, true);
            assertSeriesStyle(panel, renderer, 1, new float[] { 8f, 4f, 1.5f, 4f }, true);
            assertSeriesStyle(panel, renderer, 2, null, true);
            assertSeriesStyle(panel, renderer, 3, new float[] { 1.5f, 4f }, true);
            assertSeriesStyle(panel, renderer, 4, new float[] { 12f, 6f }, true);
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void styleButton_cyclesThroughThreeNamedChartStyles() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    ConfigState.defaultUiPreferences()));
            StatsPanel panel = onEdt(StatsPanel::new);
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            JFreeChart chart = JFreeChart.class.cast(get(panel, "docsChart"));

            assertThat(styleButton.getText()).isEqualTo("Smooth");
            assertThat(chart.getXYPlot().getRenderer()).isInstanceOf(XYSplineRenderer.class);
            assertThat(currentRenderer(chart).getSeriesShapesVisible(0)).isFalse();

            onEdt((Runnable) styleButton::doClick);
            assertThat(styleButton.getText()).isEqualTo("Simple");
            assertThat(chart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            assertThat(currentRenderer(chart).getSeriesShapesVisible(0)).isFalse();

            onEdt((Runnable) styleButton::doClick);
            assertThat(styleButton.getText()).isEqualTo("Accessible");
            assertThat(chart.getXYPlot().getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            assertThat(currentRenderer(chart).getSeriesShapesVisible(0)).isTrue();

            onEdt((Runnable) styleButton::doClick);
            assertThat(styleButton.getText()).isEqualTo("Smooth");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void smoothStyle_usesSplineRendererFillWithoutSecondaryAreaDataset() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(3, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JFreeChart chart = JFreeChart.class.cast(get(panel, "docsChart"));

            XYPlot plot = chart.getXYPlot();
            assertThat(plot.getRenderer()).isNotInstanceOf(XYSplineRenderer.class);
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            assertThat(styleButton.getText()).isEqualTo("Accessible");
            onEdt((Runnable) styleButton::doClick);
            assertThat(plot.getRenderer()).isInstanceOf(XYSplineRenderer.class);
            XYSplineRenderer renderer = (XYSplineRenderer) plot.getRenderer();
            assertThat(renderer.getPrecision()).isEqualTo(12);
            assertThat(renderer.getFillType()).isEqualTo(XYSplineRenderer.FillType.TO_LOWER_BOUND);
            assertThat(renderer.getSeriesFillPaint(0)).isInstanceOf(call(panel, "seriesAreaPaint", 0).getClass());
            assertThat(plot.getDataset(1)).isNull();
            assertThat(plot.getRenderer(1)).isNull();
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void smoothStyle_trafficAndSitemapFillsAreMoreTransparentThanExporter() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(2, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);

            GradientPaint trafficFill = GradientPaint.class.cast(call(panel, "seriesPaint", 0));
            GradientPaint exporterFill = GradientPaint.class.cast(call(panel, "seriesPaint", 1));
            GradientPaint sitemapFill = GradientPaint.class.cast(call(panel, "seriesPaint", 3));

            assertThat(trafficFill.getColor1().getAlpha()).isLessThan(exporterFill.getColor1().getAlpha());
            assertThat(sitemapFill.getColor1().getAlpha()).isLessThan(exporterFill.getColor1().getAlpha());
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void chartPanels_drawAtFullSizeWithoutJFreeChartBitmapUpscaling() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        ChartPanel docsPanel = ChartPanel.class.cast(get(panel, "openSearchDocsChartPanel"));
        ChartPanel memoryPanel = ChartPanel.class.cast(get(panel, "memoryChartPanel"));

        assertThat(docsPanel.getMinimumDrawWidth()).isZero();
        assertThat(docsPanel.getMinimumDrawHeight()).isZero();
        assertThat(docsPanel.getMaximumDrawWidth()).isEqualTo(Integer.MAX_VALUE);
        assertThat(docsPanel.getMaximumDrawHeight()).isEqualTo(Integer.MAX_VALUE);
        assertThat(memoryPanel.getMaximumDrawWidth()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void sectionHeaders_fileAndOpenSearchPlain_jvmHeapTitlePlain() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JLabel openSearch = JLabel.class.cast(get(panel, "openSearchChartsSectionHeaderLabel"));
        JLabel fileExport = JLabel.class.cast(get(panel, "fileChartsSectionHeaderLabel"));
        JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));

        assertThat(openSearch.getFont().isBold()).isFalse();
        assertThat(fileExport.getFont().isBold()).isFalse();
        assertThat(memoryChart.getTitle().getFont().isBold()).isFalse();
    }

    @Test
    void charts_useMatchingStatsRangeAxisWidthSoPlotAreasAlign() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JFreeChart docsChart = JFreeChart.class.cast(get(panel, "docsChart"));
        JFreeChart kibChart = JFreeChart.class.cast(get(panel, "kibChart"));
        JFreeChart memoryChart = JFreeChart.class.cast(get(panel, "memoryChart"));

        assertThat(docsChart.getXYPlot().getRangeAxis()).isInstanceOf(StatsChartRangeAxis.class);
        assertThat(rangeAxisWidth(docsChart)).isEqualTo(StatsChartRangeAxis.TOTAL_WIDTH);
        assertThat(rangeAxisWidth(kibChart)).isEqualTo(StatsChartRangeAxis.TOTAL_WIDTH);
        assertThat(rangeAxisWidth(memoryChart)).isEqualTo(StatsChartRangeAxis.TOTAL_WIDTH);
        assertThat(docsChart.getXYPlot().getFixedRangeAxisSpace()).isNull();
    }

    private static double rangeAxisWidth(JFreeChart chart) {
        return ((StatsChartRangeAxis) chart.getXYPlot().getRangeAxis()).getFixedDimension();
    }

    @Test
    void statsPanel_readsChartStyleFromRuntimeUiPreferences() {
        ConfigState.State previous = RuntimeConfig.getState();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    previous.dataSources(),
                    previous.scopeType(),
                    previous.customEntries(),
                    previous.sinks(),
                    previous.settingsSub(),
                    previous.trafficToolTypes(),
                    previous.findingsSeverities(),
                    previous.enabledExportFieldsByIndex(),
                    new ConfigState.UiPreferences(3, ConfigState.defaultLogPanelPreferences())));
            StatsPanel panel = onEdt(StatsPanel::new);
            JButton styleButton = JButton.class.cast(get(panel, "chartStyleButton"));
            assertThat(styleButton.getText()).isEqualTo("Accessible");
        } finally {
            RuntimeConfig.updateState(previous);
        }
    }

    @Test
    void preferredSize_growsToFitCardsAndTablesSoBottomDoesNotClip() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JPanel chartsPanel = JPanel.class.cast(get(panel, "chartsPanel"));
        JPanel sharedLegendPanel = JPanel.class.cast(get(panel, "sharedLegendPanel"));
        JPanel memoryLegendPanel = JPanel.class.cast(get(panel, "memoryLegendPanel"));
        JPanel fileChartsSection = JPanel.class.cast(get(panel, "fileChartsSectionPanel"));
        JPanel openSearchChartsSection = JPanel.class.cast(get(panel, "openSearchChartsSectionPanel"));
        JPanel memoryChartSectionPanel = JPanel.class.cast(get(panel, "memoryChartSectionPanel"));
        JPanel fileChartsSectionHeader = JPanel.class.cast(get(panel, "fileChartsSectionHeader"));
        JPanel openSearchChartsSectionHeader = JPanel.class.cast(get(panel, "openSearchChartsSectionHeader"));
        JPanel lowerPanel = JPanel.class.cast(get(panel, "lowerPanel"));
        JPanel cardsRow = JPanel.class.cast(get(panel, "cardsRow"));
        JPanel miscCard = findByName(cardsRow, "miscStatsCard", JPanel.class);
        int chartHeight = Reflect.getStaticInt(StatsPanel.class, "CHART_PANEL_HEIGHT") / 2;
        int memoryHeight = Reflect.getStaticInt(StatsPanel.class, "MEMORY_CHART_PANEL_HEIGHT");
        int padding = Reflect.getStaticInt(StatsPanel.class, "CONTENT_VERTICAL_PADDING");

        java.awt.Dimension preferred = onEdt(panel::getPreferredSize);
        int memoryLegendBudget = onEdt(memoryLegendPanel::isVisible)
                ? memoryLegendPanel.getPreferredSize().height + 4
                : 0;
        int sectionHeadersBudget =
                (onEdt(fileChartsSection::isVisible)
                        ? fileChartsSectionHeader.getPreferredSize().height + 4 : 0)
                + (onEdt(openSearchChartsSection::isVisible)
                        ? openSearchChartsSectionHeader.getPreferredSize().height + 4 : 0);
        int expectedChartsHeight = (onEdt(fileChartsSection::isVisible) ? chartHeight * 2 : 0)
                + (onEdt(openSearchChartsSection::isVisible) ? chartHeight * 2 : 0)
                + (onEdt(sharedLegendPanel::isVisible) ? sharedLegendPanel.getPreferredSize().height + 4 : 0)
                + (onEdt(memoryChartSectionPanel::isVisible) ? memoryHeight + memoryLegendBudget + 12 : 0)
                + sectionHeadersBudget;
        int requiredMinHeight = expectedChartsHeight
                + lowerPanel.getPreferredSize().height
                + padding;
        assertThat(preferred.height).isGreaterThanOrEqualTo(requiredMinHeight);
        assertThat(chartsPanel.getPreferredSize().height).isEqualTo(expectedChartsHeight);
        assertThat(cardsRow.getPreferredSize().height).isGreaterThanOrEqualTo(miscCard.getPreferredSize().height);
    }

    @Test
    void fileTablesAndCharts_updateFromFileExportStats() throws Exception {
        StatsPanel panel = onEdt(StatsPanel::new);
        DefaultTableModel fileIndexModel = DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));
        Map<String, TimeSeries> fileDocsSeriesByIndex =
                Reflect.stringKeyedMap(panel, "fileDocsSeriesByIndex", TimeSeries.class);
        String indent = String.class.cast(getStatic(StatsPanel.class, "SUBROW_INDENT"));

        onEdt(() -> call(panel, "refreshDashboard"));
        long proxyBefore = sourceTableLong(fileIndexModel, indent + "Proxy", 1);
        long trafficBefore = sourceTableLong(fileIndexModel, "Traffic", 1);

        FileExportStats.recordSuccess("traffic", 5);
        FileExportStats.recordExportedBytes("traffic", 4096L);
        FileExportStats.recordTrafficToolTypeSuccess("PROXY", 5);
        onEdt(() -> call(panel, "refreshVisibleStats"));

        assertThat(sourceTableLong(fileIndexModel, indent + "Proxy", 1) - proxyBefore).isEqualTo(5);
        assertThat(sourceTableLong(fileIndexModel, "Traffic", 1) - trafficBefore).isEqualTo(5);
        assertThat(onEdt(() -> {
            TimeSeries traffic = fileDocsSeriesByIndex.get("traffic");
            return traffic == null ? 0 : traffic.getItemCount();
        })).isGreaterThan(0);
    }

    @Test
    void fileTable_displaysRetryAndArtifactIntegrityValues() {
        FileExportStats.resetForTests();
        try {
            FileExportStats.recordSuccess("traffic", 5);
            FileExportStats.recordRetryAttempt("traffic", 2);
            FileExportStats.recordArtifactRegistration("traffic", 1024L);
            FileExportStats.recordExportedBytes("traffic", 2048L);
            FileExportStats.recordArtifactCompletion(
                    "traffic",
                    1024L,
                    3072L,
                    3000L,
                    FileExportStats.ArtifactIntegrity.FAILED,
                    "artifact changed");
            StatsPanel panel = onEdt(StatsPanel::new);
            DefaultTableModel model =
                    DefaultTableModel.class.cast(get(panel, "fileByIndexModel"));

            onEdt(() -> call(panel, "refreshDashboard"));

            assertThat(sourceTableLong(model, "Traffic", 3)).isEqualTo(2L);
            assertThat(sourceTableText(model, "Traffic", 4)).isEqualTo("1.0 KiB");
            assertThat(sourceTableText(model, "Traffic", 5)).isEqualTo("2.0 KiB");
            assertThat(sourceTableText(model, "Traffic", 6)).isEqualTo("2.9 KiB");
            assertThat(sourceTableText(model, "Traffic", 7)).isEqualTo("Failed");
            assertThat(sourceTableText(model, "Traffic", 9)).isEqualTo("artifact changed");
        } finally {
            FileExportStats.resetForTests();
        }
    }

    @Test
    void chartMaxPoints_coversConfiguredRollingWindowAtRefreshCadence() {
        int chartMaxPoints = Reflect.getStaticInt(StatsPanel.class, "CHART_MAX_POINTS");
        long chartWindowMs = ((Number) getStatic(StatsPanel.class, "CHART_WINDOW_MAX_MS")).longValue();
        int refreshIntervalMs = Reflect.getStaticInt(StatsPanel.class, "REFRESH_INTERVAL_MS");
        int requiredPoints = (int) (chartWindowMs / refreshIntervalMs);
        assertThat(chartMaxPoints).isGreaterThanOrEqualTo(requiredPoints);
    }

    @Test
    void mergedIndexTable_sortsNumericColumnsNumerically() {
        StatsPanel panel = onEdt(StatsPanel::new);
        JTable indexTable = JTable.class.cast(get(panel, "byIndexTable"));
        DefaultTableModel indexModel = DefaultTableModel.class.cast(get(panel, "byIndexModel"));

        onEdt(() -> {
            indexModel.setRowCount(0);
            indexModel.addRow(new Object[] { "Traffic", 3242L, 0, 0L, 0L, 0L, "154083", "-" });
            indexModel.addRow(new Object[] { "Sitemap", 423L, 0, 0L, 0L, 0L, "-", "-" });
            indexModel.addRow(new Object[] { "Findings", 505L, 0, 0L, 0L, 0L, "-", "-" });
            indexTable.getRowSorter().setSortKeys(List.of(new RowSorter.SortKey(1, SortOrder.DESCENDING)));
        });

        // Numeric column 1 ("Docs Exported") sorts by long value, not lexicographically: with
        // descending sort the row with 3242 sits above 505 even though its first digit is "3"
        // and a string sort would place "5..." above "3...".
        List<String> indexOrder = onEdt(() -> {
            List<String> rows = new ArrayList<>();
            for (int i = 0; i < indexTable.getRowCount(); i++) {
                rows.add(String.valueOf(indexTable.getValueAt(i, 0)));
            }
            return rows;
        });
        assertThat(indexOrder).containsExactly("Traffic", "Findings", "Sitemap");
    }

    @Test
    void timerTick_whileExportRunning_refreshesEveryTick() {
        boolean originalRunning = RuntimeConfig.isExportRunning();
        try {
            ExportStats.resetForTests();
            RuntimeConfig.setExportRunning(true);
            StatsPanel panel = onEdt(StatsPanel::new);

            ExportStats.recordSuccess("traffic", 1);
            long before = onEdt(() -> ExportStats.getTotalSuccessCount());
            onEdt(() -> call(panel, "timerTick"));

            JLabel exportedDocsValue = JLabel.class.cast(get(panel, "exportedDocsValue"));
            assertThat(exportedDocsValue.getText())
                    .isEqualTo(String.format(java.util.Locale.ROOT, "%,d docs", before));

            ExportStats.recordSuccess("traffic", 2);
            onEdt(() -> call(panel, "timerTick"));
            assertThat(exportedDocsValue.getText())
                    .as("running ticks should always refresh, no skip")
                    .isEqualTo(String.format(
                            java.util.Locale.ROOT,
                            "%,d docs",
                            ExportStats.getTotalSuccessCount()));
        } finally {
            RuntimeConfig.setExportRunning(originalRunning);
            ExportStats.resetForTests();
        }
    }

    @Test
    void timerTick_whileIdle_skipsAllButEveryFifthTick() {
        boolean originalRunning = RuntimeConfig.isExportRunning();
        try {
            ExportStats.resetForTests();
            RuntimeConfig.setExportRunning(false);
            StatsPanel panel = onEdt(StatsPanel::new);
            JLabel exportedDocsValue = JLabel.class.cast(get(panel, "exportedDocsValue"));

            // Constructor's initial refresh paints 0; bump counter and confirm idle ticks skip.
            ExportStats.recordSuccess("traffic", 7);
            // First idle tick after construction: counter == 0 means it RUNS the refresh.
            onEdt(() -> call(panel, "timerTick"));
            assertThat(exportedDocsValue.getText()).isEqualTo("7 docs");

            ExportStats.recordSuccess("traffic", 100);
            // Next four idle ticks should all skip (counter values 1..4 are non-zero mod 5).
            for (int i = 0; i < 4; i++) {
                onEdt(() -> call(panel, "timerTick"));
            }
            assertThat(exportedDocsValue.getText())
                    .as("idle ticks 1..4 should not refresh, label is stale")
                    .isEqualTo("7 docs");

            // Fifth idle tick (counter == 5 -> 5 % 5 == 0) refreshes again.
            onEdt(() -> call(panel, "timerTick"));
            assertThat(exportedDocsValue.getText()).isEqualTo("107 docs");
        } finally {
            RuntimeConfig.setExportRunning(originalRunning);
            ExportStats.resetForTests();
        }
    }

    private static void onEdt(Runnable runnable) {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
            return;
        }
        try {
            SwingUtilities.invokeAndWait(runnable);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    private static <T> T onEdt(Callable<T> callable) {
        if (SwingUtilities.isEventDispatchThread()) {
            try {
                return callable.call();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        AtomicReference<T> box = new AtomicReference<>();
        onEdt(() -> {
            try {
                box.set(callable.call());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        return box.get();
    }

    private static long sourceTableLong(DefaultTableModel model, String rowLabel, int columnIndex) {
        for (int row = 0; row < model.getRowCount(); row++) {
            if (rowLabel.equals(String.valueOf(model.getValueAt(row, 0)))) {
                Object value = model.getValueAt(row, columnIndex);
                if (value instanceof Number number) {
                    return number.longValue();
                }
                return parseStatsTableLong(String.valueOf(value));
            }
        }
        throw new AssertionError("Row not found: " + rowLabel);
    }

    private static String sourceTableText(
            DefaultTableModel model,
            String rowLabel,
            int columnIndex) {
        for (int row = 0; row < model.getRowCount(); row++) {
            if (rowLabel.equals(String.valueOf(model.getValueAt(row, 0)))) {
                return String.valueOf(model.getValueAt(row, columnIndex));
            }
        }
        throw new AssertionError("Row not found: " + rowLabel);
    }

    /** Parses a numeric table cell (plain counts or legacy formatted failure cells). */
    private static long parseStatsTableLong(String raw) {
        String text = raw == null ? "" : raw.trim();
        int attemptsIdx = text.indexOf(" attempts");
        if (attemptsIdx > 0) {
            return Long.parseLong(text.substring(0, attemptsIdx).replace(",", "").trim());
        }
        return Long.parseLong(text);
    }

    private static int firstColumnPreferredWidth(JTable table) {
        return onEdt(() -> table.getColumnModel().getColumn(0).getPreferredWidth());
    }

    private static int requiredLabelColumnWidth(JTable table, String rowLabel) {
        return onEdt(() -> {
            int rowIndex = -1;
            for (int row = 0; row < table.getRowCount(); row++) {
                if (rowLabel.equals(String.valueOf(table.getValueAt(row, 0)))) {
                    rowIndex = row;
                    break;
                }
            }
            assertThat(rowIndex).isGreaterThanOrEqualTo(0);
            Component cell = table.prepareRenderer(table.getCellRenderer(rowIndex, 0), rowIndex, 0);
            Component header = table.getTableHeader()
                    .getDefaultRenderer()
                    .getTableCellRendererComponent(table, table.getColumnName(0), false, false, -1, 0);
            return Math.max(120, Math.max(header.getPreferredSize().width, cell.getPreferredSize().width) + 18);
        });
    }

    private static List<String> collectLabelTexts(Container root) {
        List<String> labels = new ArrayList<>();
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label) {
                labels.add(label.getText());
            }
            if (component instanceof Container child) {
                labels.addAll(collectLabelTexts(child));
            }
        }
        return labels;
    }

    private static <T extends Component> T findByName(Container root, String name, Class<T> type) {
        for (Component component : root.getComponents()) {
            if (name.equals(component.getName()) && type.isInstance(component)) {
                return type.cast(component);
            }
            if (component instanceof Container child) {
                T nested = findByName(child, name, type);
                if (nested != null) {
                    return nested;
                }
            }
        }
        return null;
    }

    private static void assertSeriesStyle(
            StatsPanel panel,
            XYLineAndShapeRenderer renderer,
            int index,
            float[] expectedDashArray,
            boolean expectedShapesVisible) {
        assertThat(renderer.getSeriesPaint(index)).isEqualTo(call(panel, "seriesLinePaint", index));
        assertThat(renderer.getSeriesShape(index).getBounds2D())
                .isEqualTo(((Shape) call(panel, "seriesMarkerShape", index)).getBounds2D());
        assertThat(renderer.getSeriesShapesVisible(index)).isEqualTo(expectedShapesVisible);

        BasicStroke actualStroke = (BasicStroke) renderer.getSeriesStroke(index);
        BasicStroke expectedStroke = (BasicStroke) call(panel, "seriesStroke", index);
        if (expectedDashArray == null) {
            assertThat(actualStroke.getDashArray()).isNull();
        } else {
            assertThat(actualStroke.getDashArray()).containsExactly(expectedDashArray);
        }
        if (expectedStroke.getDashArray() == null) {
            assertThat(actualStroke.getDashArray()).isNull();
        } else {
            assertThat(actualStroke.getDashArray()).containsExactly(expectedStroke.getDashArray());
        }
    }

    private static XYLineAndShapeRenderer currentRenderer(JFreeChart chart) {
        return (XYLineAndShapeRenderer) chart.getXYPlot().getRenderer();
    }

    private static Color seriesBaseColor(StatsPanel panel, int index) {
        return (Color) call(panel, "seriesSolidColor", index);
    }

    private static ConfigState.State runtimeState(boolean filesEnabled, boolean openSearchEnabled) {
        return new ConfigState.State(
                List.of(ConfigKeys.SRC_TRAFFIC),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(
                        filesEnabled,
                        filesEnabled ? "/path/to/directory" : "",
                        filesEnabled,
                        filesEnabled,
                        true,
                        ConfigState.DEFAULT_FILE_TOTAL_CAP_GB,
                        false,
                        ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                        openSearchEnabled,
                        openSearchEnabled ? "https://opensearch.url:9200" : "",
                        "",
                        "",
                        true),
                ConfigState.DEFAULT_SETTINGS_SUB,
                List.of("proxy"),
                ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
    }
}
