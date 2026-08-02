package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CardCopySupport}: TSV and section-text rendering and safe escaping.
 */
class CardCopySupportTest {

    @Test
    void tableToTsv_rendersHeaderAndRows() {
        DefaultTableModel model = new DefaultTableModel(
                new Object[][] {
                        {"traffic", 123L, "-"},
                        {"findings", 4L, "err"}
                },
                new Object[] {"Source", "Docs", "Last Error"});
        JTable table = new JTable(model);
        String tsv = CardCopySupport.tableToTsv(table);
        String[] lines = tsv.split("\n");
        assertThat(lines).hasSize(3);
        assertThat(lines[0]).isEqualTo("Source\tDocs\tLast Error");
        assertThat(lines[1]).isEqualTo("traffic\t123\t-");
        assertThat(lines[2]).isEqualTo("findings\t4\terr");
    }

    @Test
    void tableToTsv_escapesEmbeddedTabsAndNewlines() {
        DefaultTableModel model = new DefaultTableModel(
                new Object[][] { {"with\ttab", "with\nnewline"} },
                new Object[] {"A", "B"});
        JTable table = new JTable(model);
        String tsv = CardCopySupport.tableToTsv(table);
        String[] lines = tsv.split("\n");
        assertThat(lines[1]).isEqualTo("with tab\twith newline");
    }

    @Test
    void tableToTsv_nullTableReturnsEmpty() {
        assertThat(CardCopySupport.tableToTsv(null)).isEmpty();
    }

    @Test
    void attachCopyButton_onBoxLayoutCard_insertsHeaderAtIndexZero() throws Exception {
        // Misc Stats branch: header must sit at index 0 so it appears immediately under the
        // titled border, with no other components shifted out from under it.
        JPanel card = onEdt(() -> {
            JPanel p = new JPanel();
            p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
            p.setBorder(BorderFactory.createTitledBorder("Misc Stats"));
            p.add(new JLabel("body-row-1"));
            p.add(new JLabel("body-row-2"));
            return p;
        });
        onEdt(() -> CardCopySupport.attachCopyButton(card, "Misc Stats", () -> "payload"));

        Component first = card.getComponent(0);
        assertThat(first).isInstanceOf(JPanel.class);
        // The header must clamp its max height to its preferred so BoxLayout.Y_AXIS surplus
        // does not get absorbed (the regression that produced the gap above "Overview").
        JPanel header = (JPanel) first;
        assertThat(header.getMaximumSize().height).isEqualTo(header.getPreferredSize().height);
        // Verify the header carries the named Copy button keyed by card title.
        JButton copy = (JButton) findNamed(header, "copy.Misc Stats");
        assertThat(copy).isNotNull();
        assertThat(copy.getText()).isEqualTo("Copy");
    }

    @Test
    void attachCopyButton_onBorderLayoutCardWithExistingNorth_stacksHeaderAboveExistingNorth() throws Exception {
        // Tables branch: the table card has an existing NORTH header; the copy header must be
        // stacked above it (not replace it) so the table-column header still renders.
        JLabel existingNorth = onEdt(() -> new JLabel("existing-table-header"));
        existingNorth.setName("existingNorth");
        JPanel card = onEdt(() -> {
            JPanel p = new JPanel(new BorderLayout());
            p.add(existingNorth, BorderLayout.NORTH);
            return p;
        });

        onEdt(() -> CardCopySupport.attachCopyButton(card, "Index Counts", () -> "payload"));

        BorderLayout bl = (BorderLayout) card.getLayout();
        Component north = bl.getLayoutComponent(BorderLayout.NORTH);
        assertThat(north).isInstanceOf(JPanel.class);
        JPanel stacked = (JPanel) north;
        assertThat(stacked.getLayout()).isInstanceOf(BoxLayout.class);
        assertThat(stacked.getComponentCount()).isEqualTo(2);
        assertThat(stacked.getComponent(0)).isInstanceOf(JPanel.class);
        assertThat(stacked.getComponent(1)).isSameAs(existingNorth);
        assertThat(findNamed(stacked, "copy.Index Counts")).isNotNull();
    }

    @Test
    void sectionsToText_rendersTitleAndSections() {
        LinkedHashMap<String, Map<String, String>> sections = new LinkedHashMap<>();
        LinkedHashMap<String, String> global = new LinkedHashMap<>();
        global.put("Export Running", "false");
        global.put("Traffic Queue Size", "0");
        sections.put("Overview", global);
        LinkedHashMap<String, String> process = new LinkedHashMap<>();
        process.put("Heap Used / Max", "128 MiB / 512 MiB (25%)");
        sections.put("Process", process);

        String text = CardCopySupport.sectionsToText("Misc Stats", sections);
        assertThat(text).startsWith("Misc Stats\n");
        assertThat(text).contains("\nOverview\n");
        assertThat(text).contains("  Export Running: false\n");
        assertThat(text).contains("  Traffic Queue Size: 0\n");
        assertThat(text).contains("\nProcess\n");
        assertThat(text).contains("  Heap Used / Max: 128 MiB / 512 MiB (25%)\n");
    }

    @Test
    void copyToClipboard_doesNotLogWhenExportNotRunning() throws Exception {
        List<String> infoMessages = new ArrayList<>();
        Logger.LogListener listener = (level, message) -> {
            if ("INFO".equals(level)) {
                infoMessages.add(message);
            }
        };
        Logger.registerListener(listener);
        RuntimeConfig.setExportRunning(false);
        try {
            JPanel card = onEdt(() -> {
                JPanel p = new JPanel();
                p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
                return p;
            });
            onEdt(() -> CardCopySupport.attachCopyButton(card, "Misc Stats", () -> "payload"));
            JButton copy = (JButton) onEdt(() -> findNamed(card, "copy.Misc Stats"));
            onEdt(() -> copy.getActionListeners()[0].actionPerformed(new ActionEvent(copy, 0, "copy")));
            assertThat(infoMessages).noneMatch(line -> line.contains("[StatsPanel]"));
        } finally {
            Logger.unregisterListener(listener);
            Logger.resetState();
            RuntimeConfig.setExportRunning(false);
        }
    }

    private static <T> T onEdt(java.util.concurrent.Callable<T> supplier) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            return supplier.call();
        }
        java.util.concurrent.atomic.AtomicReference<T> ref = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Exception> err = new java.util.concurrent.atomic.AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                ref.set(supplier.call());
            } catch (Exception e) {
                err.set(e);
            }
        });
        if (err.get() != null) {
            throw err.get();
        }
        return ref.get();
    }

    private static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
            return;
        }
        try {
            SwingUtilities.invokeAndWait(r);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    private static Component findNamed(Component root, String name) {
        if (name.equals(root.getName())) {
            return root;
        }
        if (root instanceof java.awt.Container c) {
            for (Component child : c.getComponents()) {
                Component match = findNamed(child, name);
                if (match != null) {
                    return match;
                }
            }
        }
        return null;
    }
}
