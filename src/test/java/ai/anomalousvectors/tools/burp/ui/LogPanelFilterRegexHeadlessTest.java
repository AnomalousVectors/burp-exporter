package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import static ai.anomalousvectors.tools.burp.testutils.Reflect.get;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.newPanel;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.resetPanelState;
import static ai.anomalousvectors.tools.burp.ui.LogPanelTestHarness.setText;
import static org.assertj.core.api.Assertions.assertThat;

class LogPanelFilterRegexHeadlessTest {

    @Test
    void filter_regex_respects_case_toggle_and_matches_substrings() throws Exception {
        LogPanel panel = newPanel();
        resetPanelState(panel);

        JTextField filterField = JTextField.class.cast(get(panel, "filterField", JTextField.class));
        JCheckBox filterCaseToggle = JCheckBox.class.cast(get(panel, "filterCaseToggle", JCheckBox.class));
        JCheckBox filterRegexToggle = JCheckBox.class.cast(get(panel, "filterRegexToggle", JCheckBox.class));
        JTextArea logTextPane = JTextArea.class.cast(get(panel, "logTextPane", JTextArea.class));
        Document doc = logTextPane.getDocument();

        // Ingest two messages with different casing
        panel.onLog("INFO", "Hello ABC");
        panel.onLog("INFO", "hello abc");

        // Ensure the REGEX filter is ON (use doClick so ActionListener fires and view rebuilds)
        SwingUtilities.invokeAndWait(() -> {
            if (!filterRegexToggle.isSelected()) filterRegexToggle.doClick();
        });

        // Case-insensitive: ensure the toggle is OFF (again via doClick for rebuild)
        SwingUtilities.invokeAndWait(() -> {
            if (filterCaseToggle.isSelected()) filterCaseToggle.doClick();
            filterField.setText("abc"); // DocumentListener triggers rebuild
        });
        String text1 = docText(doc);
        assertThat(text1)
                .contains("Hello ABC")
                .contains("hello abc");

        // Case-sensitive: turn toggle ON via doClick (rebuild happens in ActionListener)
        SwingUtilities.invokeAndWait(() -> {
            if (!filterCaseToggle.isSelected()) filterCaseToggle.doClick();
        });
        String text2 = docText(doc);
        assertThat(text2)
                .doesNotContain("Hello ABC")
                .contains("hello abc");
    }

    @Test
    void filter_reusesPreparedPatternUntilControlsChange() throws Exception {
        LogPanel panel = newPanel();
        resetPanelState(panel);
        JTextField filterField = JTextField.class.cast(get(panel, "filterField", JTextField.class));
        JCheckBox filterRegexToggle = JCheckBox.class.cast(get(panel, "filterRegexToggle", JCheckBox.class));
        JCheckBox filterCaseToggle = JCheckBox.class.cast(get(panel, "filterCaseToggle", JCheckBox.class));

        SwingUtilities.invokeAndWait(() -> {
            if (!filterRegexToggle.isSelected()) filterRegexToggle.doClick();
        });
        setText(filterField, "event-[0-9]+");
        LogPanel.TextFilterState prepared =
                LogPanel.TextFilterState.class.cast(get(panel, "textFilterState", LogPanel.TextFilterState.class));

        for (int i = 0; i < 100; i++) {
            panel.onLog("INFO", "event-" + i);
        }
        LogPanel.TextFilterState afterIngest =
                LogPanel.TextFilterState.class.cast(get(panel, "textFilterState", LogPanel.TextFilterState.class));

        assertThat(afterIngest).isSameAs(prepared);
        assertThat(afterIngest.pattern()).isSameAs(prepared.pattern());

        SwingUtilities.invokeAndWait(filterCaseToggle::doClick);
        LogPanel.TextFilterState afterControlChange =
                LogPanel.TextFilterState.class.cast(get(panel, "textFilterState", LogPanel.TextFilterState.class));
        assertThat(afterControlChange).isNotSameAs(prepared);
    }

    private static String docText(Document doc) throws BadLocationException {
        return doc.getText(0, doc.getLength());
    }

}
