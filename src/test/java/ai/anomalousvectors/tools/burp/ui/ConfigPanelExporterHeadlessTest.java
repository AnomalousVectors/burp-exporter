package ai.anomalousvectors.tools.burp.ui;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Dimension;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.Reflect;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.ui.primitives.TriStateCheckBox;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

class ConfigPanelExporterHeadlessTest {

    @Test
    void exporterSource_defaultsEnabled_withStatsIntervalAndExporterFieldsSection() throws Exception {
        ConfigPanel panel = createPanel();

        JCheckBox exporterCheckbox = Reflect.get(panel, "exporterCheckbox", TriStateCheckBox.class);
        JCheckBox exporterStatsCheckbox = Reflect.get(panel, "exporterStatsCheckbox", JCheckBox.class);
        JTextField exporterStatsIntervalField = Reflect.get(panel, "exporterStatsIntervalField", JTextField.class);
        JTextField indexNameBaseTemplateField = Reflect.get(panel, "indexNameBaseTemplateField", JTextField.class);
        JLabel indexNameValidationIndicator = Reflect.get(panel, "indexNameBaseValidationIndicator", JLabel.class);
        Map<String, JPanel> headerRows = Reflect.stringKeyedMap(panel, "fieldsSectionHeaderRows", JPanel.class);

        ConfigState.State state = (ConfigState.State) Reflect.call(panel, "buildCurrentState");

        assertThat(exporterCheckbox.isSelected()).isTrue();
        assertThat(exporterCheckbox.getToolTipText()).contains("Burp Exporter runtime logs and metrics");
        assertThat(exporterStatsCheckbox.isSelected()).isTrue();
        assertThat(exporterStatsIntervalField.getText()).isEqualTo("30");
        assertThat(indexNameBaseTemplateField.getText()).isEqualTo("tool-burp");
        assertThat(indexNameValidationIndicator.isVisible()).isTrue();
        assertThat(indexNameValidationIndicator.getText()).isEqualTo("✓");
        assertThat(indexNameValidationIndicator.getToolTipText()).contains("Valid Index Base Name");
        assertThat(headerRows).containsKey("exporter");
        assertThat(state.dataSources()).contains(ConfigKeys.SRC_EXPORTER);
        assertThat(state.exporterSubOptions()).contains(
                ConfigKeys.SRC_EXPORTER_INFO,
                ConfigKeys.SRC_EXPORTER_STATS,
                ConfigKeys.SRC_EXPORTER_CONFIG);
        assertThat(state.exporterStatsIntervalSeconds()).isEqualTo(30);
        assertThat(state.indexNameBaseTemplate()).isEqualTo("tool-burp");
    }

    @Test
    void indexBaseName_liveValidation_updatesInlineFeedback() throws Exception {
        ConfigPanel panel = createPanel();

        JTextField indexNameBaseTemplateField = Reflect.get(panel, "indexNameBaseTemplateField", JTextField.class);
        JLabel indexNameValidationIndicator = Reflect.get(panel, "indexNameBaseValidationIndicator", JLabel.class);

        SwingUtilities.invokeAndWait(() -> indexNameBaseTemplateField.setText("Invalid Base"));
        assertThat(indexNameValidationIndicator.isVisible()).isTrue();
        assertThat(indexNameValidationIndicator.getText()).isEqualTo("✖");
        assertThat(indexNameValidationIndicator.getToolTipText()).contains("Invalid Index Base Name");
        assertThat(indexNameValidationIndicator.getToolTipText()).contains("must be lowercase");
        assertThat(indexNameValidationIndicator.getToolTipText()).contains("Failing resolved index");
        assertThat(indexNameValidationIndicator.getToolTipText()).contains("Requirements");

        SwingUtilities.invokeAndWait(() -> indexNameBaseTemplateField.setText("tool-burp"));
        assertThat(indexNameValidationIndicator.isVisible()).isTrue();
        assertThat(indexNameValidationIndicator.getText()).isEqualTo("✓");
        assertThat(indexNameValidationIndicator.getToolTipText()).contains("Valid Index Base Name");
    }

    @Test
    void indexBaseName_fieldAutoSizesLikeDestinationFields() throws Exception {
        ConfigPanel panel = createPanel();

        JTextField indexNameBaseTemplateField = Reflect.get(panel, "indexNameBaseTemplateField", JTextField.class);
        JTextField openSearchUrlField = Reflect.get(panel, "openSearchUrlField", JTextField.class);

        Dimension initialIndexSize = indexNameBaseTemplateField.getPreferredSize();
        Dimension initialOpenSearchSize = openSearchUrlField.getPreferredSize();

        SwingUtilities.invokeAndWait(() -> indexNameBaseTemplateField.setText(
                "${now:yyyyMMdd-HHmmss}-tool-burp-with-a-longer-shared-base"));

        Dimension grownIndexSize = indexNameBaseTemplateField.getPreferredSize();
        Dimension unchangedOpenSearchSize = openSearchUrlField.getPreferredSize();

        assertThat(grownIndexSize.width).isGreaterThan(initialIndexSize.width);
        assertThat(grownIndexSize.height).isEqualTo(initialIndexSize.height);
        assertThat(unchangedOpenSearchSize).isEqualTo(initialOpenSearchSize);
    }

    private static ConfigPanel createPanel() throws Exception {
        AtomicReference<ConfigPanel> ref = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            ConfigPanel panel = new ConfigPanel(new ConfigController(new NoopUi()));
            panel.setSize(1000, 700);
            panel.doLayout();
            ref.set(panel);
        });
        return ref.get();
    }

    private static final class NoopUi implements ConfigController.Ui {
        @Override public void onFileStatus(String message) {}
        @Override public void onDatabaseStatus(String message) {}
        @Override public void onControlStatus(String message) {}
    }
}
