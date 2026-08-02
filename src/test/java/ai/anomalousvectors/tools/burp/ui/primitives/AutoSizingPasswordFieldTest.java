package ai.anomalousvectors.tools.burp.ui.primitives;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Focused coverage for {@link AutoSizingPasswordField} Look-and-Feel client properties.
 */
class AutoSizingPasswordFieldTest {

    @Test
    void constructor_disablesFlatLafRevealButton() {
        AutoSizingPasswordField field = new AutoSizingPasswordField();
        assertThat(field.getClientProperty("JPasswordField.showRevealButton")).isEqualTo(Boolean.FALSE);
    }

    @Test
    void updateUI_keepsFlatLafRevealButtonDisabled() {
        AutoSizingPasswordField field = new AutoSizingPasswordField(AutoSizingPasswordField.CREDENTIAL_MIN_WIDTH);
        field.updateUI();
        assertThat(field.getClientProperty("JPasswordField.showRevealButton")).isEqualTo(Boolean.FALSE);
    }
}
