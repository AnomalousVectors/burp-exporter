package ai.anomalousvectors.tools.burp.ui.primitives;

import java.awt.Component;
import java.awt.Container;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigImportPolicy;

class ScopeGridLimitTest {

    @Test
    void constructorAndReplacementRejectMoreThanSharedMaximum() {
        List<ScopeGrid.ScopeEntryInit> entries = entries(
                ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES + 1);

        assertThatThrownBy(() -> new ScopeGrid(entries))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum is 100");

        ScopeGrid grid = new ScopeGrid(List.of());
        assertThatThrownBy(() -> grid.setEntries(entries))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum is 100");
    }

    @Test
    void serializationRestoresRegexAddAndDeleteBindings() throws Exception {
        ScopeGrid original = new ScopeGrid(List.of(
                new ScopeGrid.ScopeEntryInit("one", true),
                new ScopeGrid.ScopeEntryInit("two", true)));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
            output.writeObject(original);
        }

        ScopeGrid restored;
        try (ObjectInputStream input = new ObjectInputStream(
                new ByteArrayInputStream(bytes.toByteArray()))) {
            restored = (ScopeGrid) input.readObject();
        }

        ScopeGrid grid = restored;
        SwingUtilities.invokeAndWait(() -> {
            grid.addNotify();
            JTextField firstField = (JTextField) findByName(grid, "scope.custom.regex");
            JLabel firstIndicator = (JLabel) findByName(grid, "scope.custom.regex.indicator.1");
            JButton secondDelete = (JButton) findByName(grid, "scope.custom.delete.2");

            firstField.setText("[");
            assertThat(firstIndicator.isVisible()).isTrue();
            secondDelete.doClick();
            assertThat(grid.values()).containsExactly("[");
            JButton addButton = (JButton) findByName(grid, "scope.custom.add");
            addButton.doClick();
            assertThat(grid.values()).containsExactly("[", "");
            grid.removeNotify();
        });
    }

    private static List<ScopeGrid.ScopeEntryInit> entries(int count) {
        List<ScopeGrid.ScopeEntryInit> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            entries.add(new ScopeGrid.ScopeEntryInit("scope-" + i, true));
        }
        return entries;
    }

    private static Component findByName(Container root, String name) {
        if (name.equals(root.getName())) {
            return root;
        }
        for (Component child : root.getComponents()) {
            if (name.equals(child.getName())) {
                return child;
            }
            if (child instanceof Container container) {
                Component match = findByName(container, name);
                if (match != null) {
                    return match;
                }
            }
        }
        return null;
    }
}
