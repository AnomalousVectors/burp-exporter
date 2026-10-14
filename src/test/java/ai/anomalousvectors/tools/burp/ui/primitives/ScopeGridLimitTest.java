package ai.anomalousvectors.tools.burp.ui.primitives;

import java.util.ArrayList;
import java.util.List;

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

    private static List<ScopeGrid.ScopeEntryInit> entries(int count) {
        List<ScopeGrid.ScopeEntryInit> entries = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            entries.add(new ScopeGrid.ScopeEntryInit("scope-" + i, true));
        }
        return entries;
    }
}
