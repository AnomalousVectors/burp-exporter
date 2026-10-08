package ai.anomalousvectors.tools.burp.ui;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;

class SinkCountTableSnapshotTest {

    @BeforeEach
    void resetStats() {
        ExportStats.resetForTests();
    }

    @AfterEach
    void clearStats() {
        ExportStats.resetForTests();
    }

    @Test
    void fileSnapshot_hasExactRowWidthsAndSortableNumericValues() {
        FileExportStats.recordSuccess("traffic", 1_234L);
        FileExportStats.recordTrafficToolTypeSuccess("PROXY", 1_234L);
        FileExportStats.recordArtifactRegistration("traffic", 1_024L);
        FileExportStats.recordExportedBytes("traffic", 2_048L);
        FileExportStats.recordArtifactCompletion(
                "traffic", 1_024L, 3_072L, 3_072L, FileExportStats.ArtifactIntegrity.OK, null);

        SinkCountTableSnapshot snapshot = SinkCountTableSnapshot.file();

        assertThat(snapshot.columns()).hasSize(10);
        assertThat(snapshot.rows()).allSatisfy(row -> assertThat(row.values()).hasSize(10));
        SinkCountTableSnapshot.Row traffic = rowNamed(snapshot, "Traffic");
        assertThat(traffic.values().get(1)).isInstanceOf(Number.class);
        assertThat(traffic.values().get(4)).isInstanceOf(Number.class).hasToString("1.0 KiB");
        assertThat(traffic.values().get(5)).isInstanceOf(Number.class).hasToString("2.0 KiB");
        assertThat(rowNamed(snapshot, "    Proxy").values()).hasSize(10);
        assertThat(traffic.toTextValues())
                .containsExactly("Traffic", "1,234", "0", "0", "1.0 KiB", "2.0 KiB", "3.0 KiB", "OK", "-", "-");
    }

    @Test
    void databaseSnapshot_preservesSharedOrderLabelsAndNumericRows() {
        ExportStats.recordExported("traffic", 1_234L);
        ExportStats.recordTrafficToolTypeSuccess("PROXY", 1_234L);

        SinkCountTableSnapshot snapshot = SinkCountTableSnapshot.database();

        assertThat(snapshot.columns()).containsExactly(
                "Index",
                "Exported",
                "Failures",
                "Queued",
                "Recovered Failures",
                "Retry Drops",
                "Permanent Drops",
                "Last Bulk (ms)",
                "Last Error");
        assertThat(snapshot.rows()).allSatisfy(row -> assertThat(row.values()).hasSize(9));
        SinkCountTableSnapshot.Row traffic = rowNamed(snapshot, "Traffic");
        assertThat(traffic.values().get(1)).isEqualTo(1_234L);
        assertThat(traffic.toTextValues()[1]).isEqualTo("1,234");
        assertThat(rowNamed(snapshot, "    Proxy").values().get(1)).isEqualTo(1_234L);
        assertThat(snapshot.rows().getLast().values().getFirst()).isEqualTo("Total");
    }

    @Test
    void constructor_rejectsRowsThatDoNotMatchColumnSchema() {
        SinkCountTableSnapshot.Row shortRow = new SinkCountTableSnapshot.Row(List.of("only one"));

        assertThatThrownBy(() -> new SinkCountTableSnapshot(List.of("one", "two"), List.of(shortRow)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Sink count row width does not match its columns");
    }

    private static SinkCountTableSnapshot.Row rowNamed(SinkCountTableSnapshot snapshot, String label) {
        return snapshot.rows().stream()
                .filter(row -> label.equals(row.values().getFirst()))
                .findFirst()
                .orElseThrow();
    }
}
