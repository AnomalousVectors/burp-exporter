package ai.anomalousvectors.tools.burp.ui;

import ai.anomalousvectors.tools.burp.ui.log.LogStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Compaction behavior for duplicate messages.
 *
 * <p>Verifies that consecutive duplicates compact during ingestion and that
 * visible aggregation reflects the total repeat count.</p>
 */
class LogStoreCompactionTest {

    @Test
    @ResourceLock("default-locale")
    void levelParsing_isLocaleIndependent() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));

            assertEquals(LogStore.Level.INFO, LogStore.Level.fromString("info"));
        } finally {
            Locale.setDefault(original);
        }
    }

    /**
     * Ingesting identical (level, message) triples compacts into a replace decision
     * and yields a single aggregated line with an incremented repeat count.
     */
    @Test
    void duplicate_messages_compact_and_emit_replace_with_incremented_repeats() {
        LogStore store = new LogStore(100, (lvl, msg) -> true);

        var d1 = store.ingest(LogStore.Level.INFO, "same", LocalDateTime.now());
        assertEquals(LogStore.Decision.Kind.APPEND, d1.kind());
        assertNotNull(d1.entry());
        assertEquals("same", d1.entry().message);

        var d2 = store.ingest(LogStore.Level.INFO, "same", LocalDateTime.now());
        assertEquals(LogStore.Decision.Kind.REPLACE, d2.kind());
        assertNotNull(d2.entry());

        var d3 = store.ingest(LogStore.Level.INFO, "same", LocalDateTime.now());
        assertEquals(LogStore.Decision.Kind.REPLACE, d3.kind());
        assertNotNull(d3.entry());

        List<LogStore.Aggregate> agg = store.buildVisibleAggregated();
        assertEquals(1, agg.size(), "Only one visible line after compaction");

        LogStore.Aggregate first = agg.getFirst();
        assertEquals("same", first.message());
        assertTrue(first.count() >= 3, "Repeat count should reflect all duplicates");
    }
}
