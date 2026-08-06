package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProxyCorrelationSpoolTest {

    private static final String TOKEN = "00000000-0000-0000-0000-000000000001";
    private static final String TOKEN_B = "00000000-0000-0000-0000-000000000002";

    @TempDir
    Path tempDir;

    @Test
    void persistAndRecover_preservesGenerationAndProjectOwnership() {
        ProxyCorrelationSpool owner =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A");
        ProxyCorrelationSpool.StoredEntry entry = new ProxyCorrelationSpool.StoredEntry(
                TOKEN,
                17,
                8080,
                42L,
                1_700_000_000_000L,
                1_700_000_000_100L,
                Map.of("burp", Map.of("message_id", 17)),
                false,
                false);

        assertThat(owner.persist(entry)).isEqualTo(ProxyCorrelationSpool.PersistResult.STORED);

        ProxyCorrelationSpool recovered =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A");
        ProxyCorrelationSpool foreign =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project B");

        assertThat(recovered.recover()).singleElement().satisfies(value -> {
            assertThat(value.token()).isEqualTo(TOKEN);
            assertThat(value.messageId()).isEqualTo(17);
            assertThat(value.listenerPort()).isEqualTo(8080);
            assertThat(value.generation()).isEqualTo(42L);
            assertThat(value.requestSentMs()).isEqualTo(1_700_000_000_000L);
        });
        assertThat(foreign.count()).isZero();
    }

    @Test
    void initialization_deletesOnlyOwnedTemporaryFiles() throws Exception {
        String ownedName = "project-a--" + TOKEN + ".json.tmp";
        String foreignName = "project-b--" + TOKEN + ".json.tmp";
        String deliveredName = "project-a--" + TOKEN + ".json.delivered";
        Path owned = tempDir.resolve(ownedName);
        Path foreign = tempDir.resolve(foreignName);
        Path delivered = tempDir.resolve(deliveredName);
        Files.writeString(owned, "partial");
        Files.writeString(foreign, "foreign");
        Files.writeString(delivered, "complete");

        new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A");

        assertThat(owned).doesNotExist();
        assertThat(delivered).doesNotExist();
        assertThat(foreign).exists();
    }

    @Test
    void completedToken_cannotBeRecreatedByStalePersistence() {
        ProxyCorrelationSpool spool =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A");
        ProxyCorrelationSpool.StoredEntry entry = new ProxyCorrelationSpool.StoredEntry(
                TOKEN,
                17,
                8080,
                42L,
                1_700_000_000_000L,
                1_700_000_000_100L,
                Map.of("burp", Map.of("message_id", 17)),
                true,
                true);

        assertThat(spool.persist(entry)).isEqualTo(ProxyCorrelationSpool.PersistResult.STORED);
        assertThat(spool.complete(TOKEN)).isTrue();
        assertThat(spool.persist(entry)).isEqualTo(ProxyCorrelationSpool.PersistResult.STORED);

        assertThat(spool.count()).isZero();
        assertThat(spool.recover()).isEmpty();
    }

    @Test
    void recover_quarantinesCorruptOwnedEntryAndKeepsValidEntries() throws Exception {
        ProxyCorrelationSpool writer =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A");
        ProxyCorrelationSpool.StoredEntry valid = new ProxyCorrelationSpool.StoredEntry(
                TOKEN,
                17,
                8080,
                42L,
                1_700_000_000_000L,
                1_700_000_000_100L,
                Map.of("burp", Map.of("message_id", 17)),
                false,
                false);
        assertThat(writer.persist(valid)).isEqualTo(ProxyCorrelationSpool.PersistResult.STORED);
        Path malformed = tempDir.resolve("project-a--" + TOKEN_B + ".json");
        Files.writeString(malformed, "{not-json");

        ProxyCorrelationSpool recovered =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A");

        assertThat(recovered.recover()).containsExactly(valid);
        assertThat(malformed).doesNotExist();
        assertThat(tempDir.resolve(malformed.getFileName() + ".corrupt")).exists();
        assertThat(recovered.count()).isEqualTo(1L);
        assertThat(recovered.permanentFailures()).isEqualTo(1L);
    }

    @Test
    void failedCompletionMove_leavesRestartTombstoneThatPreventsDuplicateRecovery() {
        AtomicBoolean rejectMoves = new AtomicBoolean();
        ProxyCorrelationSpool spool =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A") {
                    @Override
                    void moveAtomically(Path source, Path target) throws IOException {
                        if (rejectMoves.get()) {
                            throw new IOException("simulated completion move failure");
                        }
                        super.moveAtomically(source, target);
                    }
                };
        ProxyCorrelationSpool.StoredEntry entry = new ProxyCorrelationSpool.StoredEntry(
                TOKEN,
                17,
                8080,
                42L,
                1_700_000_000_000L,
                1_700_000_000_100L,
                Map.of("burp", Map.of("message_id", 17)),
                true,
                true);
        assertThat(spool.persist(entry)).isEqualTo(ProxyCorrelationSpool.PersistResult.STORED);

        rejectMoves.set(true);
        assertThat(spool.complete(TOKEN)).isTrue();

        ProxyCorrelationSpool restarted =
                new ProxyCorrelationSpool(tempDir, 10_000_000L, 100L, "Project A");
        assertThat(restarted.recover()).isEmpty();
        assertThat(restarted.count()).isZero();
    }
}
