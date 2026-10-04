package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;

class WholeFileSaveTest {

    @Test
    void writeUtf8_createNew_installsCompleteFileWithoutTemporaryArtifact() throws Exception {
        Path directory = TestPathSupport.createDirectory("whole-save-create");
        Path target = directory.resolve("config.json");

        WholeFileSave.writeUtf8(target, "new-content", WholeFileSave.Replacement.CREATE_NEW);

        assertThat(Files.readString(target)).isEqualTo("new-content");
        assertThat(temporaryArtifacts(directory, target)).isEmpty();
    }

    @Test
    void writeUtf8_replaceExisting_replacesCompleteFile() throws Exception {
        Path directory = TestPathSupport.createDirectory("whole-save-replace");
        Path target = directory.resolve("saved.log");
        Files.writeString(target, "original");

        WholeFileSave.writeUtf8(target, "replacement", WholeFileSave.Replacement.REPLACE_EXISTING);

        assertThat(Files.readString(target)).isEqualTo("replacement");
        assertThat(temporaryArtifacts(directory, target)).isEmpty();
    }

    @Test
    void writeUtf8_createNew_preservesExistingTarget() throws Exception {
        Path directory = TestPathSupport.createDirectory("whole-save-existing");
        Path target = directory.resolve("saved.log");
        Files.writeString(target, "original");

        assertThatThrownBy(() -> WholeFileSave.writeUtf8(
                target, "replacement", WholeFileSave.Replacement.CREATE_NEW))
                .isInstanceOf(FileAlreadyExistsException.class);

        assertThat(Files.readString(target)).isEqualTo("original");
        assertThat(temporaryArtifacts(directory, target)).isEmpty();
    }

    @Test
    void writeUtf8_createNew_preservesTargetCreatedBeforeInstall() throws Exception {
        Path directory = TestPathSupport.createDirectory("whole-save-create-race");
        Path target = directory.resolve("saved.log");

        assertThatThrownBy(() -> WholeFileSave.writeUtf8(
                target,
                "replacement",
                WholeFileSave.Replacement.CREATE_NEW,
                (source, destination, options) -> {
                    Files.writeString(destination, "appeared-after-confirmation");
                    Files.move(source, destination, options);
                }))
                .isInstanceOf(FileAlreadyExistsException.class);

        assertThat(Files.readString(target)).isEqualTo("appeared-after-confirmation");
        assertThat(temporaryArtifacts(directory, target)).isEmpty();
    }

    @Test
    void writeUtf8_moveFailure_preservesExistingTargetAndDeletesTemporaryArtifact() throws Exception {
        Path directory = TestPathSupport.createDirectory("whole-save-failure");
        Path target = directory.resolve("saved.log");
        Files.writeString(target, "original");

        assertThatThrownBy(() -> WholeFileSave.writeUtf8(
                target,
                "replacement",
                WholeFileSave.Replacement.REPLACE_EXISTING,
                (source, destination, options) -> {
                    throw new IOException("forced move failure");
                }))
                .isInstanceOf(IOException.class)
                .hasMessage("forced move failure");

        assertThat(Files.readString(target)).isEqualTo("original");
        assertThat(temporaryArtifacts(directory, target)).isEmpty();
    }

    @Test
    void writeUtf8_atomicMoveUnsupported_usesSameDirectoryFallback() throws Exception {
        Path directory = TestPathSupport.createDirectory("whole-save-fallback");
        Path target = directory.resolve("config.json");
        Files.writeString(target, "original");
        AtomicInteger moves = new AtomicInteger();

        WholeFileSave.writeUtf8(
                target,
                "content",
                WholeFileSave.Replacement.REPLACE_EXISTING,
                (source, destination, options) -> {
                    if (moves.incrementAndGet() == 1) {
                        throw new AtomicMoveNotSupportedException(
                                source.toString(), destination.toString(), "forced fallback");
                    }
                    Files.move(source, destination, options);
                });

        assertThat(moves).hasValue(2);
        assertThat(Files.readString(target)).isEqualTo("content");
        assertThat(temporaryArtifacts(directory, target)).isEmpty();
    }

    private static java.util.List<Path> temporaryArtifacts(Path directory, Path target) throws IOException {
        String prefix = "." + target.getFileName() + ".";
        try (var paths = Files.list(directory)) {
            return paths.filter(path -> path.getFileName().toString().startsWith(prefix)).toList();
        }
    }
}
