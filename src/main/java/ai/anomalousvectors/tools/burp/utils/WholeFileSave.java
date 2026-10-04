package ai.anomalousvectors.tools.burp.utils;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

/**
 * Transactional UTF-8 replacement for explicit user-initiated whole-file saves.
 *
 * <p>The complete payload is written to a uniquely named sibling temporary file before the final
 * target is changed. Confirmed replacements prefer an atomic move and fall back to a
 * same-directory move when the filesystem does not support atomic moves. New-file saves use a
 * non-replacing move so a file created after UI confirmation is never overwritten. This helper is
 * intended for explicit Config exports, not append-oriented exporter output or managed spill
 * files.</p>
 */
public final class WholeFileSave {

    /** Controls whether an existing regular target may be replaced. */
    public enum Replacement {
        /** Fail if the target exists when replacement begins. */
        CREATE_NEW,
        /** Replace an existing regular file after the UI has confirmed the operation. */
        REPLACE_EXISTING
    }

    @FunctionalInterface
    interface MoveOperation {
        void move(Path source, Path target, CopyOption... options) throws IOException;
    }

    private WholeFileSave() { }

    /**
     * Writes UTF-8 text through a sibling temporary file and installs it at {@code target}.
     *
     * <p>Caller should invoke off the EDT. Parent directories are created before the temporary
     * file. If writing, interruption, or the final move fails, the temporary file is deleted and
     * the previous target remains unchanged unless the filesystem fails during its non-atomic
     * replacement operation.</p>
     *
     * @param target final standalone file
     * @param content complete file contents; {@code null} is written as an empty string
     * @param replacement whether an existing regular target may be replaced
     * @throws IOException when validation, writing, or replacement fails
     * @throws NullPointerException when {@code target} or {@code replacement} is {@code null}
     */
    public static void writeUtf8(Path target, String content, Replacement replacement) throws IOException {
        writeUtf8(target, content, replacement, Files::move);
    }

    static void writeUtf8(
            Path target,
            String content,
            Replacement replacement,
            MoveOperation mover) throws IOException {
        Path normalizedTarget = Objects.requireNonNull(target, "target").toAbsolutePath().normalize();
        Replacement resolvedReplacement = Objects.requireNonNull(replacement, "replacement");
        MoveOperation resolvedMover = Objects.requireNonNull(mover, "mover");
        Path parent = normalizedTarget.getParent();
        if (parent == null) {
            throw new IOException("Save target must have a parent directory.");
        }
        Files.createDirectories(parent);
        validateExistingTarget(normalizedTarget, resolvedReplacement);

        String payload = content == null ? "" : content;
        DiskSpaceGuard.ensureWritable(normalizedTarget, FileUtil.estimatedUtf8Bytes(payload), "whole-file save");
        Path temporary = Files.createTempFile(parent, temporaryPrefix(normalizedTarget), ".tmp");
        boolean installed = false;
        try {
            Files.writeString(
                    temporary,
                    payload,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            throwIfInterrupted();
            install(temporary, normalizedTarget, resolvedReplacement, resolvedMover);
            installed = true;
        } finally {
            if (!installed) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static void validateExistingTarget(Path target, Replacement replacement) throws IOException {
        if (!Files.exists(target)) {
            return;
        }
        if (!Files.isRegularFile(target)) {
            throw new IOException("Save target exists but is not a regular file: " + target);
        }
        if (replacement == Replacement.CREATE_NEW) {
            throw new FileAlreadyExistsException(target.toString());
        }
    }

    private static String temporaryPrefix(Path target) {
        Path fileName = target.getFileName();
        String name = fileName == null ? "burp-exporter-save" : fileName.toString();
        String prefix = "." + name + ".";
        return prefix.length() >= 3 ? prefix : "burp-exporter-save";
    }

    private static void install(
            Path temporary,
            Path target,
            Replacement replacement,
            MoveOperation mover) throws IOException {
        if (replacement == Replacement.CREATE_NEW) {
            mover.move(temporary, target);
            return;
        }
        CopyOption[] atomicOptions = {
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING
        };
        try {
            mover.move(temporary, target, atomicOptions);
        } catch (AtomicMoveNotSupportedException e) {
            throwIfInterrupted();
            mover.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void throwIfInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("Whole-file save interrupted before replacement.");
        }
    }
}
