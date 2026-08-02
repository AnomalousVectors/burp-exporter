package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;
import ai.anomalousvectors.tools.burp.utils.Logger;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

/**
 * Base class for per-index line-oriented file sinks that append to one file per format.
 *
 * <p>Each append opens the target path, writes the payload, and returns immediately. Transient I/O
 * failures receive bounded retries only after the sink restores the file to its pre-attempt size,
 * preventing a partial append from becoming a duplicate NDJSON record. These sinks do not keep a
 * long-lived writer open, so they do not require separate flush/close lifecycle hooks between
 * export runs.</p>
 */
abstract class RotatingLineFileSink implements FileSink {

    private static final int MAX_WRITE_ATTEMPTS = 3;
    private static final long RETRY_BACKOFF_MS = 25L;

    private final Path rootDirectory;
    private final String indexName;
    private final String indexKey;
    private final String extension;
    private final FileAppendOperation appendOperation;
    private Path currentPath;

    RotatingLineFileSink(Path rootDirectory, String indexName, String indexKey, String extension) {
        this(rootDirectory, indexName, indexKey, extension, RotatingLineFileSink::writePayload);
    }

    RotatingLineFileSink(
            Path rootDirectory,
            String indexName,
            String indexKey,
            String extension,
            FileAppendOperation appendOperation) {
        this.rootDirectory = rootDirectory;
        this.indexName = indexName;
        this.indexKey = indexKey;
        this.extension = extension;
        this.appendOperation = appendOperation;
    }

    @Override
    public synchronized long estimateBytes(PreparedExportDocument document) {
        List<String> lines = linesFor(document);
        if (lines == null || lines.isEmpty()) {
            return 0L;
        }
        return String.join("", lines).getBytes(StandardCharsets.UTF_8).length;
    }

    @Override
    public synchronized long appendDocument(PreparedExportDocument document) {
        if (document == null) {
            return 0L;
        }
        return appendLines(linesFor(document));
    }

    /**
     * Encodes one prepared document as complete lines for this sink format.
     *
     * @param document prepared document to encode
     * @return ordered complete lines; {@code null} or empty skips the append
     */
    protected abstract List<String> linesFor(PreparedExportDocument document);

    /**
     * Appends pre-encoded bytes with integrity validation and bounded retry.
     *
     * <p>Caller must hold this sink's monitor; the public append methods satisfy that precondition.
     * Before retrying a failed write, the target is restored to its original size so a partial
     * append cannot become a duplicate record. Failures are logged and recorded instead of
     * thrown.</p>
     *
     * @param bytes encoded bytes to append; {@code null} or empty is ignored
     * @return appended byte count, or {@code 0} when no complete append occurred
     */
    protected long appendBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return 0L;
        }
        try {
            initializeIfNeeded();
            Path target = currentPath;
            if (!FileExportService.verifyArtifactBeforeAppend(
                    rootDirectory, indexName, indexKey, extension)) {
                return 0L;
            }
            DiskSpaceGuard.ensureWritable(target, bytes.length, "file export");
            long written = appendBytesWithRetries(target, bytes);
            FileExportService.recordArtifactAppend(
                    rootDirectory, indexName, indexKey, extension, written);
            return written;
        } catch (IOException e) {
            Logger.logError("[Files] Write failed for " + indexName + extension + ": " + e.getMessage());
            FileExportStats.recordLastError(indexKey, summarize(e));
            return 0L;
        }
    }

    private long appendLines(List<String> lines) {
        if (lines == null || lines.isEmpty()) {
            return 0L;
        }
        String payload = String.join("", lines);
        return appendBytes(payload.getBytes(StandardCharsets.UTF_8));
    }

    private long appendBytesWithRetries(Path target, byte[] bytes) {
        IOException lastFailure = null;
        int attemptsMade = 0;
        for (int attempt = 1; attempt <= MAX_WRITE_ATTEMPTS; attempt++) {
            attemptsMade = attempt;
            long originalSize = -1L;
            try {
                originalSize = Files.exists(target) ? Files.size(target) : 0L;
                appendOperation.append(target, bytes);
                return bytes.length;
            } catch (IOException e) {
                lastFailure = e;
                if (!restoreOriginalSize(target, originalSize) || attempt >= MAX_WRITE_ATTEMPTS) {
                    break;
                }
                Logger.logWarnPanelOnly("[Files] Write retry "
                        + (attempt + 1) + "/" + MAX_WRITE_ATTEMPTS
                        + " for " + indexName + extension
                        + " after " + summarize(e) + ".");
                try {
                    TimeUnit.MILLISECONDS.sleep(RETRY_BACKOFF_MS * attempt);
                } catch (InterruptedException interruptedException) {
                    Thread.currentThread().interrupt();
                    break;
                }
                FileExportStats.recordRetryAttempt(indexKey, 1);
            }
        }
        Logger.logError("[Files] Write failed for "
                + indexName + extension + " after "
                + attemptsMade + " attempt(s): " + summarize(lastFailure));
        FileExportStats.recordLastError(indexKey, summarize(lastFailure));
        return 0L;
    }

    private static void writePayload(Path target, byte[] bytes) throws IOException {
        try (FileChannel channel = FileChannel.open(
                target, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
        }
    }

    private static boolean restoreOriginalSize(Path target, long originalSize) {
        if (originalSize < 0L) {
            return true;
        }
        try {
            if (!Files.exists(target)) {
                return originalSize == 0L;
            }
            if (Files.size(target) == originalSize) {
                return true;
            }
            try (FileChannel channel = FileChannel.open(target, StandardOpenOption.WRITE)) {
                channel.truncate(originalSize);
            }
            return Files.size(target) == originalSize;
        } catch (IOException rollbackFailure) {
            Logger.logError("[Files] Cannot safely retry partial append for "
                    + target.getFileName() + ": " + summarize(rollbackFailure));
            return false;
        }
    }

    private static String summarize(Exception exception) {
        if (exception == null) {
            return "unknown I/O failure";
        }
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }

    private void initializeIfNeeded() throws IOException {
        Files.createDirectories(rootDirectory);
        if (currentPath != null) {
            return;
        }
        currentPath = defaultPath();
    }

    private Path defaultPath() {
        return rootDirectory.resolve(indexName + extension);
    }

    @FunctionalInterface
    interface FileAppendOperation {
        void append(Path target, byte[] bytes) throws IOException;
    }
}
