package ai.anomalousvectors.tools.burp.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Small file utilities used by the UI and sinks. Keeps I/O concerns out of UI code.
 */
public final class FileUtil {

    /**
     * Status of file creation attempts.
     */
    public enum Status { CREATED, EXISTS, FAILED }

    /**
     * Describes the outcome of ensuring a JSON file exists.
     *
     * @param path   target path
     * @param status creation status
     * @param error  error message when {@link Status#FAILED}
     */
    public record CreateResult(Path path, Status status, String error) {}

    private static final String JSON_EXTENSION = ".json";

    private FileUtil() {}

    /**
     * Convenience overload that keeps UI code free of {@link Path} construction.
     *
     * @param rootDir   root directory string
     * @param fileNames file names to ensure
     * @return results per file
     */
    public static List<CreateResult> ensureJsonFiles(String rootDir, List<String> fileNames) {
        return ensureFiles(Path.of(rootDir), fileNames);
    }

    /**
     * Ensures JSON files exist under {@code rootDir}.
     *
     * <p>Parent directories are created as needed. Each result reports
     * {@link Status#CREATED}, {@link Status#EXISTS}, or {@link Status#FAILED}.</p>
     *
     * @param rootDir   base directory
     * @param fileNames file names to create
     * @return creation results
     */
    public static List<CreateResult> ensureJsonFiles(Path rootDir, List<String> fileNames) {
        return ensureFiles(rootDir, fileNames);
    }

    /**
     * Ensure a set of files exist under {@code rootDir}. Creates parent dirs as needed.
     * For each file, returns CREATED, EXISTS, or FAILED with error message.
     *
     * @param rootDir base directory
     * @param fileNames file names to create
     * @return creation results
     */
    public static List<CreateResult> ensureFiles(Path rootDir, List<String> fileNames) {
        List<CreateResult> out = new ArrayList<>(fileNames.size());

        try {
            ensureDirectoryWritable(rootDir, "file export root");
        } catch (IOException e) {
            for (String n : fileNames) {
                out.add(new CreateResult(rootDir.resolve(n), Status.FAILED, e.getMessage()));
            }
            return out;
        }

        for (String name : fileNames) {
            Path p = rootDir.resolve(name);
            out.add(ensureSingleJsonFile(p));
        }

        return out;
    }

    /**
     * Ensures a directory is creatable and writable by performing a tiny probe write.
     *
     * <p>This is used before user-visible file export work so the UI can fail fast with a clean
     * status instead of starting export and discovering write failures later.</p>
     *
     * @param rootDir directory that should accept exporter-managed writes
     * @param context short user/log context for low-disk errors
     * @throws IOException when the directory cannot be created or written
     */
    public static void ensureDirectoryWritable(Path rootDir, String context) throws IOException {
        java.nio.file.Files.createDirectories(rootDir);
        Path probe = rootDir.resolve(".burp-exporter-write-probe-" + java.util.UUID.randomUUID() + ".tmp");
        try {
            DiskSpaceGuard.ensureWritable(probe, 1L, context);
            java.nio.file.Files.writeString(probe, "\n", StandardCharsets.UTF_8);
        } finally {
            java.nio.file.Files.deleteIfExists(probe);
        }
    }

    /**
     * Parses and validates a file-export root entered in the UI.
     *
     * <p>The exporter expects an absolute directory path so operators always know exactly where
     * files are being written. Relative paths are rejected instead of being resolved against the
     * host process working directory.</p>
     *
     * @param rootDir raw UI path string
     * @return normalized absolute path
     * @throws IOException when the path is blank, invalid, or not absolute
     */
    public static Path requireAbsoluteDirectoryPath(String rootDir) throws IOException {
        if (rootDir == null || rootDir.trim().isEmpty()) {
            throw new IOException("file export root is blank.");
        }
        String raw = rootDir.trim();
        try {
            Path path = Path.of(raw);
            if (!path.isAbsolute() && !raw.startsWith("/") && !raw.startsWith("\\")) {
                throw new IOException("file export root must be an absolute path.");
            }
            return path.toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            throw new IOException("file export root is invalid: " + e.getMessage(), e);
        }
    }

    /**
     * Ensures a single JSON file exists, creating parent directories as needed.
     *
     * @param p target path
     * @return result describing outcome
     */
    private static CreateResult ensureSingleJsonFile(Path p) {
        try {
            if (java.nio.file.Files.exists(p)) {
                return new CreateResult(p, Status.EXISTS, null);
            }

            Path parent = p.getParent();
            if (parent != null) {
                java.nio.file.Files.createDirectories(parent);
            }

            DiskSpaceGuard.ensureWritable(p, 1L, "JSON file creation");
            java.nio.file.Files.createFile(p);
            return new CreateResult(p, Status.CREATED, null);

        } catch (FileAlreadyExistsException e) {
            // File was created between the existence check and createFile call; treat as EXISTS.
            return new CreateResult(p, Status.EXISTS, null);
        } catch (DiskSpaceGuard.LowDiskSpaceException e) {
            return new CreateResult(p, Status.FAILED, e.userMessage());
        } catch (DirectoryNotEmptyException e) {
            return new CreateResult(p, Status.FAILED, "Directory not empty: " + e.getMessage());
        } catch (IOException e) {
            return new CreateResult(p, Status.FAILED, e.getMessage());
        } catch (RuntimeException e) {
            return new CreateResult(p, Status.FAILED, e.toString());
        }
    }

    // ---------- Generic helpers used by ConfigPanel import/export ----------

    /**
     * Ensures a {@code .json} extension on the provided file name.
     *
     * @param f file to normalize
     * @return file with .json suffix ensured
     */
    public static File ensureJsonExtension(File f) {
        if (f == null) return null;
        String nameLower = f.getName().toLowerCase(Locale.ROOT);
        if (nameLower.endsWith(JSON_EXTENSION)) return f;
        File parent = f.getParentFile();
        return (parent == null)
                ? new File(f.getName() + JSON_EXTENSION)
                : new File(parent, f.getName() + JSON_EXTENSION);
    }

    /**
     * Write UTF-8 text to a file, creating parent directories if necessary.
     *
     * <p>Caller may invoke from any thread. Before writing, this method applies the shared
     * low-disk guard so exporter code does not keep writing until the destination volume is nearly
     * full.</p>
     *
     * @param file    destination path
     * @param content content to write
     * @throws IOException when writing fails
     */
    public static void writeStringCreateDirs(Path file, String content) throws IOException {
        Path parent = file.getParent();
        if (parent != null) java.nio.file.Files.createDirectories(parent);
        DiskSpaceGuard.ensureWritable(file, estimatedUtf8Bytes(content), "file");
        java.nio.file.Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    /**
     * Read UTF-8 text from a file.
     *
     * @param file file to read
     * @return file contents as string
     * @throws IOException when reading fails
     */
    public static String readString(Path file) throws IOException {
        return java.nio.file.Files.readString(file, StandardCharsets.UTF_8);
    }

    /**
     * Create a temp file and write UTF-8 content to it.
     *
     * <p>The file is created under {@link ManagedDiskPaths#managedRootDirectory()} so
     * exporter-managed temporary files remain grouped under one discoverable root. This method also
     * applies the shared low-disk guard before creating the file.</p>
     *
     * @param prefix  temp file prefix
     * @param suffix  temp file suffix
     * @param content content to write
     * @return path to created temp file
     * @throws IOException when creation or write fails
     */
    public static Path writeTempFile(String prefix, String suffix, String content) throws IOException {
        Path root = ManagedDiskPaths.managedRootDirectory();
        java.nio.file.Files.createDirectories(root);
        DiskSpaceGuard.ensureWritable(root, estimatedUtf8Bytes(content), "temporary file");
        Path p = java.nio.file.Files.createTempFile(root, prefix, suffix);
        java.nio.file.Files.writeString(p, content, StandardCharsets.UTF_8);
        return p;
    }

    private static long estimatedUtf8Bytes(String content) {
        return content == null ? 0L : content.getBytes(StandardCharsets.UTF_8).length;
    }
}
