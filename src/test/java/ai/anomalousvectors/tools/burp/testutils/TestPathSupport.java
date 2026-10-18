package ai.anomalousvectors.tools.burp.testutils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.FileVisitResult;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Creates test-only paths under {@code build/tmp} instead of the system temp directory.
 *
 * <p>This keeps test artifacts out of the user's OS temp folder while still giving each test an
 * isolated workspace. The shared UI fixture is JVM-specific and must not be used by concurrent
 * file-writing tests. Cleanup rejects paths outside the test root and never follows symlinks.</p>
 */
public final class TestPathSupport {

    private static final Path ROOT = Path.of("build", "tmp", "burp-exporter-tests")
            .toAbsolutePath().normalize();
    private static final Path UI_FILE_ROOT = ROOT.resolve("ui-files-" + UUID.randomUUID());

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(
                TestPathSupport::cleanIsolatedUiRootTree,
                "burp-exporter-test-path-cleanup"));
    }

    private TestPathSupport() { }

    /**
     * Creates a unique test directory under {@code build/tmp}.
     *
     * @param prefix logical test prefix used in the directory name
     * @return created directory path
     * @throws IOException when the directory cannot be created
     */
    public static Path createDirectory(String prefix) throws IOException {
        prepareTestRoot();
        return Files.createTempDirectory(ROOT, prefix + "-");
    }

    /**
     * Creates a unique test file path under {@code build/tmp}.
     *
     * @param prefix logical test prefix used in the file name
     * @param suffix file suffix, including the leading dot when desired
     * @return created file path
     * @throws IOException when the file cannot be created
     */
    public static Path createFile(String prefix, String suffix) throws IOException {
        prepareTestRoot();
        return Files.createTempFile(ROOT, prefix + "-", suffix);
    }

    /**
     * Creates the isolated UI export fixture below {@code build/tmp}.
     *
     * <p>File-writing tests explicitly assign this path to the UI instead of using the
     * operator-facing default. Existing fixture contents remain until explicit test cleanup.</p>
     *
     * @return absolute, JVM-specific test directory
     * @throws IOException if ownership validation or directory creation fails
     */
    public static Path isolatedUiFileRoot() throws IOException {
        prepareTestRoot();
        return Files.createDirectories(requireOwnedDirectory(UI_FILE_ROOT));
    }

    /**
     * Returns whether the provided directory can be created and written.
     *
     * <p>Only directories below the test root are eligible; an operator path is never probed.</p>
     *
     * @param root test-owned directory
     * @return whether the directory can be created and written safely
     */
    public static boolean isWritableDirectory(Path root) {
        try {
            Path owned = requireOwnedDirectory(root);
            Files.createDirectories(owned);
            Path probe = Files.createTempFile(owned, "burp-exporter-test-write-", ".tmp");
            Files.deleteIfExists(probe);
            return true;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Deletes exporter artifacts only from a test-owned directory.
     *
     * <p>The shared UI fixture is removed completely; other fixtures retain non-export files.
     * Neither symlink directories nor symlink files are followed.</p>
     *
     * @param root directory strictly below the test root; {@code null} is ignored
     * @throws IOException if the directory is outside the test root, crosses a symlink, or
     *     deletion fails
     */
    public static void cleanupExportArtifacts(Path root) throws IOException {
        if (root == null) {
            return;
        }
        Path owned = requireOwnedDirectory(root);
        if (UI_FILE_ROOT.equals(owned)) {
            deleteOwnedTree(owned);
            return;
        }
        if (!Files.isDirectory(owned, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        List<Path> toDelete = new ArrayList<>();
        try (var stream = Files.list(owned)) {
            for (Path path : stream.toList()) {
                String fileName = path.getFileName() == null ? "" : path.getFileName().toString();
                if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                        && (fileName.endsWith(".jsonl") || fileName.endsWith(".ndjson"))) {
                    toDelete.add(path);
                }
            }
        }
        for (Path path : toDelete) {
            Files.deleteIfExists(path);
        }
    }

    private static void prepareTestRoot() throws IOException {
        requireOwnedDirectory(ROOT.resolve("entry"));
        Files.createDirectories(ROOT);
    }

    private static Path requireOwnedDirectory(Path path) throws IOException {
        if (path == null) {
            throw new IOException("Test directory is required.");
        }
        Path normalized = path.toAbsolutePath().normalize();
        if (normalized.equals(ROOT) || !normalized.startsWith(ROOT)) {
            throw new IOException("Path is outside the test-owned directory boundary.");
        }
        for (Path current = normalized; current != null && current.startsWith(ROOT);
                current = current.getParent()) {
            if (Files.isSymbolicLink(current)) {
                throw new IOException("Test-owned directory crosses a symbolic link.");
            }
        }
        return normalized;
    }

    private static void cleanIsolatedUiRootTree() {
        try {
            deleteOwnedTree(UI_FILE_ROOT);
        } catch (IOException | RuntimeException ignored) {
            // Only this JVM's fixture is eligible; Gradle clean can reclaim it after a failed delete.
        }
    }

    private static void deleteOwnedTree(Path path) throws IOException {
        Path owned = requireOwnedDirectory(path);
        if (!Files.exists(owned, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        // walkFileTree does not follow symlinks unless FOLLOW_LINKS is explicitly requested.
        Files.walkFileTree(owned, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path directory, IOException failure) throws IOException {
                if (failure != null) {
                    throw failure;
                }
                Files.delete(directory);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
