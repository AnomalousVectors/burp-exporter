package ai.anomalousvectors.tools.burp.utils.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Defines resource limits for configuration imports.
 *
 * <p>The file boundary is checked before decoding and remains bounded if the selected file grows
 * between the size check and read. Limit violations reject the complete import; callers must not
 * apply partial configuration state.</p>
 */
public final class ConfigImportPolicy {

    /** Maximum accepted configuration-file size: 10 MiB. */
    public static final int MAX_FILE_BYTES = 10 * 1024 * 1024;

    /** Maximum JSON nesting depth accepted by the configuration parser. */
    public static final int MAX_JSON_NESTING_DEPTH = 64;

    /** Maximum length of one JSON string value: 64 KiB characters. */
    public static final int MAX_JSON_STRING_LENGTH = 64 * 1024;

    /** Maximum number of custom-scope entries accepted by import and displayed by the UI. */
    public static final int MAX_CUSTOM_SCOPE_ENTRIES = 100;

    private ConfigImportPolicy() { }

    /**
     * Reads a UTF-8 configuration file without exceeding the import byte budget.
     *
     * @param path selected configuration file
     * @return decoded UTF-8 content
     * @throws IOException when the file cannot be read, is not valid UTF-8, or exceeds 10 MiB
     */
    public static String readUtf8(Path path) throws IOException {
        long declaredSize = Files.size(path);
        if (declaredSize > MAX_FILE_BYTES) {
            throw fileSizeExceeded(declaredSize);
        }

        byte[] content;
        try (InputStream input = Files.newInputStream(path)) {
            content = input.readNBytes(MAX_FILE_BYTES + 1);
        }
        if (content.length > MAX_FILE_BYTES) {
            throw fileSizeExceeded(content.length);
        }

        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(content)).toString();
        } catch (CharacterCodingException e) {
            throw new IOException("Configuration file is not valid UTF-8.", e);
        }
    }

    /**
     * Rejects an oversized custom-scope collection before state is constructed or applied.
     *
     * @param jsonPath collection path used in the operator-facing error
     * @param entryCount number of supplied entries
     * @throws IOException when {@code entryCount} exceeds 100
     */
    public static void requireCustomScopeEntryCount(String jsonPath, int entryCount) throws IOException {
        if (entryCount > MAX_CUSTOM_SCOPE_ENTRIES) {
            throw new IOException("Invalid config: '" + jsonPath + "' has " + entryCount
                    + " entries; maximum is " + MAX_CUSTOM_SCOPE_ENTRIES + ".");
        }
    }

    private static IOException fileSizeExceeded(long actualBytes) {
        return new IOException("Configuration file is " + actualBytes
                + " bytes; maximum is " + MAX_FILE_BYTES + " bytes (10 MiB).");
    }
}
