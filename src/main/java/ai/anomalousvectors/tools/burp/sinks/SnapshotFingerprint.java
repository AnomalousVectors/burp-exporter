package ai.anomalousvectors.tools.burp.sinks;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

/** Hashes an exported snapshot without retaining a second serialized payload in memory. */
final class SnapshotFingerprint {
    private static final ObjectMapper JSON = new ObjectMapper();

    private SnapshotFingerprint() { }

    static String ofBytes(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static String of(Map<String, Object> document) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (DigestOutputStream output = new DigestOutputStream(
                    java.io.OutputStream.nullOutputStream(), digest)) {
                JSON.writeValue(output, document);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
