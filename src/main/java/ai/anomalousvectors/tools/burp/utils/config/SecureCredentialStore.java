package ai.anomalousvectors.tools.burp.utils.config;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores database-destination credentials in memory for the current Burp session only.
 */
public final class SecureCredentialStore {
    private static final String DEFAULT_DESTINATION = ConfigState.SearchDestination.OPEN_SEARCH.configKey();
    private static final ConcurrentHashMap<String, String> selectedAuthTypes = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, BasicCredentials> basicCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, ApiKeyCredentials> apiKeyCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, JwtCredentials> jwtCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CertificateCredentials> certificateCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, PinnedTlsCertificate> pinnedTlsCertificates = new ConcurrentHashMap<>();

    private SecureCredentialStore() {}

    /** Immutable basic credentials pair read from session memory. */
    public record BasicCredentials(String username, String password) {}
    /** Immutable API key read from session memory. */
    public record ApiKeyCredentials(String token) {}
    /** Immutable bearer-token credentials read from session memory. */
    public record JwtCredentials(String token) {}
    /** Immutable certificate credentials read from session memory. */
    public record CertificateCredentials(String certPath, String keyPath, String passphrase) {}
    /** Immutable imported TLS pin material read from session memory. */
    public record PinnedTlsCertificate(String sourcePath, String fingerprintSha256, byte[] encodedBytes) {}

    /** Saves selected auth type for the current Burp session. */
    public static void saveSelectedAuthType(String authType) {
        saveSelectedAuthType(DEFAULT_DESTINATION, authType);
    }

    /** Saves selected auth type for one database destination in the current Burp session. */
    public static void saveSelectedAuthType(String destination, String authType) {
        selectedAuthTypes.put(destinationKey(destination), normalizeAuthType(authType));
    }

    /** Loads selected auth type for the current Burp session. */
    public static String loadSelectedAuthType() {
        return loadSelectedAuthType(DEFAULT_DESTINATION);
    }

    /** Loads selected auth type for one database destination in the current Burp session. */
    public static String loadSelectedAuthType(String destination) {
        return normalizeAuthType(selectedAuthTypes.getOrDefault(destinationKey(destination), "Basic"));
    }

    /** Returns whether an auth type has been selected for one database destination this session. */
    public static boolean hasSelectedAuthType(String destination) {
        return selectedAuthTypes.containsKey(destinationKey(destination));
    }

    /** Saves basic credentials for the current Burp session. Blank values clear stored credentials. */
    public static void saveOpenSearchCredentials(String username, String password) {
        saveBasicCredentials(DEFAULT_DESTINATION, username, password);
    }

    /** Saves basic credentials for one database destination. Blank values clear stored credentials. */
    public static void saveBasicCredentials(String destination, String username, String password) {
        String user = safe(username);
        String pass = safe(password);
        if (user.isBlank() || pass.isBlank()) {
            clearBasicCredentials(destination);
            return;
        }
        basicCredentials.put(destinationKey(destination), new BasicCredentials(user, pass));
    }

    /** Loads basic credentials for the current Burp session. */
    public static BasicCredentials loadOpenSearchCredentials() {
        return loadBasicCredentials(DEFAULT_DESTINATION);
    }

    /** Loads basic credentials for one database destination. */
    public static BasicCredentials loadBasicCredentials(String destination) {
        return basicCredentials.getOrDefault(destinationKey(destination), new BasicCredentials("", ""));
    }

    /** Saves API key for the current Burp session. */
    public static void saveApiKeyCredentials(String token) {
        saveApiKeyCredentials(DEFAULT_DESTINATION, token);
    }

    /** Saves API key for one database destination. */
    public static void saveApiKeyCredentials(String destination, String token) {
        String apiKeyToken = safe(token);
        if (apiKeyToken.isBlank()) {
            clearApiKeyCredentials(destination);
            return;
        }
        apiKeyCredentials.put(destinationKey(destination), new ApiKeyCredentials(apiKeyToken));
    }

    /** Loads API key credentials for the current Burp session. */
    public static ApiKeyCredentials loadApiKeyCredentials() {
        return loadApiKeyCredentials(DEFAULT_DESTINATION);
    }

    /** Loads API key credentials for one database destination. */
    public static ApiKeyCredentials loadApiKeyCredentials(String destination) {
        return apiKeyCredentials.getOrDefault(destinationKey(destination), new ApiKeyCredentials(""));
    }

    /** Saves bearer-token credentials for the current Burp session. */
    public static void saveJwtCredentials(String token) {
        saveJwtCredentials(DEFAULT_DESTINATION, token);
    }

    /** Saves bearer-token credentials for one database destination. */
    public static void saveJwtCredentials(String destination, String token) {
        String jwt = safe(token);
        if (jwt.isBlank()) {
            clearJwtCredentials(destination);
            return;
        }
        jwtCredentials.put(destinationKey(destination), new JwtCredentials(jwt));
    }

    /** Loads bearer-token credentials for the current Burp session. */
    public static JwtCredentials loadJwtCredentials() {
        return loadJwtCredentials(DEFAULT_DESTINATION);
    }

    /** Loads bearer-token credentials for one database destination. */
    public static JwtCredentials loadJwtCredentials(String destination) {
        return jwtCredentials.getOrDefault(destinationKey(destination), new JwtCredentials(""));
    }

    /** Saves certificate credentials for the current Burp session. */
    public static void saveCertificateCredentials(String certPath, String keyPath, String passphrase) {
        saveCertificateCredentials(DEFAULT_DESTINATION, certPath, keyPath, passphrase);
    }

    /** Saves certificate credentials for one database destination. */
    public static void saveCertificateCredentials(
            String destination, String certPath, String keyPath, String passphrase) {
        String cert = safe(certPath);
        String key = safe(keyPath);
        String pass = safe(passphrase);
        if (cert.isBlank() || key.isBlank()) {
            clearCertificateCredentials(destination);
            return;
        }
        certificateCredentials.put(destinationKey(destination), new CertificateCredentials(cert, key, pass));
    }

    /** Loads certificate credentials for the current Burp session. */
    public static CertificateCredentials loadCertificateCredentials() {
        return loadCertificateCredentials(DEFAULT_DESTINATION);
    }

    /** Loads certificate credentials for one database destination. */
    public static CertificateCredentials loadCertificateCredentials(String destination) {
        return certificateCredentials.getOrDefault(destinationKey(destination), new CertificateCredentials("", "", ""));
    }

    /** Saves pinned TLS certificate material for the current Burp session. */
    public static void savePinnedTlsCertificate(String sourcePath, String fingerprintSha256, byte[] encodedBytes) {
        savePinnedTlsCertificate(DEFAULT_DESTINATION, sourcePath, fingerprintSha256, encodedBytes);
    }

    /** Saves pinned TLS certificate material for one database destination. */
    public static void savePinnedTlsCertificate(
            String destination, String sourcePath, String fingerprintSha256, byte[] encodedBytes) {
        String path = safe(sourcePath);
        String fingerprint = safe(fingerprintSha256);
        byte[] bytes = encodedBytes == null ? new byte[0] : java.util.Arrays.copyOf(encodedBytes, encodedBytes.length);
        if (path.isBlank() || fingerprint.isBlank() || bytes.length == 0) {
            clearPinnedTlsCertificate(destination);
            return;
        }
        pinnedTlsCertificates.put(destinationKey(destination), new PinnedTlsCertificate(path, fingerprint, bytes));
    }

    /** Loads pinned TLS certificate material for the current Burp session. */
    public static PinnedTlsCertificate loadPinnedTlsCertificate() {
        return loadPinnedTlsCertificate(DEFAULT_DESTINATION);
    }

    /** Loads pinned TLS certificate material for one database destination. */
    public static PinnedTlsCertificate loadPinnedTlsCertificate(String destination) {
        PinnedTlsCertificate current = pinnedTlsCertificates.getOrDefault(
                destinationKey(destination),
                new PinnedTlsCertificate("", "", new byte[0]));
        return new PinnedTlsCertificate(current.sourcePath(), current.fingerprintSha256(),
                java.util.Arrays.copyOf(current.encodedBytes(), current.encodedBytes().length));
    }

    /** Clears basic credentials for the current Burp session. */
    public static void clearOpenSearchCredentials() {
        clearBasicCredentials(DEFAULT_DESTINATION);
    }

    /** Clears basic credentials for one database destination. */
    public static void clearBasicCredentials(String destination) {
        basicCredentials.remove(destinationKey(destination));
    }

    /** Clears API key credentials for the current Burp session. */
    public static void clearApiKeyCredentials() {
        clearApiKeyCredentials(DEFAULT_DESTINATION);
    }

    /** Clears API key credentials for one database destination. */
    public static void clearApiKeyCredentials(String destination) {
        apiKeyCredentials.remove(destinationKey(destination));
    }

    /** Clears bearer-token credentials for the current Burp session. */
    public static void clearJwtCredentials() {
        clearJwtCredentials(DEFAULT_DESTINATION);
    }

    /** Clears bearer-token credentials for one database destination. */
    public static void clearJwtCredentials(String destination) {
        jwtCredentials.remove(destinationKey(destination));
    }

    /** Clears certificate credentials for the current Burp session. */
    public static void clearCertificateCredentials() {
        clearCertificateCredentials(DEFAULT_DESTINATION);
    }

    /** Clears certificate credentials for one database destination. */
    public static void clearCertificateCredentials(String destination) {
        certificateCredentials.remove(destinationKey(destination));
    }

    /** Clears pinned TLS certificate material for the current Burp session. */
    public static void clearPinnedTlsCertificate() {
        clearPinnedTlsCertificate(DEFAULT_DESTINATION);
    }

    /** Clears pinned TLS certificate material for one database destination. */
    public static void clearPinnedTlsCertificate(String destination) {
        pinnedTlsCertificates.remove(destinationKey(destination));
    }

    /** Clears all session-scoped auth values. Intended for tests and extension reload/reset paths. */
    public static void clearAll() {
        selectedAuthTypes.clear();
        basicCredentials.clear();
        apiKeyCredentials.clear();
        jwtCredentials.clear();
        certificateCredentials.clear();
        pinnedTlsCertificates.clear();
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizeAuthType(String authType) {
        if (authType == null || authType.isBlank()) {
            return "None";
        }
        return switch (authType.trim().toLowerCase()) {
            case "basic" -> "Basic";
            case "api key", "apikey" -> "API key";
            case "bearer token", "bearer", "jwt" -> "Bearer token";
            case "certificate", "cert" -> "Certificate";
            case "iam", "iam (sigv4)", "sigv4" -> "IAM (sigV4)";
            default -> "None";
        };
    }

    private static String destinationKey(String destination) {
        return ConfigState.normalizeSearchDestination(destination).configKey();
    }
}
