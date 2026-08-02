package ai.anomalousvectors.tools.burp.utils.config;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores database-destination credentials in memory for the current Burp session only.
 *
 * <p>Thread-safe. Null, blank, and unrecognized destination keys normalize to upstream
 * OpenSearch. Credentials are held as immutable {@link String} values and therefore cannot be
 * actively zeroed before garbage collection.</p>
 */
public final class SecureCredentialStore {
    private static final String DEFAULT_DESTINATION = ConfigState.SearchDestination.OPEN_SEARCH.configKey();
    private static final ConcurrentHashMap<String, String> selectedAuthTypes = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, BasicCredentials> basicCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, ApiKeyCredentials> apiKeyCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, JwtCredentials> jwtCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, CertificateCredentials> certificateCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, AwsStaticCredentials> awsStaticCredentials = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, PinnedTlsCertificate> pinnedTlsCertificates = new ConcurrentHashMap<>();

    private SecureCredentialStore() {}

    /**
     * Immutable basic credentials pair read from session memory.
     *
     * @param username username; store load methods use empty when absent
     * @param password password; store load methods use empty when absent
     */
    public record BasicCredentials(String username, String password) {}
    /**
     * Immutable API key read from session memory.
     *
     * @param token API key token; store load methods use empty when absent
     */
    public record ApiKeyCredentials(String token) {}
    /**
     * Immutable bearer-token credentials read from session memory.
     *
     * @param token bearer token; store load methods use empty when absent
     */
    public record JwtCredentials(String token) {}
    /**
     * Immutable certificate credentials read from session memory.
     *
     * @param certPath certificate path; store load methods use empty when absent
     * @param keyPath private-key path; store load methods use empty when absent
     * @param passphrase private-key passphrase; store load methods use empty when absent
     */
    public record CertificateCredentials(String certPath, String keyPath, String passphrase) {}
    /**
     * Immutable AWS static credentials read from session memory.
     *
     * @param accessKeyId AWS access-key identifier; store load methods use empty when absent
     * @param secretAccessKey AWS secret access key; store load methods use empty when absent
     * @param sessionToken optional temporary session token
     */
    public record AwsStaticCredentials(String accessKeyId, String secretAccessKey, String sessionToken) {}
    /**
     * Detached imported TLS pin material read from session memory.
     *
     * <p>Store save/load operations defensively copy {@code encodedBytes}, so mutating an array
     * returned to a caller cannot alter stored state. The record itself exposes its caller-owned
     * array directly and is therefore not deeply immutable.</p>
     *
     * @param sourcePath imported certificate source path
     * @param fingerprintSha256 certificate SHA-256 fingerprint
     * @param encodedBytes caller-owned encoded certificate bytes; store load methods return a
     *                     non-null array
     */
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

    /**
     * Saves AWS static credentials for one database destination.
     *
     * <p>Blank required fields clear the stored credential. The session token is optional.</p>
     *
     * @param destination destination key; null, blank, or unknown selects upstream OpenSearch
     * @param accessKeyId required AWS access-key identifier
     * @param secretAccessKey required AWS secret access key
     * @param sessionToken optional temporary session token
     */
    public static void saveAwsStaticCredentials(
            String destination,
            String accessKeyId,
            String secretAccessKey,
            String sessionToken) {
        String accessKey = safe(accessKeyId);
        String secretKey = safe(secretAccessKey);
        String token = safe(sessionToken);
        if (accessKey.isBlank() || secretKey.isBlank()) {
            clearAwsStaticCredentials(destination);
            return;
        }
        awsStaticCredentials.put(destinationKey(destination), new AwsStaticCredentials(accessKey, secretKey, token));
    }

    /**
     * Loads AWS static credentials for one database destination.
     *
     * @param destination destination key; null, blank, or unknown selects upstream OpenSearch
     * @return stored credentials, or an all-empty value when absent
     */
    public static AwsStaticCredentials loadAwsStaticCredentials(String destination) {
        return awsStaticCredentials.getOrDefault(destinationKey(destination), new AwsStaticCredentials("", "", ""));
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

    /**
     * Clears AWS static credentials for one database destination.
     *
     * @param destination destination key; null, blank, or unknown selects upstream OpenSearch
     */
    public static void clearAwsStaticCredentials(String destination) {
        awsStaticCredentials.remove(destinationKey(destination));
    }

    /** Clears all session-scoped auth values. Intended for tests and extension reload/reset paths. */
    public static void clearAll() {
        selectedAuthTypes.clear();
        basicCredentials.clear();
        apiKeyCredentials.clear();
        jwtCredentials.clear();
        certificateCredentials.clear();
        awsStaticCredentials.clear();
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
            case "iam", "iam (sigv4)", "sigv4", "iam sigv4 - static credentials",
                    "iam sigv4 static credentials" -> ConfigState.OPEN_SEARCH_AMAZON_AUTH_STATIC;
            case "iam sigv4 - profile", "iam sigv4 profile", "profile" -> ConfigState.OPEN_SEARCH_AMAZON_AUTH_PROFILE;
            default -> "None";
        };
    }

    private static String destinationKey(String destination) {
        return ConfigState.normalizeSearchDestination(destination).configKey();
    }
}
