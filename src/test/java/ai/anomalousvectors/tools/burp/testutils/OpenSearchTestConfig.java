package ai.anomalousvectors.tools.burp.testutils;

/**
 * OpenSearch URL and credentials for integration tests. Values are read from JVM system
 * properties (forwarded from Gradle {@code -POPENSEARCH_USER=admin} etc. or environment
 * variables by {@code build.gradle.kts}) or environment variables in the test process.
 *
 * <ul>
 *   <li>{@code OPENSEARCH_URL} – base URL (default https://opensearch.url:9200)</li>
 *   <li>{@code OPENSEARCH_USER} – username for basic auth</li>
 *   <li>{@code OPENSEARCH_PASSWORD} – password for basic auth</li>
 * </ul>
 *
 * <p>When {@code OPENSEARCH_USER} and {@code OPENSEARCH_PASSWORD} are set ({@code -P}, env, or
 * both), integration tests use basic auth. When not set, tests connect without auth (e.g. for a
 * dev cluster with security disabled).
 */
public final class OpenSearchTestConfig {

    private static final String DEFAULT_BASE_URL = "https://opensearch.url:9200";
    private static final String ENV_URL = "OPENSEARCH_URL";
    private static final String ENV_USER = "OPENSEARCH_USER";
    private static final String ENV_PASSWORD = "OPENSEARCH_PASSWORD";

    private static OpenSearchTestConfig instance;

    private final String baseUrl;
    private final String username;
    private final String password;

    private OpenSearchTestConfig(String baseUrl, String username, String password) {
        this.baseUrl = baseUrl != null && !baseUrl.isBlank() ? baseUrl.trim() : DEFAULT_BASE_URL;
        this.username = (username != null && !username.isBlank()) ? username.trim() : null;
        this.password = (password != null && !password.isBlank()) ? password : null;
    }

    private static String getOption(String key) {
        String v = System.getProperty(key);
        if (v != null && !v.isBlank()) return v;
        v = System.getenv(key);
        return (v != null && !v.isBlank()) ? v : null;
    }

    private static OpenSearchTestConfig load() {
        String url = getOption(ENV_URL);
        String user = getOption(ENV_USER);
        String pass = getOption(ENV_PASSWORD);
        return new OpenSearchTestConfig(url, user, pass);
    }

    /**
     * Returns the singleton test config (lazy-loaded from system properties and env).
     */
    public static synchronized OpenSearchTestConfig get() {
        if (instance == null) {
            instance = load();
        }
        return instance;
    }

    /** Base URL for the OpenSearch instance (e.g. https://opensearch.url:9200). */
    public String baseUrl() {
        return baseUrl;
    }

    /** Username for basic auth, or null if not configured. */
    public String username() {
        return username;
    }

    /** Password for basic auth, or null if not configured. */
    public String password() {
        return password;
    }

    /** True when both username and password are set (use basic auth). */
    public boolean hasCredentials() {
        return username != null && password != null;
    }

    /**
     * Returns whether any OpenSearch test connection option was explicitly configured.
     *
     * @return {@code true} when the URL, username, or password is set as a system property or
     *         environment variable
     */
    public static boolean hasExplicitConfiguration() {
        return getOption(ENV_URL) != null
                || getOption(ENV_USER) != null
                || getOption(ENV_PASSWORD) != null;
    }
}
