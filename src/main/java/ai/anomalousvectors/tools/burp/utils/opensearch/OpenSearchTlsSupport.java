package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import org.apache.hc.core5.ssl.SSLContextBuilder;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

/**
 * Shared TLS helpers for OpenSearch connectivity, pin import, and trust-mode enforcement.
 *
 * <p>The persisted TLS mode lives in {@link RuntimeConfig}. Imported pinned certificate material is
 * session-scoped and held only in {@link SecureCredentialStore}, similar to auth secrets.</p>
 *
 * <p>Stateless and safe for concurrent callers. Certificate import and SSL-context construction
 * perform blocking file or cryptographic work on the calling thread.</p>
 */
public final class OpenSearchTlsSupport {

    private OpenSearchTlsSupport() { }

    /**
     * Returns the effective upstream OpenSearch TLS mode.
     *
     * @return normalized TLS mode, honoring the insecure override property
     */
    public static String currentTlsMode() {
        return currentTlsMode(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Returns the effective TLS mode for one database destination.
     *
     * @param destination destination to inspect; {@code null} selects upstream OpenSearch
     * @return normalized TLS mode, honoring the insecure override property
     */
    public static String currentTlsMode(ConfigState.SearchDestination destination) {
        return "true".equalsIgnoreCase(System.getProperty("OPENSEARCH_INSECURE", "").trim())
                ? ConfigState.OPEN_SEARCH_TLS_INSECURE
                : configuredTlsMode(destination);
    }

    /**
     * Returns whether upstream OpenSearch trusts all certificates insecurely.
     *
     * @return {@code true} when insecure trust-all mode is active
     */
    public static boolean isInsecureMode() {
        return isInsecureMode(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Returns whether one destination trusts all certificates insecurely.
     *
     * @param destination destination to inspect; {@code null} selects upstream OpenSearch
     * @return {@code true} when insecure trust-all mode is active
     */
    public static boolean isInsecureMode(ConfigState.SearchDestination destination) {
        return isInsecureMode(currentTlsMode(destination));
    }

    /**
     * Returns whether a TLS mode value selects insecure trust-all behavior.
     *
     * @param tlsMode persisted or normalized mode; {@code null} normalizes to the default
     * @return {@code true} for insecure trust-all mode
     */
    public static boolean isInsecureMode(String tlsMode) {
        return ConfigState.OPEN_SEARCH_TLS_INSECURE.equals(ConfigState.normalizeOpenSearchTlsMode(tlsMode));
    }

    /**
     * Returns whether upstream OpenSearch requires a pinned certificate.
     *
     * @return {@code true} when pinned-certificate mode is active
     */
    public static boolean isPinnedMode() {
        return isPinnedMode(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Returns whether one destination requires a pinned certificate.
     *
     * @param destination destination to inspect; {@code null} selects upstream OpenSearch
     * @return {@code true} when pinned-certificate mode is active
     */
    public static boolean isPinnedMode(ConfigState.SearchDestination destination) {
        return isPinnedMode(currentTlsMode(destination));
    }

    /**
     * Returns whether a TLS mode value selects pinned-certificate behavior.
     *
     * @param tlsMode persisted or normalized mode; {@code null} normalizes to the default
     * @return {@code true} for pinned-certificate mode
     */
    public static boolean isPinnedMode(String tlsMode) {
        return ConfigState.OPEN_SEARCH_TLS_PINNED.equals(ConfigState.normalizeOpenSearchTlsMode(tlsMode));
    }

    /**
     * Returns whether upstream OpenSearch has pinned certificate material in session memory.
     *
     * @return {@code true} when encoded certificate material is loaded
     */
    public static boolean hasPinnedCertificate() {
        return hasPinnedCertificate(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Returns whether one destination has pinned certificate material in session memory.
     *
     * @param destination destination to inspect; {@code null} selects upstream OpenSearch
     * @return {@code true} when encoded certificate material is loaded
     */
    public static boolean hasPinnedCertificate(ConfigState.SearchDestination destination) {
        return pinnedCertificate(destination).encodedBytes().length > 0;
    }

    /**
     * Returns upstream OpenSearch's loaded pinned-certificate fingerprint.
     *
     * @return SHA-256 fingerprint, or blank when no pin is loaded
     */
    public static String pinnedCertificateFingerprint() {
        return pinnedCertificateFingerprint(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Returns one destination's loaded pinned-certificate fingerprint.
     *
     * @param destination destination to inspect; {@code null} selects upstream OpenSearch
     * @return SHA-256 fingerprint, or blank when no pin is loaded
     */
    public static String pinnedCertificateFingerprint(ConfigState.SearchDestination destination) {
        return pinnedCertificate(destination).fingerprintSha256();
    }

    /**
     * Imports one X.509 certificate file and returns session-ready pin material.
     *
     * <p>DER and PEM encodings are supported by the JCA certificate factory as long as the file
     * contains a single X.509 certificate.</p>
     *
     * @param path source file chosen by the user
     * @return imported pin material
     * @throws IOException when the file cannot be read
     * @throws CertificateException when the file does not contain a readable X.509 certificate
     */
    public static SecureCredentialStore.PinnedTlsCertificate importPinnedCertificate(Path path)
            throws IOException, CertificateException {
        if (path == null) {
            throw new CertificateException("Certificate file was not selected.");
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream input = Files.newInputStream(path)) {
            X509Certificate cert = (X509Certificate) factory.generateCertificate(input);
            byte[] encoded = cert.getEncoded();
            return new SecureCredentialStore.PinnedTlsCertificate(
                    path.toAbsolutePath().normalize().toString(),
                    sha256Fingerprint(encoded),
                    encoded
            );
        } catch (GeneralSecurityException e) {
            if (e instanceof CertificateException certificateException) {
                throw certificateException;
            }
            throw new CertificateException("Failed to import certificate.", e);
        }
    }

    /**
     * Builds an SSL context that trusts only upstream OpenSearch's imported pin.
     *
     * @return initialized pinned-trust SSL context
     * @throws GeneralSecurityException if no pin is loaded or trust setup fails
     */
    public static SSLContext buildPinnedSslContext() throws GeneralSecurityException {
        return buildPinnedSslContext(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Builds an SSL context that trusts only one destination's imported pin.
     *
     * @param destination destination to configure; {@code null} selects upstream OpenSearch
     * @return initialized pinned-trust SSL context
     * @throws GeneralSecurityException if no pin is loaded or trust setup fails
     */
    public static SSLContext buildPinnedSslContext(ConfigState.SearchDestination destination)
            throws GeneralSecurityException {
        return pinnedSslContextBuilder(destination).build();
    }

    /**
     * Builds an SSL context builder that trusts only upstream OpenSearch's imported pin.
     *
     * @return pinned-trust SSL context builder
     * @throws GeneralSecurityException if no pin is loaded or trust setup fails
     */
    public static SSLContextBuilder pinnedSslContextBuilder() throws GeneralSecurityException {
        return pinnedSslContextBuilder(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Builds an SSL context builder that trusts only one destination's imported pin.
     *
     * @param destination destination to configure; {@code null} selects upstream OpenSearch
     * @return pinned-trust SSL context builder
     * @throws GeneralSecurityException if no pin is loaded or trust setup fails
     */
    public static SSLContextBuilder pinnedSslContextBuilder(ConfigState.SearchDestination destination)
            throws GeneralSecurityException {
        SecureCredentialStore.PinnedTlsCertificate pinned = pinnedCertificate(destination);
        if (pinned.encodedBytes().length == 0) {
            throw new GeneralSecurityException("Pinned TLS certificate not imported.");
        }
        byte[] expected = java.util.Arrays.copyOf(pinned.encodedBytes(), pinned.encodedBytes().length);
        return SSLContextBuilder.create()
                .loadTrustMaterial((chain, authType) -> leafMatchesPinnedCertificate(chain, expected));
    }

    /**
     * Returns a trust summary for a successful upstream OpenSearch connection.
     *
     * @param baseUrl connected base URL
     * @return operator-facing trust summary
     */
    public static String successTrustSummary(String baseUrl) {
        return successTrustSummary(baseUrl, ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Returns a trust summary for a destination's successful connection.
     *
     * @param baseUrl connected base URL
     * @param destination destination that was tested; {@code null} selects upstream OpenSearch
     * @return operator-facing trust summary
     */
    public static String successTrustSummary(String baseUrl, ConfigState.SearchDestination destination) {
        if (!isHttps(baseUrl)) {
            return "Not applicable (HTTP)";
        }
        String mode = currentTlsMode(destination);
        return switch (mode) {
            case ConfigState.OPEN_SEARCH_TLS_PINNED -> {
                String fingerprint = pinnedCertificateFingerprint(destination);
                yield fingerprint.isBlank()
                        ? "Pinned certificate matched"
                        : "Pinned certificate matched (" + fingerprint + ")";
            }
            case ConfigState.OPEN_SEARCH_TLS_INSECURE -> "Trust-all certificates (insecure)";
            default -> "Verified with system trust store";
        };
    }

    /**
     * Returns a trust summary for a failed upstream OpenSearch connection.
     *
     * @param baseUrl attempted base URL
     * @param detail failure detail; {@code null} becomes blank
     * @return operator-facing trust summary
     */
    public static String failureTrustSummary(String baseUrl, String detail) {
        return failureTrustSummary(baseUrl, detail, ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /**
     * Returns a trust summary for a destination's failed connection.
     *
     * <p>The returned string may include {@code detail} verbatim when it appears TLS-related.
     * Callers must not pass credentials or other secrets in the detail.</p>
     *
     * @param baseUrl attempted base URL
     * @param detail failure detail; {@code null} becomes blank
     * @param destination destination that was tested; {@code null} selects upstream OpenSearch
     * @return operator-facing trust summary
     */
    public static String failureTrustSummary(
            String baseUrl, String detail, ConfigState.SearchDestination destination) {
        if (!isHttps(baseUrl)) {
            return "Not applicable (HTTP)";
        }
        String mode = currentTlsMode(destination);
        if (ConfigState.OPEN_SEARCH_TLS_PINNED.equals(mode) && !hasPinnedCertificate(destination)) {
            return "Pinned certificate not imported";
        }
        String safeDetail = detail == null ? "" : detail;
        if (looksLikeTrustFailure(safeDetail)) {
            return "Failed: " + safeDetail;
        }
        return switch (mode) {
            case ConfigState.OPEN_SEARCH_TLS_PINNED -> "Pinned certificate not verified";
            case ConfigState.OPEN_SEARCH_TLS_INSECURE -> "Trust-all certificates (insecure)";
            // Non-TLS failures (auth, signing, HTTP) must not be labeled as trust failures.
            default -> "Not tested";
        };
    }

    /**
     * Returns whether a message looks like a TLS trust, pin, or hostname-verification failure.
     *
     * @param message failure detail; {@code null} is not a trust failure
     * @return {@code true} when a known TLS/trust marker is present
     */
    public static boolean looksLikeTrustFailure(String message) {
        if (message == null || message.isBlank()) {
            return false;
        }
        String normalized = message.toLowerCase(java.util.Locale.ROOT);
        return normalized.contains("ssl")
                || normalized.contains("tls")
                || normalized.contains("certificate")
                || normalized.contains("pkix")
                || normalized.contains("handshake")
                || normalized.contains("hostname");
    }

    private static boolean isHttps(String baseUrl) {
        return baseUrl != null && baseUrl.trim().toLowerCase(java.util.Locale.ROOT).startsWith("https://");
    }

    private static String configuredTlsMode(ConfigState.SearchDestination destination) {
        ConfigState.State current = RuntimeConfig.getState();
        if (current == null || current.sinks() == null) {
            return ConfigState.OPEN_SEARCH_TLS_VERIFY;
        }
        ConfigState.Sinks sinks = current.sinks();
        return switch (destination == null ? ConfigState.SearchDestination.OPEN_SEARCH : destination) {
            case OPEN_SEARCH -> ConfigState.normalizeOpenSearchTlsMode(sinks.openSearchTlsMode());
            case OPEN_SEARCH_AMAZON -> ConfigState.normalizeOpenSearchTlsMode(
                    sinks.openSearchAmazonOptions().tlsMode());
            case ELASTICSEARCH -> ConfigState.normalizeOpenSearchTlsMode(
                    sinks.elasticSearchOptions().tlsMode());
        };
    }

    private static SecureCredentialStore.PinnedTlsCertificate pinnedCertificate(
            ConfigState.SearchDestination destination) {
        ConfigState.SearchDestination normalized = destination == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : destination;
        return SecureCredentialStore.loadPinnedTlsCertificate(normalized.configKey());
    }

    private static boolean leafMatchesPinnedCertificate(X509Certificate[] chain, byte[] expected) {
        if (chain == null || chain.length == 0 || expected == null || expected.length == 0) {
            return false;
        }
        try {
            return MessageDigest.isEqual(chain[0].getEncoded(), expected);
        } catch (CertificateException e) {
            return false;
        }
    }

    private static String sha256Fingerprint(byte[] encoded) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(encoded);
        StringBuilder sb = new StringBuilder(hash.length * 3 - 1);
        for (int i = 0; i < hash.length; i++) {
            if (i > 0) {
                sb.append(':');
            }
            int value = hash[i] & 0xFF;
            if (value < 0x10) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(value).toUpperCase(java.util.Locale.ROOT));
        }
        return sb.toString();
    }
}
