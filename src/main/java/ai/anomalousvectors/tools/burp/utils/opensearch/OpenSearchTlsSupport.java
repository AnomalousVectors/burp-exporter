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
 */
public final class OpenSearchTlsSupport {

    private OpenSearchTlsSupport() { }

    /** Returns the effective OpenSearch TLS mode, honoring the insecure override property when set. */
    public static String currentTlsMode() {
        return currentTlsMode(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Returns the effective TLS mode for one database destination. */
    public static String currentTlsMode(ConfigState.SearchDestination destination) {
        return "true".equalsIgnoreCase(System.getProperty("OPENSEARCH_INSECURE", "").trim())
                ? ConfigState.OPEN_SEARCH_TLS_INSECURE
                : configuredTlsMode(destination);
    }

    /** Returns whether the current TLS mode trusts all certificates insecurely. */
    public static boolean isInsecureMode() {
        return isInsecureMode(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Returns whether one destination's current TLS mode trusts all certificates insecurely. */
    public static boolean isInsecureMode(ConfigState.SearchDestination destination) {
        return isInsecureMode(currentTlsMode(destination));
    }

    /** Returns whether a TLS mode value trusts all certificates insecurely. */
    public static boolean isInsecureMode(String tlsMode) {
        return ConfigState.OPEN_SEARCH_TLS_INSECURE.equals(ConfigState.normalizeOpenSearchTlsMode(tlsMode));
    }

    /** Returns whether the current TLS mode requires a pinned certificate. */
    public static boolean isPinnedMode() {
        return isPinnedMode(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Returns whether one destination's current TLS mode requires a pinned certificate. */
    public static boolean isPinnedMode(ConfigState.SearchDestination destination) {
        return isPinnedMode(currentTlsMode(destination));
    }

    /** Returns whether a TLS mode value requires a pinned certificate. */
    public static boolean isPinnedMode(String tlsMode) {
        return ConfigState.OPEN_SEARCH_TLS_PINNED.equals(ConfigState.normalizeOpenSearchTlsMode(tlsMode));
    }

    /** Returns whether pinned certificate material is currently loaded in session memory. */
    public static boolean hasPinnedCertificate() {
        return hasPinnedCertificate(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Returns whether one destination has pinned certificate material loaded in session memory. */
    public static boolean hasPinnedCertificate(ConfigState.SearchDestination destination) {
        return pinnedCertificate(destination).encodedBytes().length > 0;
    }

    /** Returns the loaded pinned certificate fingerprint, or blank when none is loaded. */
    public static String pinnedCertificateFingerprint() {
        return pinnedCertificateFingerprint(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Returns one destination's loaded pinned certificate fingerprint, or blank when none is loaded. */
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

    /** Builds an SSL context that trusts only the currently imported pinned certificate. */
    public static SSLContext buildPinnedSslContext() throws GeneralSecurityException {
        return buildPinnedSslContext(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Builds an SSL context that trusts only one destination's imported pinned certificate. */
    public static SSLContext buildPinnedSslContext(ConfigState.SearchDestination destination)
            throws GeneralSecurityException {
        return pinnedSslContextBuilder(destination).build();
    }

    /** Builds an SSL context builder that trusts only the currently imported pinned certificate. */
    public static SSLContextBuilder pinnedSslContextBuilder() throws GeneralSecurityException {
        return pinnedSslContextBuilder(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Builds an SSL context builder that trusts only one destination's imported pinned certificate. */
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

    /** Returns a user-facing trust summary for successful connections under the current mode. */
    public static String successTrustSummary(String baseUrl) {
        return successTrustSummary(baseUrl, ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Returns a user-facing trust summary for a destination's successful connection. */
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

    /** Returns a user-facing trust summary for failed connections under the current mode. */
    public static String failureTrustSummary(String baseUrl, String detail) {
        return failureTrustSummary(baseUrl, detail, ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Returns a user-facing trust summary for a destination's failed connection. */
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
            default -> "System trust verification failed";
        };
    }

    /** Returns true when the message looks like a TLS trust, pin, or hostname-verification failure. */
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
