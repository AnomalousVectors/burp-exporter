package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.ssl.SSLContextBuilder;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

/**
 * Runtime OpenSearch authentication material resolved from UI config and session credentials.
 */
public final class OpenSearchAuth {
    private static final char[] EMPTY_PASSWORD = new char[0];

    /** Supported upstream OpenSearch authentication modes. */
    public enum Mode {
        NONE,
        BASIC,
        API_KEY,
        BEARER_TOKEN,
        CERTIFICATE
    }

    private final Mode mode;
    private final String username;
    private final String password;
    private final String token;
    private final String certificatePath;
    private final String keyPath;
    private final String keyPassphrase;

    private OpenSearchAuth(
            Mode mode,
            String username,
            String password,
            String token,
            String certificatePath,
            String keyPath,
            String keyPassphrase) {
        this.mode = mode == null ? Mode.NONE : mode;
        this.username = safe(username);
        this.password = safe(password);
        this.token = safe(token);
        this.certificatePath = safe(certificatePath);
        this.keyPath = safe(keyPath);
        this.keyPassphrase = safe(keyPassphrase);
    }

    /** Returns an unauthenticated OpenSearch auth descriptor. */
    public static OpenSearchAuth none() {
        return new OpenSearchAuth(Mode.NONE, "", "", "", "", "", "");
    }

    /** Returns a Basic auth descriptor for compatibility with existing call sites and tests. */
    public static OpenSearchAuth basic(String username, String password) {
        return new OpenSearchAuth(Mode.BASIC, username, password, "", "", "", "");
    }

    /** Returns an API key auth descriptor. */
    public static OpenSearchAuth apiKey(String token) {
        return new OpenSearchAuth(Mode.API_KEY, "", "", token, "", "", "");
    }

    /** Returns a bearer-token auth descriptor. */
    public static OpenSearchAuth bearerToken(String token) {
        return new OpenSearchAuth(Mode.BEARER_TOKEN, "", "", token, "", "", "");
    }

    /** Returns a client-certificate auth descriptor. */
    public static OpenSearchAuth certificate(String certificatePath, String keyPath, String keyPassphrase) {
        return new OpenSearchAuth(Mode.CERTIFICATE, "", "", "", certificatePath, keyPath, keyPassphrase);
    }

    /** Resolves the currently selected upstream OpenSearch auth mode from runtime/session state. */
    public static OpenSearchAuth fromRuntime() {
        return fromRuntime(ConfigState.SearchDestination.OPEN_SEARCH);
    }

    /** Resolves the selected database destination's auth mode from runtime/session state. */
    public static OpenSearchAuth fromRuntime(ConfigState.SearchDestination destination) {
        ConfigState.SearchDestination selected = destination == null
                ? ConfigState.SearchDestination.OPEN_SEARCH
                : destination;
        if (selected == ConfigState.SearchDestination.ELASTICSEARCH) {
            return elasticsearchFromRuntime();
        }
        ConfigState.State state = RuntimeConfig.getState();
        ConfigState.OpenSearchOptions options = state == null || state.sinks() == null
                ? ConfigState.defaultOpenSearchOptions()
                : state.sinks().openSearchOptions();
        String authType = options == null ? ConfigState.DEFAULT_OPEN_SEARCH_AUTH_TYPE : options.authType();
        return switch (ConfigState.normalizeOpenSearchAuthType(authType)) {
            case "Basic" -> new OpenSearchAuth(
                    Mode.BASIC,
                    RuntimeConfig.openSearchUser(),
                    RuntimeConfig.openSearchPassword(),
                    "",
                    "",
                    "",
                    "");
            case "API key" -> {
                SecureCredentialStore.ApiKeyCredentials apiKey = SecureCredentialStore.loadApiKeyCredentials();
                yield new OpenSearchAuth(Mode.API_KEY, "", "", apiKey.token(), "", "", "");
            }
            case "Bearer token" -> {
                SecureCredentialStore.JwtCredentials jwt = SecureCredentialStore.loadJwtCredentials();
                yield new OpenSearchAuth(Mode.BEARER_TOKEN, "", "", jwt.token(), "", "", "");
            }
            case "Certificate" -> {
                SecureCredentialStore.CertificateCredentials cert = SecureCredentialStore.loadCertificateCredentials();
                yield new OpenSearchAuth(
                        Mode.CERTIFICATE,
                        "",
                        "",
                        "",
                        cert.certPath(),
                        cert.keyPath(),
                        cert.passphrase());
            }
            default -> none();
        };
    }

    private static OpenSearchAuth elasticsearchFromRuntime() {
        ConfigState.State state = RuntimeConfig.getState();
        ConfigState.ElasticsearchOptions options = state == null || state.sinks() == null
                ? ConfigState.defaultElasticsearchOptions()
                : state.sinks().elasticSearchOptions();
        String destination = ConfigState.SearchDestination.ELASTICSEARCH.configKey();
        return switch (ConfigState.normalizeElasticsearchAuthType(options.authType())) {
            case "Basic" -> {
                SecureCredentialStore.BasicCredentials basic =
                        SecureCredentialStore.loadBasicCredentials(destination);
                String username = options.username().isBlank() ? basic.username() : options.username();
                yield basic(username, basic.password());
            }
            case "API key" -> apiKey(SecureCredentialStore.loadApiKeyCredentials(destination).token());
            case "Bearer token" -> bearerToken(SecureCredentialStore.loadJwtCredentials(destination).token());
            case "Certificate" -> {
                SecureCredentialStore.CertificateCredentials cert =
                        SecureCredentialStore.loadCertificateCredentials(destination);
                String certPath = options.certPath().isBlank() ? cert.certPath() : options.certPath();
                String keyPath = options.certKeyPath().isBlank() ? cert.keyPath() : options.certKeyPath();
                yield certificate(certPath, keyPath, cert.passphrase());
            }
            default -> none();
        };
    }

    /** Returns the selected authentication mode. */
    public Mode mode() {
        return mode;
    }

    /** Returns whether this auth descriptor has enough material to make an authenticated request. */
    public boolean isComplete() {
        return switch (mode) {
            case NONE -> true;
            case BASIC -> !username.isBlank() && !password.isBlank();
            case API_KEY, BEARER_TOKEN -> !token.isBlank();
            case CERTIFICATE -> !certificatePath.isBlank() && !keyPath.isBlank();
        };
    }

    /** Returns a validation message for missing auth material, or blank when complete. */
    public String validationMessage() {
        return switch (mode) {
            case NONE -> "";
            case BASIC -> isComplete() ? "" : "Basic auth requires username and password.";
            case API_KEY -> isComplete() ? "" : "API key auth requires an API key.";
            case BEARER_TOKEN -> isComplete() ? "" : "Bearer token auth requires a bearer token.";
            case CERTIFICATE -> isComplete() ? "" : "Certificate auth requires a certificate path and private key path.";
        };
    }

    /** Returns whether requests carry an Authorization header. */
    public boolean usesAuthorizationHeader() {
        return mode == Mode.BASIC || mode == Mode.API_KEY || mode == Mode.BEARER_TOKEN;
    }

    /** Returns the redacted authorization label used in request logs. */
    public String redactedAuthorizationForLog() {
        return switch (mode) {
            case BASIC -> "Basic ***";
            case API_KEY -> "ApiKey ***";
            case BEARER_TOKEN -> "Bearer ***";
            default -> "";
        };
    }

    /** Returns the Authorization header value for header-based modes, or blank when not used. */
    public String authorizationHeaderValue() {
        Header header = authorizationHeader();
        return header == null ? "" : header.getValue();
    }

    /** Returns a cache-safe discriminator that never includes raw secret values. */
    public String cacheKey() {
        return switch (mode) {
            case NONE -> "auth=none";
            case BASIC -> "auth=basic:" + fingerprint(username + ":" + password);
            case API_KEY -> "auth=apikey:" + fingerprint(token);
            case BEARER_TOKEN -> "auth=bearer:" + fingerprint(token);
            case CERTIFICATE -> "auth=certificate:" + certificatePath + "|" + keyPath + "|pass=" + !keyPassphrase.isBlank();
        };
    }

    /** Returns default headers for API key and bearer-token auth. */
    public Header[] defaultHeaders() {
        return authorizationHeader() == null ? new Header[0] : new Header[] { authorizationHeader() };
    }

    /** Applies auth headers to a classic request builder. */
    public void applyTo(ClassicRequestBuilder builder) {
        Header header = authorizationHeader();
        if (header != null) {
            builder.setHeader(header);
        }
    }

    /** Applies auth headers to a classic request. */
    public void applyTo(HttpRequest request) {
        Header header = authorizationHeader();
        if (header != null) {
            request.setHeader(header);
        }
    }

    /** Loads client certificate key material into the supplied SSL context builder when selected. */
    public void loadClientKeyMaterial(SSLContextBuilder builder) throws GeneralSecurityException, IOException {
        if (mode != Mode.CERTIFICATE) {
            return;
        }
        if (!isComplete()) {
            throw new GeneralSecurityException(validationMessage());
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        char[] passphrase = keyPassphrase.isBlank() ? EMPTY_PASSWORD : keyPassphrase.toCharArray();
        try {
            keyStore.load(null, EMPTY_PASSWORD);
            Certificate certificate = readCertificate(Path.of(certificatePath));
            PrivateKey privateKey = readPrivateKey(Path.of(keyPath), passphrase);
            keyStore.setKeyEntry("opensearch-client", privateKey, passphrase, new Certificate[] { certificate });
            builder.loadKeyMaterial(keyStore, passphrase);
        } catch (IOException | GeneralSecurityException e) {
            throw e;
        }
    }

    private Header authorizationHeader() {
        if (!isComplete()) {
            return null;
        }
        return switch (mode) {
            case BASIC -> new BasicHeader(HttpHeaders.AUTHORIZATION, basicHeaderValue());
            case API_KEY -> new BasicHeader(HttpHeaders.AUTHORIZATION, "ApiKey " + token);
            case BEARER_TOKEN -> new BasicHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
            default -> null;
        };
    }

    private String basicHeaderValue() {
        String encoded = Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }

    private static Certificate readCertificate(Path path) throws IOException, GeneralSecurityException {
        try (var input = Files.newInputStream(path)) {
            return CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }

    private static PrivateKey readPrivateKey(Path path, char[] passphrase) throws IOException, GeneralSecurityException {
        byte[] keyBytes = Files.readAllBytes(path);
        boolean rsaPkcs1 = isPemBlock(keyBytes, "RSA PRIVATE KEY");
        byte[] encoded = decodePemOrDer(keyBytes);
        if (rsaPkcs1) {
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(wrapRsaPkcs1Key(encoded)));
            } catch (GeneralSecurityException e) {
                // Continue through the common failure path so callers get a consistent error.
            }
        }
        GeneralSecurityException last = null;
        for (String algorithm : List.of("RSA", "EC", "DSA")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        if (passphrase != null && passphrase.length > 0) {
            try {
                EncryptedPrivateKeyInfo encrypted = new EncryptedPrivateKeyInfo(encoded);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(encrypted.getAlgName());
                var secretKey = factory.generateSecret(new PBEKeySpec(passphrase));
                PKCS8EncodedKeySpec keySpec = encrypted.getKeySpec(secretKey);
                for (String algorithm : List.of("RSA", "EC", "DSA")) {
                    try {
                        return KeyFactory.getInstance(algorithm).generatePrivate(keySpec);
                    } catch (GeneralSecurityException e) {
                        last = e;
                    }
                }
            } catch (GeneralSecurityException e) {
                last = e;
            }
        }
        throw new GeneralSecurityException("Unsupported or unreadable PKCS#8 private key.", last);
    }

    private static boolean isPemBlock(byte[] bytes, String label) {
        String text = new String(bytes, StandardCharsets.US_ASCII);
        return text.contains("-----BEGIN " + label + "-----");
    }

    private static byte[] decodePemOrDer(byte[] bytes) {
        String text = new String(bytes, StandardCharsets.US_ASCII);
        if (!text.contains("-----BEGIN")) {
            return bytes;
        }
        String base64 = text.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(base64);
    }

    private static byte[] wrapRsaPkcs1Key(byte[] pkcs1) throws IOException {
        byte[] version = new byte[] { 0x02, 0x01, 0x00 };
        byte[] algorithmIdentifier = new byte[] {
                0x30, 0x0d,
                0x06, 0x09,
                0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
                0x05, 0x00 };
        byte[] privateKey = der(0x04, pkcs1);
        return der(0x30, concat(version, algorithmIdentifier, privateKey));
    }

    private static byte[] der(int tag, byte[] payload) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeDerLength(out, payload.length);
        out.write(payload);
        return out.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }
        int bytes = Integer.BYTES - Integer.numberOfLeadingZeros(length) / Byte.SIZE;
        out.write(0x80 | bytes);
        for (int shift = (bytes - 1) * Byte.SIZE; shift >= 0; shift -= Byte.SIZE) {
            out.write((length >> shift) & 0xff);
        }
    }

    private static byte[] concat(byte[]... values) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] value : values) {
            out.write(value);
        }
        return out.toByteArray();
    }

    private static String fingerprint(String value) {
        byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
            return new BigInteger(1, digest).toString(16);
        } catch (GeneralSecurityException e) {
            return Integer.toHexString(java.util.Arrays.hashCode(bytes));
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
