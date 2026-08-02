package ai.anomalousvectors.tools.burp.testutils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;

import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchAuth;
import ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchRawGet;

/**
 * Resolves and provisions the local multi/opensearch client certificate used by certificate ITs.
 *
 * <p>Looks up {@code DATA_VOLUME_ROOT} from the process environment / JVM properties, then from
 * {@code .env} files (project root, then the sibling {@code multi/opensearch} stack repo). Client
 * certs live under {@code ${DATA_VOLUME_ROOT}/armis/certs} (compose mount) or
 * {@code ${DATA_VOLUME_ROOT}/certs}, and are signed by that directory's
 * {@code root-ca.pem}. When the CA fingerprint changes, or a quick certificate probe fails before
 * an HTTP response, the helper recreates {@code burp-exporter-client.pem} via {@code docker exec}
 * + openssl (matching the stack's auth-matrix script). When the cert is valid but OpenSearch still
 * returns HTTP 401, the helper enables client-certificate auth on the local stack once (admin DN +
 * securityadmin), because signing alone cannot unlock a disabled {@code clientcert_auth_domain}.
 * Certificate ITs may skip before provisioning when none of the OpenSearch or certificate-stack
 * options are configured; once any option is explicit, provisioning failures remain hard
 * failures.</p>
 */
public final class OpenSearchClientCertificateSupport {

    private static final String CLIENT_CERT_NAME = "burp-exporter-client.pem";
    private static final String CLIENT_KEY_NAME = "burp-exporter-client-key.pem";
    private static final String CLIENT_CA_STAMP_NAME = "burp-exporter-client.ca-sha256";
    private static final String ADMIN_CERT_NAME = "admin.pem";
    private static final String ADMIN_KEY_NAME = "admin-key.pem";
    private static final String ROOT_CA_NAME = "root-ca.pem";
    private static final String ROOT_CA_KEY_NAME = "root-ca-key.pem";
    private static final String CONTAINER_CERTS = "/usr/share/opensearch/config/certs";
    private static final String CLIENT_CN = "burp-exporter-client";

    private static final Object LOCK = new Object();
    private static volatile Paths cached;

    private OpenSearchClientCertificateSupport() {
    }

    /**
     * Client certificate paths under the resolved data-volume certs directory.
     *
     * @param certsDirectory host path to {@code ${DATA_VOLUME_ROOT}/certs}
     * @param certificatePath host path to the client certificate PEM
     * @param privateKeyPath host path to the client private key PEM
     */
    public record Paths(Path certsDirectory, Path certificatePath, Path privateKeyPath) {
    }

    /**
     * Ensures a CA-signed burp-exporter client certificate is present and accepted by OpenSearch.
     *
     * <p>Safe to call repeatedly; recreates the client cert only when the CA fingerprint changes,
     * files are missing, or a TLS-level probe failure indicates the existing pair is stale.</p>
     *
     * @return host paths to the client certificate and key
     * @throws IllegalStateException when certs cannot be resolved, created, or authenticated
     */
    public static Paths ensureReady() {
        synchronized (LOCK) {
            if (cached != null && Files.isRegularFile(cached.certificatePath())
                    && Files.isRegularFile(cached.privateKeyPath())
                    && probeStatus(cached) == 200) {
                return cached;
            }
            Path certsDir = resolveCertsDirectory();
            Path rootCa = certsDir.resolve(ROOT_CA_NAME);
            Path rootCaKey = certsDir.resolve(ROOT_CA_KEY_NAME);
            requireFile(rootCa, "OpenSearch root CA");
            requireFile(rootCaKey, "OpenSearch root CA private key");

            String caSha = sha256Hex(rootCa);
            Path clientCert = certsDir.resolve(CLIENT_CERT_NAME);
            Path clientKey = certsDir.resolve(CLIENT_KEY_NAME);
            Path stamp = certsDir.resolve(CLIENT_CA_STAMP_NAME);

            boolean stampMatches = caSha.equals(readStamp(stamp));
            boolean filesPresent = Files.isRegularFile(clientCert) && Files.isRegularFile(clientKey);
            Paths paths = new Paths(certsDir, clientCert, clientKey);
            int status = filesPresent ? probeStatus(paths) : 0;

            boolean needsRecreate = !filesPresent || !stampMatches || status == 0;
            if (needsRecreate) {
                recreateClientCertificate();
                writeStamp(stamp, caSha);
                status = probeStatus(paths);
            }

            if (status != 200) {
                enableClientCertificateAuthentication(certsDir);
                status = probeStatus(paths);
            }
            if (status != 200) {
                throw new IllegalStateException(
                        "Client certificate is present at " + clientCert
                                + " but OpenSearch returned HTTP " + status
                                + " for certificate auth. Enable clientcert auth on the local stack "
                                + "(multi/opensearch auth-matrix setup) or check admin DN / role mapping.");
            }
            cached = paths;
            return paths;
        }
    }

    /**
     * Returns whether the certificate/OpenSearch integration-test environment is explicitly
     * configured.
     *
     * <p>The same system-property-before-environment convention as {@link OpenSearchTestConfig} is
     * used. A discovered stack {@code .env} containing {@code DATA_VOLUME_ROOT} also counts as
     * explicit configuration. This method does not validate the configuration; callers that
     * proceed must let {@link #ensureReady()} report broken paths, certificates, containers, or
     * clusters.</p>
     *
     * @return {@code true} when any OpenSearch connection or certificate-stack option is present
     */
    public static boolean hasExplicitTestEnvironment() {
        return OpenSearchTestConfig.hasExplicitConfiguration()
                || firstNonBlank(
                                System.getProperty("OPENSEARCH_CERT_PATH"),
                                System.getenv("OPENSEARCH_CERT_PATH"),
                                System.getProperty("OPENSEARCH_CERT_KEY_PATH"),
                                System.getenv("OPENSEARCH_CERT_KEY_PATH"),
                                System.getProperty("DATA_VOLUME_ROOT"),
                                System.getenv("DATA_VOLUME_ROOT"),
                                System.getProperty("OPENSEARCH_STACK_ENV"),
                                System.getenv("OPENSEARCH_STACK_ENV"),
                                System.getProperty("OPENSEARCH_CONTAINER"),
                                System.getenv("OPENSEARCH_CONTAINER"),
                                readEnvFileValue(discoverEnvFiles(), "DATA_VOLUME_ROOT"))
                        != null;
    }

    /** Clears the cached paths (test teardown). */
    public static void resetForTests() {
        synchronized (LOCK) {
            cached = null;
        }
    }

    private static int probeStatus(Paths paths) {
        try {
            OpenSearchAuth auth = OpenSearchAuth.certificate(
                    paths.certificatePath().toString(),
                    paths.privateKeyPath().toString(),
                    "");
            OpenSearchRawGet.RawGetResult result =
                    OpenSearchRawGet.performRawGet(OpenSearchTestConfig.get().baseUrl(), auth);
            return result.statusCode();
        } catch (RuntimeException ex) {
            return 0;
        }
    }

    private static Path resolveCertsDirectory() {
        String explicitCert = firstNonBlank(
                System.getProperty("OPENSEARCH_CERT_PATH"),
                System.getenv("OPENSEARCH_CERT_PATH"));
        if (explicitCert != null) {
            Path cert = Path.of(explicitCert).toAbsolutePath().normalize();
            Path parent = cert.getParent();
            if (parent != null) {
                return parent;
            }
        }

        String dataRoot = firstNonBlank(
                System.getProperty("DATA_VOLUME_ROOT"),
                System.getenv("DATA_VOLUME_ROOT"),
                readEnvFileValue(discoverEnvFiles(), "DATA_VOLUME_ROOT"));
        if (dataRoot == null || dataRoot.isBlank()) {
            throw new IllegalStateException(
                    "DATA_VOLUME_ROOT is not set. Set it in the environment or in multi/opensearch .env "
                            + "(certs live under ${DATA_VOLUME_ROOT}/certs or "
                            + "${DATA_VOLUME_ROOT}/armis/certs).");
        }
        Path root = Path.of(dataRoot.trim()).toAbsolutePath().normalize();
        // multi/opensearch docker-compose mounts ${DATA_VOLUME_ROOT}/armis/certs into the
        // container. Prefer that tree when it has the CA; fall back to ${DATA_VOLUME_ROOT}/certs.
        Path armisCerts = root.resolve("armis").resolve("certs");
        if (looksLikeOpenSearchCertsDir(armisCerts)) {
            return armisCerts;
        }
        Path directCerts = root.resolve("certs");
        if (looksLikeOpenSearchCertsDir(directCerts)) {
            return directCerts;
        }
        throw new IllegalStateException(
                "OpenSearch certs directory not found under " + root
                        + " (checked armis/certs and certs).");
    }

    private static boolean looksLikeOpenSearchCertsDir(Path certsDir) {
        return Files.isDirectory(certsDir)
                && Files.isRegularFile(certsDir.resolve(ROOT_CA_NAME))
                && Files.isRegularFile(certsDir.resolve(ROOT_CA_KEY_NAME));
    }

    private static List<Path> discoverEnvFiles() {
        List<Path> candidates = new ArrayList<>();
        String explicit = firstNonBlank(
                System.getProperty("OPENSEARCH_STACK_ENV"),
                System.getenv("OPENSEARCH_STACK_ENV"));
        if (explicit != null) {
            candidates.add(Path.of(explicit));
        }
        Path userDir = Path.of("").toAbsolutePath().normalize();
        candidates.add(userDir.resolve(".env"));
        candidates.add(userDir.resolve("..").resolve("multi").resolve("opensearch").resolve(".env"));
        candidates.add(userDir.resolve("..").resolve("..").resolve("multi").resolve("opensearch").resolve(".env"));
        return candidates;
    }

    private static String readEnvFileValue(List<Path> envFiles, String key) {
        for (Path envFile : envFiles) {
            if (envFile == null || !Files.isRegularFile(envFile)) {
                continue;
            }
            try {
                for (String raw : Files.readAllLines(envFile, StandardCharsets.UTF_8)) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#") || !line.contains("=")) {
                        continue;
                    }
                    int eq = line.indexOf('=');
                    String name = line.substring(0, eq).trim();
                    if (!key.equals(name)) {
                        continue;
                    }
                    String value = line.substring(eq + 1).trim();
                    if (!value.isEmpty()) {
                        return value;
                    }
                }
            } catch (IOException ignored) {
                // try next candidate
            }
        }
        return null;
    }

    private static void recreateClientCertificate() {
        String container = containerName();
        String script = "set -euo pipefail; "
                + "cd " + CONTAINER_CERTS + "; "
                + "test -f root-ca.pem && test -f root-ca-key.pem; "
                + "openssl genrsa -out burp-exporter-client-key.pem 2048; "
                + "openssl req -new -key burp-exporter-client-key.pem -out burp-exporter-client.csr "
                + "-subj '/C=US/ST=State/L=City/O=AnomalousVectors/OU=Dev/CN=" + CLIENT_CN + "'; "
                + "printf '%s\\n' "
                + "'authorityKeyIdentifier=keyid,issuer' "
                + "'basicConstraints=CA:FALSE' "
                + "'keyUsage=digitalSignature,keyEncipherment' "
                + "'extendedKeyUsage=clientAuth' "
                + "> burp-exporter-client.ext; "
                + "openssl x509 -req -in burp-exporter-client.csr -CA root-ca.pem -CAkey root-ca-key.pem "
                + "-CAcreateserial -out burp-exporter-client.pem -days 3650 -sha256 "
                + "-extfile burp-exporter-client.ext; "
                + "rm -f burp-exporter-client.csr burp-exporter-client.ext; "
                + "chmod 600 burp-exporter-client-key.pem || true";
        runDocker(List.of("exec", container, "bash", "-lc", script));
    }

    private static void enableClientCertificateAuthentication(Path certsDir) {
        String container = containerName();
        ensureAdminCertificate(certsDir, container);
        ensureAdminDnAndClientAuthMode(container);
        restartOpenSearch(container);
        awaitOpenSearchReachable();
        applyClientCertSecurityConfig(certsDir, container);
    }

    private static void ensureAdminCertificate(Path certsDir, String container) {
        Path adminCert = certsDir.resolve(ADMIN_CERT_NAME);
        Path adminKey = certsDir.resolve(ADMIN_KEY_NAME);
        if (Files.isRegularFile(adminCert) && Files.isRegularFile(adminKey)) {
            return;
        }
        String script = "set -euo pipefail; "
                + "cd " + CONTAINER_CERTS + "; "
                + "openssl genrsa -out admin-key.pem 2048; "
                + "openssl req -new -key admin-key.pem -out admin.csr "
                + "-subj '/C=US/ST=State/L=City/O=AnomalousVectors/OU=Dev/CN=opensearch-admin'; "
                + "printf '%s\\n' "
                + "'authorityKeyIdentifier=keyid,issuer' "
                + "'basicConstraints=CA:FALSE' "
                + "'keyUsage=digitalSignature,keyEncipherment' "
                + "'extendedKeyUsage=clientAuth' "
                + "> admin.ext; "
                + "openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem "
                + "-CAcreateserial -out admin.pem -days 3650 -sha256 -extfile admin.ext; "
                + "rm -f admin.csr admin.ext; "
                + "chmod 600 admin-key.pem || true";
        runDocker(List.of("exec", container, "bash", "-lc", script));
        requireFile(adminCert, "admin certificate");
        requireFile(adminKey, "admin private key");
    }

    private static void ensureAdminDnAndClientAuthMode(String container) {
        String script = "set -euo pipefail; "
                + "YML=/usr/share/opensearch/config/opensearch.yml; "
                + "if ! grep -q 'plugins.security.authcz.admin_dn' \"$YML\"; then "
                + "printf '\\nplugins.security.authcz.admin_dn:\\n"
                + "  - \"CN=opensearch-admin,OU=Dev,O=AnomalousVectors,L=City,ST=State,C=US\"\\n' >> \"$YML\"; "
                + "fi; "
                + "if grep -q 'plugins.security.ssl.http.clientauth_mode:' \"$YML\"; then "
                + "sed -i 's/^plugins.security.ssl.http.clientauth_mode:.*/"
                + "plugins.security.ssl.http.clientauth_mode: OPTIONAL/' \"$YML\"; "
                + "else "
                + "printf 'plugins.security.ssl.http.clientauth_mode: OPTIONAL\\n' >> \"$YML\"; "
                + "fi";
        runDocker(List.of("exec", container, "bash", "-lc", script));
    }

    private static void restartOpenSearch(String container) {
        runDocker(List.of("restart", container));
    }

    private static void awaitOpenSearchReachable() {
        Duration budget = Duration.ofSeconds(180);
        long deadline = System.nanoTime() + budget.toNanos();
        RuntimeException last = null;
        OpenSearchTestConfig config = OpenSearchTestConfig.get();
        while (System.nanoTime() < deadline) {
            try {
                if (ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper
                        .testConnection(config.baseUrl(), config.username(), config.password())
                        .success()) {
                    return;
                }
            } catch (RuntimeException ex) {
                last = ex;
            }
            try {
                Thread.sleep(2_000L);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for OpenSearch restart", ie);
            }
        }
        throw new IllegalStateException(
                "OpenSearch did not become reachable after enabling client-certificate auth",
                last);
    }

    private static void applyClientCertSecurityConfig(Path certsDir, String container) {
        Path helper = certsDir.resolve("burp-exporter-enable-clientcert.py");
        String python = """
                from pathlib import Path
                import re
                src = Path('/usr/share/opensearch/config/opensearch-security')
                out = Path('/tmp/burp-exporter-clientcert-security')
                out.mkdir(parents=True, exist_ok=True)
                cfg = (src / 'config.yml').read_text()
                cfg = re.sub(
                    r'(clientcert_auth_domain:[\\s\\S]*?http_enabled:\\s*)false',
                    r'\\1true',
                    cfg,
                    count=1,
                )
                cfg = re.sub(
                    r'(clientcert_auth_domain:[\\s\\S]*?transport_enabled:\\s*)false',
                    r'\\1true',
                    cfg,
                    count=1,
                )
                (out / 'config.yml').write_text(cfg)
                roles = (src / 'roles_mapping.yml').read_text()
                if 'burp-exporter-client' not in roles:
                    roles = roles.replace(
                        'description: "Maps admin to all_access"',
                        'users:\\n  - "burp-exporter-client"\\n  description: "Maps admin to all_access"',
                        1,
                    )
                (out / 'roles_mapping.yml').write_text(roles)
                """;
        try {
            Files.writeString(helper, python, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to write " + helper, ex);
        }
        String script = "set -euo pipefail; "
                + "python3 " + CONTAINER_CERTS + "/burp-exporter-enable-clientcert.py; "
                + "TOOLS=/usr/share/opensearch/plugins/opensearch-security/tools; "
                + "\"$TOOLS/securityadmin.sh\" -h localhost -p 9200 -nhnv -icl "
                + "-cacert " + CONTAINER_CERTS + "/root-ca.pem "
                + "-cert " + CONTAINER_CERTS + "/admin.pem "
                + "-key " + CONTAINER_CERTS + "/admin-key.pem "
                + "-f /tmp/burp-exporter-clientcert-security/config.yml -t config; "
                + "\"$TOOLS/securityadmin.sh\" -h localhost -p 9200 -nhnv -icl "
                + "-cacert " + CONTAINER_CERTS + "/root-ca.pem "
                + "-cert " + CONTAINER_CERTS + "/admin.pem "
                + "-key " + CONTAINER_CERTS + "/admin-key.pem "
                + "-f /tmp/burp-exporter-clientcert-security/roles_mapping.yml -t rolesmapping";
        try {
            runDocker(List.of("exec", container, "bash", "-lc", script));
        } finally {
            try {
                Files.deleteIfExists(helper);
            } catch (IOException ignored) {
                // best-effort cleanup
            }
        }
    }

    private static String containerName() {
        String name = firstNonBlank(
                System.getProperty("OPENSEARCH_CONTAINER"),
                System.getenv("OPENSEARCH_CONTAINER"),
                "opensearch");
        return name == null ? "opensearch" : name;
    }

    private static void runDocker(List<String> args) {
        List<String> command = new ArrayList<>();
        command.add("docker");
        command.addAll(args);
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        try {
            Process process = pb.start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean finished = process.waitFor(3, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("docker command timed out: " + command);
            }
            if (process.exitValue() != 0) {
                throw new IllegalStateException(
                        "docker command failed (" + process.exitValue() + "): " + command
                                + "\n" + output);
            }
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("Failed to run docker command: " + command, ex);
        }
    }

    private static void requireFile(Path path, String label) {
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(label + " missing: " + path);
        }
    }

    private static String readStamp(Path stamp) {
        if (!Files.isRegularFile(stamp)) {
            return "";
        }
        try {
            return Files.readString(stamp, StandardCharsets.UTF_8).trim();
        } catch (IOException ex) {
            return "";
        }
    }

    private static void writeStamp(Path stamp, String sha) {
        try {
            Files.writeString(stamp, sha + "\n", StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to write CA stamp " + stamp, ex);
        }
    }

    private static String sha256Hex(Path file) {
        try {
            byte[] bytes = Files.readAllBytes(file);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            return HexFormat.of().formatHex(digest);
        } catch (IOException | NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Failed to hash " + file, ex);
        }
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }
}
