package ai.anomalousvectors.tools.burp.utils.search;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.util.concurrent.TimeUnit;

import burp.api.montoya.http.message.HttpHeader;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.core5.http.HttpHost;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

/** Verifies strict pinning against an otherwise trusted peer in an isolated packaged runtime. */
class SearchPinnedTrustPolicyTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void wrongPinRejectsOtherwiseTrustedServerAcrossDestinationsAndTransports() throws Exception {
        Path trustStore = temporaryDirectory.resolve("trusted-server.p12");
        var factory = CertificateFactory.getInstance("X.509");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        try (TlsTestServer server = TlsTestServer.start(false)) {
            store.setCertificateEntry("server", factory.generateCertificate(
                    new ByteArrayInputStream(server.certificateBytes())));
        }
        try (var output = Files.newOutputStream(trustStore)) {
            store.store(output, "fixture".toCharArray());
        }
        Path differentPin = temporaryDirectory.resolve("different-server.cer");
        try (var input = getClass().getResourceAsStream("/tls/different-server.pem")) {
            if (input == null) throw new IllegalStateException("Missing different-server certificate fixture");
            Files.write(differentPin, factory.generateCertificate(input).getEncoded());
        }
        String testClasses = Path.of(getClass().getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String montoya = Path.of(HttpHeader.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String classpath = testClasses + File.pathSeparator + System.getProperty("burp.exporter.packagedJar")
                + File.pathSeparator + montoya;
        Path log = temporaryDirectory.resolve("pin-policy.log");
        Process child = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx128m", "-Djava.awt.headless=true", "-Djava.io.tmpdir=" + temporaryDirectory,
                "-Djavax.net.ssl.trustStore=" + trustStore, "-Djavax.net.ssl.trustStorePassword=fixture",
                "-cp", classpath, Probe.class.getName(), differentPin.toString())
                .redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try {
            assertThat(child.waitFor(60, TimeUnit.SECONDS)).as("pin-policy process completed").isTrue();
            String output = Files.readString(log, StandardCharsets.UTF_8);
            assertThat(child.exitValue()).as(output).isZero();
            assertThat(output).contains("pin-policy checks=45 passed");
        } finally {
            if (child.isAlive()) {
                child.destroyForcibly();
                assertThat(child.waitFor(10, TimeUnit.SECONDS)).as("pin-policy process terminated").isTrue();
            }
        }
    }

    /** Child-process entry point keeps its synthetic default trust store out of the test runner. */
    public static final class Probe {
        private Probe() { }

        /**
         * Exercises normal trust, an exact pin and a mismatched pin through the packaged clients.
         *
         * @param args path to the unrelated certificate's DER encoding
         * @throws Exception if fixture setup or an expected transport outcome fails
         */
        public static void main(String[] args) throws Exception {
            System.clearProperty("OPENSEARCH_INSECURE");
            int checks = 0;
            try (TlsTestServer server = TlsTestServer.start(false)) {
                String url = "https://localhost:" + server.port();
                for (var destination : ConfigState.SearchDestination.values()) {
                    for (String selection : List.of("verify", "exact", "different")) {
                        SearchConnector.closeAll();
                        SecureCredentialStore.clearAll();
                        String mode = selection.equals("verify")
                                ? ConfigState.OPEN_SEARCH_TLS_VERIFY : ConfigState.OPEN_SEARCH_TLS_PINNED;
                        RuntimeConfig.updateState(state(destination, mode));
                        byte[] pin = selection.equals("different") ? Files.readAllBytes(Path.of(args[0]))
                                : server.certificateBytes();
                        SecureCredentialStore.savePinnedTlsCertificate(destination.configKey(), "fixture", selection, pin);
                        boolean expected = !selection.equals("different");
                        for (String path : List.of("classic", "async", "sdk", "connection", "bulk")) {
                            boolean accepted;
                            try {
                                accepted = execute(path, destination, url);
                            } catch (Exception failure) {
                                if (expected) throw failure;
                                // Positive controls exercise the same routes before the wrong-pin case.
                                // Transport wrappers do not expose identical TLS exception chains.
                                accepted = false;
                            }
                            if (accepted != expected) throw new AssertionError(destination + "/" + selection + "/" + path);
                            checks++;
                        }
                    }
                }
            } finally {
                SearchConnector.closeAll();
                SecureCredentialStore.clearAll();
            }
            System.out.println("pin-policy checks=" + checks + " passed");
        }

        private static boolean execute(String path, ConfigState.SearchDestination destination, String url) throws Exception {
            return switch (path) {
                case "classic" -> SearchConnector.getClassicHttpClient(url, SearchAuth.none())
                        .execute(HttpHost.create(url), new HttpGet("/"), response -> {
                            SearchResponseBodies.read(response);
                            return response.getCode() == 200;
                        });
                case "async" -> SearchConnector.getAsyncHttpClient(url, SearchAuth.none())
                        .execute(SimpleRequestBuilder.get(url + "/").build(), null)
                        .get(10, TimeUnit.SECONDS).getCode() == 200;
                case "sdk" -> SearchConnector.getClient(url, SearchAuth.none()).info().name().equals("fixture");
                case "connection" -> {
                    var status = SearchConnectionTester.safeTestConnection(destination, url);
                    yield status.success();
                }
                case "bulk" -> SearchBulkHttpExecutor.executeBulkPost(url, "traffic",
                        "{\"index\":{}}\n{\"fixture\":true}\n".getBytes(StandardCharsets.UTF_8), 65_536,
                        (response, requestId) -> {
                            SearchResponseBodies.read(response);
                            return response.getCode() == 200;
                        });
                default -> throw new IllegalArgumentException(path);
            };
        }

        private static ConfigState.State state(ConfigState.SearchDestination destination, String mode) {
            var amazon = new ConfigState.OpenSearchAmazonOptions("None", "", "", "", "", "",
                    ConfigState.DEPLOYMENT_HOSTED, mode, "", "", "");
            var elastic = new ConfigState.ElasticsearchOptions("None", "", "", "",
                    ConfigState.DEPLOYMENT_AUTO, mode, "", "", "");
            var open = new ConfigState.OpenSearchOptions("None", "", "", "", "", "", "");
            var sinks = new ConfigState.Sinks(false, "", false, false,
                    true, ConfigState.DEFAULT_FILE_TOTAL_CAP_GB, true, ConfigState.DEFAULT_FILE_MAX_DISK_USED_PERCENT,
                    true, "", "", "", mode, open, destination.configKey(), "", amazon, "", elastic);
            return new ConfigState.State(List.of(ConfigKeys.SRC_TRAFFIC), ConfigKeys.SCOPE_ALL, List.of(), sinks,
                    ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES,
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES, null);
        }
    }
}
