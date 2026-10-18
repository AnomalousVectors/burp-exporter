package ai.anomalousvectors.tools.burp.utils.opensearch;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Minimal loopback HTTPS server for deterministic TLS trust and client-certificate tests.
 *
 * <p>The embedded PKCS#12 fixture contains one long-lived self-signed certificate for
 * {@code localhost}. Tests can therefore distinguish certificate trust from hostname verification
 * without relying on the developer's trust store, network, OpenSearch cluster, or external tools.</p>
 */
final class TlsTestServer implements AutoCloseable {

    private static final char[] STORE_PASSWORD = "changeit".toCharArray();
    private static final String ALIAS = "localhost";
    private static final String STORE_BASE64 =
            "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";

    private final SSLServerSocket serverSocket;
    private final Thread acceptThread;
    private final AtomicReference<IOException> failure = new AtomicReference<>();
    private volatile boolean closed;

    private TlsTestServer(boolean requireClientCertificate) throws Exception {
        SSLContext context = serverContext(requireClientCertificate);
        serverSocket = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 16, InetAddress.getLoopbackAddress());
        serverSocket.setNeedClientAuth(requireClientCertificate);
        acceptThread = new Thread(this::acceptLoop, "burp-exporter-test-tls-server");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    static TlsTestServer start(boolean requireClientCertificate) throws Exception {
        return new TlsTestServer(requireClientCertificate);
    }

    int port() {
        return serverSocket.getLocalPort();
    }

    byte[] certificateBytes() throws Exception {
        return certificate().getEncoded();
    }

    ClientPem writeClientPem(Path directory) throws Exception {
        Files.createDirectories(directory);
        KeyStore store = keyStore();
        X509Certificate certificate = (X509Certificate) store.getCertificate(ALIAS);
        PrivateKey privateKey = (PrivateKey) store.getKey(ALIAS, STORE_PASSWORD);
        Path certificatePath = directory.resolve("client-certificate.pem");
        Path privateKeyPath = directory.resolve("client-private-key.pem");
        Files.writeString(certificatePath, pem("CERTIFICATE", certificate.getEncoded()), StandardCharsets.US_ASCII);
        Files.writeString(privateKeyPath, pem("PRIVATE KEY", privateKey.getEncoded()), StandardCharsets.US_ASCII);
        return new ClientPem(certificatePath, privateKeyPath);
    }

    private void acceptLoop() {
        while (!closed) {
            SSLSocket acceptedSocket;
            try {
                acceptedSocket = (SSLSocket) serverSocket.accept();
            } catch (SocketException e) {
                if (!closed) {
                    failure.compareAndSet(null, e);
                    return;
                }
                continue;
            } catch (IOException e) {
                if (!closed) {
                    failure.compareAndSet(null, e);
                    return;
                }
                continue;
            }

            try (SSLSocket socket = acceptedSocket) {
                socket.setSoTimeout(2_000);
                socket.startHandshake();
                consumeRequest(socket);
                writeResponse(socket.getOutputStream());
            } catch (SSLException | SocketException ignored) {
                // Negative tests may reject TLS explicitly or abort the peer connection during the handshake.
            } catch (IOException e) {
                if (!closed) {
                    failure.compareAndSet(null, e);
                    return;
                }
            }
        }
    }

    private static void consumeRequest(SSLSocket socket) throws IOException {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            // Consume one HTTP request head; the tests send bodyless GET requests.
        }
    }

    private static void writeResponse(OutputStream output) throws IOException {
        byte[] body = "{}".getBytes(StandardCharsets.US_ASCII);
        String head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + body.length + "\r\nConnection: close\r\n\r\n";
        output.write(head.getBytes(StandardCharsets.US_ASCII));
        output.write(body);
        output.flush();
    }

    private static SSLContext serverContext(boolean requireClientCertificate) throws Exception {
        KeyStore store = keyStore();
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(store, STORE_PASSWORD);

        TrustManagerFactory trustManagers = null;
        if (requireClientCertificate) {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry(ALIAS, store.getCertificate(ALIAS));
            trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trustStore);
        }

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(
                keyManagers.getKeyManagers(),
                trustManagers == null ? null : trustManagers.getTrustManagers(),
                null);
        return context;
    }

    private static X509Certificate certificate() throws Exception {
        return (X509Certificate) keyStore().getCertificate(ALIAS);
    }

    private static KeyStore keyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        byte[] encoded = Base64.getDecoder().decode(STORE_BASE64);
        try (ByteArrayInputStream input = new ByteArrayInputStream(encoded)) {
            store.load(input, STORE_PASSWORD);
        }
        return store;
    }

    private static String pem(String type, byte[] encoded) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    /** {@inheritDoc} */
    @Override
    public void close() throws IOException {
        closed = true;
        serverSocket.close();
        try {
            acceptThread.join(TimeUnit.SECONDS.toMillis(2));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while stopping TLS test server", e);
        }
        IOException observedFailure = failure.get();
        if (observedFailure != null) {
            throw new AssertionError("TLS test server failed", observedFailure);
        }
    }

    record ClientPem(Path certificatePath, Path privateKeyPath) { }
}
