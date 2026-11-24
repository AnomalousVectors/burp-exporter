package ai.anomalousvectors.tools.burp.ui.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.timeout;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.swing.SwingUtilities;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.SecureCredentialStore;

/** Verifies off-EDT certificate reads, destination isolation, and stale-result fencing. */
class ConfigControllerCertificateImportTest {

    @ParameterizedTest
    @EnumSource(ConfigState.SearchDestination.class)
    void blockedImportLeavesEdtFreeAndSavesOnlyItsDestination(ConfigState.SearchDestination destination)
            throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController.Ui ui = mock(ConfigController.Ui.class);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ConfigController controller = controller(ui, executor, path -> {
            assertThat(SwingUtilities.isEventDispatchThread()).isFalse();
            started.countDown();
            awaitIgnoringInterrupt(release);
            return certificate("new");
        });
        try {
            clearPins();
            SwingUtilities.invokeAndWait(() -> controller.importPinnedCertificateAsync(destination, Path.of("new")));
            assertThat(started.await(2, TimeUnit.SECONDS)).isTrue();
            CountDownLatch edtFree = new CountDownLatch(1);
            SwingUtilities.invokeLater(edtFree::countDown);
            assertThat(edtFree.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(SecureCredentialStore.loadPinnedTlsCertificate(destination.configKey()).encodedBytes()).isEmpty();
            release.countDown();
            verify(ui, timeout(2000)).onDatabaseStatus("Pinned TLS certificate imported\nTrust: new\nSource: new");
            for (ConfigState.SearchDestination other : ConfigState.SearchDestination.values()) {
                assertThat(SecureCredentialStore.loadPinnedTlsCertificate(other.configKey()).fingerprintSha256())
                        .isEqualTo(other == destination ? "new" : "");
            }
        } finally {
            release.countDown();
            finish(controller, executor);
        }
    }

    @Test
    void newerImportWinsEvenWhenOlderIoIgnoresCancellation() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(3);
        ConfigController.Ui ui = mock(ConfigController.Ui.class);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ConfigController controller = controller(ui, executor, path -> {
            if (path.toString().equals("old")) {
                started.countDown();
                awaitIgnoringInterrupt(release);
            }
            return certificate(path.toString());
        });
        try {
            clearPins();
            controller.importPinnedCertificateAsync(ConfigState.SearchDestination.OPEN_SEARCH, Path.of("old"));
            assertThat(started.await(2, TimeUnit.SECONDS)).isTrue();
            controller.importPinnedCertificateAsync(ConfigState.SearchDestination.OPEN_SEARCH, Path.of("new"));
            verify(ui, timeout(2000)).onDatabaseStatus("Pinned TLS certificate imported\nTrust: new\nSource: new");
            release.countDown();
            executor.shutdown();
            assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
            SwingUtilities.invokeAndWait(() -> { });
            assertThat(SecureCredentialStore.loadPinnedTlsCertificate().fingerprintSha256()).isEqualTo("new");
            org.mockito.Mockito.verifyNoMoreInteractions(ui);
        } finally {
            release.countDown();
            finish(controller, executor);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void closeOrConfigReplacementFencesLateImport(boolean close) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ConfigController.Ui ui = mock(ConfigController.Ui.class);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ConfigController controller = controller(ui, executor, path -> {
            started.countDown();
            awaitIgnoringInterrupt(release);
            return certificate("stale");
        });
        try {
            clearPins();
            controller.importPinnedCertificateAsync(ConfigState.SearchDestination.OPEN_SEARCH, Path.of("stale"));
            assertThat(started.await(2, TimeUnit.SECONDS)).isTrue();
            if (close) {
                controller.close();
            } else {
                controller.cancelCertificateImports();
            }
            release.countDown();
            executor.shutdown();
            assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
            SwingUtilities.invokeAndWait(() -> { });
            assertThat(SecureCredentialStore.loadPinnedTlsCertificate().encodedBytes()).isEmpty();
            org.mockito.Mockito.verifyNoInteractions(ui);
        } finally {
            release.countDown();
            finish(controller, executor);
        }
    }

    @Test
    void failedImportPreservesPreviousPinAndReportsFailure() throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ConfigController.Ui ui = mock(ConfigController.Ui.class);
        ConfigController controller = controller(ui, executor, path -> { throw new java.io.IOException("unreadable"); });
        try {
            clearPins();
            SecureCredentialStore.savePinnedTlsCertificate("openSearch", "previous", "previous", new byte[]{1});
            controller.importPinnedCertificateAsync(ConfigState.SearchDestination.OPEN_SEARCH, Path.of("missing"));
            verify(ui, timeout(2000)).onDatabaseStatus("Pinned TLS certificate import failed\nDetails: unreadable");
            assertThat(SecureCredentialStore.loadPinnedTlsCertificate().fingerprintSha256()).isEqualTo("previous");
        } finally {
            finish(controller, executor);
        }
    }

    private static ConfigController controller(ConfigController.Ui ui, ExecutorService executor,
            ConfigController.CertificateImporter importer) {
        return new ConfigController(ui, executor, path -> null, (path, json, replacement) -> { },
                (destination, url) -> null, importer);
    }

    private static SecureCredentialStore.PinnedTlsCertificate certificate(String value) {
        return new SecureCredentialStore.PinnedTlsCertificate(value, value, new byte[]{1, 2, 3});
    }

    private static void awaitIgnoringInterrupt(CountDownLatch release) {
        boolean done = false;
        while (!done) {
            try {
                done = release.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                // A network-backed filesystem may finish after cancellation.
            }
        }
    }

    private static void clearPins() {
        for (ConfigState.SearchDestination destination : ConfigState.SearchDestination.values()) {
            SecureCredentialStore.clearPinnedTlsCertificate(destination.configKey());
        }
    }

    private static void finish(ConfigController controller, ExecutorService executor) throws Exception {
        controller.close();
        assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> { });
        clearPins();
    }
}
