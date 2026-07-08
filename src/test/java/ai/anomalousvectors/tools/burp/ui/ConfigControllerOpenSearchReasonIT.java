package ai.anomalousvectors.tools.burp.ui;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;

class ConfigControllerOpenSearchReasonIT {

    private static final class TestUi implements ConfigController.Ui {
        final CountDownLatch done;
        volatile String osMsg;

        TestUi(CountDownLatch done) {
            this.done = done;
        }

        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onDatabaseStatus(String message) {
            this.osMsg = message;
            done.countDown();
        }
        @Override public void onControlStatus(String message) { /* not used */ }
    }

    @Test
    void testConnection_failure_containsReason_whenAvailable() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        TestUi ui = new TestUi(done);
        ConfigController cc = new ConfigController(ui);

        cc.testConnectionAsync("http://127.0.0.1:1");
        assertThat(done.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.osMsg).contains("Connection: Failed").containsAnyOf("Details:", "interrupted");
    }
}
