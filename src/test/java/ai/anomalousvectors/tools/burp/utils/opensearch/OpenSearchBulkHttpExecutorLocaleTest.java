package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import ai.anomalousvectors.tools.burp.testutils.Reflect;

class OpenSearchBulkHttpExecutorLocaleTest {

    @Test
    @ResourceLock("default-locale")
    void timeoutClassification_isLocaleIndependent() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));

            Object result = Reflect.callStatic(
                    OpenSearchBulkHttpExecutor.class,
                    "leaseOrConnectTimeoutHint",
                    new IOException("CONNECTION REQUEST TIMEOUT"));

            assertThat(result).isEqualTo("connection-request/lease");
        } finally {
            Locale.setDefault(original);
        }
    }
}
