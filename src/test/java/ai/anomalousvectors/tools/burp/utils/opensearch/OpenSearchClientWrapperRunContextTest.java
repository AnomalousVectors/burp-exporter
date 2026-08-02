package ai.anomalousvectors.tools.burp.utils.opensearch;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.export.BulkPushOutcome;
import ai.anomalousvectors.tools.burp.utils.export.ExportDocumentIdentity;
import ai.anomalousvectors.tools.burp.utils.export.PreparedExportDocument;

class OpenSearchClientWrapperRunContextTest {

    @Test
    void pushPreparedBulk_rejectsScopedStaleTokenInsteadOfCapturingNextRun() {
        RuntimeConfig.resetExportRunForTests();
        try {
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.ExportRunToken stale = RuntimeConfig.currentExportRunToken();
            RuntimeConfig.setExportRunning(false);
            RuntimeConfig.setExportRunning(true);
            RuntimeConfig.ExportRunToken current = RuntimeConfig.currentExportRunToken();
            PreparedExportDocument document = ExportDocumentIdentity.prepare(
                    "tool-burp-traffic", "traffic", Map.of("marker", "stale"));

            BulkPushOutcome outcome = ExportRunContext.call(
                    stale,
                    () -> OpenSearchClientWrapper.pushPreparedBulk(
                            "https://must-not-be-contacted.invalid",
                            "tool-burp-traffic",
                            "traffic",
                            List.of(document)));

            assertThat(current).isNotEqualTo(stale);
            assertThat(RuntimeConfig.isExportRunActive(current)).isTrue();
            assertThat(outcome.attempted()).isZero();
            assertThat(outcome.exportedCount()).isZero();
        } finally {
            RuntimeConfig.resetExportRunForTests();
        }
    }
}
