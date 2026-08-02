package ai.anomalousvectors.tools.burp.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExportShutdownStatusTest {

    @Test
    void initialStoppingMessage_noBacklog_mentionsBatchOnly() {
        ExportShutdownStatus.Snapshot snapshot = new ExportShutdownStatus.Snapshot(0, 0, 0, 500);

        assertThat(ExportShutdownStatus.initialStoppingMessage(snapshot))
                .isEqualTo("Stopping: waiting for in-flight traffic batch …");
    }

    @Test
    void initialStoppingMessage_withTrafficAndRetries_mentionsBoth() {
        ExportShutdownStatus.Snapshot snapshot = new ExportShutdownStatus.Snapshot(10, 5, 3, 500);

        assertThat(ExportShutdownStatus.initialStoppingMessage(snapshot))
                .isEqualTo("Stopping: waiting for in-flight traffic batch, then clearing 15 traffic docs and draining 3 retries …");
    }

    @Test
    void initialStoppingMessage_retriesOnly_mentionsDrain() {
        ExportShutdownStatus.Snapshot snapshot = new ExportShutdownStatus.Snapshot(0, 0, 7, 500);

        assertThat(ExportShutdownStatus.initialStoppingMessage(snapshot))
                .isEqualTo("Stopping: waiting for in-flight traffic batch, then draining 7 retries …");
    }

    @Test
    void clearingQueuedTrafficMessage_usesTrafficBacklogOnly() {
        ExportShutdownStatus.Snapshot snapshot = new ExportShutdownStatus.Snapshot(1, 0, 9, 100);

        assertThat(ExportShutdownStatus.clearingQueuedTrafficMessage(snapshot))
                .isEqualTo("Stopping: clearing 1 queued traffic docs …");
    }

    @Test
    void drainingRetriesMessage_includesCount() {
        assertThat(ExportShutdownStatus.drainingRetriesMessage(12))
                .isEqualTo("Stopping: draining 12 retry docs …");
        assertThat(ExportShutdownStatus.drainingRetriesMessage(0))
                .isEqualTo("Stopping: checking retry queue …");
    }

    @Test
    void waitingForInFlightRetryMessage_isStable() {
        assertThat(ExportShutdownStatus.waitingForInFlightRetryMessage())
                .isEqualTo("Stopping: waiting for in-flight retry push …");
    }

    @Test
    void validatingFileArtifactsMessage_namesFinalIntegrityCheck() {
        assertThat(ExportShutdownStatus.validatingFileArtifactsMessage())
                .isEqualTo("Stopping: validating file artifacts …");
    }

    @Test
    void stoppedMessage_isShortFinalLine() {
        assertThat(ExportShutdownStatus.stoppedMessage()).isEqualTo("Stopped");
    }
}
