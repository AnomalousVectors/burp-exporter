package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.sinks.ExportReporterLifecycle;
import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;

/** Tests low-disk refusal and forced-stop control synchronization. */
class DiskSpaceGuardTest {

    @Test
    void ensureWritable_filesOnlyRunForcesStopAndNotifiesControls() throws Exception {
        Path root = TestPathSupport.createDirectory("low-disk-forced-stop");
        AtomicReference<String> status = new AtomicReference<>();
        AtomicInteger forcedStops = new AtomicInteger();
        try {
            RuntimeConfig.updateState(new ConfigState.State(
                    List.of(ConfigKeys.SRC_TRAFFIC),
                    ConfigKeys.SCOPE_ALL,
                    List.of(),
                    new ConfigState.Sinks(
                            true, root.toString(), true, false, false, "", "", "", false),
                    ConfigState.DEFAULT_SETTINGS_SUB,
                    List.of("proxy"),
                    ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                    null));
            RuntimeConfig.setExportRunning(true);
            ControlStatusBridge.register(status::set);
            ExportControlBridge.registerForcedStopped(forcedStops::incrementAndGet);
            DiskSpaceGuard.setUsableSpaceOverride(
                    ignored -> DiskSpaceGuard.MIN_FREE_BYTES - 1L);

            assertThatThrownBy(() ->
                    DiskSpaceGuard.ensureWritable(root.resolve("tool-burp-traffic.ndjson"), 1L, "test"))
                    .isInstanceOf(DiskSpaceGuard.LowDiskSpaceException.class)
                    .hasMessageContaining("Low disk space");

            assertThat(RuntimeConfig.isExportRunning()).isFalse();
            assertThat(status.get()).isEqualTo("Stopped due to low disk space");
            assertThat(forcedStops).hasValue(1);
        } finally {
            DiskSpaceGuard.resetForTests();
            ControlStatusBridge.clear();
            ExportControlBridge.clear();
            ExportReporterLifecycle.resetForTests();
        }
    }
}
