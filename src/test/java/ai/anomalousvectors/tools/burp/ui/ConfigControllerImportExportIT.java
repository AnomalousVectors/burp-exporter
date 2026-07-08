package ai.anomalousvectors.tools.burp.ui;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;
import ai.anomalousvectors.tools.burp.ui.controller.ConfigController;
import ai.anomalousvectors.tools.burp.utils.DiskSpaceGuard;
import ai.anomalousvectors.tools.burp.utils.config.ConfigJsonMapper;
import ai.anomalousvectors.tools.burp.utils.config.ConfigKeys;
import ai.anomalousvectors.tools.burp.utils.config.ConfigState;

class ConfigControllerImportExportIT {

    private static final class TestUi implements ConfigController.Ui {
        volatile String control;
        private CountDownLatch exportDone;
        private CountDownLatch importDone;

        void setExportLatch(CountDownLatch latch) {
            this.exportDone = latch;
        }

        void setImportLatch(CountDownLatch latch) {
            this.importDone = latch;
        }

        @Override public void onFileStatus(String message) { /* not used */ }
        @Override public void onDatabaseStatus(String message) { /* not used */ }
        @Override public void onControlStatus(String message) {
            this.control = message;
            if (message == null) {
                return;
            }

            CountDownLatch exp = exportDone;
            if (exp != null && message.startsWith("Export")) {
                exp.countDown();
            }

            CountDownLatch imp = importDone;
            if (imp != null && (message.startsWith("Imported")
                    || message.startsWith("Import failed")
                    || message.contains("not recognized"))) {
                imp.countDown();
            }
        }
    }

    @Test
    void export_then_import_roundtrip_emitsStatus() throws Exception {
        // Build a small state
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);

        String json = ConfigJsonMapper.build(state);
        Path tmp = TestPathSupport.createFile("cc-export", ".json");

        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);

        CountDownLatch exportDone = new CountDownLatch(1);
        ui.setExportLatch(exportDone);

        cc.exportConfigAsync(tmp, json);
        assertThat(exportDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.control).contains("Exported");

        CountDownLatch importDone = new CountDownLatch(1);
        ui.control = null;
        ui.setImportLatch(importDone);

        cc.importConfigAsync(tmp);
        assertThat(importDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.control).contains("Imported");
    }

    @Test
    void import_flat_sinks_shape_reportsGuidedStatus() throws Exception {
        String invalid = """
            {
              "version": "1.0",
              "sinks": {
                "filesEnabled": true,
                "files": "C:/exports"
              }
            }
            """;
        Path tmp = TestPathSupport.createFile("cc-import-invalid-sinks", ".json");
        Files.writeString(tmp, invalid);

        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);
        CountDownLatch importDone = new CountDownLatch(1);
        ui.setImportLatch(importDone);

        cc.importConfigAsync(tmp);
        assertThat(importDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.control).contains("Import failed:");
        assertThat(ui.control).contains("sinks.database");
        assertThat(ui.control).contains("sinks.database.openSearch.url");
    }

    @Test
    void import_nested_sink_typo_reportsGuidedStatus() throws Exception {
        String invalid = """
            {
              "version": "1.0",
              "sinks": {
                "files": {
                  "enabled": true,
                  "limit": {
                    "totalEnabled": true
                  }
                }
              }
            }
            """;
        Path tmp = TestPathSupport.createFile("cc-import-invalid-sink-typo", ".json");
        Files.writeString(tmp, invalid);

        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);
        CountDownLatch importDone = new CountDownLatch(1);
        ui.setImportLatch(importDone);

        cc.importConfigAsync(tmp);
        assertThat(importDone.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(ui.control).contains("Imported configuration from:");
        assertThat(ui.control).contains("not recognized and were skipped");
        assertThat(ui.control).contains("sinks.files.limit");
        assertThat(ui.control).contains("All other settings were applied");
    }

    @Test
    void export_whenDiskIsLow_reportsFriendlyStatus() throws Exception {
        ConfigState.State state = new ConfigState.State(
                List.of(ConfigKeys.SRC_SETTINGS),
                ConfigKeys.SCOPE_ALL,
                List.of(),
                new ConfigState.Sinks(false, null, false, null, null, null, false),
                ConfigState.DEFAULT_SETTINGS_SUB, ConfigState.DEFAULT_TRAFFIC_TOOL_TYPES, ConfigState.DEFAULT_FINDINGS_SEVERITIES,
                null);
        String json = ConfigJsonMapper.build(state);
        Path tmp = TestPathSupport.createFile("cc-export-low-disk", ".json");

        TestUi ui = new TestUi();
        ConfigController cc = new ConfigController(ui);
        CountDownLatch exportDone = new CountDownLatch(1);
        ui.setExportLatch(exportDone);

        try {
            DiskSpaceGuard.resetForTests();
            DiskSpaceGuard.setUsableSpaceOverride(path -> DiskSpaceGuard.MIN_FREE_BYTES - 1);

            cc.exportConfigAsync(tmp, json);
            assertThat(exportDone.await(3, TimeUnit.SECONDS)).isTrue();
            assertThat(ui.control).isEqualTo("Export failed: Write cancelled due to low disk space");
        } finally {
            DiskSpaceGuard.resetForTests();
        }
    }
}
