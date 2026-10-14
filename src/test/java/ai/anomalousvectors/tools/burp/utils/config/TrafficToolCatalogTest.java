package ai.anomalousvectors.tools.burp.utils.config;

import java.util.HashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;

class TrafficToolCatalogTest {

    @Test
    void catalogPreservesCanonicalConfigurationAndStatisticsOrder() {
        assertThat(TrafficToolCatalog.configurationIds()).containsExactly(
                "burp_ai",
                "extensions",
                "intruder",
                "proxy",
                "proxy_history",
                "repeater",
                "repeater_tabs",
                "scanner",
                "sequencer");
        assertThat(TrafficToolCatalog.statisticsKeys()).containsExactly(
                "BURP_AI",
                "EXTENSIONS",
                "INTRUDER",
                "PROXY",
                "PROXY_HISTORY",
                "REPEATER",
                "REPEATER_TABS",
                "SCANNER",
                "SEQUENCER");
        assertThat(ConfigState.ALL_TRAFFIC_TOOL_TYPES)
                .containsExactlyElementsOf(TrafficToolCatalog.configurationIds());
        assertThat(ExportStats.getTrafficToolTypeKeys())
                .containsExactlyElementsOf(TrafficToolCatalog.statisticsKeysWithUnknown());
        assertThat(FileExportStats.getTrafficToolTypeKeys())
                .containsExactlyElementsOf(TrafficToolCatalog.statisticsKeysWithUnknown());
    }

    @Test
    void defaultsAndEditionAvailabilityPreserveExistingSelectionContract() {
        assertThat(TrafficToolCatalog.defaultConfigurationIds())
                .containsExactly(
                        "burp_ai",
                        "extensions",
                        "intruder",
                        "proxy",
                        "proxy_history",
                        "repeater",
                        "scanner",
                        "sequencer");
        assertThat(TrafficToolCatalog.defaultConfigurationIdsForEdition(true))
                .containsExactly(
                        "extensions",
                        "intruder",
                        "proxy",
                        "proxy_history",
                        "repeater",
                        "sequencer");
        assertThat(TrafficToolCatalog.isAvailableInEdition("burp_ai", true)).isFalse();
        assertThat(TrafficToolCatalog.isAvailableInEdition("scanner", true)).isFalse();
        assertThat(TrafficToolCatalog.isAvailableInEdition("repeater_tabs", true)).isTrue();
        assertThat(TrafficToolCatalog.isAvailableInEdition("scanner", false)).isTrue();
    }

    @Test
    void runtimeMasksRemainUniqueSingleBitsAndRejectUnknownValues() {
        List<Integer> masks = TrafficToolCatalog.tools().stream()
                .map(tool -> tool.runtimeMask())
                .toList();

        assertThat(new HashSet<>(masks)).hasSize(TrafficToolCatalog.tools().size());
        assertThat(masks).allMatch(mask -> mask > 0 && Integer.bitCount(mask) == 1);
        assertThat(masks.stream().reduce(0, (left, right) -> left | right)).isEqualTo(0x1FF);
        assertThat(TrafficToolCatalog.runtimeMask("unknown")).isZero();
        assertThat(TrafficToolCatalog.runtimeMask(null)).isZero();
    }

    @Test
    void displayLabelsRemainExactForSpecialAndMultiwordTools() {
        assertThat(TrafficToolCatalog.Tool.BURP_AI.displayLabel()).isEqualTo("Burp AI");
        assertThat(TrafficToolCatalog.Tool.PROXY_HISTORY.displayLabel()).isEqualTo("Proxy History");
        assertThat(TrafficToolCatalog.Tool.REPEATER_TABS.displayLabel()).isEqualTo("Repeater Tabs");
    }

    @Test
    void findingsCapabilityRuleIsIndependentFromTrafficToolAvailability() {
        assertThat(DataSourceCapabilityPolicy.isAvailableInEdition(ConfigKeys.SRC_FINDINGS, true)).isFalse();
        assertThat(DataSourceCapabilityPolicy.isAvailableInEdition(ConfigKeys.SRC_FINDINGS, false)).isTrue();
        assertThat(DataSourceCapabilityPolicy.isAvailableInEdition(ConfigKeys.SRC_TRAFFIC, true)).isTrue();
    }
}
