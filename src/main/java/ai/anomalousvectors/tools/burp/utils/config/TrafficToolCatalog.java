package ai.anomalousvectors.tools.burp.utils.config;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Canonical metadata for selectable Burp traffic tools.
 *
 * <p>This catalog contains only properties that are invariant across configuration, runtime
 * gating, statistics, and generic presentation. Route-specific buckets and source-specific
 * behavior remain with their owning exporters.</p>
 */
public final class TrafficToolCatalog {

    /** Statistics fallback for traffic whose selectable Burp tool cannot be identified. */
    public static final String UNKNOWN_STATISTICS_KEY = "UNKNOWN";

    /**
     * One selectable traffic tool in canonical Config-panel order.
     */
    public enum Tool {
        BURP_AI("burp_ai", "BURP_AI", "Burp AI", true, false, 1),
        EXTENSIONS("extensions", "EXTENSIONS", "Extensions", true, true, 1 << 1),
        INTRUDER("intruder", "INTRUDER", "Intruder", true, true, 1 << 2),
        PROXY("proxy", "PROXY", "Proxy", true, true, 1 << 3),
        PROXY_HISTORY("proxy_history", "PROXY_HISTORY", "Proxy History", true, true, 1 << 4),
        REPEATER("repeater", "REPEATER", "Repeater", true, true, 1 << 5),
        REPEATER_TABS("repeater_tabs", "REPEATER_TABS", "Repeater Tabs", false, true, 1 << 6),
        SCANNER("scanner", "SCANNER", "Scanner", true, false, 1 << 7),
        SEQUENCER("sequencer", "SEQUENCER", "Sequencer", true, true, 1 << 8);

        private final String configurationId;
        private final String statisticsKey;
        private final String displayLabel;
        private final boolean enabledByDefault;
        private final boolean availableInCommunity;
        private final int runtimeMask;

        Tool(
                String configurationId,
                String statisticsKey,
                String displayLabel,
                boolean enabledByDefault,
                boolean availableInCommunity,
                int runtimeMask) {
            this.configurationId = configurationId;
            this.statisticsKey = statisticsKey;
            this.displayLabel = displayLabel;
            this.enabledByDefault = enabledByDefault;
            this.availableInCommunity = availableInCommunity;
            this.runtimeMask = runtimeMask;
        }

        /** Returns the lowercase configuration identifier. */
        public String configurationId() {
            return configurationId;
        }

        /** Returns the uppercase statistics key. */
        public String statisticsKey() {
            return statisticsKey;
        }

        /** Returns the human-readable display label. */
        public String displayLabel() {
            return displayLabel;
        }

        /** Returns whether the tool is selected in a new Professional-edition configuration. */
        public boolean enabledByDefault() {
            return enabledByDefault;
        }

        /** Returns whether Community Edition exposes this traffic source. */
        public boolean availableInCommunity() {
            return availableInCommunity;
        }

        /** Returns this tool's single-bit runtime mask. */
        public int runtimeMask() {
            return runtimeMask;
        }
    }

    private static final List<Tool> TOOLS = List.copyOf(Arrays.asList(Tool.values()));
    private static final Map<String, Tool> BY_CONFIGURATION_ID = TOOLS.stream()
            .collect(Collectors.toUnmodifiableMap(tool -> tool.configurationId(), Function.identity()));
    private static final Map<String, Tool> BY_STATISTICS_KEY = TOOLS.stream()
            .collect(Collectors.toUnmodifiableMap(tool -> tool.statisticsKey(), Function.identity()));
    private static final List<String> CONFIGURATION_IDS = TOOLS.stream()
            .map(tool -> tool.configurationId())
            .toList();
    private static final List<String> DEFAULT_CONFIGURATION_IDS = TOOLS.stream()
            .filter(tool -> tool.enabledByDefault())
            .map(tool -> tool.configurationId())
            .toList();
    private static final List<String> STATISTICS_KEYS = TOOLS.stream()
            .map(tool -> tool.statisticsKey())
            .toList();
    private static final List<String> STATISTICS_KEYS_WITH_UNKNOWN = java.util.stream.Stream.concat(
            STATISTICS_KEYS.stream(),
            java.util.stream.Stream.of(UNKNOWN_STATISTICS_KEY))
            .toList();

    private TrafficToolCatalog() { }

    /** Returns all selectable tools in canonical order. */
    public static List<Tool> tools() {
        return TOOLS;
    }

    /** Returns all known configuration identifiers in canonical order. */
    public static List<String> configurationIds() {
        return CONFIGURATION_IDS;
    }

    /** Returns default-enabled configuration identifiers in canonical order. */
    public static List<String> defaultConfigurationIds() {
        return DEFAULT_CONFIGURATION_IDS;
    }

    /** Returns selectable statistics keys in canonical order. */
    public static List<String> statisticsKeys() {
        return STATISTICS_KEYS;
    }

    /** Returns selectable statistics keys followed by the non-selectable Unknown fallback. */
    public static List<String> statisticsKeysWithUnknown() {
        return STATISTICS_KEYS_WITH_UNKNOWN;
    }

    /** Returns the catalog entry for a configuration identifier, ignoring surrounding whitespace. */
    public static Optional<Tool> findByConfigurationId(String configurationId) {
        return Optional.ofNullable(toolByConfigurationId(configurationId));
    }

    /** Returns the catalog entry for an exact statistics key. */
    public static Optional<Tool> findByStatisticsKey(String statisticsKey) {
        if (statisticsKey == null || statisticsKey.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(BY_STATISTICS_KEY.get(statisticsKey.trim()));
    }

    /** Returns whether the value is a known traffic-tool configuration identifier. */
    public static boolean isKnownConfigurationId(String configurationId) {
        return toolByConfigurationId(configurationId) != null;
    }

    /** Returns whether a known configuration identifier is available in the requested edition. */
    public static boolean isAvailableInEdition(String configurationId, boolean communityEdition) {
        Tool tool = toolByConfigurationId(configurationId);
        return tool != null && (!communityEdition || tool.availableInCommunity());
    }

    /** Returns default-enabled configuration identifiers available in the requested edition. */
    public static List<String> defaultConfigurationIdsForEdition(boolean communityEdition) {
        return TOOLS.stream()
                .filter(tool -> tool.enabledByDefault())
                .filter(tool -> !communityEdition || tool.availableInCommunity())
                .map(tool -> tool.configurationId())
                .toList();
    }

    /** Returns the runtime bit for a known configuration identifier, or zero when unknown. */
    public static int runtimeMask(String configurationId) {
        Tool tool = toolByConfigurationId(configurationId);
        return tool == null ? 0 : tool.runtimeMask();
    }

    private static Tool toolByConfigurationId(String configurationId) {
        if (configurationId == null || configurationId.isBlank()) {
            return null;
        }
        return BY_CONFIGURATION_ID.get(configurationId.trim().toLowerCase(Locale.ROOT));
    }
}
