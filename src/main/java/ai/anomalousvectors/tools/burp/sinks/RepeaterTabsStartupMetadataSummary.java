package ai.anomalousvectors.tools.burp.sinks;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Aggregates startup Repeater-tab observation diagnostics for user-visible summaries.
 *
 * <p>The unsupported startup walk is intentionally trace-heavy because Montoya does not expose a
 * first-class Repeater tabs API. This summary keeps the high-signal counters compact for info
 * and debug logs while per-tab detail remains available at trace level.</p>
 */
final class RepeaterTabsStartupMetadataSummary {
    private static final int DUPLICATE_SLOT_HIGHLIGHT_LIMIT = 5;

    private final Map<String, Integer> observationsByCapturePath = new LinkedHashMap<>();
    private final Map<String, Integer> observationsByGroupName = new LinkedHashMap<>();
    private final Map<String, Integer> ignoredAnonymousBindingsByCapturePath = new LinkedHashMap<>();
    private final Map<String, Integer> duplicateSlotSuppressionsByCapturePath = new LinkedHashMap<>();
    private final Map<String, Integer> duplicateSlotSuppressionsBySlotPath = new LinkedHashMap<>();
    private final Map<String, Integer> metadataUpgradesByCapturePath = new LinkedHashMap<>();
    private final Set<String> uniqueLogicalSlots = new java.util.LinkedHashSet<>();
    private final Set<String> uniqueLogicalTabGroupPairs = new java.util.LinkedHashSet<>();
    private int totalObservations;
    private int logicalSlotObservations;
    private int groupedLogicalSlotObservations;
    private int ignoredAnonymousBindings;
    private int duplicateSlotSuppressions;
    private int metadataUpgrades;

    synchronized void clear() {
        observationsByCapturePath.clear();
        observationsByGroupName.clear();
        ignoredAnonymousBindingsByCapturePath.clear();
        duplicateSlotSuppressionsByCapturePath.clear();
        duplicateSlotSuppressionsBySlotPath.clear();
        metadataUpgradesByCapturePath.clear();
        uniqueLogicalSlots.clear();
        uniqueLogicalTabGroupPairs.clear();
        totalObservations = 0;
        logicalSlotObservations = 0;
        groupedLogicalSlotObservations = 0;
        ignoredAnonymousBindings = 0;
        duplicateSlotSuppressions = 0;
        metadataUpgrades = 0;
    }

    synchronized void recordObservation(
            String capturePath,
        RepeaterTabsIndexReporter.RepeaterTabMetadata metadata) {
        totalObservations++;
        increment(observationsByCapturePath, capturePath);
        String logicalSlotKey = RepeaterTabsCapturePolicy.startupSlotKey(metadata);
        if (logicalSlotKey == null) {
            return;
        }
        logicalSlotObservations++;
        if (metadata.groupName() != null) {
            groupedLogicalSlotObservations++;
            increment(observationsByGroupName, metadata.groupName());
        }
        uniqueLogicalSlots.add(RepeaterTabsCapturePolicy.safeLogValue(logicalSlotKey));
        String tabGroupKey = RepeaterTabsCapturePolicy.safeLogValue(metadata.tabName())
                + "|"
                + RepeaterTabsCapturePolicy.safeLogValue(metadata.groupName());
        uniqueLogicalTabGroupPairs.add(tabGroupKey);
    }

    synchronized void recordIgnoredAnonymousBinding(String capturePath) {
        ignoredAnonymousBindings++;
        increment(ignoredAnonymousBindingsByCapturePath, capturePath);
    }

    synchronized void recordDuplicateSlotSuppression(String capturePath, String startupSlotKey) {
        duplicateSlotSuppressions++;
        increment(duplicateSlotSuppressionsByCapturePath, capturePath);
        incrementDuplicateSlotBySlotPath(startupSlotKey, capturePath);
    }

    synchronized void recordMetadataUpgrade(String capturePath) {
        metadataUpgrades++;
        increment(metadataUpgradesByCapturePath, capturePath);
    }

    synchronized String describe() {
        if (totalObservations <= 0
                && ignoredAnonymousBindings <= 0
                && duplicateSlotSuppressions <= 0
                && metadataUpgrades <= 0) {
            return "none";
        }
        return "observations=" + totalObservations
                + ", logicalSlotObservations=" + logicalSlotObservations
                + ", groupedLogicalSlotObservations=" + groupedLogicalSlotObservations
                + ", standaloneLogicalSlotObservations="
                + (logicalSlotObservations - groupedLogicalSlotObservations)
                + ", uniqueLogicalSlots=" + uniqueLogicalSlots.size()
                + ", uniqueLogicalTabGroupPairs=" + uniqueLogicalTabGroupPairs.size()
                + ", groups=[" + describeCounts(observationsByGroupName) + "]"
                + ", noIdentityObservationsSkipped=" + ignoredAnonymousBindings
                + ", alreadyCapturedSlotObservations=" + duplicateSlotSuppressions
                + ", metadataUpgrades=" + metadataUpgrades
                + ", capturePaths=[" + describeCounts(observationsByCapturePath) + "]"
                + ", noIdentityPaths=[" + describeCounts(ignoredAnonymousBindingsByCapturePath) + "]"
                + ", alreadyCapturedSlotPaths=[" + describeCounts(duplicateSlotSuppressionsByCapturePath) + "]"
                + ", alreadyCapturedSlotHighlights=[" + describeTopDuplicateSlotCounts() + "]"
                + ", upgradedPaths=[" + describeCounts(metadataUpgradesByCapturePath) + "]";
    }

    private static void increment(Map<String, Integer> counts, String capturePath) {
        String normalizedCapturePath =
                RepeaterTabsCapturePolicy.safeLogValue(normalizeBlank(capturePath));
        Integer currentCount = counts.get(normalizedCapturePath);
        counts.put(normalizedCapturePath, currentCount == null ? 1 : currentCount + 1);
    }

    private static String describeCounts(Map<String, Integer> counts) {
        if (counts.isEmpty()) {
            return "none";
        }
        StringBuilder summary = new StringBuilder();
        java.util.List<String> capturePaths = new ArrayList<>(counts.keySet());
        Collections.sort(capturePaths);
        for (String capturePath : capturePaths) {
            if (summary.length() > 0) {
                summary.append(", ");
            }
            summary.append(capturePath)
                    .append("=")
                    .append(counts.getOrDefault(capturePath, 0));
        }
        return summary.toString();
    }

    private void incrementDuplicateSlotBySlotPath(String startupSlotKey, String capturePath) {
        String slotPathKey = RepeaterTabsCapturePolicy.safeLogValue(normalizeBlank(startupSlotKey))
                + "|"
                + RepeaterTabsCapturePolicy.safeLogValue(normalizeBlank(capturePath));
        Integer currentCount = duplicateSlotSuppressionsBySlotPath.get(slotPathKey);
        duplicateSlotSuppressionsBySlotPath.put(slotPathKey, currentCount == null ? 1 : currentCount + 1);
    }

    private String describeTopDuplicateSlotCounts() {
        if (duplicateSlotSuppressionsBySlotPath.isEmpty()) {
            return "none";
        }
        java.util.List<Map.Entry<String, Integer>> entries =
                new ArrayList<>(duplicateSlotSuppressionsBySlotPath.entrySet());
        entries.sort((left, right) -> {
            int countComparison = Integer.compare(right.getValue(), left.getValue());
            if (countComparison != 0) {
                return countComparison;
            }
            return left.getKey().compareTo(right.getKey());
        });
        StringBuilder summary = new StringBuilder();
        int limit = Math.min(DUPLICATE_SLOT_HIGHLIGHT_LIMIT, entries.size());
        for (int i = 0; i < limit; i++) {
            Map.Entry<String, Integer> entry = entries.get(i);
            if (summary.length() > 0) {
                summary.append(", ");
            }
            summary.append(entry.getKey())
                    .append("=")
                    .append(entry.getValue());
        }
        return summary.toString();
    }

    private static String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
