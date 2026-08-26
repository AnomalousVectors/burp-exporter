package ai.anomalousvectors.tools.burp.sinks;

import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.accessibility.AccessibleContext;
import javax.swing.AbstractButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

/**
 * Collects selected Repeater tab snapshots and infers tab/group metadata from them.
 *
 * <p>This helper isolates Burp-specific Repeater header heuristics from
 * {@link RepeaterTabsIndexReporter} so startup-walk orchestration and editor capture do not also
 * need to carry the detailed label parsing rules. Caller must invoke Swing traversal methods on
 * the EDT because they inspect live tab selection state.</p>
 */
final class RepeaterTabMetadataHeuristics {

    /**
     * Lowercase titles for Burp message-view {@link JTabbedPane}s: request/response views (Raw,
     * Pretty, Hex, …) and the Repeater right rail (Inspector, Notes, Explanations, Custom actions).
     * When every titled tab in a pane matches this set, the pane is not cycled during startup tab
     * walks and its labels are not used as {@code burp.repeater.tab_name}.
     */
    private static final Set<String> MESSAGE_VIEW_TAB_TITLES = Set.of(
            "beautify",
            "burp ai",
            "custom actions",
            "explanations",
            "headers",
            "hex",
            "inspector",
            "notes",
            "params",
            "pretty",
            "raw",
            "render");

    private RepeaterTabMetadataHeuristics() { }

    /**
     * Returns the currently selected tab snapshots beneath {@code root}.
     *
     * <p>Caller must invoke on the EDT. Auxiliary view tabs such as Raw/Pretty are skipped when
     * choosing panes to cycle, but their selected children are still traversed so the containing
     * Repeater path remains intact.</p>
     */
    static List<SelectedTabSnapshot> collectSelectedTabSnapshots(Component root) {
        List<SelectedTabSnapshot> selectedTabs = new ArrayList<>();
        if (root == null) {
            return selectedTabs;
        }
        if (root instanceof JTabbedPane pane) {
            if (shouldCycleTabPane(pane)) {
                selectedTabs.add(selectedTabSnapshot(pane, pane.getSelectedIndex()));
            }
            Component selected = pane.getSelectedComponent();
            if (selected != null) {
                selectedTabs.addAll(collectSelectedTabSnapshots(selected));
            }
            return selectedTabs;
        }
        if (!(root instanceof Container container)) {
            return selectedTabs;
        }
        for (Component child : container.getComponents()) {
            selectedTabs.addAll(collectSelectedTabSnapshots(child));
        }
        return selectedTabs;
    }

    /**
     * Returns selected tab snapshots for the parent tab path that contains {@code uiAnchor}.
     *
     * <p>Caller must invoke on the EDT. The returned list is ordered outermost-to-innermost so the
     * inference logic can reason about both the visible tab and any nested auxiliary tab panes.</p>
     */
    static List<SelectedTabSnapshot> collectSelectedTabSnapshotsFromAnchor(Component uiAnchor) {
        if (uiAnchor == null) {
            return List.of();
        }
        List<SelectedTabSnapshot> selectedTabs = new ArrayList<>();
        IdentityHashMap<JTabbedPane, Boolean> seen = new IdentityHashMap<>();
        for (Component current = uiAnchor; current != null; current = current.getParent()) {
            if (!(current instanceof JTabbedPane pane) || seen.put(pane, Boolean.TRUE) != null) {
                continue;
            }
            int index = indexContainingDescendant(pane, uiAnchor);
            if (index >= 0 && shouldCycleTabPane(pane)) {
                selectedTabs.add(selectedTabSnapshot(pane, index));
            }
        }
        if (selectedTabs.isEmpty()) {
            return List.of();
        }
        Collections.reverse(selectedTabs);
        return selectedTabs;
    }

    /**
     * Infers the best-effort tab and group names from the supplied snapshot path.
     */
    static InferenceResult infer(List<SelectedTabSnapshot> selectedTabs) {
        if (selectedTabs == null || selectedTabs.isEmpty()) {
            return new InferenceResult(null, null);
        }
        SelectedTabSnapshot outerSnapshot = selectedTabs.getFirst();
        String tabName = preferredRepeaterTabName(selectedTabs);
        String groupName = shouldInspectPaneLevelGroupCandidates(outerSnapshot, tabName)
                ? nearestPaneGroupNameCandidate(outerSnapshot, tabName)
                : null;
        if (groupName == null) {
            groupName = bestGroupNameCandidate(outerSnapshot.candidateLabels(), tabName);
        }
        if (groupName == null && selectedTabs.size() >= 2) {
            groupName = distinctFrom(tabName, outerSnapshot.primaryLabel());
        }
        return new InferenceResult(tabName, groupName);
    }

    /**
     * Appends one selected-tab snapshot to an existing outer-to-inner path.
     */
    static List<SelectedTabSnapshot> appendSelectedPath(
            List<SelectedTabSnapshot> selectedPath,
            SelectedTabSnapshot snapshot) {
        List<SelectedTabSnapshot> nextPath =
                new ArrayList<>(selectedPath == null ? List.of() : selectedPath);
        if (snapshot != null) {
            nextPath.add(snapshot);
        }
        return nextPath;
    }

    /**
     * Returns a stable slot identity for startup capture, excluding auxiliary message-view tabs.
     */
    static String buildSlotIdentityKey(List<SelectedTabSnapshot> selectedTabs) {
        if (selectedTabs == null || selectedTabs.isEmpty()) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        boolean added = false;
        for (SelectedTabSnapshot snapshot : selectedTabs) {
            if (snapshot == null || snapshot.selectedIndex() < 0) {
                return null;
            }
            if (isAuxiliaryRepeaterTabLabel(snapshot.primaryLabel())) {
                continue;
            }
            if (out.length() > 0) {
                out.append(">");
            }
            out.append(safeLogValue(snapshot.paneClass())).append("#").append(snapshot.selectedIndex());
            added = true;
        }
        return added ? out.toString() : null;
    }

    /**
     * Returns whether the pane should be treated as a selectable Repeater tab container.
     */
    static boolean shouldCycleTabPane(JTabbedPane pane) {
        return pane != null && pane.getTabCount() > 1 && !isMessageViewTabPane(pane);
    }

    /**
     * Returns whether the label refers to an auxiliary message view (request/response or Repeater
     * right rail), not a Repeater request tab name.
     */
    static boolean isAuxiliaryRepeaterTabLabel(String value) {
        String normalized = normalizeBlank(value);
        return normalized != null && MESSAGE_VIEW_TAB_TITLES.contains(normalized.toLowerCase(Locale.ROOT));
    }

    /**
     * Captures the best-effort label snapshot for one tab index in a pane.
     *
     * <p>Caller must invoke on the EDT.</p>
     */
    static SelectedTabSnapshot selectedTabSnapshot(JTabbedPane pane, int index) {
        return new SelectedTabSnapshot(
                primaryTabLabelFor(pane, index),
                tabLabelCandidatesFor(pane, index),
                paneLabelCandidatesFor(pane),
                paneTabSnapshotsFor(pane),
                panePrimaryLabelsFor(pane),
                pane == null ? null : pane.getClass().getName(),
                index,
                pane == null ? 0 : pane.getTabCount());
    }

    private static String preferredRepeaterTabName(List<SelectedTabSnapshot> selectedTabs) {
        SelectedTabSnapshot outerSnapshot = selectedTabs.getFirst();
        String outerPrimary = outerSnapshot.primaryLabel();
        String outerGroupCandidate = bestGroupNameCandidate(outerSnapshot.candidateLabels(), outerPrimary);
        if (outerPrimary != null && outerGroupCandidate != null) {
            return outerPrimary;
        }
        String singleSnapshotCandidate = singleSnapshotTabNameCandidate(outerSnapshot);
        if (singleSnapshotCandidate != null) {
            return singleSnapshotCandidate;
        }
        for (int i = selectedTabs.size() - 1; i >= 0; i--) {
            String candidate = selectedTabs.get(i).primaryLabel();
            if (!isAuxiliaryRepeaterTabLabel(candidate)) {
                return candidate;
            }
        }
        return outerPrimary;
    }

    /**
     * Handles Burp tab components that expose only one readable label for a standalone tab.
     *
     * <p>In some live/startup editor-bind paths Burp does not provide a normal primary tab title,
     * but the selected tab still exposes a single readable candidate label. When the pane only has
     * one tab, that lone label is more likely the tab name than a group header.</p>
     */
    private static String singleSnapshotTabNameCandidate(SelectedTabSnapshot snapshot) {
        if (snapshot == null
                || snapshot.primaryLabel() != null
                || snapshot.tabCount() != 1
                || snapshot.candidateLabels().isEmpty()) {
            return null;
        }
        String tabName = null;
        for (String candidate : snapshot.candidateLabels()) {
            String normalized = normalizeBlank(candidate);
            if (normalized == null
                    || isUiChromeLabel(normalized)
                    || isAuxiliaryRepeaterTabLabel(normalized)) {
                continue;
            }
            if (tabName != null && !sameNormalized(tabName, normalized)) {
                return null;
            }
            tabName = normalized;
        }
        return tabName;
    }

    private static int indexContainingDescendant(JTabbedPane pane, Component descendant) {
        if (pane == null || descendant == null) {
            return -1;
        }
        for (int i = 0; i < pane.getTabCount(); i++) {
            Component tabComponent = pane.getComponentAt(i);
            if (tabComponent == descendant || SwingUtilities.isDescendingFrom(descendant, tabComponent)) {
                return i;
            }
        }
        return -1;
    }

    private static String primaryTabLabelFor(JTabbedPane pane, int index) {
        if (pane == null || index < 0 || index >= pane.getTabCount()) {
            return null;
        }
        String title = normalizeBlank(pane.getTitleAt(index));
        if (title != null) {
            return title;
        }
        String tooltip = normalizeBlank(pane.getToolTipTextAt(index));
        if (tooltip != null) {
            return tooltip;
        }
        String customTabText = componentDisplayText(pane.getTabComponentAt(index));
        if (customTabText != null) {
            return customTabText;
        }
        return componentDisplayText(pane.getComponentAt(index));
    }

    private static List<String> tabLabelCandidatesFor(JTabbedPane pane, int index) {
        if (pane == null || index < 0 || index >= pane.getTabCount()) {
            return List.of();
        }
        List<String> candidates = new ArrayList<>();
        addIfNonBlank(candidates, pane.getTitleAt(index));
        addIfNonBlank(candidates, pane.getToolTipTextAt(index));
        collectComponentTexts(pane.getTabComponentAt(index), candidates);
        return candidates;
    }

    private static List<String> paneLabelCandidatesFor(JTabbedPane pane) {
        if (pane == null || pane.getTabCount() <= 0) {
            return List.of();
        }
        List<String> candidates = new ArrayList<>();
        for (int i = 0; i < pane.getTabCount(); i++) {
            addIfNonBlank(candidates, pane.getTitleAt(i));
            addIfNonBlank(candidates, pane.getToolTipTextAt(i));
            collectComponentTexts(pane.getTabComponentAt(i), candidates);
        }
        return candidates;
    }

    private static List<String> panePrimaryLabelsFor(JTabbedPane pane) {
        if (pane == null || pane.getTabCount() <= 0) {
            return List.of();
        }
        List<String> labels = new ArrayList<>(pane.getTabCount());
        for (int i = 0; i < pane.getTabCount(); i++) {
            labels.add(normalizeBlank(primaryTabLabelFor(pane, i)));
        }
        return Collections.unmodifiableList(labels);
    }

    private static List<PaneTabSnapshot> paneTabSnapshotsFor(JTabbedPane pane) {
        if (pane == null || pane.getTabCount() <= 0) {
            return List.of();
        }
        List<PaneTabSnapshot> paneTabs = new ArrayList<>(pane.getTabCount());
        for (int i = 0; i < pane.getTabCount(); i++) {
            paneTabs.add(new PaneTabSnapshot(
                    primaryTabLabelFor(pane, i),
                    tabLabelCandidatesFor(pane, i)));
        }
        return List.copyOf(paneTabs);
    }

    private static String componentDisplayText(Component component) {
        if (component == null) {
            return null;
        }
        if (component instanceof JLabel label) {
            String text = normalizeBlank(label.getText());
            if (text != null) {
                return text;
            }
        }
        if (component instanceof AbstractButton button) {
            String text = normalizeBlank(button.getText());
            if (text != null) {
                return text;
            }
        }
        if (component instanceof JComponent swingComponent) {
            String tooltip = normalizeBlank(swingComponent.getToolTipText());
            if (tooltip != null) {
                return tooltip;
            }
        }
        AccessibleContext accessibleContext = component.getAccessibleContext();
        if (accessibleContext != null) {
            String accessibleName = normalizeBlank(accessibleContext.getAccessibleName());
            if (accessibleName != null) {
                return accessibleName;
            }
            String accessibleDescription = normalizeBlank(accessibleContext.getAccessibleDescription());
            if (accessibleDescription != null) {
                return accessibleDescription;
            }
        }
        if (!(component instanceof Container container)) {
            return null;
        }
        for (Component child : container.getComponents()) {
            String childText = componentDisplayText(child);
            if (childText != null) {
                return childText;
            }
        }
        return null;
    }

    private static void collectComponentTexts(Component component, List<String> values) {
        if (component == null) {
            return;
        }
        if (component instanceof JLabel label) {
            addIfNonBlank(values, label.getText());
        }
        if (component instanceof AbstractButton button) {
            addIfNonBlank(values, button.getText());
        }
        if (component instanceof JComponent swingComponent) {
            addIfNonBlank(values, swingComponent.getToolTipText());
        }
        AccessibleContext accessibleContext = component.getAccessibleContext();
        if (accessibleContext != null) {
            addIfNonBlank(values, accessibleContext.getAccessibleName());
            addIfNonBlank(values, accessibleContext.getAccessibleDescription());
        }
        if (!(component instanceof Container container)) {
            return;
        }
        for (Component child : container.getComponents()) {
            collectComponentTexts(child, values);
        }
    }

    private static String bestGroupNameCandidate(List<String> candidates, String tabName) {
        String bestCandidate = null;
        int bestScore = Integer.MIN_VALUE;
        for (String candidate : candidates) {
            String normalized = normalizeBlank(candidate);
            if (normalized == null
                    || sameNormalized(normalized, tabName)
                    || isUiChromeLabel(normalized)
                    || isAuxiliaryRepeaterTabLabel(normalized)) {
                continue;
            }
            int score = scoreGroupNameCandidate(normalized);
            if (score > bestScore) {
                bestScore = score;
                bestCandidate = normalized;
            }
        }
        return bestScore > 0 ? bestCandidate : null;
    }

    private static boolean shouldInspectPaneLevelGroupCandidates(
            SelectedTabSnapshot snapshot,
            String tabName) {
        return snapshot != null
                && normalizeBlank(tabName) != null
                && snapshot.selectedIndex() >= 0
                && snapshot.selectedIndex() < snapshot.tabCount()
                && snapshot.paneCandidateLabels() != null
                && snapshot.paneCandidateLabels().size() > snapshot.candidateLabels().size();
    }

    private static String nearestPaneGroupNameCandidate(
            SelectedTabSnapshot snapshot,
            String tabName) {
        if (!shouldInspectPaneLevelGroupCandidates(snapshot, tabName)) {
            return null;
        }
        String explicitGroup = declaredPaneGroupNameCandidate(snapshot);
        if (explicitGroup != null) {
            return explicitGroup;
        }
        return prefixedPaneGroupNameCandidate(snapshot, tabName);
    }

    private static String declaredPaneGroupNameCandidate(SelectedTabSnapshot snapshot) {
        if (snapshot == null
                || snapshot.selectedIndex() <= 0
                || snapshot.selectedIndex() >= snapshot.tabCount()
                || snapshot.paneTabs().isEmpty()) {
            return null;
        }
        for (int i = snapshot.selectedIndex() - 1; i >= 0 && i < snapshot.paneTabs().size(); i--) {
            PaneTabSnapshot paneTab = snapshot.paneTabs().get(i);
            String groupName = explicitGroupHeaderName(paneTab);
            if (groupName == null) {
                continue;
            }
            int childCount = explicitGroupChildCount(paneTab, snapshot.tabCount() - i - 1);
            if (childCount <= 0) {
                continue;
            }
            if (snapshot.selectedIndex() <= i + childCount) {
                return groupName;
            }
        }
        return null;
    }

    private static String prefixedPaneGroupNameCandidate(
            SelectedTabSnapshot snapshot,
            String tabName) {
        if (snapshot == null
                || snapshot.panePrimaryLabels().isEmpty()
                || normalizeBlank(tabName) == null) {
            return null;
        }
        for (int i = snapshot.selectedIndex() - 1; i >= 0; i--) {
            String candidate = normalizeBlank(snapshot.panePrimaryLabels().get(i));
            if (candidate == null
                    || sameNormalized(candidate, tabName)
                    || isUiChromeLabel(candidate)
                    || isAuxiliaryRepeaterTabLabel(candidate)
                    || candidate.chars().allMatch(Character::isDigit)) {
                continue;
            }
            if (startsWithIgnoreCase(tabName, candidate)
                    && tabName.length() > candidate.length()
                    && countContiguousFollowingPrefixedTabs(snapshot.panePrimaryLabels(), i, candidate) >= 2) {
                return candidate;
            }
        }
        return null;
    }

    private static int countContiguousFollowingPrefixedTabs(
            List<String> panePrimaryLabels,
            int candidateIndex,
            String candidate) {
        if (panePrimaryLabels == null
                || panePrimaryLabels.isEmpty()
                || candidateIndex < 0
                || candidateIndex >= panePrimaryLabels.size()
                || candidate == null) {
            return 0;
        }
        int count = 0;
        for (int i = candidateIndex + 1; i < panePrimaryLabels.size(); i++) {
            String next = normalizeBlank(panePrimaryLabels.get(i));
            if (next == null
                    || isUiChromeLabel(next)
                    || isAuxiliaryRepeaterTabLabel(next)
                    || !startsWithIgnoreCase(next, candidate)
                    || next.length() <= candidate.length()) {
                break;
            }
            count++;
        }
        return count;
    }

    private static String explicitGroupHeaderName(PaneTabSnapshot paneTab) {
        if (paneTab == null) {
            return null;
        }
        String candidate = normalizeBlank(paneTab.primaryLabel());
        if (candidate == null
                || isUiChromeLabel(candidate)
                || isAuxiliaryRepeaterTabLabel(candidate)
                || candidate.chars().allMatch(Character::isDigit)) {
            return null;
        }
        return candidate;
    }

    private static int explicitGroupChildCount(
            PaneTabSnapshot paneTab,
            int maxRemainingTabs) {
        if (paneTab == null || maxRemainingTabs <= 0) {
            return -1;
        }
        int bestCount = -1;
        for (String candidate : paneTab.candidateLabels()) {
            String normalized = normalizeBlank(candidate);
            if (normalized == null
                    || sameNormalized(normalized, paneTab.primaryLabel())
                    || !normalized.chars().allMatch(Character::isDigit)) {
                continue;
            }
            try {
                int value = Integer.parseInt(normalized);
                if (value > 0 && value <= maxRemainingTabs && value > bestCount) {
                    bestCount = value;
                }
            } catch (NumberFormatException ignored) {
                // Ignore large or malformed badge values and fall back to non-explicit heuristics.
            }
        }
        return bestCount;
    }

    private static boolean startsWithIgnoreCase(String value, String prefix) {
        return value != null
                && prefix != null
                && value.length() >= prefix.length()
                && value.regionMatches(true, 0, prefix, 0, prefix.length());
    }

    private static int scoreGroupNameCandidate(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return Integer.MIN_VALUE;
        }
        int score = 0;
        if (containsLetter(candidate)) {
            score += 100;
        } else if (candidate.chars().allMatch(Character::isDigit)) {
            score -= 100;
        }
        if (candidate.indexOf(' ') >= 0) {
            score += 10;
        }
        score += Math.min(candidate.length(), 60);
        return score;
    }

    private static boolean containsLetter(String value) {
        return value != null && value.chars().anyMatch(Character::isLetter);
    }

    private static boolean isUiChromeLabel(String value) {
        if (value == null) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "<", ">", "x", "+", "-", "*", "\u00d7" -> true;
            default -> normalized.contains("tabclosebutton")
                    || normalized.contains("closebutton")
                    || normalized.startsWith("javax.swing.");
        };
    }

    private static void addIfNonBlank(List<String> values, String candidate) {
        String normalized = normalizeBlank(candidate);
        if (normalized != null && !containsSameNormalized(values, normalized)) {
            values.add(normalized);
        }
    }

    private static boolean containsSameNormalized(List<String> values, String candidate) {
        for (String value : values) {
            if (sameNormalized(value, candidate)) {
                return true;
            }
        }
        return false;
    }

    private static String distinctFrom(String first, String second) {
        return sameNormalized(first, second) ? null : normalizeBlank(second);
    }

    private static boolean sameNormalized(String first, String second) {
        String normalizedFirst = normalizeBlank(first);
        String normalizedSecond = normalizeBlank(second);
        if (normalizedFirst == null || normalizedSecond == null) {
            return normalizedFirst == null && normalizedSecond == null;
        }
        return normalizedFirst.equalsIgnoreCase(normalizedSecond);
    }

    private static String normalizeBlank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    static boolean isMessageViewTabPane(JTabbedPane pane) {
        int titledTabs = 0;
        int knownViewTabs = 0;
        for (int i = 0; i < pane.getTabCount(); i++) {
            String title = pane.getTitleAt(i);
            if (title == null || title.isBlank()) {
                continue;
            }
            titledTabs++;
            if (MESSAGE_VIEW_TAB_TITLES.contains(title.trim().toLowerCase(Locale.ROOT))) {
                knownViewTabs++;
            }
        }
        return titledTabs > 0 && titledTabs == knownViewTabs;
    }

    private static String safeLogValue(String value) {
        return value == null ? "<null>" : value;
    }

    /**
     * Immutable tab/group inference result used by the history/live reporters.
     */
    static record InferenceResult(String tabName, String groupName) { }

    /**
     * Snapshot of one selected tab within a traversed Repeater tab path.
     */
    static record SelectedTabSnapshot(
            String primaryLabel,
            List<String> candidateLabels,
            List<String> paneCandidateLabels,
            List<PaneTabSnapshot> paneTabs,
            List<String> panePrimaryLabels,
            String paneClass,
            int selectedIndex,
            int tabCount) {
        SelectedTabSnapshot {
            primaryLabel = normalizeBlank(primaryLabel);
            candidateLabels = candidateLabels == null ? List.of() : List.copyOf(candidateLabels);
            paneCandidateLabels = paneCandidateLabels == null ? List.of() : List.copyOf(paneCandidateLabels);
            paneTabs = paneTabs == null ? List.of() : List.copyOf(paneTabs);
            panePrimaryLabels = panePrimaryLabels == null
                    ? List.of()
                    : Collections.unmodifiableList(new ArrayList<>(panePrimaryLabels));
            paneClass = normalizeBlank(paneClass);
        }
    }

    /**
     * Snapshot of one sibling tab in the selected tab pane.
     */
    static record PaneTabSnapshot(
            String primaryLabel,
            List<String> candidateLabels) {
        PaneTabSnapshot {
            primaryLabel = normalizeBlank(primaryLabel);
            candidateLabels = candidateLabels == null ? List.of() : List.copyOf(candidateLabels);
        }
    }
}
