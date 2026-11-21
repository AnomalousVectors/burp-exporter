package ai.anomalousvectors.tools.burp.sinks;

import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

/**
 * Owns the unsupported Swing selection lifecycle used to visit historic Repeater tabs.
 *
 * <p>All mutable state is confined to the EDT. Selection failures stop the current walk, while
 * restoration attempts continue independently for every still-present tab component.</p>
 *
 * @param <M> metadata associated with one planned top-level Repeater slot
 */
final class RepeaterSwingTabWalker<M> {

    private final String toolTitle;
    private final int firstPassDelayMs;
    private final int retryDelayMs;
    private final int stepDelayMs;
    private final Supplier<? extends Iterable<? extends Component>> rootsSupplier;
    private final Delegate<M> delegate;
    private Timer pendingPassTimer;
    private WalkSession activeSession;

    RepeaterSwingTabWalker(
            String toolTitle,
            int firstPassDelayMs,
            int retryDelayMs,
            int stepDelayMs,
            Supplier<? extends Iterable<? extends Component>> rootsSupplier,
            Delegate<M> delegate) {
        this.toolTitle = toolTitle;
        this.firstPassDelayMs = firstPassDelayMs;
        this.retryDelayMs = retryDelayMs;
        this.stepDelayMs = stepDelayMs;
        this.rootsSupplier = rootsSupplier;
        this.delegate = delegate;
    }

    /** Schedules one startup pass, with at most one retry for an observed problem. */
    void schedule(int generation) {
        runOnEdt(() -> {
            if (!delegate.isWalkValid(generation)) {
                return;
            }
            cancelOwnedWork(true);
            schedulePass(generation, 1, firstPassDelayMs, false);
        });
    }

    /** Cancels pending work and restores an active walk on the EDT. */
    void cancelAndRestore() {
        runOnEdt(() -> cancelOwnedWork(true));
    }

    /** Returns whether this walker currently owns a delayed pass or active selection session. */
    boolean hasOwnedWork() {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException("Caller must invoke on the EDT");
        }
        return pendingPassTimer != null || activeSession != null;
    }

    private void schedulePass(int generation, int passNumber, int delayMs, boolean unresolvedOnly) {
        if (!delegate.isWalkValid(generation)) {
            return;
        }
        Timer timer = new Timer(delayMs, ignored -> {
            pendingPassTimer = null;
            runPass(generation, passNumber, delayMs, unresolvedOnly);
        });
        timer.setRepeats(false);
        pendingPassTimer = timer;
        timer.start();
    }

    private void runPass(int generation, int passNumber, int delayMs, boolean unresolvedOnly) {
        if (!delegate.isWalkValid(generation)) {
            return;
        }
        WalkPlan<M> plan;
        try {
            ToolTabLocation location = findToolTabLocation(rootsSupplier.get(), toolTitle);
            if (location == null) {
                delegate.onPassUnavailable(passNumber, delayMs);
                scheduleFollowUp(generation, passNumber, true, false);
                return;
            }
            plan = buildPlan(location, delegate::metadataFor, delegate.captureCount());
        } catch (RuntimeException exception) {
            delegate.onPassFailed(
                    passNumber,
                    delayMs,
                    new WalkFailure("planning", exception, 0, null));
            scheduleFollowUp(generation, passNumber, true, false);
            return;
        }
        WalkSession session = new WalkSession(generation, passNumber, delayMs, plan, unresolvedOnly);
        activeSession = session;
        session.start();
    }

    private void scheduleFollowUp(
            int generation, int completedPassNumber, boolean retryNeeded, boolean unresolvedOnly) {
        if (!delegate.isWalkValid(generation)) {
            return;
        }
        if (retryNeeded && completedPassNumber < 2) {
            schedulePass(generation, completedPassNumber + 1, retryDelayMs, unresolvedOnly);
        } else {
            completeWalk(generation);
        }
    }

    private void completeWalk(int generation) {
        if (delegate.isWalkValid(generation)) {
            delegate.onWalkCompleted();
        }
    }

    private void sessionCompleted(WalkSession session, PassResult result) {
        if (activeSession != session) {
            return;
        }
        activeSession = null;
        delegate.onPassCompleted(session.passNumber, session.delayMs, result);
        scheduleFollowUp(session.generation, session.passNumber, result.unobservedSlotCount() > 0, true);
    }

    private void sessionFailed(WalkSession session, WalkFailure failure) {
        if (activeSession != session) {
            return;
        }
        activeSession = null;
        delegate.onPassFailed(session.passNumber, session.delayMs, failure);
        // Never change selections again when restoration itself failed. Otherwise one fresh
        // plan can recover a transient selection failure without an unbounded retry loop.
        scheduleFollowUp(session.generation, session.passNumber, failure.restorationFailureCount() == 0, false);
    }

    private void cancelOwnedWork(boolean reportRestorationFailure) {
        if (pendingPassTimer != null) {
            pendingPassTimer.stop();
            pendingPassTimer = null;
        }
        if (activeSession != null) {
            WalkSession session = activeSession;
            activeSession = null;
            WalkFailure failure = session.cancelAndRestore();
            if (reportRestorationFailure && failure != null) {
                delegate.onPassFailed(session.passNumber, session.delayMs, failure);
            }
        }
        delegate.setActiveMetadata(null);
    }

    private static void runOnEdt(Runnable action) {
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeLater(action);
        }
    }

    static ToolTabLocation findAncestorToolTabLocation(Component descendant, String title) {
        for (Component current = descendant; current != null; current = current.getParent()) {
            if (!(current instanceof JTabbedPane pane)) {
                continue;
            }
            for (int index = 0; index < pane.getTabCount(); index++) {
                if (title.equalsIgnoreCase(pane.getTitleAt(index))
                        && indexContainingDescendant(pane, descendant) == index) {
                    return new ToolTabLocation(pane, index);
                }
            }
        }
        return null;
    }

    static ToolTabLocation findToolTabLocation(Iterable<? extends Component> roots, String title) {
        if (roots == null || title == null || title.isBlank()) {
            return null;
        }
        for (Component root : roots) {
            ToolTabLocation location = findToolTabLocation(root, title);
            if (location != null) {
                return location;
            }
        }
        return null;
    }

    static List<JTabbedPane> collectTopLevelRepeaterTabPanes(Component root) {
        List<JTabbedPane> panes = new ArrayList<>();
        collectTopLevelRepeaterTabPanes(root, panes);
        return panes;
    }

    static <T> WalkPlan<T> buildPlanForInspection(
            ToolTabLocation location,
            MetadataFactory<T> metadataFactory,
            int captureCountBefore) {
        return buildPlan(location, metadataFactory, captureCountBefore);
    }

    static <T> SynchronousWalkResult performSynchronously(
            Iterable<? extends Component> roots,
            String title,
            IntSupplier captureCount,
            MetadataFactory<T> metadataFactory,
            ActiveMetadataConsumer<T> metadataConsumer) {
        ToolTabLocation location;
        try {
            location = findToolTabLocation(roots, title);
        } catch (RuntimeException exception) {
            return SynchronousWalkResult.failed(exception);
        }
        if (location == null) {
            return SynchronousWalkResult.notLocated();
        }
        WalkPlan<T> plan;
        try {
            plan = buildPlan(location, metadataFactory, captureCount.getAsInt());
        } catch (RuntimeException exception) {
            return SynchronousWalkResult.failed(exception);
        }
        int selectionChanges = 0;
        RuntimeException selectionFailure = null;
        String phase = "selection";
        try {
            selectionChanges += selectPlannedComponent(
                    plan.toolTabs(), plan.repeaterComponent(), "Repeater tool tab");
            for (SelectionStep<T> step : plan.steps()) {
                metadataConsumer.accept(step.metadata());
                selectionChanges += selectPlannedStep(plan, step, "Repeater request tab");
            }
        } catch (RuntimeException exception) {
            selectionFailure = exception;
        } finally {
            metadataConsumer.accept(null);
        }
        RestorationFailures restoration = restorePlan(plan);
        WalkFailure failure = combineFailure(phase, selectionFailure, restoration);
        return new SynchronousWalkResult(
                true,
                plan.visitedOrder().size(),
                selectionChanges,
                plan.captureCountBefore(),
                captureCount.getAsInt(),
                failure);
    }

    private static ToolTabLocation findToolTabLocation(Component root, String title) {
        if (root == null) {
            return null;
        }
        if (root instanceof JTabbedPane pane) {
            for (int index = 0; index < pane.getTabCount(); index++) {
                if (title.equalsIgnoreCase(pane.getTitleAt(index))) {
                    return new ToolTabLocation(pane, index);
                }
            }
        }
        if (!(root instanceof Container container)) {
            return null;
        }
        for (Component child : container.getComponents()) {
            ToolTabLocation location = findToolTabLocation(child, title);
            if (location != null) {
                return location;
            }
        }
        return null;
    }

    private static void collectTopLevelRepeaterTabPanes(Component root, List<JTabbedPane> panes) {
        if (root instanceof JTabbedPane pane) {
            if (pane.getTabCount() > 0
                    && !RepeaterTabMetadataHeuristics.isMessageViewTabPane(pane)) {
                panes.add(pane);
            }
            return;
        }
        if (!(root instanceof Container container)) {
            return;
        }
        for (Component child : container.getComponents()) {
            collectTopLevelRepeaterTabPanes(child, panes);
        }
    }

    static int indexContainingDescendant(JTabbedPane pane, Component descendant) {
        if (pane == null || descendant == null) {
            return -1;
        }
        for (int index = 0; index < pane.getTabCount(); index++) {
            Component tabComponent = pane.getComponentAt(index);
            if (tabComponent == descendant
                    || SwingUtilities.isDescendingFrom(descendant, tabComponent)) {
                return index;
            }
        }
        return -1;
    }

    private static <T> WalkPlan<T> buildPlan(
            ToolTabLocation location,
            MetadataFactory<T> metadataFactory,
            int captureCountBefore) {
        JTabbedPane toolTabs = location.tabbedPane();
        Component repeaterComponent = toolTabs.getComponentAt(location.index());
        Component originalToolComponent = selectedComponent(toolTabs);
        List<JTabbedPane> visitedOrder = collectTopLevelRepeaterTabPanes(repeaterComponent);
        IdentityHashMap<JTabbedPane, SelectionStep<T>> originalSelections =
                new IdentityHashMap<>();
        List<SelectionStep<T>> steps = new ArrayList<>();
        List<CollapsedGroup> collapsedGroups = new ArrayList<>();
        for (int paneOrdinal = 0; paneOrdinal < visitedOrder.size(); paneOrdinal++) {
            JTabbedPane pane = visitedOrder.get(paneOrdinal);
            rememberCollapsedGroups(pane, collapsedGroups);
            int originalIndex = pane.getSelectedIndex();
            if (originalIndex >= 0 && originalIndex < pane.getTabCount()) {
                originalSelections.put(
                        pane,
                        selectionStep(pane, originalIndex, paneOrdinal, metadataFactory));
            }
            for (int selectedIndex : selectionOrder(pane)) {
                steps.add(selectionStep(pane, selectedIndex, paneOrdinal, metadataFactory));
            }
        }
        return new WalkPlan<>(
                toolTabs,
                originalToolComponent,
                repeaterComponent,
                List.copyOf(visitedOrder),
                originalSelections,
                List.copyOf(steps),
                List.copyOf(collapsedGroups),
                metadataFactory,
                captureCountBefore);
    }

    private static <T> SelectionStep<T> selectionStep(
            JTabbedPane pane,
            int selectedIndex,
            int paneOrdinal,
            MetadataFactory<T> metadataFactory) {
        return new SelectionStep<>(
                pane,
                pane.getComponentAt(selectedIndex),
                selectedIndex,
                paneOrdinal,
                metadataFactory.create(pane, selectedIndex, paneOrdinal));
    }

    private static Component selectedComponent(JTabbedPane pane) {
        int selectedIndex = pane.getSelectedIndex();
        return selectedIndex >= 0 && selectedIndex < pane.getTabCount()
                ? pane.getComponentAt(selectedIndex)
                : null;
    }

    private static List<Integer> selectionOrder(JTabbedPane pane) {
        if (pane == null || pane.getTabCount() <= 0) {
            return List.of();
        }
        int originalIndex = pane.getSelectedIndex();
        List<Integer> order = new ArrayList<>(pane.getTabCount());
        for (int index = 0; index < pane.getTabCount(); index++) {
            // Group headers occupy Swing slots but never bind a request editor. Visiting one
            // toggles group presentation and would also manufacture a missing-binding retry.
            if (index != originalIndex && !RepeaterTabMetadataHeuristics.isGroupHeader(pane, index)) {
                order.add(index);
            }
        }
        if (originalIndex >= 0 && originalIndex < pane.getTabCount()
                && !RepeaterTabMetadataHeuristics.isGroupHeader(pane, originalIndex)) {
            order.add(originalIndex);
        }
        return order;
    }

    private static int selectPlannedComponent(
            JTabbedPane pane,
            Component plannedComponent,
            String description) {
        int selectedIndex = indexOfComponent(pane, plannedComponent);
        if (selectedIndex < 0) {
            throw new IllegalStateException(description + " changed before it could be selected");
        }
        if (pane.getSelectedIndex() == selectedIndex) {
            return 0;
        }
        pane.setSelectedIndex(selectedIndex);
        return 1;
    }

    private static <T> int selectPlannedStep(
            WalkPlan<T> plan,
            SelectionStep<T> step,
            String description) {
        int selectedIndex = resolvePlannedIndex(plan, step);
        if (selectedIndex < 0) {
            throw new IllegalStateException(description + " changed before it could be selected");
        }
        if (step.pane().getSelectedIndex() == selectedIndex) {
            return 0;
        }
        step.pane().setSelectedIndex(selectedIndex);
        return 1;
    }

    private static <T> int resolvePlannedIndex(WalkPlan<T> plan, SelectionStep<T> step) {
        int componentIndex = indexOfComponent(step.pane(), step.tabComponent());
        if (componentIndex >= 0) {
            return componentIndex;
        }
        // Burp may replace a request tab's content component after selection. Reuse its planned
        // index only when fresh metadata proves that the same logical slot still occupies it.
        int plannedIndex = step.plannedIndex();
        if (plannedIndex < 0 || plannedIndex >= step.pane().getTabCount()) {
            return -1;
        }
        T currentMetadata = plan.metadataFactory().create(
                step.pane(), plannedIndex, step.paneOrdinal());
        return Objects.equals(step.metadata(), currentMetadata) ? plannedIndex : -1;
    }

    private static int indexOfComponent(JTabbedPane pane, Component component) {
        if (pane == null || component == null) {
            return -1;
        }
        for (int index = 0; index < pane.getTabCount(); index++) {
            if (pane.getComponentAt(index) == component) {
                return index;
            }
        }
        return -1;
    }

    private static <T> RestorationFailures restorePlan(WalkPlan<T> plan) {
        RestorationFailures failures = new RestorationFailures();
        for (int index = plan.visitedOrder().size() - 1; index >= 0; index--) {
            JTabbedPane pane = plan.visitedOrder().get(index);
            restoreSelection(plan, plan.originalSelections().get(pane), failures);
        }
        for (CollapsedGroup group : plan.collapsedGroups()) {
            try {
                group.restore();
            } catch (RuntimeException exception) {
                failures.record(exception);
            }
        }
        restoreSelection(plan.toolTabs(), plan.originalToolComponent(), failures);
        return failures;
    }

    /** Remembers collapsed headers before selecting their hidden request tabs on the EDT. */
    private static void rememberCollapsedGroups(JTabbedPane pane, List<CollapsedGroup> groups) {
        for (int index = 0; index < pane.getTabCount(); index++) {
            if (!RepeaterTabMetadataHeuristics.isGroupHeader(pane, index)) {
                continue;
            }
            int count = RepeaterTabMetadataHeuristics.groupChildCount(pane, index);
            List<Component> children = new ArrayList<>();
            for (int offset = 1; offset <= count; offset++) {
                children.add(pane.getTabComponentAt(index + offset));
            }
            if (children.stream().allMatch(RepeaterSwingTabWalker::hasCollapsedHeaderBounds)) {
                groups.add(new CollapsedGroup(pane, pane.getTabComponentAt(index), List.copyOf(children)));
            }
        }
    }

    /** Recognizes children lifted above Burp's horizontal strip when their group is collapsed. */
    private static boolean hasCollapsedHeaderBounds(Component header) {
        // Hidden children retain an x coordinate relative to their group; only the vertical
        // displacement is consistent. Horizontal tab-strip scrolling must not count as collapse.
        return header != null && header.getY() < 0;
    }

    static <T> WalkFailure restoreSelections(WalkPlan<T> plan) {
        return combineFailure("restoring selections", null, restorePlan(plan));
    }

    private static <T> void restoreSelection(
            WalkPlan<T> plan,
            SelectionStep<T> originalSelection,
            RestorationFailures failures) {
        if (originalSelection == null) {
            return;
        }
        try {
            int originalIndex = resolvePlannedIndex(plan, originalSelection);
            if (originalIndex < 0) {
                throw new IllegalStateException(
                        "Original Repeater request tab changed before it could be restored");
            }
            if (originalSelection.pane().getSelectedIndex() == originalIndex) {
                return;
            }
            originalSelection.pane().setSelectedIndex(originalIndex);
        } catch (RuntimeException exception) {
            failures.record(exception);
        }
    }

    private static void restoreSelection(
            JTabbedPane pane,
            Component originalComponent,
            RestorationFailures failures) {
        try {
            int originalIndex = indexOfComponent(pane, originalComponent);
            if (originalIndex < 0 || pane.getSelectedIndex() == originalIndex) {
                return;
            }
            pane.setSelectedIndex(originalIndex);
        } catch (RuntimeException exception) {
            failures.record(exception);
        }
    }

    private static WalkFailure combineFailure(
            String phase,
            RuntimeException primary,
            RestorationFailures restoration) {
        if (primary == null && restoration.count == 0) {
            return null;
        }
        RuntimeException effectivePrimary = primary == null ? restoration.first : primary;
        return new WalkFailure(phase, effectivePrimary, restoration.count, restoration.first);
    }

    /** Creates slot metadata while the walker observes Swing selection on the EDT. */
    @FunctionalInterface
    interface MetadataFactory<T> {
        /**
         * Describes the currently selected slot without changing its selection.
         *
         * @param pane observed tabbed pane
         * @param selectedIndex selected tab index
         * @param paneOrdinal ordinal assigned to the pane within this walk
         * @return slot metadata
         */
        T create(JTabbedPane pane, int selectedIndex, int paneOrdinal);
    }

    /** Publishes the slot context used by editor callbacks during an EDT selection change. */
    @FunctionalInterface
    interface ActiveMetadataConsumer<T> {
        /**
         * Replaces the active slot context for the current capture step.
         *
         * @param metadata active metadata, or {@code null} when clearing the context
         */
        void accept(T metadata);
    }

    /** Supplies capture state and receives walk outcomes on the EDT. */
    interface Delegate<T> {
        /**
         * Checks whether delayed work still belongs to the active run.
         *
         * @param generation run generation captured when the walk was scheduled
         * @return {@code true} when selection and capture may continue
         */
        boolean isWalkValid(int generation);

        /** Returns the current captured-item count for pass-delta accounting. */
        int captureCount();

        /**
         * Resolves metadata for one selected tab slot.
         *
         * @param pane observed tabbed pane
         * @param selectedIndex selected tab index
         * @param paneOrdinal ordinal assigned within this walk
         * @return metadata to associate with editor observations for the slot
         */
        T metadataFor(JTabbedPane pane, int selectedIndex, int paneOrdinal);

        /**
         * Publishes or clears the slot context consumed by editor capture hooks.
         *
         * @param metadata active metadata, or {@code null} to clear it
         */
        void setActiveMetadata(T metadata);

        /**
         * Reports whether Burp supplied an editor binding for this slot during startup.
         *
         * <p>A request-only binding counts as observed. This checks callback availability,
         * not whether a response exists or whether a captured payload is final.</p>
         *
         * @param metadata metadata of the planned slot
         * @return {@code true} after an editor binding was observed for the slot
         */
        boolean hasObservedBinding(T metadata);

        /**
         * Reports that a scheduled pass found no usable Repeater root.
         *
         * @param passNumber scheduled pass ordinal
         * @param delayMs delay assigned to that pass
         */
        void onPassUnavailable(int passNumber, int delayMs);

        /**
         * Reports a completed pass after its selection-restoration attempts.
         *
         * @param passNumber scheduled pass ordinal
         * @param delayMs delay assigned to that pass
         * @param result observed pane, selection, and capture counts
         */
        void onPassCompleted(int passNumber, int delayMs, PassResult result);

        /**
         * Reports a pass failure and any accompanying restoration failures.
         *
         * @param passNumber scheduled pass ordinal
         * @param delayMs delay assigned to that pass
         * @param failure failure details retained by the walker
         */
        void onPassFailed(int passNumber, int delayMs, WalkFailure failure);

        /** Reports that the owned walk has reached its completion boundary. */
        void onWalkCompleted();
    }

    static record PassResult(
            int tabbedPaneCount,
            int selectionChangeCount,
            int captureCountBefore,
            int captureCountAfter,
            int unobservedSlotCount) { }

    static record WalkFailure(
            String phase,
            RuntimeException primaryFailure,
            int restorationFailureCount,
            RuntimeException firstRestorationFailure) { }

    static record SynchronousWalkResult(
            boolean locatedRepeaterToolTab,
            int tabbedPaneCount,
            int selectionChangeCount,
            int captureCountBefore,
            int captureCountAfter,
            WalkFailure failure) {

        private static SynchronousWalkResult notLocated() {
            return new SynchronousWalkResult(false, 0, 0, 0, 0, null);
        }

        private static SynchronousWalkResult failed(RuntimeException failure) {
            return new SynchronousWalkResult(
                    false,
                    0,
                    0,
                    0,
                    0,
                    new WalkFailure("planning", failure, 0, null));
        }
    }

    static record ToolTabLocation(JTabbedPane tabbedPane, int index) { }

    static record SelectionStep<T>(
            JTabbedPane pane,
            Component tabComponent,
            int plannedIndex,
            int paneOrdinal,
            T metadata) { }

    static record WalkPlan<T>(
            JTabbedPane toolTabs,
            Component originalToolComponent,
            Component repeaterComponent,
            List<JTabbedPane> visitedOrder,
            IdentityHashMap<JTabbedPane, SelectionStep<T>> originalSelections,
            List<SelectionStep<T>> steps,
            List<CollapsedGroup> collapsedGroups,
            MetadataFactory<T> metadataFactory,
            int captureCountBefore) { }

    /** Restores one recognized group using its public Swing mouse control, never private state. */
    static record CollapsedGroup(JTabbedPane pane, Component header, List<Component> children) {
        private void restore() {
            if (children.stream().allMatch(RepeaterSwingTabWalker::hasCollapsedHeaderBounds)) {
                return;
            }
            int index = -1;
            for (int candidate = 0; candidate < pane.getTabCount(); candidate++) {
                if (pane.getTabComponentAt(candidate) == header) {
                    index = candidate;
                    break;
                }
            }
            if (index < 0 || index + children.size() >= pane.getTabCount()) {
                throw new IllegalStateException("Original Repeater group changed before restoration");
            }
            for (int offset = 0; offset < children.size(); offset++) {
                if (pane.getTabComponentAt(index + offset + 1) != children.get(offset)) {
                    throw new IllegalStateException("Original Repeater group children changed before restoration");
                }
            }
            // The header's trailing chevron is the same public UI control used by a mouse click.
            // Do not toggle an unrecognized/rebuilt header or guess from a group name alone.
            int x = header.getWidth() - 8;
            int y = header.getHeight() / 2;
            Component target = header instanceof Container container
                    ? SwingUtilities.getDeepestComponentAt(container, x, y) : header;
            if (target == null || x < 0 || y <= 0) {
                throw new IllegalStateException("Repeater group collapse control is unavailable");
            }
            // Native mouse dispatch retargets passive header children to a listening ancestor.
            // The tabbed pane can own the control even when the painted chevron has no listener.
            while (target != pane && target.getMouseListeners().length == 0
                    && target.getParent() != null) {
                target = target.getParent();
            }
            Point point = SwingUtilities.convertPoint(header, x, y, target);
            long when = System.currentTimeMillis();
            for (int event : new int[]{MouseEvent.MOUSE_PRESSED, MouseEvent.MOUSE_RELEASED, MouseEvent.MOUSE_CLICKED}) {
                int modifiers = event == MouseEvent.MOUSE_PRESSED ? InputEvent.BUTTON1_DOWN_MASK : 0;
                target.dispatchEvent(new MouseEvent(target, event, when, modifiers, point.x, point.y,
                        1, false, MouseEvent.BUTTON1));
            }
            pane.doLayout();
            if (!children.stream().allMatch(RepeaterSwingTabWalker::hasCollapsedHeaderBounds)) {
                throw new IllegalStateException("Repeater group did not return to its collapsed state");
            }
        }
    }

    private static final class RestorationFailures {
        private int count;
        private RuntimeException first;

        private void record(RuntimeException exception) {
            count++;
            if (first == null) {
                first = exception;
            }
        }
    }

    private final class WalkSession {
        private final int generation;
        private final int passNumber;
        private final int delayMs;
        private final WalkPlan<M> plan;
        private final boolean unresolvedOnly;
        private final Timer timer;
        private int nextStepIndex;
        private int selectionChanges;

        private WalkSession(
                int generation,
                int passNumber,
                int delayMs,
                WalkPlan<M> plan,
                boolean unresolvedOnly) {
            this.generation = generation;
            this.passNumber = passNumber;
            this.delayMs = delayMs;
            this.plan = plan;
            this.unresolvedOnly = unresolvedOnly;
            this.timer = new Timer(stepDelayMs, ignored -> processNextStep());
            this.timer.setRepeats(true);
        }

        private void start() {
            if (plan.steps().isEmpty()
                    || (unresolvedOnly && plan.steps().stream()
                            .allMatch(step -> delegate.hasObservedBinding(step.metadata())))) {
                finish();
                return;
            }
            try {
                // A single request tab need not change its selection. Attribute editor
                // callbacks caused by opening Repeater to that sole slot before activation.
                if (plan.steps().size() == 1) {
                    delegate.setActiveMetadata(plan.steps().getFirst().metadata());
                }
                selectionChanges += selectPlannedComponent(
                        plan.toolTabs(), plan.repeaterComponent(), "Repeater tool tab");
                timer.start();
            } catch (RuntimeException exception) {
                fail("selecting Repeater tool tab", exception);
            }
        }

        private void processNextStep() {
            if (!delegate.isWalkValid(generation)) {
                WalkFailure failure = cancelAndRestore();
                if (activeSession == this) {
                    activeSession = null;
                }
                if (failure != null) {
                    delegate.onPassFailed(passNumber, delayMs, failure);
                }
                return;
            }
            while (unresolvedOnly && nextStepIndex < plan.steps().size()
                    && delegate.hasObservedBinding(plan.steps().get(nextStepIndex).metadata())) {
                nextStepIndex++;
            }
            if (nextStepIndex >= plan.steps().size()) {
                finish();
                return;
            }
            // Keep the slot metadata active until the next tick so Burp's asynchronous final
            // editor binding can replace an initial stale binding for the selected slot.
            SelectionStep<M> step = plan.steps().get(nextStepIndex++);
            delegate.setActiveMetadata(step.metadata());
            try {
                selectionChanges += selectPlannedStep(plan, step, "Repeater request tab");
            } catch (RuntimeException exception) {
                fail("selecting Repeater request tab", exception);
            }
        }

        private void finish() {
            timer.stop();
            delegate.setActiveMetadata(null);
            RestorationFailures restoration = restorePlan(plan);
            WalkFailure failure = combineFailure("restoring selections", null, restoration);
            if (failure != null) {
                sessionFailed(this, failure);
                return;
            }
            sessionCompleted(this, new PassResult(
                    plan.visitedOrder().size(),
                    selectionChanges,
                    plan.captureCountBefore(),
                    delegate.captureCount(),
                    (int) plan.steps().stream()
                            .filter(step -> !delegate.hasObservedBinding(step.metadata()))
                            .count()));
        }

        private void fail(String phase, RuntimeException exception) {
            timer.stop();
            delegate.setActiveMetadata(null);
            RestorationFailures restoration = restorePlan(plan);
            sessionFailed(this, combineFailure(phase, exception, restoration));
        }

        private WalkFailure cancelAndRestore() {
            timer.stop();
            delegate.setActiveMetadata(null);
            RestorationFailures restoration = restorePlan(plan);
            return combineFailure("cancelling and restoring selections", null, restoration);
        }
    }
}
