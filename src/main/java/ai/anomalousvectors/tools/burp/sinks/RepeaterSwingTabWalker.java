package ai.anomalousvectors.tools.burp.sinks;

import java.awt.Component;
import java.awt.Container;
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
    private final int secondPassDelayMs;
    private final int stepDelayMs;
    private final Supplier<? extends Iterable<? extends Component>> rootsSupplier;
    private final Delegate<M> delegate;
    private Timer pendingPassTimer;
    private WalkSession activeSession;

    RepeaterSwingTabWalker(
            String toolTitle,
            int firstPassDelayMs,
            int secondPassDelayMs,
            int stepDelayMs,
            Supplier<? extends Iterable<? extends Component>> rootsSupplier,
            Delegate<M> delegate) {
        this.toolTitle = toolTitle;
        this.firstPassDelayMs = firstPassDelayMs;
        this.secondPassDelayMs = secondPassDelayMs;
        this.stepDelayMs = stepDelayMs;
        this.rootsSupplier = rootsSupplier;
        this.delegate = delegate;
    }

    /** Schedules both startup passes on the EDT for one export-run generation. */
    void schedule(int generation) {
        runOnEdt(() -> {
            if (!delegate.isWalkValid(generation)) {
                return;
            }
            cancelOwnedWork(true);
            schedulePass(generation, 1, firstPassDelayMs);
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

    private void schedulePass(int generation, int passNumber, int delayMs) {
        if (!delegate.isWalkValid(generation)) {
            return;
        }
        Timer timer = new Timer(delayMs, ignored -> {
            pendingPassTimer = null;
            runPass(generation, passNumber, delayMs);
        });
        timer.setRepeats(false);
        pendingPassTimer = timer;
        timer.start();
    }

    private void runPass(int generation, int passNumber, int delayMs) {
        if (!delegate.isWalkValid(generation)) {
            return;
        }
        WalkPlan<M> plan;
        try {
            ToolTabLocation location = findToolTabLocation(rootsSupplier.get(), toolTitle);
            if (location == null) {
                delegate.onPassUnavailable(passNumber, delayMs);
                scheduleFollowUp(generation, passNumber);
                return;
            }
            plan = buildPlan(location, delegate::metadataFor, delegate.captureCount());
        } catch (RuntimeException exception) {
            delegate.onPassFailed(
                    passNumber,
                    delayMs,
                    new WalkFailure("planning", exception, 0, null));
            completeWalk(generation);
            return;
        }
        WalkSession session = new WalkSession(generation, passNumber, delayMs, plan);
        activeSession = session;
        session.start();
    }

    private void scheduleFollowUp(int generation, int completedPassNumber) {
        if (!delegate.isWalkValid(generation)) {
            return;
        }
        if (completedPassNumber < 2) {
            schedulePass(generation, completedPassNumber + 1, secondPassDelayMs);
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
        scheduleFollowUp(session.generation, session.passNumber);
    }

    private void sessionFailed(WalkSession session, WalkFailure failure) {
        if (activeSession != session) {
            return;
        }
        activeSession = null;
        delegate.onPassFailed(session.passNumber, session.delayMs, failure);
        completeWalk(session.generation);
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
        for (int paneOrdinal = 0; paneOrdinal < visitedOrder.size(); paneOrdinal++) {
            JTabbedPane pane = visitedOrder.get(paneOrdinal);
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
            if (index != originalIndex) {
                order.add(index);
            }
        }
        if (originalIndex >= 0 && originalIndex < pane.getTabCount()) {
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
        restoreSelection(plan.toolTabs(), plan.originalToolComponent(), failures);
        return failures;
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

    @FunctionalInterface
    interface MetadataFactory<T> {
        T create(JTabbedPane pane, int selectedIndex, int paneOrdinal);
    }

    @FunctionalInterface
    interface ActiveMetadataConsumer<T> {
        void accept(T metadata);
    }

    interface Delegate<T> {
        boolean isWalkValid(int generation);

        int captureCount();

        T metadataFor(JTabbedPane pane, int selectedIndex, int paneOrdinal);

        void setActiveMetadata(T metadata);

        void onPassUnavailable(int passNumber, int delayMs);

        void onPassCompleted(int passNumber, int delayMs, PassResult result);

        void onPassFailed(int passNumber, int delayMs, WalkFailure failure);

        void onWalkCompleted();
    }

    static record PassResult(
            int tabbedPaneCount,
            int selectionChangeCount,
            int captureCountBefore,
            int captureCountAfter) { }

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
            MetadataFactory<T> metadataFactory,
            int captureCountBefore) { }

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
        private final Timer timer;
        private int nextStepIndex;
        private int selectionChanges;

        private WalkSession(
                int generation,
                int passNumber,
                int delayMs,
                WalkPlan<M> plan) {
            this.generation = generation;
            this.passNumber = passNumber;
            this.delayMs = delayMs;
            this.plan = plan;
            this.timer = new Timer(stepDelayMs, ignored -> processNextStep());
            this.timer.setRepeats(true);
        }

        private void start() {
            if (plan.steps().isEmpty()) {
                finish();
                return;
            }
            try {
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
                    delegate.captureCount()));
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
