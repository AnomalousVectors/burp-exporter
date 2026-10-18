package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.io.Serial;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;

class RepeaterSwingTabWalkerTest {

    @Test
    void cancelAndRestore_stopsPendingFirstPass() throws Exception {
        TestDelegate delegate = new TestDelegate();
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 60_000, 60_000, 60_000, List::of, delegate);

        SwingUtilities.invokeAndWait(() -> {
            walker.schedule(1);
            assertThat(walker.hasOwnedWork()).isTrue();
            walker.cancelAndRestore();
            assertThat(walker.hasOwnedWork()).isFalse();
        });

        assertThat(delegate.failures.get()).isZero();
    }

    @Test
    void cancelAndRestore_stopsPendingSecondPass() throws Exception {
        TestDelegate delegate = new TestDelegate();
        SwingTree tree = swingTreeWithRepeaterRoot(new JPanel());
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 60_000, 60_000, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.passCompleted.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(walker.hasOwnedWork()).isTrue();
            walker.cancelAndRestore();
            assertThat(walker.hasOwnedWork()).isFalse();
        });

        assertThat(delegate.failures.get()).isZero();
        assertThat(delegate.walkCompleted.get()).isZero();
    }

    @Test
    void cancelAndRestore_restoresToolSelectionDuringActiveWalk() throws Exception {
        TestDelegate delegate = new TestDelegate();
        JTabbedPane requestTabs = requestTabs(new JTabbedPane());
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs);
        CountDownLatch repeaterSelected = new CountDownLatch(1);
        tree.toolTabs().addChangeListener(ignored -> {
            if (tree.toolTabs().getSelectedComponent() == tree.repeaterRoot()) {
                repeaterSelected.countDown();
            }
        });
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 60_000, 60_000, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(repeaterSelected.await(2, TimeUnit.SECONDS)).isTrue();
        walker.cancelAndRestore();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
            assertThat(requestTabs.getSelectedIndex()).isZero();
        });

        assertThat(delegate.failures.get()).isZero();
    }

    @Test
    void staleSchedule_cannotCancelActiveNewerGeneration() throws Exception {
        TestDelegate delegate = new TestDelegate();
        JTabbedPane requestTabs = requestTabs(new JTabbedPane());
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs);
        AtomicInteger repeaterSelections = new AtomicInteger();
        CountDownLatch firstSelection = new CountDownLatch(1);
        CountDownLatch secondSelection = new CountDownLatch(1);
        tree.toolTabs().addChangeListener(ignored -> {
            if (tree.toolTabs().getSelectedComponent() != tree.repeaterRoot()) {
                return;
            }
            int selection = repeaterSelections.incrementAndGet();
            if (selection == 1) {
                firstSelection.countDown();
            } else if (selection == 2) {
                secondSelection.countDown();
            }
        });
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 60_000, 60_000, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(firstSelection.await(2, TimeUnit.SECONDS)).isTrue();
        delegate.activeGeneration.set(2);
        SwingUtilities.invokeAndWait(() -> walker.schedule(2));
        assertThat(secondSelection.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            walker.schedule(1);
            assertThat(walker.hasOwnedWork()).isTrue();
            assertThat(tree.toolTabs().getSelectedIndex()).isEqualTo(1);
            walker.cancelAndRestore();
        });

        assertThat(delegate.failures.get()).isZero();
    }

    @Test
    void selectionFailure_stopsPassAndRestoresSelectionsWithoutFollowUpPass() throws Exception {
        TestDelegate delegate = new TestDelegate();
        FailingTabbedPane requestTabs = new FailingTabbedPane();
        requestTabs(requestTabs);
        requestTabs.failAfterSelecting(1);
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs);
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 60_000, 1, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.failed.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
            assertThat(requestTabs.getSelectedIndex()).isZero();
        });

        assertThat(delegate.failures.get()).isOne();
        assertThat(delegate.walkCompleted.get()).isOne();
        assertThat(delegate.passCompletions.get()).isZero();
        assertThat(delegate.lastFailure.get().phase()).isEqualTo("selecting Repeater request tab");
    }

    @Test
    void removedPlannedTab_failsSoftlyAndRestoresToolSelection() throws Exception {
        TestDelegate delegate = new TestDelegate();
        JTabbedPane requestTabs = requestTabs(new JTabbedPane());
        Component removedBeforeSelection = requestTabs.getComponentAt(1);
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs);
        AtomicBoolean removed = new AtomicBoolean();
        tree.toolTabs().addChangeListener(ignored -> {
            if (tree.toolTabs().getSelectedComponent() == tree.repeaterRoot()
                    && removed.compareAndSet(false, true)) {
                requestTabs.remove(removedBeforeSelection);
            }
        });
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 60_000, 1, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.failed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
            assertThat(requestTabs.getTabCount()).isOne();
        });

        assertThat(delegate.failures.get()).isOne();
        assertThat(delegate.lastFailure.get().primaryFailure())
                .hasMessageContaining("changed before it could be selected");
    }

    @Test
    void replacedTabContent_preservesLogicalWalkAndRestoresSelections() throws Exception {
        TestDelegate delegate = new TestDelegate();
        JTabbedPane requestTabs = requestTabs(new JTabbedPane());
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs);
        AtomicBoolean replaced = new AtomicBoolean();
        requestTabs.addChangeListener(ignored -> {
            if (requestTabs.getSelectedIndex() == 1
                    && replaced.compareAndSet(false, true)) {
                requestTabs.setComponentAt(0, new JPanel());
                requestTabs.setComponentAt(1, new JPanel());
            }
        });
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 60_000, 1, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.passCompleted.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            walker.cancelAndRestore();
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
            assertThat(requestTabs.getSelectedIndex()).isZero();
        });

        assertThat(replaced).isTrue();
        assertThat(delegate.failures.get()).isZero();
        assertThat(delegate.passCompletions.get()).isOne();
    }

    @Test
    void restoreSelections_continuesAfterOnePaneRestorationFails() throws Exception {
        AtomicReference<RepeaterSwingTabWalker.WalkFailure> failureRef = new AtomicReference<>();
        AtomicReference<JTabbedPane> firstPaneRef = new AtomicReference<>();
        AtomicReference<FailingTabbedPane> secondPaneRef = new AtomicReference<>();
        AtomicReference<SwingTree> treeRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane firstPane = requestTabs(new JTabbedPane());
            FailingTabbedPane secondPane = requestTabs(new FailingTabbedPane());
            JPanel repeaterRoot = new JPanel(new GridLayout(1, 2));
            repeaterRoot.add(firstPane);
            repeaterRoot.add(secondPane);
            SwingTree tree = swingTreeWithRepeaterRoot(repeaterRoot);
            RepeaterSwingTabWalker.ToolTabLocation location =
                    RepeaterSwingTabWalker.findToolTabLocation(List.of(tree.root()), "Repeater");
            RepeaterSwingTabWalker.WalkPlan<String> plan =
                    RepeaterSwingTabWalker.buildPlanForInspection(
                            location,
                            (pane, selectedIndex, paneOrdinal) -> paneOrdinal + ":" + selectedIndex,
                            0);

            tree.toolTabs().setSelectedIndex(1);
            firstPane.setSelectedIndex(1);
            secondPane.setSelectedIndex(1);
            secondPane.failBeforeSelecting(0);
            failureRef.set(RepeaterSwingTabWalker.restoreSelections(plan));
            firstPaneRef.set(firstPane);
            secondPaneRef.set(secondPane);
            treeRef.set(tree);
        });

        assertThat(failureRef.get()).isNotNull();
        assertThat(failureRef.get().restorationFailureCount()).isOne();
        assertThat(firstPaneRef.get().getSelectedIndex()).isZero();
        assertThat(secondPaneRef.get().getSelectedIndex()).isOne();
        assertThat(treeRef.get().toolTabs().getSelectedIndex()).isZero();
    }

    private static <T extends JTabbedPane> T requestTabs(T pane) {
        pane.addTab("One", new JPanel());
        pane.addTab("Two", new JPanel());
        pane.setSelectedIndex(0);
        return pane;
    }

    private static SwingTree swingTreeWithRepeaterRoot(Component repeaterRoot) {
        JTabbedPane toolTabs = new JTabbedPane();
        toolTabs.addTab("Dashboard", new JPanel());
        toolTabs.addTab("Repeater", repeaterRoot);
        toolTabs.setSelectedIndex(0);
        JPanel root = new JPanel(new BorderLayout());
        root.add(toolTabs, BorderLayout.CENTER);
        return new SwingTree(root, toolTabs, repeaterRoot);
    }

    private record SwingTree(
            JPanel root,
            JTabbedPane toolTabs,
            Component repeaterRoot) { }

    private static final class FailingTabbedPane extends JTabbedPane {
        @Serial private static final long serialVersionUID = 1L;

        private int failBeforeIndex = -1;
        private int failAfterIndex = -1;

        private void failBeforeSelecting(int index) {
            failBeforeIndex = index;
        }

        private void failAfterSelecting(int index) {
            failAfterIndex = index;
        }

        @Override
        public void setSelectedIndex(int index) {
            if (index == failBeforeIndex) {
                throw new IllegalStateException("synthetic selection failure before change");
            }
            super.setSelectedIndex(index);
            if (index == failAfterIndex) {
                failAfterIndex = -1;
                throw new IllegalStateException("synthetic selection failure after change");
            }
        }
    }

    private static final class TestDelegate
            implements RepeaterSwingTabWalker.Delegate<String> {
        private final AtomicBoolean valid = new AtomicBoolean(true);
        private final AtomicInteger activeGeneration = new AtomicInteger(1);
        private final AtomicInteger failures = new AtomicInteger();
        private final AtomicInteger passCompletions = new AtomicInteger();
        private final AtomicInteger walkCompleted = new AtomicInteger();
        private final AtomicReference<RepeaterSwingTabWalker.WalkFailure> lastFailure =
                new AtomicReference<>();
        private final CountDownLatch passCompleted = new CountDownLatch(1);
        private final CountDownLatch failed = new CountDownLatch(1);
        private final CountDownLatch completed = new CountDownLatch(1);

        @Override
        public boolean isWalkValid(int generation) {
            return valid.get() && generation == activeGeneration.get();
        }

        @Override
        public int captureCount() {
            return 0;
        }

        @Override
        public String metadataFor(JTabbedPane pane, int selectedIndex, int paneOrdinal) {
            return paneOrdinal + ":" + selectedIndex;
        }

        @Override
        public void setActiveMetadata(String metadata) { }

        @Override
        public void onPassUnavailable(int passNumber, int delayMs) { }

        @Override
        public void onPassCompleted(
                int passNumber,
                int delayMs,
                RepeaterSwingTabWalker.PassResult result) {
            passCompletions.incrementAndGet();
            passCompleted.countDown();
        }

        @Override
        public void onPassFailed(
                int passNumber,
                int delayMs,
                RepeaterSwingTabWalker.WalkFailure failure) {
            failures.incrementAndGet();
            lastFailure.set(failure);
            failed.countDown();
        }

        @Override
        public void onWalkCompleted() {
            walkCompleted.incrementAndGet();
            completed.countDown();
        }
    }
}
