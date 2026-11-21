package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.event.MouseEvent;
import java.io.Serial;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JPanel;
import javax.swing.JLabel;
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
    void cancelAndRestore_stopsPendingRetryForUnavailableRoot() throws Exception {
        TestDelegate delegate = new TestDelegate();
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 60_000, 60_000, List::of, delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.unavailable.await(2, TimeUnit.SECONDS)).isTrue();
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
    void transientSelectionFailure_restoresSelectionsAndRetriesOnlyOnce() throws Exception {
        TestDelegate delegate = new TestDelegate();
        FailingTabbedPane requestTabs = new FailingTabbedPane();
        requestTabs(requestTabs);
        requestTabs.failAfterSelecting(1);
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs);
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 1, () -> List.of(tree.root()), delegate);

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
        assertThat(delegate.passCompletions.get()).isOne();
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
            walker.cancelAndRestore();
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
            assertThat(requestTabs.getTabCount()).isOne();
        });

        assertThat(delegate.failures.get()).isOne();
        assertThat(delegate.lastFailure.get().primaryFailure())
                .hasMessageContaining("changed before it could be selected");
    }

    @Test
    void observedTabs_completeAfterOnePassAndRestoreSelections() throws Exception {
        TestDelegate delegate = new TestDelegate();
        delegate.assumeObserved = false;
        JTabbedPane tabs = requestTabs(new JTabbedPane());
        tabs.addChangeListener(ignored -> delegate.observeActiveSlot());
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        AtomicInteger plans = new AtomicInteger();
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 5, () -> {
                    plans.incrementAndGet();
                    return List.of(tree.root());
                }, delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
            assertThat(tabs.getSelectedIndex()).isZero();
        });
        assertThat(plans.get()).isOne();
        assertThat(delegate.passCompletions.get()).isOne();
        assertThat(delegate.observedSlots).containsExactlyInAnyOrder("0:0", "0:1");
        assertThat(delegate.lastResult.get().unobservedSlotCount()).isZero();
    }

    @Test
    void missingBinding_retriesOnlyTheUnobservedTab() throws Exception {
        TestDelegate delegate = new TestDelegate();
        delegate.assumeObserved = false;
        JTabbedPane tabs = requestTabs(new JTabbedPane());
        AtomicInteger missingTabVisits = new AtomicInteger();
        List<String> activeSelections = new ArrayList<>();
        tabs.addChangeListener(ignored -> {
            if (delegate.activeMetadata == null) {
                return;
            }
            activeSelections.add(delegate.activeMetadata);
            if ("0:1".equals(delegate.activeMetadata) && missingTabVisits.incrementAndGet() == 1) {
                return;
            }
            delegate.observeActiveSlot();
        });
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 5, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tabs.getSelectedIndex()).isZero();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
        });
        assertThat(activeSelections).containsExactly("0:1", "0:0", "0:1");
        assertThat(delegate.passCompletions.get()).isEqualTo(2);
        assertThat(delegate.lastResult.get().unobservedSlotCount()).isZero();
    }

    @Test
    void groupHeaders_areNeitherVisitedNorCountedAsMissingBindings() throws Exception {
        TestDelegate delegate = new TestDelegate();
        delegate.assumeObserved = false;
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("CurrentCreds", new JPanel());
        JPanel header = new JPanel();
        header.add(new JLabel("CurrentCreds"));
        header.add(new JLabel("2"));
        tabs.setTabComponentAt(0, header);
        tabs.addTab("Access", new JPanel());
        tabs.addTab("Open", new JPanel());
        tabs.addTab("123", new JPanel());
        tabs.setSelectedIndex(3);
        List<Integer> selected = new ArrayList<>();
        tabs.addChangeListener(ignored -> {
            if (delegate.activeMetadata != null) {
                selected.add(tabs.getSelectedIndex());
                delegate.observeActiveSlot();
            }
        });
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 5, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(tabs.getSelectedIndex()).isEqualTo(3);
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
            assertThat(walker.hasOwnedWork()).isFalse();
        });
        assertThat(selected).containsExactly(1, 2, 3);
        assertThat(delegate.passCompletions.get()).isOne();
        assertThat(delegate.lastResult.get().unobservedSlotCount()).isZero();
    }

    @Test
    void permanentlyMissingBinding_stopsAfterOneRetry() throws Exception {
        TestDelegate delegate = new TestDelegate();
        delegate.assumeObserved = false;
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs(new JTabbedPane()));
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 1, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> assertThat(walker.hasOwnedWork()).isFalse());
        assertThat(delegate.passCompletions.get()).isEqualTo(2);
        assertThat(delegate.walkCompleted.get()).isOne();
        assertThat(delegate.lastResult.get().unobservedSlotCount()).isEqualTo(2);
    }

    @Test
    void collapsedGroup_isRestoredAfterOnePassWithoutVisitingItsHeader() throws Exception {
        assertGroupPresentationAfterWalk(true);
    }

    @Test
    void expandedGroup_isNotToggledAfterOnePass() throws Exception {
        assertGroupPresentationAfterWalk(false);
    }

    @Test
    void twoCollapsedGroups_restoreChildrenAtDifferentHorizontalOffsets() throws Exception {
        TestDelegate delegate = new TestDelegate();
        CollapsibleTabbedPane tabs = new CollapsibleTabbedPane(true, true);
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 5, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(tabs.collapsed).isTrue();
            assertThat(tabs.secondCollapsed).isTrue();
            assertThat(tabs.toggles).isEqualTo(2);
            assertThat(tabs.getSelectedIndex()).isEqualTo(5);
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
        });
        assertThat(delegate.failures.get()).isZero();
        assertThat(delegate.passCompletions.get()).isOne();
    }

    private static void assertGroupPresentationAfterWalk(boolean collapsed) throws Exception {
        TestDelegate delegate = new TestDelegate();
        CollapsibleTabbedPane tabs = new CollapsibleTabbedPane(collapsed);
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 5, () -> List.of(tree.root()), delegate);
        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(tabs.collapsed).isEqualTo(collapsed);
            assertThat(tabs.toggles).isEqualTo(collapsed ? 1 : 0);
            assertThat(tabs.getSelectedIndex()).isEqualTo(3);
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
        });
        assertThat(delegate.failures.get()).isZero();
        assertThat(delegate.passCompletions.get()).isOne();
    }

    @Test
    void cancellation_restoresCollapsedGroupAfterSelectingAChild() throws Exception {
        TestDelegate delegate = new TestDelegate();
        CollapsibleTabbedPane tabs = new CollapsibleTabbedPane(true);
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        AtomicReference<RepeaterSwingTabWalker<String>> owner = new AtomicReference<>();
        tabs.addChangeListener(ignored -> {
            if (tabs.getSelectedIndex() == 1) {
                SwingUtilities.invokeLater(() -> owner.get().cancelAndRestore());
            }
        });
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 5, () -> List.of(tree.root()), delegate);
        owner.set(walker);
        CountDownLatch cancelled = new CountDownLatch(1);
        tabs.addChangeListener(ignored -> {
            if (tabs.getSelectedIndex() == 3 && delegate.activeMetadata == null) {
                cancelled.countDown();
            }
        });
        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(cancelled.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {
            assertThat(walker.hasOwnedWork()).isFalse();
            assertThat(tabs.collapsed).isTrue();
            assertThat(tabs.toggles).isOne();
            assertThat(tree.toolTabs().getSelectedIndex()).isZero();
        });
        assertThat(delegate.failures.get()).isZero();
    }

    private static final class CollapsibleTabbedPane extends JTabbedPane {
        @Serial
        private static final long serialVersionUID = 1L;
        private boolean collapsed;
        private boolean secondCollapsed;
        private int toggles;
        private final JPanel groupHeader = new JPanel(null);
        private final JPanel firstChildHeader = new JPanel();
        private final JPanel secondChildHeader = new JPanel();
        private JPanel secondGroupHeader;
        private JPanel thirdChildHeader;

        private CollapsibleTabbedPane(boolean initiallyCollapsed) {
            this(initiallyCollapsed, false);
        }

        private CollapsibleTabbedPane(boolean initiallyCollapsed, boolean secondGroup) {
            addTab("CurrentCreds", new JPanel());
            JLabel name = new JLabel("CurrentCreds");
            name.setBounds(0, 0, 100, 24);
            groupHeader.add(name);
            JLabel badge = new JLabel("2");
            badge.setBounds(100, 0, 20, 24);
            groupHeader.add(badge);
            JPanel chevron = new JPanel();
            addMouseListener(new java.awt.event.MouseAdapter() {
                /** {@inheritDoc} */
                @Override
                public void mouseClicked(MouseEvent event) {
                    if (event.getX() == 142 && event.getY() == 22) {
                        collapsed = !collapsed;
                        toggles++;
                        CollapsibleTabbedPane.this.doLayout();
                    } else if (secondGroupHeader != null && event.getX() == 492 && event.getY() == 22) {
                        secondCollapsed = !secondCollapsed;
                        toggles++;
                        CollapsibleTabbedPane.this.doLayout();
                    }
                }
            });
            chevron.setBounds(120, 0, 20, 24);
            groupHeader.add(chevron);
            setTabComponentAt(0, groupHeader);
            addTab("Access", new JPanel());
            setTabComponentAt(1, firstChildHeader);
            addTab("Open", new JPanel());
            setTabComponentAt(2, secondChildHeader);
            if (secondGroup) {
                secondGroupHeader = new JPanel(null);
                JLabel secondName = new JLabel("Open-Findings");
                secondName.setBounds(0, 0, 100, 24);
                secondGroupHeader.add(secondName);
                JLabel secondBadge = new JLabel("1");
                secondBadge.setBounds(100, 0, 20, 24);
                secondGroupHeader.add(secondBadge);
                addTab("Open-Findings", new JPanel());
                setTabComponentAt(3, secondGroupHeader);
                thirdChildHeader = new JPanel();
                addTab("VersionDisclosure1", new JPanel());
                setTabComponentAt(4, thirdChildHeader);
                secondCollapsed = true;
            }
            addTab("123", new JPanel());
            setSelectedIndex(secondGroup ? 5 : 3);
            collapsed = initiallyCollapsed;
            addChangeListener(ignored -> {
                if (getSelectedIndex() == 1 || getSelectedIndex() == 2) {
                    collapsed = false;
                    doLayout();
                } else if (secondGroupHeader != null && getSelectedIndex() == 4) {
                    secondCollapsed = false;
                    doLayout();
                }
            });
            doLayout();
        }

        /** {@inheritDoc} */
        @Override
        public void doLayout() {
            if (groupHeader == null) {
                return;
            }
            groupHeader.setBounds(10, 10, 140, 24);
            firstChildHeader.setBounds(collapsed ? -33 : 160, collapsed ? -5 : 10, 80, 24);
            secondChildHeader.setBounds(collapsed ? -33 : 250, collapsed ? -5 : 10, 80, 24);
            if (secondGroupHeader != null) {
                secondGroupHeader.setBounds(360, 10, 140, 24);
                thirdChildHeader.setBounds(secondCollapsed ? 150 : 510,
                        secondCollapsed ? -5 : 10, 173, 24);
            }
        }
    }

    @Test
    void singleTab_observesBindingDuringToolActivationWithoutAnotherWalk() throws Exception {
        TestDelegate delegate = new TestDelegate();
        delegate.assumeObserved = false;
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Only", new JPanel());
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        tree.toolTabs().addChangeListener(ignored -> {
            if (tree.toolTabs().getSelectedComponent() == tree.repeaterRoot()) {
                delegate.observeActiveSlot();
            }
        });
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 1, () -> List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(delegate.observedSlots).containsExactly("0:0");
        assertThat(delegate.passCompletions.get()).isOne();
    }

    @Test
    void unavailableRoot_isRetriedOnceAndCanRecover() throws Exception {
        TestDelegate delegate = new TestDelegate();
        SwingTree tree = swingTreeWithRepeaterRoot(requestTabs(new JTabbedPane()));
        AtomicInteger plans = new AtomicInteger();
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 1,
                () -> plans.incrementAndGet() == 1 ? List.of() : List.of(tree.root()), delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(plans.get()).isEqualTo(2);
        assertThat(delegate.passCompletions.get()).isOne();
        assertThat(delegate.unavailablePasses.get()).isOne();
    }

    @Test
    void restorationFailure_doesNotScheduleAnotherSelectionPass() throws Exception {
        TestDelegate delegate = new TestDelegate();
        FailingTabbedPane tabs = requestTabs(new FailingTabbedPane());
        tabs.addChangeListener(ignored -> {
            if (tabs.getSelectedIndex() == 1) {
                tabs.failBeforeSelecting(0);
            }
        });
        SwingTree tree = swingTreeWithRepeaterRoot(tabs);
        AtomicInteger plans = new AtomicInteger();
        RepeaterSwingTabWalker<String> walker = new RepeaterSwingTabWalker<>(
                "Repeater", 1, 1, 1, () -> {
                    plans.incrementAndGet();
                    return List.of(tree.root());
                }, delegate);

        SwingUtilities.invokeAndWait(() -> walker.schedule(1));
        assertThat(delegate.completed.await(2, TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> assertThat(walker.hasOwnedWork()).isFalse());
        assertThat(plans.get()).isOne();
        assertThat(delegate.lastFailure.get().restorationFailureCount()).isOne();
        assertThat(tree.toolTabs().getSelectedIndex()).isZero();
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
        private final AtomicInteger unavailablePasses = new AtomicInteger();
        private final CountDownLatch unavailable = new CountDownLatch(1);
        private final Set<String> observedSlots = ConcurrentHashMap.newKeySet();
        private final AtomicReference<RepeaterSwingTabWalker.PassResult> lastResult = new AtomicReference<>();
        private boolean assumeObserved = true;
        private String activeMetadata;
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
        public void setActiveMetadata(String metadata) {
            activeMetadata = metadata;
        }

        @Override
        public boolean hasObservedBinding(String metadata) {
            return assumeObserved || observedSlots.contains(metadata);
        }

        private void observeActiveSlot() {
            if (activeMetadata != null) {
                observedSlots.add(activeMetadata);
            }
        }

        @Override
        public void onPassUnavailable(int passNumber, int delayMs) {
            unavailablePasses.incrementAndGet();
            unavailable.countDown();
        }

        @Override
        public void onPassCompleted(
                int passNumber,
                int delayMs,
                RepeaterSwingTabWalker.PassResult result) {
            passCompletions.incrementAndGet();
            lastResult.set(result);
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
