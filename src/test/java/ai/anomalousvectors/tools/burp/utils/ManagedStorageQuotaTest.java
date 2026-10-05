package ai.anomalousvectors.tools.burp.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import ai.anomalousvectors.tools.burp.testutils.TestPathSupport;

/** Tests cross-instance, per-project managed-storage accounting. */
class ManagedStorageQuotaTest {

    private Path testRoot;
    private Path managedDirectory;

    @BeforeEach
    void initializeManagedRoot() throws Exception {
        testRoot = TestPathSupport.createDirectory("managed-quota-parent").resolve("managed");
        ManagedDiskPaths.setManagedRootForTests(testRoot);
        ManagedDiskPaths.initialize();
        managedDirectory = directoryForProject("default-project");
    }

    @AfterEach
    void resetManagedRoot() throws IOException {
        ManagedDiskPaths.resetForTests();
        deleteTree(testRoot);
    }

    @Test
    void reserve_enforcesCapsPerProjectNotAcrossTheSharedRoot() throws Exception {
        try (ManagedStorageQuota.Reservation projectA = reserve("project-a", 8L, 10L);
                ManagedStorageQuota.Reservation projectB = reserve("project-b", 8L, 10L)) {
            assertThat(projectA.accepted()).isTrue();
            assertThat(projectB.accepted()).isTrue();
            projectA.commit();
            projectB.commit();
        }

        try (ManagedStorageQuota.Reservation projectAOverflow = reserve("project-a", 3L, 10L);
                ManagedStorageQuota.Reservation projectBRemaining = reserve("project-b", 2L, 10L)) {
            assertThat(projectAOverflow.accepted()).isFalse();
            assertThat(projectBRemaining.accepted()).isTrue();
            projectBRemaining.commit();
        }
    }

    @Test
    void close_withoutCommitRollsBackReservation() throws Exception {
        try (ManagedStorageQuota.Reservation reservation = reserve("rollback", 10L, 10L)) {
            assertThat(reservation.accepted()).isTrue();
        }

        try (ManagedStorageQuota.Reservation retry = reserve("rollback", 10L, 10L)) {
            assertThat(retry.accepted()).isTrue();
            retry.commit();
        }
    }

    @Test
    void reconcile_preservesQuotaForAProjectOwnedByARetainedInstance() throws Exception {
        Path retained = directoryForProject("retained-project");
        try (ManagedStorageQuota.Reservation existing = reserve(retained, "retained-project", 8L, 10L)) {
            assertThat(existing.accepted()).isTrue();
            existing.commit();
        }

        ManagedStorageQuota.reconcileAll();

        try (ManagedStorageQuota.Reservation overflow =
                reserve(retained, "retained-project", 3L, 10L)) {
            assertThat(overflow.accepted()).isFalse();
        }
    }

    @Test
    void reconcile_clearsCrashStaleQuotaWhenNoInstanceRetainsTheProject() throws Exception {
        Path stale = directoryForProject("stale-project");
        try (ManagedStorageQuota.Reservation existing = reserve(stale, "stale-project", 8L, 10L)) {
            assertThat(existing.accepted()).isTrue();
            existing.commit();
        }
        Files.delete(stale);
        Files.delete(stale.getParent());

        ManagedStorageQuota.reconcileAll();

        Path replacement = directoryForProject("stale-project");
        try (ManagedStorageQuota.Reservation full = reserve(replacement, "stale-project", 10L, 10L)) {
            assertThat(full.accepted()).isTrue();
            full.commit();
        }
    }

    @Test
    void concurrentReservationsCannotExceedOneProjectCap() throws Exception {
        List<Callable<Boolean>> calls = new ArrayList<>();
        for (int index = 0; index < 20; index++) {
            calls.add(() -> {
                try (ManagedStorageQuota.Reservation reservation = reserve("concurrent", 1L, 10L)) {
                    if (reservation.accepted()) {
                        reservation.commit();
                        return true;
                    }
                    return false;
                }
            });
        }
        try (var executor = Executors.newFixedThreadPool(8)) {
            long accepted = executor.invokeAll(calls).stream()
                    .filter(future -> {
                        try {
                            return future.get();
                        } catch (Exception e) {
                            throw new AssertionError(e);
                        }
                    })
                    .count();
            assertThat(accepted).isEqualTo(10L);
        }
    }

    @Test
    void reservation_holdsProjectLockUntilCommitSoReconciliationCannotLoseIt() throws Exception {
        CountDownLatch attempted = new CountDownLatch(1);
        try (var executor = Executors.newSingleThreadExecutor();
                ManagedStorageQuota.Reservation first = reserve("locked", 8L, 10L)) {
            var competing = executor.submit(() -> {
                attempted.countDown();
                return reserve("locked", 3L, 10L);
            });

            assertThat(attempted.await(5L, TimeUnit.SECONDS)).isTrue();
            assertThat(competing).isNotDone();
            first.commit();

            try (ManagedStorageQuota.Reservation second = competing.get(5L, TimeUnit.SECONDS)) {
                assertThat(second.accepted()).isFalse();
            }
        }
    }

    private ManagedStorageQuota.Reservation reserve(String project, long bytes, long maximum)
            throws IOException {
        return reserve(directoryForProject(project), project, bytes, maximum);
    }

    private ManagedStorageQuota.Reservation reserve(
            Path directory, String project, long bytes, long maximum) throws IOException {
        return ManagedStorageQuota.reserve(
                directory,
                ManagedStorageQuota.Category.TRAFFIC_SPILL,
                project,
                bytes,
                maximum);
    }

    private Path directoryForProject(String project) throws IOException {
        Path projects = managedDirectory == null
                ? ManagedDiskPaths.spillDirectory().getParent().getParent()
                : managedDirectory.getParent().getParent();
        return ManagedDiskPaths.ensureManagedDirectory(projects.resolve(project).resolve("spill"));
    }

    private static void deleteTree(Path root) throws IOException {
        if (root == null || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted((left, right) -> right.compareTo(left)).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}
