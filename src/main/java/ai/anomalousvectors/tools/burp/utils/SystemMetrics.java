package ai.anomalousvectors.tools.burp.utils;

import java.lang.management.BufferPoolMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import java.util.List;

/**
 * JVM heap and process resource metrics for admission and reporting.
 *
 * <p>Centralized so the periodic exporter stats snapshot, the Stats panel Misc Stats card, and
 * the plain-text stats summary use the same collection logic. Admission uses only
 * {@link #heapSnapshot()}, avoiding unrelated JMX and native process queries on traffic threads.
 * Reporting fields are collected independently and fall back to {@code -1} (or {@code NaN} for
 * CPU load) when unavailable.</p>
 */
public final class SystemMetrics {

    private SystemMetrics() {}

    /**
     * Immutable heap readings used by resource admission and full process snapshots.
     *
     * @param heapUsedBytes committed heap minus currently free heap
     * @param heapCommittedBytes heap currently allocated to the JVM
     * @param heapMaxBytes maximum heap reported by the JVM
     */
    public record HeapSnapshot(long heapUsedBytes, long heapCommittedBytes, long heapMaxBytes) {}

    /**
     * Samples heap usage without collecting JMX or operating-system process metrics.
     *
     * <p>Thread-safe and uncached so admission uses current heap headroom. The runtime readings
     * are not atomic with respect to allocation or garbage collection.</p>
     *
     * @return immutable heap readings shared with full process reporting
     */
    public static HeapSnapshot heapSnapshot() {
        Runtime rt = Runtime.getRuntime();
        long committed = rt.totalMemory();
        long used = Math.max(-1L, committed - rt.freeMemory());
        return new HeapSnapshot(used, committed, rt.maxMemory());
    }

    /**
     * Immutable process-wide resource snapshot.
     *
     * <p>Negative numeric fields signal "unavailable" - either JMX failed to report or the
     * platform does not expose the metric. {@link #processCpuLoad} returns {@link Double#NaN}
     * when the {@code com.sun.management} extension is not reachable (for example on non-HotSpot
     * JVMs or restricted security managers).</p>
     *
     * <p>{@code heapCommittedBytes} is the heap currently allocated from the OS
     * ({@link Runtime#totalMemory()}). It bounds {@code heapUsedBytes} from above and
     * tracks more closely with process RSS than {@code heapUsedBytes} alone -- HotSpot does not
     * eagerly return committed heap to the OS after a peak, so committed often stays high after
     * used drops, which is what makes Task Manager / RSS still look elevated post-Stop.</p>
     */
    public record Snapshot(
            long heapUsedBytes,
            long heapCommittedBytes,
            long heapMaxBytes,
            long nonHeapUsedBytes,
            long nonHeapMaxBytes,
            int threadCount,
            int peakThreadCount,
            long gcCollectionCount,
            long gcCollectionTimeMs,
            double processCpuLoad,
            long directBufferUsedBytes,
            long mappedBufferUsedBytes) {}

    /**
     * Collects a full process snapshot for periodic or user-requested reporting.
     *
     * <p>Thread-safe, but JMX and native process queries may be costly. Use
     * {@link #heapSnapshot()} for heap-only admission checks.</p>
     *
     * @return immutable resource readings with unavailable reporting fields marked by sentinels
     */
    public static Snapshot snapshot() {
        HeapSnapshot heap = heapSnapshot();

        long nonHeapUsed = -1L;
        long nonHeapMax = -1L;
        int threadCount = -1;
        int peakThreadCount = -1;
        long gcCount = -1L;
        long gcTimeMs = -1L;
        double processCpuLoad = Double.NaN;

        try {
            MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
            MemoryUsage nonHeap = memoryBean.getNonHeapMemoryUsage();
            if (nonHeap != null) {
                nonHeapUsed = nonHeap.getUsed() >= 0 ? nonHeap.getUsed() : -1L;
                nonHeapMax = nonHeap.getMax() >= 0 ? nonHeap.getMax() : -1L;
            }
        } catch (RuntimeException ignored) {
            // JMX may be restricted in some environments.
        }

        try {
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            threadCount = Math.max(-1, threadBean.getThreadCount());
            peakThreadCount = Math.max(-1, threadBean.getPeakThreadCount());
        } catch (RuntimeException ignored) {
            // Thread bean may be disabled; keep defaults.
        }

        try {
            List<GarbageCollectorMXBean> gcBeans = ManagementFactory.getGarbageCollectorMXBeans();
            long counts = 0L;
            long times = 0L;
            boolean any = false;
            for (GarbageCollectorMXBean gc : gcBeans) {
                long c = gc.getCollectionCount();
                long t = gc.getCollectionTime();
                if (c >= 0) {
                    counts += c;
                    any = true;
                }
                if (t >= 0) {
                    times += t;
                    any = true;
                }
            }
            if (any) {
                gcCount = counts;
                gcTimeMs = times;
            }
        } catch (RuntimeException ignored) {
            // GC beans may be unavailable; keep defaults.
        }

        try {
            OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
            if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOs) {
                double load = sunOs.getProcessCpuLoad();
                if (load >= 0.0) {
                    processCpuLoad = load;
                }
            }
        } catch (RuntimeException | LinkageError ignored) {
            // Non-HotSpot JVM or restricted; leave as NaN.
        }

        // Off-heap buffer pool totals (NIO direct + memory-mapped). These do not count against
        // heap_used or non_heap_used; they are separate process-level allocations tracked by the
        // JVM. Reporting them closes the observability gap where HTTP client TLS buffers and
        // other direct allocations inflate RSS without showing up in heap metrics.
        long directBufferUsed = -1L;
        long mappedBufferUsed = -1L;
        try {
            for (BufferPoolMXBean pool : ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class)) {
                String name = pool.getName();
                long used = pool.getMemoryUsed();
                if (used < 0) {
                    continue;
                }
                if ("direct".equals(name)) {
                    directBufferUsed = used;
                } else if ("mapped".equals(name)) {
                    mappedBufferUsed = used;
                }
            }
        } catch (RuntimeException ignored) {
            // BufferPoolMXBean may be unavailable on some JVMs; keep defaults.
        }

        return new Snapshot(
                heap.heapUsedBytes(),
                heap.heapCommittedBytes(),
                heap.heapMaxBytes(),
                nonHeapUsed,
                nonHeapMax,
                threadCount,
                peakThreadCount,
                gcCount,
                gcTimeMs,
                processCpuLoad,
                directBufferUsed,
                mappedBufferUsed);
    }
}
