package ai.anomalousvectors.tools.burp.sinks;

import java.util.Set;
import java.util.HashSet;
import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/**
 * Per-export-run set of stable item keys already exported during backlog or periodic polls.
 *
 * <p>Periodic sitemap/findings polls skip known keys without building documents. Cleared on
 * reporter {@code stop()}.</p>
 */
final class PeriodicExportSeenKeys {

    private Set<String> seenKeys = new HashSet<>();
    private ExportRunToken token;

    // Swapping the set keeps a late old-run preparation from repopulating a new run's keys.
    private boolean selectRun() {
        if (ExportRunContext.isStale()) return false;
        ExportRunToken owner = ExportRunContext.captureToken();
        if (!owner.equals(token)) {
            seenKeys = new HashSet<>();
            token = owner;
        }
        return true;
    }

    synchronized void recordSeen(String itemKey) {
        if (itemKey == null || itemKey.isBlank()) {
            return;
        }
        if (selectRun()) seenKeys.add(itemKey);
    }

    synchronized boolean isNew(String itemKey) {
        if (itemKey == null || itemKey.isBlank()) {
            return false;
        }
        return selectRun() && !seenKeys.contains(itemKey);
    }

    synchronized boolean claimNew(String itemKey) {
        if (itemKey == null || itemKey.isBlank()) {
            return false;
        }
        return selectRun() && seenKeys.add(itemKey);
    }

    synchronized void clear() {
        seenKeys = new HashSet<>();
        token = null;
    }

    synchronized int trackedCount() {
        return selectRun() ? seenKeys.size() : 0;
    }
}
