package ai.anomalousvectors.tools.burp.sinks;

import java.util.concurrent.atomic.AtomicReference;

import ai.anomalousvectors.tools.burp.utils.concurrent.ExportRunContext;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig;
import ai.anomalousvectors.tools.burp.utils.config.RuntimeConfig.ExportRunToken;

/** Keeps one reporter pass active per run without letting an old pass release its successor. */
final class ReporterRunActivity {
    private final AtomicReference<ExportRunToken> owner = new AtomicReference<>();

    boolean tryEnter() {
        ExportRunToken token = ExportRunContext.captureToken();
        while (RuntimeConfig.isExportRunActive(token)) {
            ExportRunToken previous = owner.get();
            if (previous != null && RuntimeConfig.isExportRunActive(previous)) return false;
            if (owner.compareAndSet(previous, token)) return true;
        }
        return false;
    }

    void exit() {
        owner.compareAndSet(ExportRunContext.captureToken(), null);
    }

    void clear() {
        owner.set(null);
    }
}
