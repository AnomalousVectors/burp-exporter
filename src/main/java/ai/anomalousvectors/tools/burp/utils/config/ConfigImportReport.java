package ai.anomalousvectors.tools.burp.utils.config;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Collects non-fatal issues encountered while importing configuration JSON.
 *
 * <p>Warnings are surfaced in the log panel and control status after a successful import; they do
 * not prevent recognized settings from being applied.</p>
 *
 * <p>Not thread-safe. One import operation owns the report until it hands the result to the UI.</p>
 */
public final class ConfigImportReport {

    /**
     * Categories of skipped import content.
     */
    public enum Kind {
        /** Object key not present in {@link ConfigImportCatalog}. */
        UNKNOWN_KEY,
        /** List or scalar value not in the known set for its JSON path. */
        UNKNOWN_VALUE,
        /** Unsupported entry in {@code sinks.files.formats}. */
        UNSUPPORTED_FORMAT,
        /** Scope shorthand array value other than {@code all} or {@code burp}. */
        UNRECOGNIZED_SCOPE,
        /** Value removed because it is unavailable in the current Burp edition. */
        EDITION_STRIPPED
    }

    /**
     * One skipped key or value with its JSON path for operator messaging.
     *
     * @param kind classification used for log and status formatting
     * @param jsonPath dotted path (e.g. {@code dataSources}, {@code exportFields.traffic})
     * @param rejectedValue raw value from the file, or {@code <unspecified>} when absent
     */
    public record Warning(Kind kind, String jsonPath, String rejectedValue) { }

    private final List<Warning> warnings = new ArrayList<>();

    /**
     * Records a skipped key or value. Null or blank {@code jsonPath} entries are ignored.
     *
     * @param kind warning category; {@code null} is ignored
     * @param jsonPath dotted JSON path; null or blank is ignored
     * @param rejectedValue rejected value; null or blank uses an unspecified-value label
     */
    public void add(Kind kind, String jsonPath, String rejectedValue) {
        if (kind == null || jsonPath == null || jsonPath.isBlank()) {
            return;
        }
        String value = rejectedValue == null || rejectedValue.isBlank()
                ? "<unspecified>"
                : rejectedValue.trim();
        warnings.add(new Warning(kind, jsonPath.trim(), value));
    }

    /** Returns whether no skipped settings have been recorded. */
    public boolean isEmpty() {
        return warnings.isEmpty();
    }

    /** Returns the number of recorded skipped-setting warnings. */
    public int warningCount() {
        return warnings.size();
    }

    /**
     * Returns a read-only view of warnings in encounter order.
     *
     * @return unmodifiable view that reflects any later additions to this report
     */
    public List<Warning> warnings() {
        return Collections.unmodifiableList(warnings);
    }

    /**
     * Returns INFO log lines describing skipped settings (capped).
     *
     * @param maxLines maximum warning lines before an overflow summary; non-positive uses 20
     * @return empty when there are no warnings; otherwise lines suitable for the Log panel
     */
    public List<String> formatLogLines(int maxLines) {
        if (warnings.isEmpty()) {
            return List.of();
        }
        int cap = maxLines <= 0 ? 20 : maxLines;
        List<String> lines = new ArrayList<>();
        lines.add("[Config] Import applied recognized settings; "
                + warningCount() + " value(s) were not recognized and were skipped:");
        int shown = 0;
        for (Warning warning : warnings) {
            if (shown >= cap) {
                int remaining = warningCount() - cap;
                if (remaining > 0) {
                    lines.add("[Config]   … and " + remaining + " more skipped value(s).");
                }
                break;
            }
            lines.add("[Config]   " + formatWarningLine(warning));
            shown++;
        }
        lines.add("[Config] All other settings from the file were applied.");
        return List.copyOf(lines);
    }

    /**
     * Returns a multi-line control-status message after a successful import.
     *
     * @param importPath source file path shown to the operator; may be {@code null}
     * @return single-line success text when there are no warnings; otherwise a short summary
     */
    public String formatControlStatusSummary(Path importPath) {
        String pathLabel = importPath == null ? "configuration file" : importPath.toString();
        if (warnings.isEmpty()) {
            return "Imported configuration from: " + pathLabel;
        }
        StringBuilder out = new StringBuilder();
        out.append("Imported configuration from: ").append(pathLabel).append('\n');
        out.append(warningCount()).append(" setting(s) were not recognized and were skipped.").append('\n');
        int cap = 5;
        int shown = 0;
        for (Warning warning : warnings) {
            if (shown >= cap) {
                int remaining = warningCount() - cap;
                if (remaining > 0) {
                    out.append("… and ").append(remaining).append(" more.").append('\n');
                }
                break;
            }
            out.append("Skipped: ").append(formatWarningBrief(warning)).append('\n');
            shown++;
        }
        out.append("All other settings were applied.");
        return out.toString();
    }

    private static String formatWarningLine(Warning warning) {
        return switch (warning.kind()) {
            case UNKNOWN_KEY -> warning.jsonPath() + " (unknown key)";
            case UNKNOWN_VALUE -> warning.jsonPath() + " = \"" + warning.rejectedValue() + "\"";
            case UNSUPPORTED_FORMAT -> warning.jsonPath() + " = \"" + warning.rejectedValue() + "\"";
            case UNRECOGNIZED_SCOPE -> warning.jsonPath() + " = \"" + warning.rejectedValue() + "\"";
            case EDITION_STRIPPED -> warning.jsonPath() + " = \"" + warning.rejectedValue()
                    + "\" (not available in this edition)";
        };
    }

    private static String formatWarningBrief(Warning warning) {
        return switch (warning.kind()) {
            case UNKNOWN_KEY -> warning.jsonPath();
            case EDITION_STRIPPED -> warning.jsonPath() + " \"" + warning.rejectedValue() + "\" (edition)";
            default -> warning.jsonPath() + " \"" + warning.rejectedValue() + "\"";
        };
    }
}
