package ai.anomalousvectors.tools.burp.ui;

import java.io.Serial;
import java.util.ArrayList;
import java.util.List;

import ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket;
import ai.anomalousvectors.tools.burp.utils.ExportStats;
import ai.anomalousvectors.tools.burp.utils.FileExportStats;

/** Immutable database/file count-table values shared by Swing and clipboard rendering. */
record SinkCountTableSnapshot(List<String> columns, List<Row> rows) {

    static final String SUBROW_INDENT = "    ";
    private static final List<String> FILE_COLUMNS = List.of(
            "Index",
            "Written",
            "Failures",
            "Retry Attempts",
            "Baseline",
            "Appended",
            "Final Size",
            "Integrity",
            "Last Append (ms)",
            "Last Error");
    private static final List<String> DATABASE_COLUMNS = List.of(
            "Index",
            "Exported",
            "Failures",
            "Queued",
            "Recovered Failures",
            "Retry Drops",
            "Permanent Drops",
            "Last Bulk (ms)",
            "Last Error");

    SinkCountTableSnapshot {
        columns = List.copyOf(columns);
        rows = List.copyOf(rows);
        for (Row row : rows) {
            if (row.values().size() != columns.size()) {
                throw new IllegalArgumentException("Sink count row width does not match its columns");
            }
        }
    }

    /** Immutable typed row whose numeric values remain sortable in the Swing table. */
    record Row(List<Object> values) {
        Row {
            values = List.copyOf(values);
        }

        Object[] toSwingValues() {
            return values.toArray();
        }

        String[] toTextValues() {
            return values.stream()
                    .map(SinkCountTableSnapshot::formatTextValue)
                    .toArray(String[]::new);
        }
    }

    /** Returns the stable File Counts column schema. */
    static List<String> fileColumns() {
        return FILE_COLUMNS;
    }

    /** Returns the stable Database Counts column schema. */
    static List<String> databaseColumns() {
        return DATABASE_COLUMNS;
    }

    /** Samples the complete File Counts table, including traffic sub-rows and Total. */
    static SinkCountTableSnapshot file() {
        List<Row> rows = new ArrayList<>();
        List<String> sortedKeys = FileExportStats.getIndexKeys().stream()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .toList();
        long totalSuccess = 0L;
        long totalFailure = 0L;
        long totalRetryAttempts = 0L;
        long totalBaselineBytes = 0L;
        long totalAppendedBytes = 0L;
        long totalFinalBytes = 0L;
        boolean anyArtifacts = false;
        boolean anyIntegrityFailure = false;
        boolean anyIntegrityPending = false;
        for (String indexKey : sortedKeys) {
            long written = FileExportStats.getWrittenCount(indexKey);
            long failure = FileExportStats.getFailureCount(indexKey);
            long retryAttempts = FileExportStats.getRetryAttemptCount(indexKey);
            long artifactCount = FileExportStats.getArtifactCount(indexKey);
            long baselineBytes = FileExportStats.getArtifactBaselineBytes(indexKey);
            long appendedBytes = FileExportStats.getExportedBytes(indexKey);
            long finalBytes = FileExportStats.getArtifactFinalBytes(indexKey);
            FileExportStats.ArtifactIntegrity integrity = FileExportStats.getArtifactIntegrity(indexKey);
            boolean selected = artifactCount > 0L;
            long lastWriteMs = FileExportStats.getLastWriteDurationMs(indexKey);
            totalSuccess += written;
            totalFailure += failure;
            totalRetryAttempts += retryAttempts;
            totalBaselineBytes += baselineBytes;
            totalAppendedBytes += appendedBytes;
            totalFinalBytes += finalBytes;
            anyArtifacts |= selected;
            anyIntegrityFailure |= integrity == FileExportStats.ArtifactIntegrity.FAILED;
            anyIntegrityPending |= integrity == FileExportStats.ArtifactIntegrity.PENDING;
            rows.add(row(
                    StatsPanelFormatters.formatKeyLabel(indexKey),
                    written,
                    failure,
                    retryAttempts,
                    selected ? new HumanByteCount(baselineBytes) : "-",
                    selected ? new HumanByteCount(appendedBytes) : "-",
                    isComplete(integrity) ? new HumanByteCount(finalBytes) : "-",
                    fileIntegrityLabel(integrity),
                    lastWriteMs >= 0L ? lastWriteMs : "-",
                    nullToDash(FileExportStats.getLastError(indexKey))));
            if ("traffic".equalsIgnoreCase(indexKey)) {
                appendFileTrafficRows(rows);
            }
        }
        rows.add(row(
                "Total",
                totalSuccess,
                totalFailure,
                totalRetryAttempts,
                anyArtifacts ? new HumanByteCount(totalBaselineBytes) : "-",
                anyArtifacts ? new HumanByteCount(totalAppendedBytes) : "-",
                !anyArtifacts || anyIntegrityPending ? "-" : new HumanByteCount(totalFinalBytes),
                combinedIntegrityLabel(anyArtifacts, anyIntegrityFailure, anyIntegrityPending),
                "-",
                "-"));
        return new SinkCountTableSnapshot(FILE_COLUMNS, rows);
    }

    /** Samples the complete Database Counts table, including traffic sub-rows and Total. */
    static SinkCountTableSnapshot database() {
        List<Row> rows = new ArrayList<>();
        List<String> sortedKeys = ExportStats.getIndexKeys().stream()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .toList();
        long totalSuccess = 0L;
        long totalQueued = 0L;
        long totalRetryDrops = 0L;
        long totalPermanentDrops = 0L;
        long totalFailure = 0L;
        long totalRecovered = 0L;
        for (String indexKey : sortedKeys) {
            long exported = ExportStats.getExportedCount(indexKey);
            int queued = ExportStats.getQueueSize(indexKey);
            long retryDrops = ExportStats.getRetryQueueDrops(indexKey);
            long permanentDrops = ExportStats.getPermanentDrops(indexKey);
            long failure = ExportStats.getFailureCount(indexKey);
            long recovered = ExportStats.getRecoveredFailureCount(indexKey);
            long lastBulkMs = "traffic".equalsIgnoreCase(indexKey)
                    ? ExportStats.getLastLiveBulkDurationMs(indexKey)
                    : -1L;
            totalSuccess += exported;
            totalQueued += queued;
            totalRetryDrops += retryDrops;
            totalPermanentDrops += permanentDrops;
            totalFailure += failure;
            totalRecovered += recovered;
            rows.add(row(
                    StatsPanelFormatters.formatKeyLabel(indexKey),
                    exported,
                    failure,
                    queued,
                    recovered,
                    retryDrops,
                    permanentDrops,
                    lastBulkMs >= 0L ? lastBulkMs : "-",
                    nullToDash(ExportStats.getLastError(indexKey))));
            if ("traffic".equalsIgnoreCase(indexKey)) {
                appendDatabaseTrafficRows(rows);
            }
        }
        rows.add(row(
                "Total",
                totalSuccess,
                totalFailure,
                totalQueued,
                totalRecovered,
                totalRetryDrops,
                totalPermanentDrops,
                "-",
                "-"));
        return new SinkCountTableSnapshot(DATABASE_COLUMNS, rows);
    }

    /** Returns rows rendered with the same text used by table-cell display. */
    List<String[]> textRows() {
        return rows.stream().map(row -> row.toTextValues()).toList();
    }

    private static void appendFileTrafficRows(List<Row> rows) {
        for (String sourceKey : FileExportStats.getTrafficToolTypeKeys()) {
            if (!"UNKNOWN".equals(sourceKey)) {
                rows.add(row(
                        SUBROW_INDENT + StatsPanelFormatters.formatKeyLabel(sourceKey),
                        TrafficRouteBucket.resolveFileSourceSuccess(sourceKey),
                        TrafficRouteBucket.resolveFileSourceFailure(sourceKey),
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-"));
            }
        }
    }

    private static void appendDatabaseTrafficRows(List<Row> rows) {
        for (String sourceKey : ExportStats.getTrafficToolTypeKeys()) {
            if (!"UNKNOWN".equals(sourceKey)) {
                rows.add(row(
                        SUBROW_INDENT + StatsPanelFormatters.formatKeyLabel(sourceKey),
                        TrafficRouteBucket.resolveOpenSearchSourceSuccess(sourceKey),
                        TrafficRouteBucket.resolveOpenSearchSourceFailure(sourceKey),
                        ExportStats.getTrafficDisplaySourceQueueSize(sourceKey),
                        TrafficRouteBucket.resolveOpenSearchSourceRecovery(sourceKey),
                        TrafficRouteBucket.resolveOpenSearchSourceRetryQueueDrops(sourceKey),
                        TrafficRouteBucket.resolveOpenSearchSourcePermanentDrops(sourceKey),
                        "-",
                        "-"));
            }
        }
    }

    private static Row row(Object... values) {
        return new Row(List.of(values));
    }

    private static boolean isComplete(FileExportStats.ArtifactIntegrity integrity) {
        return integrity == FileExportStats.ArtifactIntegrity.OK
                || integrity == FileExportStats.ArtifactIntegrity.FAILED;
    }

    private static String fileIntegrityLabel(FileExportStats.ArtifactIntegrity integrity) {
        return switch (integrity) {
            case PENDING -> "Pending";
            case OK -> "OK";
            case FAILED -> "Failed";
            case NOT_SELECTED -> "Not selected";
        };
    }

    private static String combinedIntegrityLabel(
            boolean anyArtifacts,
            boolean anyIntegrityFailure,
            boolean anyIntegrityPending) {
        if (!anyArtifacts) {
            return "Not selected";
        }
        if (anyIntegrityFailure) {
            return "Failed";
        }
        return anyIntegrityPending ? "Pending" : "OK";
    }

    private static String nullToDash(String value) {
        return value == null ? "-" : value;
    }

    private static String formatTextValue(Object value) {
        if (value instanceof HumanByteCount bytes) {
            return bytes.toString();
        }
        if (value instanceof Number number) {
            return StatsPanelFormatters.formatWhole(number.longValue());
        }
        return String.valueOf(value);
    }

    /** Sortable numeric byte value whose Swing display retains the existing IEC labels. */
    private static final class HumanByteCount extends Number implements Comparable<HumanByteCount> {
        @Serial private static final long serialVersionUID = 1L;

        private final long bytes;

        private HumanByteCount(long bytes) {
            this.bytes = bytes;
        }

        @Override
        public int intValue() {
            return (int) bytes;
        }

        @Override
        public long longValue() {
            return bytes;
        }

        @Override
        public float floatValue() {
            return bytes;
        }

        @Override
        public double doubleValue() {
            return bytes;
        }

        @Override
        public int compareTo(HumanByteCount other) {
            return Long.compare(bytes, other.bytes);
        }

        @Override
        public String toString() {
            return StatsPanelFormatters.formatBytesHuman(bytes);
        }
    }
}
