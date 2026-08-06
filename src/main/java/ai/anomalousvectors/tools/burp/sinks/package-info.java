/**
 * Turns Burp sources into exporter output for search database and file destinations.
 *
 * <p>This package houses:</p>
 * <ul>
 *   <li><b>Traffic reporters</b> — {@link ai.anomalousvectors.tools.burp.sinks.TrafficHttpHandler},
 *       {@link ai.anomalousvectors.tools.burp.sinks.ProxyLiveMetadataCorrelator},
 *       {@link ai.anomalousvectors.tools.burp.sinks.ProxyHistoryIndexReporter},
 *       {@link ai.anomalousvectors.tools.burp.sinks.ProxyWebSocketIndexReporter},
 *       {@link ai.anomalousvectors.tools.burp.sinks.ToolWebSocketLiveHandler},
 *       {@link ai.anomalousvectors.tools.burp.sinks.RepeaterTabsIndexReporter} — that feed
 *       the shared {@code traffic} index.</li>
 *   <li><b>Non-traffic reporters</b> —
 *       {@link ai.anomalousvectors.tools.burp.sinks.SitemapIndexReporter},
 *       {@link ai.anomalousvectors.tools.burp.sinks.FindingsIndexReporter},
 *       {@link ai.anomalousvectors.tools.burp.sinks.ExporterIndexConfigReporter},
 *       {@link ai.anomalousvectors.tools.burp.sinks.ExporterIndexStatsReporter} — that write
 *       their own domain indices.</li>
 *   <li><b>Parameter integrity</b> — {@link ai.anomalousvectors.tools.burp.sinks.BodyContentEncodingSupport},
 *       session-boundary rollups ({@link ai.anomalousvectors.tools.burp.sinks.ParameterIntegritySessionLog},
 *       {@link ai.anomalousvectors.tools.burp.sinks.BodyEnumerationSkippedLog},
 *       {@link ai.anomalousvectors.tools.burp.sinks.CompressedWireBodyParamsLog}), and Stats /
 *       exporter {@code stats_snapshot} stats for operator reconciliation.</li>
 *   <li><b>Shared infrastructure</b> —
 *       {@link ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue} bounded queue and spill,
 *       {@link ai.anomalousvectors.tools.burp.sinks.FileExportService} file-sink writer,
 *       {@link ai.anomalousvectors.tools.burp.sinks.SearchRecoveryBootstrap} search authorization
 *       recovery and reproducible snapshot replay,
 *       {@link ai.anomalousvectors.tools.burp.sinks.TrafficRouteBucket} route mapping for
 *       traffic counters, {@link ai.anomalousvectors.tools.burp.sinks.BulkOutcomeRecorder}
 *       bulk success/failure accounting,
 *       {@link ai.anomalousvectors.tools.burp.sinks.SingleDocOutcomeRecorder} single-document
 *       success/failure accounting, and
 *       {@link ai.anomalousvectors.tools.burp.sinks.SnapshotSummary} one-shot run summaries.</li>
 * </ul>
 *
 * <p>One-shot snapshot backlogs (Proxy History, Sitemap initial, Findings backlog, Proxy WebSocket
 * historic) run in cooperative slices through
 * {@link ai.anomalousvectors.tools.burp.utils.concurrent.StartupSnapshotCoordinator} and use
 * {@link ai.anomalousvectors.tools.burp.utils.concurrent.SnapshotExportEngine} with
 * {@link ai.anomalousvectors.tools.burp.utils.opensearch.OpenSearchClientWrapper#pushPreparedBulk}
 * (pre-serialized NDJSON). Live traffic uses
 * {@link ai.anomalousvectors.tools.burp.sinks.TrafficExportQueue} and
 * {@link ai.anomalousvectors.tools.burp.utils.opensearch.ChunkedBulkSender}. Incremental reporters
 * (Sitemap 30s, Findings 30s) batch prepared documents directly. All paths converge on
 * {@link ai.anomalousvectors.tools.burp.sinks.FileExportService} for file output, where run-scoped
 * directory ownership and artifact identity/size checks protect append integrity.</p>
 */
package ai.anomalousvectors.tools.burp.sinks;
