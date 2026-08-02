package ai.anomalousvectors.tools.burp.utils.opensearch;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the poison-pill error classifier. Ensures the well-known document-rejection
 * error types map to {@link BulkErrorClassification#PERMANENT} and everything else falls
 * through to {@link BulkErrorClassification#TRANSIENT} (which is the "retry, it may recover"
 * default).
 */
class BulkErrorClassificationTest {

    @Test
    void knownMappingAndParseErrors_classifyAsPermanent() {
        assertThat(BulkErrorClassification.of("illegal_argument_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("mapper_parsing_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("document_parsing_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("strict_dynamic_mapping_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("mapper_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("validation_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("parse_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("query_shard_exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of(BulkErrorClassification.DOCUMENT_TOO_LARGE_TYPE))
                .isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of(BulkErrorClassification.SEARCH_MAX_BUDGET_EXCEEDED_TYPE))
                .isEqualTo(BulkErrorClassification.PERMANENT);
    }

    @Test
    void classificationIsCaseInsensitive() {
        assertThat(BulkErrorClassification.of("Mapper_Parsing_Exception")).isEqualTo(BulkErrorClassification.PERMANENT);
        assertThat(BulkErrorClassification.of("ILLEGAL_ARGUMENT_EXCEPTION")).isEqualTo(BulkErrorClassification.PERMANENT);
    }

    @Test
    void cliqueAndBackpressureErrors_defaultToTransient() {
        assertThat(BulkErrorClassification.of("circuit_breaking_exception")).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("es_rejected_execution_exception")).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("cluster_block_exception")).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("unavailable_shards_exception")).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("process_cluster_event_timeout_exception")).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("live_bulk_budget_exceeded"))
                .isEqualTo(BulkErrorClassification.TRANSIENT);
    }

    @Test
    void nullOrBlankOrUnknown_defaultsToTransient() {
        assertThat(BulkErrorClassification.of(null)).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("")).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("   ")).isEqualTo(BulkErrorClassification.TRANSIENT);
        assertThat(BulkErrorClassification.of("some_future_type_we_have_not_seen")).isEqualTo(BulkErrorClassification.TRANSIENT);
    }
}
