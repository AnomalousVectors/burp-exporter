package ai.anomalousvectors.tools.burp.utils.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import tools.jackson.core.JacksonException;

import org.junit.jupiter.api.Test;

class ExportLineCodecTest {

    @Test
    void jsonAndBulk_preserveInsertionOrderNullBinaryAndNumericValues() throws IOException {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("z", null);
        document.put("binary", new byte[] {0, 1, (byte) 255});
        document.put("integer", new BigInteger("123456789012345678901234567890"));
        document.put("decimal", new BigDecimal("0.000000000000000000123456789"));
        document.put("text", "line\n\"quoted\"");
        String expected = "{\"z\":null,\"binary\":\"AAH/\","
                + "\"integer\":123456789012345678901234567890,"
                + "\"decimal\":1.23456789E-19,\"text\":\"line\\n\\\"quoted\\\"\"}\n";
        assertThat(ExportLineCodec.jsonDocumentLine(document)).isEqualTo(expected);
        assertThat(new String(ExportLineCodec.bulkNdjsonBytes("stable-id", document), StandardCharsets.UTF_8))
                .isEqualTo("{\"index\":{\"_id\":\"stable-id\"}}\n" + expected);
    }

    @Test
    void serializationFailures_preserveCheckedBulkIoBoundary() {
        Map<String, Object> document = Map.of("unsupported", new Object());
        var prepared = new PreparedExportDocument(
                "stable-id", "tool-burp-traffic", "traffic", document, 1, new byte[] {1}, null);
        assertThatThrownBy(() -> ExportLineCodec.jsonDocumentLine(document))
                .isInstanceOf(JacksonException.class);
        assertThatThrownBy(() -> ExportLineCodec.bulkNdjsonBytes("stable-id", document))
                .isInstanceOf(IOException.class).hasCauseInstanceOf(JacksonException.class);
        assertThatThrownBy(() -> ExportLineCodec.writeBulkNdjson(new ByteArrayOutputStream(), prepared))
                .isInstanceOf(IOException.class).hasCauseInstanceOf(JacksonException.class);
    }
}
