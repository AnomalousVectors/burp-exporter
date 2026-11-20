package ai.anomalousvectors.tools.burp.utils.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

class JsonFixtureRoundTripTest {

    @Test
    void example_export_fixture_matches_current_export_shape() throws IOException {
        String fixture = normalizeLineEndings(readResource("/config/example-exported-config.json"));

        ConfigState.State parsed = ConfigJsonMapper.parseState(fixture);
        String rebuilt = normalizeLineEndings(ConfigJsonMapper.build(parsed)).stripTrailing();
        String expected = fixture.replace("${VERSION}", Json.MAPPER.readTree(rebuilt).path("version").asString())
                .stripTrailing();

        assertThat(parsed.sinks().filesPath()).isEqualTo("C:/Burp/exports");
        assertThat(parsed.sinks().openSearchUrl()).isEqualTo("https://opensearch.example:9200");
        assertThat(parsed.sinks().openSearchOptions().certPath()).isEqualTo("certs/client.pem");
        assertThat(parsed.uiPreferences().logPanel().minLevel()).isEqualTo("warn");
        assertThat(rebuilt).isEqualTo(expected);
    }

    private static String readResource(String path) throws IOException {
        try (InputStream in = JsonFixtureRoundTripTest.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IOException("Missing test resource: " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String normalizeLineEndings(String text) {
        return text.replace("\r\n", "\n");
    }
}
