package ai.anomalousvectors.tools.burp.utils.config;

import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigImportPolicyTest {

    @TempDir Path tempDir;

    @Test
    void readUtf8_acceptsValidConfigurationWithinFileLimit() throws Exception {
        Path config = tempDir.resolve("config.json");
        Files.writeString(config, "{\"scope\":[\"all\"]}");

        assertThat(ConfigImportPolicy.readUtf8(config)).isEqualTo("{\"scope\":[\"all\"]}");
    }

    @Test
    void readUtf8_rejectsFileLargerThanTenMebibytesBeforeDecoding() throws Exception {
        Path config = tempDir.resolve("oversized.json");
        try (SeekableByteChannel channel = Files.newByteChannel(
                config,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            channel.position(ConfigImportPolicy.MAX_FILE_BYTES);
            channel.write(ByteBuffer.wrap(new byte[] {'}'}));
        }

        assertThatThrownBy(() -> ConfigImportPolicy.readUtf8(config))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("10485761 bytes")
                .hasMessageContaining("maximum is 10485760 bytes (10 MiB)");
    }

    @Test
    void parser_acceptsMaximumStringLengthAndRejectsNextCharacter() throws Exception {
        String accepted = "a".repeat(ConfigImportPolicy.MAX_JSON_STRING_LENGTH);
        String acceptedJson = "{\"ui\":{\"log\":{\"filterText\":\"" + accepted + "\"}}}";

        ConfigParseResult result = ConfigJsonMapper.parse(acceptedJson);
        assertThat(result.state().uiPreferences().logPanel().filterText()).hasSize(accepted.length());

        String rejected = accepted + "b";
        String rejectedJson = "{\"ui\":{\"log\":{\"filterText\":\"" + rejected + "\"}}}";
        assertThatThrownBy(() -> ConfigJsonMapper.parse(rejectedJson))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("String value length")
                .hasMessageContaining("65536");
    }

    @Test
    void parser_rejectsJsonBeyondMaximumNestingDepth() {
        String json = "{\"nested\":".repeat(ConfigImportPolicy.MAX_JSON_NESTING_DEPTH + 1)
                + "null"
                + "}".repeat(ConfigImportPolicy.MAX_JSON_NESTING_DEPTH + 1);

        assertThatThrownBy(() -> ConfigJsonMapper.parse(json))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("nesting depth")
                .hasMessageContaining("64");
    }

    @Test
    void parser_acceptsOneHundredCustomScopeEntriesAndRejectsOneHundredOne() throws Exception {
        List<String> accepted = scopeValues(ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES);
        ConfigParseResult result = ConfigJsonMapper.parse(customScopeJson(accepted));

        assertThat(result.state().customEntries()).hasSize(ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES);

        List<String> rejected = scopeValues(ConfigImportPolicy.MAX_CUSTOM_SCOPE_ENTRIES + 1);
        assertThatThrownBy(() -> ConfigJsonMapper.parse(customScopeJson(rejected)))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("'scope.custom' has 101 entries")
                .hasMessageContaining("maximum is 100");
    }

    private static List<String> scopeValues(int count) {
        List<String> values = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            values.add("scope-" + i);
        }
        return values;
    }

    private static String customScopeJson(List<String> values) {
        return "{\"scope\":{\"custom\":[\"" + String.join("\",\"", values) + "\"]}}";
    }
}
