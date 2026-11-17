package ai.anomalousvectors.tools.burp.sinks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class StreamingResponseRulesTest {
    @Test
    void prefixRules_areLiteralAndDisabledRulesAreIgnored() {
        var rules = parse("""
                [{"enabled":true,"prefix":"https://example.test/video?x=."},
                 {"enabled":false,"prefix":"https://other.test/"}]
                """);
        assertThat(rules.matches("https://example.test/video?x=.abc")).isTrue();
        assertThat(rules.matches("https://example.test/video?x=Xabc")).isFalse();
        assertThat(rules.matches("https://other.test/")).isFalse();
    }

    @Test
    void advancedRules_matchHostPortProtocolAndFileTogether() {
        var rules = parse("""
                [{"enabled":true,"host":"^example[.]test$","port":"^8443$",
                  "protocol":"https","file":"^/video"}]
                """);
        assertThat(rules.matches("https://example.test:8443/video/a")).isTrue();
        assertThat(rules.matches("http://example.test:8443/video/a")).isFalse();
        assertThat(rules.matches("https://example.test/video/a")).isFalse();
        assertThat(rules.matches("https://other.test:8443/video/a")).isFalse();
    }

    @Test
    void actualBurpAdvancedShapeAllowsOmittedPortAndFileAndIgnoresQuery() {
        var rules = parse("[{\"enabled\":true,\"host\":\"^127[.]0[.]0[.]1$\",\"protocol\":\"any\"}]");
        assertThat(rules.matches("https://127.0.0.1:18443/sse/short?case=lab")).isTrue();
        var pathOnly = parse("[{\"host\":\"\",\"file\":\"^/video$\",\"protocol\":\"any\"}]");
        assertThat(pathOnly.matches("https://example.test/video?case=lab")).isTrue();
        assertThat(parse("[{\"protocol\":\"any\"}]")
                .matches("https://example.test/video")).isTrue();
    }

    @Test
    void normalPrefixesSupportOptionalProtocolAndLiteralSubdomains() {
        var rules = parse("[{\"prefix\":\"example.test/video\",\"include_subdomains\":true}]");
        assertThat(rules.matches("https://Sub.Example.Test/video/a")).isTrue();
        assertThat(rules.matches("http://example.test/video")).isTrue();
        assertThat(rules.matches("https://notexample.test/video")).isFalse();
        assertThat(rules.matches("https://example.test/Video")).isFalse();
    }

    @Test
    void unsupportedOrMalformedSettings_areNotSilentlyTreatedAsAllTraffic() {
        assertThatThrownBy(() -> parse("[{\"unknown\":\"x\"}]"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> StreamingResponseRules.parse("{}"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> parse("[{\"host\":\"127.0.0.1/32\"}]"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(StreamingResponseRules.empty().matches("https://example.test/")).isFalse();
    }

    private static StreamingResponseRules parse(String entries) {
        return StreamingResponseRules.parse("{\"project_options\":{\"http\":{\"streaming_responses\":"
                + "{\"store\":true,\"urls\":" + entries + "}}}}");
    }
}
