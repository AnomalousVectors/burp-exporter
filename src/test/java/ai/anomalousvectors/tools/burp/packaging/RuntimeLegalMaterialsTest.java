package ai.anomalousvectors.tools.burp.packaging;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipFile;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

/** Verifies pinned legal-text supplements and source references in the loadable JAR. */
class RuntimeLegalMaterialsTest {

    private static final String ROOT = "META-INF/burp-exporter/";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void legalSupplements_preservePinnedWholeFilesOrExactLeadingComments() throws Exception {
        JsonNode manifest = manifest();
        try (ZipFile jar = packaged()) {
            Set<String> owners = new HashSet<>();
            int count = 0;
            JsonNode inventory;
            try (InputStream stream = open(jar, ROOT + "THIRD-PARTY.json")) {
                inventory = JSON.readTree(stream);
            }
            for (JsonNode component : inventory.path("components")) {
                for (JsonNode supplement : component.path("supplementalNotices")) {
                    owners.add(component.path("coordinate").asText());
                    count++;
                    JsonNode material = find(manifest.path("materials"), "id", supplement.path("material").asText());
                    Path cached = Path.of(System.getProperty("burp.exporter.legalMaterialCache"))
                            .resolve(material.path("path").asText());
                    byte[] expected;
                    if (supplement.path("sourceEntry").isTextual()) {
                        try (ZipFile upstream = new ZipFile(cached.toFile());
                                InputStream source = open(upstream, supplement.path("sourceEntry").asText())) {
                            expected = source.readAllBytes();
                        }
                    } else {
                        expected = Files.readAllBytes(cached);
                    }
                    if (supplement.path("leadingComment").asBoolean()) {
                        int end = new String(expected, StandardCharsets.UTF_8).indexOf("*/") + 2;
                        assertThat(end).isGreaterThan(2);
                        // These pinned headers are ASCII. Preserve original CRLF/LF bytes as supplied.
                        expected = java.util.Arrays.copyOf(expected, end);
                    }
                    try (InputStream copy = open(jar, supplement.path("resourcePath").asText())) {
                        assertThat(copy.readAllBytes()).isEqualTo(expected);
                    }
                }
            }
            assertThat(count).isEqualTo(31);
            assertThat(owners).hasSize(9);
            JsonNode jsr305 = find(inventory.path("components"), "coordinate", "com.google.code.findbugs:jsr305:3.0.2");
            String prefix = jsr305.path("pom").asText().replace("/pom.xml", "/supplemental/");
            try (InputStream notice = open(jar, prefix + "concurrent-attribution.txt")) {
                assertThat(new String(notice.readAllBytes(), StandardCharsets.UTF_8))
                        .contains("Brian Goetz", "Creative Commons Attribution", "by/2.5");
            }
            JsonNode zstd = find(inventory.path("components"), "coordinate", "com.github.luben:zstd-jni:1.5.7-28");
            String nativePrefix = zstd.path("pom").asText().replace("/pom.xml", "/supplemental/");
            try (InputStream notice = open(jar, nativePrefix + "MIT-divsufsort.txt")) {
                assertThat(new String(notice.readAllBytes(), StandardCharsets.UTF_8))
                        .contains("Yuta Mori", "Permission is hereby granted", "THE SOFTWARE IS PROVIDED");
            }
        }
    }

    @Test
    void pinnedMaterials_matchTheResolvedBinaryGraphAndPackagedProvenance() throws Exception {
        JsonNode manifest = manifest();
        Path cache = Path.of(System.getProperty("burp.exporter.legalMaterialCache"));
        Set<String> used = new HashSet<>();
        manifest.path("supplements").forEach(item -> used.add(item.path("material").asText()));
        assertThat(manifest.path("materials")).hasSize(used.size());
        for (JsonNode material : manifest.path("materials")) {
            assertThat(used).contains(material.path("id").asText());
            Path file = cache.resolve(material.path("path").asText());
            assertThat(Files.size(file)).isEqualTo(material.path("bytes").asLong());
            try (InputStream bytes = Files.newInputStream(file)) {
                assertThat(digest(bytes)).as(material.path("id").asText()).isEqualTo(material.path("sha256").asText());
            }
        }
        try (ZipFile jar = packaged(); InputStream provenance = open(jar, ROOT + "LEGAL-MATERIALS.json");
                InputStream inventoryBytes = open(jar, ROOT + "THIRD-PARTY.json")) {
            assertThat(JSON.readTree(provenance)).isEqualTo(manifest);
            assertThat(jar.getEntry(ROOT + "SOURCE-MATERIALS.json")).isNull();
            JsonNode inventory = JSON.readTree(inventoryBytes);
            Set<String> expected = new HashSet<>();
            for (JsonNode component : inventory.path("components")) {
                String coordinate = component.path("coordinate").asText();
                expected.add(coordinate);
                JsonNode pin = find(manifest.path("components"), "coordinate", coordinate);
                assertThat(pin.path("binarySha256").asText()).isEqualTo(component.path("sha256").asText());
                String[] parts = coordinate.split(":");
                assertThat(pin.path("publishedSourcesUrl").asText()).isEqualTo("https://repo.maven.apache.org/maven2/"
                        + parts[0].replace('.', '/') + "/" + parts[1] + "/" + parts[2] + "/"
                        + parts[1] + "-" + parts[2] + "-sources.jar");
            }
            assertThat(manifest.path("components")).hasSize(expected.size());
            for (JsonNode pin : manifest.path("components")) {
                assertThat(expected).contains(pin.path("coordinate").asText());
            }
        }
    }

    private static JsonNode manifest() throws Exception {
        return JSON.readTree(Path.of("gradle/runtime-legal-materials.json").toFile());
    }

    private static JsonNode find(JsonNode array, String key, String value) {
        List<JsonNode> matches = new ArrayList<>();
        array.forEach(item -> {
            if (item.path(key).asText().equals(value)) {
                matches.add(item);
            }
        });
        assertThat(matches).as("Unique %s=%s", key, value).hasSize(1);
        return matches.getFirst();
    }

    private static ZipFile packaged() throws Exception {
        return new ZipFile(System.getProperty("burp.exporter.packagedJar"));
    }

    private static InputStream open(ZipFile archive, String name) throws Exception {
        var entry = archive.getEntry(name);
        assertThat(entry).as("Archive entry: %s", name).isNotNull();
        return archive.getInputStream(entry);
    }

    private static String digest(InputStream input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) != -1) {
            digest.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
