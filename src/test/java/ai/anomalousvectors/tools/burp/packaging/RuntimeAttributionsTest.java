package ai.anomalousvectors.tools.burp.packaging;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

/** Verifies owner-qualified attribution completeness against the resolved runtime artifacts. */
class RuntimeAttributionsTest {

    private static final String ROOT = "META-INF/burp-exporter/";
    private static final Pattern LEGAL_NAME = Pattern.compile(
            "(?i)^(licen[sc]e|notice|copying|copyright|dependencies|third[-_ .]?party)([._-].*)?$|^about\\.html$");
    private static final Pattern LEGAL_DIRECTORY = Pattern.compile(
            "(?i)^(META-INF/)?(licenses?|notices?|legal|about_files|third[-_]party)/");

    @Test
    void inventory_identifiesEveryResolvedRuntimeArtifactAndExactDigest() throws Exception {
        try (JarFile packaged = packagedJar()) {
            JsonNode inventory = inventory(packaged);
            assertThat(inventory.path("schemaVersion").asInt()).isEqualTo(1);
            assertThat(inventory.path("applicationVersion").asText())
                    .isEqualTo(System.getProperty("burp.exporter.version"));
            Map<String, Path> expected = runtimeArtifacts();
            Set<String> actual = new HashSet<>();
            for (JsonNode component : inventory.path("components")) {
                String key = component.path("coordinate").asText() + "/" + component.path("artifact").asText();
                assertThat(actual.add(key)).as("Unique inventory component: %s", key).isTrue();
                Path input = expected.get(key);
                assertThat(input).as("Only resolved runtime artifacts belong in the inventory: %s", key).isNotNull();
                try (InputStream stream = Files.newInputStream(input)) {
                    assertThat(component.path("sha256").asText()).isEqualTo(sha256(stream));
                }
                String pom = component.path("pom").asText();
                assertThat(pom).startsWith(ROOT + "third-party/").endsWith("/pom.xml");
                try (InputStream stream = resource(packaged, pom)) {
                    assertThat(sha256(stream)).isEqualTo(component.path("pomSha256").asText());
                }
            }
            assertThat(actual).containsExactlyInAnyOrderElementsOf(expected.keySet());
        }
    }

    @Test
    void everyUpstreamLegalResource_isPreservedByteForByteUnderItsOwner() throws Exception {
        try (JarFile packaged = packagedJar()) {
            Map<String, Path> artifacts = runtimeArtifacts();
            Set<String> destinations = new HashSet<>();
            for (JsonNode component : inventory(packaged).path("components")) {
                String key = component.path("coordinate").asText() + "/" + component.path("artifact").asText();
                Set<String> originalNames = new HashSet<>();
                try (JarFile original = new JarFile(artifacts.get(key).toFile())) {
                    Set<String> expected = new HashSet<>();
                    original.stream().filter(entry -> !entry.isDirectory() && isLegal(entry.getName()))
                            .forEach(entry -> expected.add(entry.getName()));
                    for (JsonNode notice : component.path("notices")) {
                        String sourcePath = notice.path("sourcePath").asText();
                        String destination = notice.path("resourcePath").asText();
                        assertThat(originalNames.add(sourcePath)).isTrue();
                        assertThat(destinations.add(destination)).as("Collision-free legal resource: %s", destination).isTrue();
                        assertThat(destination).startsWith(ROOT + "third-party/")
                                .endsWith("/notices/" + sourcePath);
                        try (InputStream source = resource(original, sourcePath);
                                InputStream output = resource(packaged, destination)) {
                            String digest = sha256(source);
                            assertThat(sha256(output)).as(destination).isEqualTo(digest);
                            assertThat(notice.path("sha256").asText()).isEqualTo(digest);
                        }
                    }
                    assertThat(originalNames).containsExactlyInAnyOrderElementsOf(expected);
                }
            }
            assertThat(destinations).isNotEmpty();
        }
    }

    @Test
    void inventory_explainsMissingEmbeddedNoticesWithoutInventingLegalConclusions() throws Exception {
        try (JarFile packaged = packagedJar()) {
            for (JsonNode component : inventory(packaged).path("components")) {
                if (component.path("notices").isEmpty()) {
                    assertThat(component.path("noticeCoverage").asText()).isEqualTo("POM_ONLY_REVIEW_REQUIRED");
                } else {
                    assertThat(component.path("noticeCoverage").asText()).isEqualTo("BUNDLED_TEXTS_PRESERVED");
                }
            }
            try (InputStream stream = resource(packaged, ROOT + "THIRD-PARTY.txt")) {
                assertThat(new String(stream.readAllBytes(), StandardCharsets.UTF_8))
                        .contains("POM_ONLY_REVIEW_REQUIRED", "not a legal-compliance certification",
                                "not Burp Exporter's runtime graph");
            }
        }
    }

    @Test
    void projectLicense_isExactAndGenericFirstWinsLegalFilesAreAbsent() throws Exception {
        Path applicationResources = Path.of("src/main/resources");
        try (JarFile packaged = packagedJar();
                InputStream license = Files.newInputStream(Path.of("LICENSE"));
                InputStream bundled = resource(packaged, ROOT + "LICENSE.txt")) {
            assertThat(sha256(bundled)).isEqualTo(sha256(license));
            assertThat(packaged.stream().filter(entry -> !entry.isDirectory()).map(entry -> entry.getName())
                    .filter(name -> isLegal(name) && !name.startsWith(ROOT))
                    .filter(name -> !Files.isRegularFile(applicationResources.resolve(name))).toList()).isEmpty();
        }
    }

    private static JsonNode inventory(JarFile jar) throws IOException {
        try (InputStream stream = resource(jar, ROOT + "THIRD-PARTY.json")) {
            return new ObjectMapper().readTree(stream);
        }
    }

    private static Map<String, Path> runtimeArtifacts() {
        Map<String, Path> artifacts = new HashMap<>();
        System.getProperty("burp.exporter.runtimeCoordinates").lines().forEach(line -> {
            String[] parts = line.split("\t", 2);
            Path file = Path.of(parts[1]);
            artifacts.put(parts[0] + "/" + file.getFileName(), file);
        });
        return artifacts;
    }

    private static boolean isLegal(String name) {
        String fileName = name.substring(name.lastIndexOf('/') + 1);
        return !name.endsWith(".class")
                && (LEGAL_NAME.matcher(fileName).matches() || LEGAL_DIRECTORY.matcher(name).find());
    }

    private static JarFile packagedJar() throws IOException {
        return new JarFile(System.getProperty("burp.exporter.packagedJar"));
    }

    private static InputStream resource(JarFile jar, String name) throws IOException {
        var entry = jar.getJarEntry(name);
        if (entry == null) {
            throw new IOException("Missing packaged attribution: " + name);
        }
        return jar.getInputStream(entry);
    }

    private static String sha256(InputStream source) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        // The caller owns the stream; keep memory bounded even for large native dependency JARs.
        byte[] buffer = new byte[8192];
        int count;
        while ((count = source.read(buffer)) != -1) {
            digest.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
