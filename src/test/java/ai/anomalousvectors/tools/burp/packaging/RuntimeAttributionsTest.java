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
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

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
            assertThat(inventory.path("schemaVersion").asInt()).isEqualTo(2);
            assertThat(inventory.path("applicationVersion").asString())
                    .isEqualTo(System.getProperty("burp.exporter.version"));
            Map<String, Path> expected = runtimeArtifacts();
            Set<String> actual = new HashSet<>();
            for (JsonNode component : inventory.path("components")) {
                String key = component.path("coordinate").asString() + "/" + component.path("artifact").asString();
                assertThat(actual.add(key)).as("Unique inventory component: %s", key).isTrue();
                Path input = expected.get(key);
                assertThat(input).as("Only resolved runtime artifacts belong in the inventory: %s", key).isNotNull();
                try (InputStream stream = Files.newInputStream(input)) {
                    assertThat(component.path("sha256").asString()).isEqualTo(sha256(stream));
                }
                String pom = component.path("pom").asString();
                assertThat(pom).startsWith(ROOT + "third-party/").endsWith("/pom.xml");
                try (InputStream stream = resource(packaged, pom)) {
                    assertThat(sha256(stream)).isEqualTo(component.path("pomSha256").asString());
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
                String key = component.path("coordinate").asString() + "/" + component.path("artifact").asString();
                Set<String> originalNames = new HashSet<>();
                try (JarFile original = new JarFile(artifacts.get(key).toFile())) {
                    Set<String> expected = new HashSet<>();
                    original.stream().filter(entry -> !entry.isDirectory() && isLegal(entry.getName()))
                            .forEach(entry -> expected.add(entry.getName()));
                    for (JsonNode notice : component.path("notices")) {
                        String sourcePath = notice.path("sourcePath").asString();
                        String destination = notice.path("resourcePath").asString();
                        assertThat(originalNames.add(sourcePath)).isTrue();
                        assertThat(destinations.add(destination)).as("Collision-free legal resource: %s", destination).isTrue();
                        assertThat(destination).startsWith(ROOT + "third-party/")
                                .endsWith("/notices/" + sourcePath);
                        try (InputStream source = resource(original, sourcePath);
                                InputStream output = resource(packaged, destination)) {
                            String digest = sha256(source);
                            assertThat(sha256(output)).as(destination).isEqualTo(digest);
                            assertThat(notice.path("sha256").asString()).isEqualTo(digest);
                        }
                    }
                    assertThat(originalNames).containsExactlyInAnyOrderElementsOf(expected);
                }
            }
            assertThat(destinations).isNotEmpty();
        }
    }

    @Test
    void inventory_distinguishesSupplementalTextsFromOriginalBinaryNotices() throws Exception {
        try (JarFile packaged = packagedJar()) {
            for (JsonNode component : inventory(packaged).path("components")) {
                if (component.path("notices").isEmpty()) {
                    assertThat(component.path("supplementalNotices")).isNotEmpty();
                    assertThat(component.path("noticeCoverage").asString()).isEqualTo("UPSTREAM_TEXTS_SUPPLEMENTED");
                } else {
                    assertThat(component.path("noticeCoverage").asString()).isEqualTo("BUNDLED_TEXTS_PRESERVED");
                }
            }
            try (InputStream stream = resource(packaged, ROOT + "THIRD-PARTY.txt")) {
                assertThat(new String(stream.readAllBytes(), StandardCharsets.UTF_8))
                        .contains("UPSTREAM_TEXTS_SUPPLEMENTED", "not a legal-compliance certification",
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

    @Test
    void packaging_removesOnlyRedundantEmbeddedPomsAndJvmIrrelevantBuildInputs() throws Exception {
        int redundant = 0;
        int distinct = 0;
        try (JarFile packaged = packagedJar()) {
            assertThat(packaged.getJarEntry("VersionInfo.java")).isNull();
            assertThat(packaged.getJarEntry("META-INF/INDEX.LIST")).isNull();
            assertThat(packaged.stream().map(entry -> entry.getName())
                    .filter(name -> name.startsWith("META-INF/native-image/")).toList()).isEmpty();
            Map<String, Path> artifacts = runtimeArtifacts();
            for (JsonNode component : inventory(packaged).path("components")) {
                String key = component.path("coordinate").asString() + "/" + component.path("artifact").asString();
                byte[] published;
                try (InputStream input = resource(packaged, component.path("pom").asString())) {
                    published = input.readAllBytes();
                }
                try (JarFile original = new JarFile(artifacts.get(key).toFile())) {
                    for (var entry : original.stream().filter(item -> !item.isDirectory()
                            && item.getName().startsWith("META-INF/maven/")
                            && item.getName().endsWith("/pom.xml")).toList()) {
                        byte[] bytes;
                        try (InputStream input = original.getInputStream(entry)) {
                            bytes = input.readAllBytes();
                        }
                        if (Arrays.equals(bytes, published)) {
                            assertThat(packaged.getJarEntry(entry.getName())).as(entry.getName()).isNull();
                            redundant++;
                        } else {
                            try (InputStream input = resource(packaged, entry.getName())) {
                                assertThat(input.readAllBytes()).as(entry.getName()).isEqualTo(bytes);
                            }
                            distinct++;
                        }
                    }
                }
            }
        }
        assertThat(redundant).as("Published POM copies actually removed").isPositive();
        assertThat(distinct).as("Distinct embedded POM evidence actually retained").isPositive();
    }

    @Test
    void mavenVersionProperties_surviveAtOriginalLookupPathsByteForByte() throws Exception {
        int checked = 0;
        try (JarFile packaged = packagedJar()) {
            for (Path dependency : runtimeArtifacts().values()) {
                try (JarFile original = new JarFile(dependency.toFile())) {
                    for (var entry : original.stream().filter(item -> !item.isDirectory()
                            && item.getName().startsWith("META-INF/maven/")
                            && item.getName().endsWith("/pom.properties")).toList()) {
                        try (InputStream source = original.getInputStream(entry);
                                InputStream output = resource(packaged, entry.getName())) {
                            assertThat(output.readAllBytes()).as(entry.getName()).isEqualTo(source.readAllBytes());
                        }
                        checked++;
                    }
                }
            }
        }
        assertThat(checked).isPositive();
    }

    private static JsonNode inventory(JarFile jar) throws IOException {
        try (InputStream stream = resource(jar, ROOT + "THIRD-PARTY.json")) {
            return JsonMapper.builderWithJackson2Defaults().build().readTree(stream);
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
