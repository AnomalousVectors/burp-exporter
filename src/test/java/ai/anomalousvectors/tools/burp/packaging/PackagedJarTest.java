package ai.anomalousvectors.tools.burp.packaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Properties;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Checks the distributable independently of dependency resolution on the test classpath. */
class PackagedJarTest {

    private static final String SERVLET_SERVICE = "META-INF/services/jakarta.servlet.ServletContainerInitializer";
    private static final String MERGED_SERVICE = "META-INF/services/software.amazon.awssdk.core.warmup.SdkWarmUpProvider";

    @Test
    void applicationResources_survivePackagingByteForByteAndRemainLoadable() throws Exception {
        Path resources = Path.of("src/main/resources");
        try (var paths = Files.walk(resources);
                JarFile jar = new JarFile(packagedJar().toFile());
                URLClassLoader loader = runtimeLoader()) {
            for (Path source : paths.filter(Files::isRegularFile).toList()) {
                String name = resources.relativize(source).toString().replace(File.separatorChar, '/');
                assertThat(jar.getJarEntry(name)).as("Application resource: %s", name).isNotNull();
                try (var input = loader.getResourceAsStream(name)) {
                    assertThat(input).as("Isolated resource lookup: %s", name).isNotNull();
                    assertThat(input.readAllBytes()).as(name).isEqualTo(Files.readAllBytes(source));
                }
            }
        }
    }

    @Test
    void isolatedUi_initializesSourcesNoticeFromThePackagedImage() throws Exception {
        try (URLClassLoader loader = runtimeLoader()) {
            try (var input = loader.getResourceAsStream("ui/notice-info.png")) {
                assertThat(input).as("Required Sources notice icon").isNotNull();
                var image = ImageIO.read(input);
                assertThat(image).as("Decodable packaged PNG").isNotNull();
                assertThat(image.getWidth()).isPositive();
                assertThat(image.getHeight()).isPositive();
            }
            // Initialize the real UI class, not its source-classpath twin, on Swing's EDT.
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Class.forName("ai.anomalousvectors.tools.burp.ui.ConfigSourcesPanel", true, loader);
                } catch (ClassNotFoundException failure) {
                    throw new AssertionError(failure);
                }
            });
        }
    }

    @Test
    void runtimeJars_haveNoDuplicateNonModuleClassesOrLostServiceProviders() throws Exception {
        Map<String, Path> classes = new HashMap<>();
        Map<String, Set<String>> services = new HashMap<>();
        List<String> collisions = new ArrayList<>();
        for (Path dependency : runtimeJars()) {
            try (JarFile jar = new JarFile(dependency.toFile())) {
                for (var entry : jar.stream().filter(item -> !item.isDirectory()).toList()) {
                    String name = entry.getName();
                    if (name.endsWith(".class") && !name.endsWith("module-info.class")) {
                        Path previous = classes.putIfAbsent(name, dependency);
                        if (previous != null) {
                            collisions.add(name + " in " + previous.getFileName() + " and " + dependency.getFileName());
                        }
                    }
                    if (name.startsWith("META-INF/services/") && !SERVLET_SERVICE.equals(name)) {
                        Set<String> providers = providers(jar, name);
                        Set<String> previous = services.putIfAbsent(name, providers);
                        if (previous != null && MERGED_SERVICE.equals(name)) {
                            previous.addAll(providers);
                        } else if (previous != null && !previous.equals(providers)) {
                            collisions.add("Distinct service providers at " + name + ": " + previous + " / " + providers);
                        }
                    }
                }
            }
        }
        assertThat(collisions).as("Fat-JAR first-wins must not hide classes or distinct providers").isEmpty();
        try (JarFile packaged = new JarFile(packagedJar().toFile())) {
            assertThat(classes.keySet().stream()
                    .filter(name -> !name.startsWith("ch/qos/logback/classic/servlet/"))
                    .filter(name -> packaged.getJarEntry(packagedRuntimePath(name)) == null).toList())
                    .as("Every retained runtime class must survive packaging").isEmpty();
            for (var service : services.entrySet()) {
                assertThat(providers(packaged, service.getKey())).isEqualTo(service.getValue());
            }
        }
    }

    @Test
    void allPackagedServiceProviders_arePresentAndAssignableToTheirService() throws Exception {
        try (JarFile jar = new JarFile(packagedJar().toFile()); URLClassLoader loader = runtimeLoader()) {
            for (var entry : jar.stream().filter(item -> !item.isDirectory()
                    && item.getName().startsWith("META-INF/services/")).toList()) {
                String serviceName = entry.getName().substring("META-INF/services/".length());
                Class<?> service = Class.forName(serviceName, false, loader);
                for (String providerName : providers(jar, entry.getName())) {
                    assertThat(jar.getJarEntry(providerName.replace('.', '/') + ".class")).isNotNull();
                    Class<?> provider = Class.forName(providerName, false, loader);
                    assertThat(service.isAssignableFrom(provider)).as(providerName).isTrue();
                }
            }
        }
    }

    @Test
    void java21Jackson3Adapter_isPromotedWithoutChangingClassBytes() throws Exception {
        int checked = 0;
        try (JarFile packaged = new JarFile(packagedJar().toFile())) {
            for (Path dependency : runtimeJars()) {
                try (JarFile upstream = new JarFile(dependency.toFile())) {
                    for (var entry : upstream.stream().filter(item -> !item.isDirectory()
                            && item.getName().endsWith(".class")
                            && !packagedRuntimePath(item.getName()).equals(item.getName())).toList()) {
                        String path = packagedRuntimePath(entry.getName());
                        assertThat(packaged.getJarEntry(path)).as(path).isNotNull();
                        assertThat(packaged.getJarEntry(entry.getName())).isNull();
                        try (var original = upstream.getInputStream(entry);
                                var copy = packaged.getInputStream(packaged.getJarEntry(path))) {
                            assertThat(copy.readAllBytes()).as(path).isEqualTo(original.readAllBytes());
                        }
                        checked++;
                    }
                }
            }
        }
        assertThat(checked).as("Versioned adapter classes were actually inspected").isPositive();
    }

    @Test
    void distributable_excludesUnusedBranchesAndTestOrHostApiClasses() throws Exception {
        List<String> forbidden = List.of("co/elastic/", "com/fasterxml/jackson/core/",
                "com/fasterxml/jackson/databind/", "io/opentelemetry/", "io/netty/",
                "org/eclipse/yasson/", "org/glassfish/json/", "jakarta/json/bind/",
                "ch/qos/logback/classic/servlet/", "org/junit/", "org/mockito/", "org/assertj/",
                "burp/api/montoya/", "ai/anomalousvectors/tools/burp/packaging/",
                "ai/anomalousvectors/tools/burp/testutils/");
        try (JarFile jar = new JarFile(packagedJar().toFile())) {
            assertThat(jar.stream().map(item -> item.getName())
                    .filter(name -> forbidden.stream().anyMatch(name::startsWith)).toList()).isEmpty();
            assertThat(jar.getJarEntry(SERVLET_SERVICE)).isNull();
            assertThat(jar.getJarEntry("org/eclipse/parsson/JsonProviderImpl.class")).isNotNull();
            assertThat(jar.getJarEntry("org/elasticsearch/client/RestClient.class")).isNotNull();
            assertThat(jar.getJarEntry("tools/jackson/databind/json/JsonMapper.class")).isNotNull();
            assertThat(jar.getJarEntry("org/opensearch/client/json/jackson3/JacksonJsonpMapper.class")).isNotNull();
            assertThat(jar.getManifest().getMainAttributes().getValue("Multi-Release")).isNull();
            // Keep native encodings portable; the BApp is not a Windows-only artifact.
            assertThat(jar.stream().anyMatch(item -> item.getName().endsWith(".dll"))).isTrue();
            assertThat(jar.stream().anyMatch(item -> item.getName().endsWith(".so"))).isTrue();
            assertThat(jar.stream().anyMatch(item -> item.getName().endsWith(".dylib"))).isTrue();
        }
        try (URLClassLoader loader = runtimeLoader()) {
            assertThatThrownBy(() -> loader.loadClass("org.junit.jupiter.api.Test"))
                    .isInstanceOf(ClassNotFoundException.class);
        }
    }

    @Test
    void isolatedRuntime_retainsRuntimeVersionMetadata() throws Exception {
        try (URLClassLoader loader = runtimeLoader()) {
            Class<?> factory = loader.loadClass("software.amazon.awssdk.thirdparty.jackson.core.JsonFactory");
            Object version = factory.getMethod("version").invoke(factory.getConstructor().newInstance());
            assertThat(version.toString()).isNotEqualTo("0.0.0");
            Properties sdk = versionProperties(loader, "software.amazon.awssdk", "sdk-core");
            assertThat(loader.loadClass("software.amazon.awssdk.core.util.VersionInfo")
                    .getField("SDK_VERSION").get(null)).isEqualTo(sdk.getProperty("version"));
            Properties jackson = versionProperties(loader, "tools.jackson.core", "jackson-core");
            assertThat(jackson.getProperty("version")).isNotBlank();
        }
    }

    private static Properties versionProperties(ClassLoader loader, String group, String artifact) throws IOException {
        Properties properties = new Properties();
        try (var input = loader.getResourceAsStream("META-INF/maven/" + group + "/" + artifact + "/pom.properties")) {
            assertThat(input).as("Version resource for %s:%s", group, artifact).isNotNull();
            properties.load(input);
        }
        return properties;
    }

    @Test
    @Timeout(45)
    void isolatedRuntime_initializesJsonCompressionLoggingTlsAndDestinationClients() throws Throwable {
        runProbe("coreAndDestinations");
    }

    @Test
    @Timeout(45)
    void isolatedRuntime_resolvesStaticRoleAndSsoCredentialsWithSynchronousTransport() throws Throwable {
        runProbe("awsProfilesAndTransport");
    }

    private static String packagedRuntimePath(String name) {
        return name.startsWith("META-INF/versions/21/org/opensearch/client/json/jackson3/")
                ? name.substring("META-INF/versions/21/".length()) : name;
    }

    private static void runProbe(String method) throws Throwable {
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        try (URLClassLoader runtime = runtimeLoader();
                URLClassLoader probe = new URLClassLoader(new URL[] {
                    PackagedJarTest.class.getProtectionDomain().getCodeSource().getLocation()
                }, runtime)) {
            // ServiceLoader must see the distributable, never the IDE/Gradle dependency classpath.
            Thread.currentThread().setContextClassLoader(runtime);
            Class<?> harness = Class.forName(PackagedRuntimeProbe.class.getName(), true, probe);
            try {
                harness.getMethod(method).invoke(null);
            } catch (InvocationTargetException failure) {
                // Render SDK-specific failures before closing their defining classloader. JUnit's
                // later exception rendering otherwise can lose lazily linked diagnostic classes.
                StringWriter details = new StringWriter();
                failure.getCause().printStackTrace(new PrintWriter(details));
                throw new AssertionError(details.toString());
            }
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }

    private static URLClassLoader runtimeLoader() throws IOException {
        return new URLClassLoader(new URL[] {packagedJar().toUri().toURL()}, ClassLoader.getPlatformClassLoader());
    }

    private static Path packagedJar() {
        return Path.of(System.getProperty("burp.exporter.packagedJar"));
    }

    private static List<Path> runtimeJars() {
        return Pattern.compile(Pattern.quote(File.pathSeparator))
                .splitAsStream(System.getProperty("burp.exporter.runtimeJars"))
                .map(Path::of).toList();
    }

    private static Set<String> providers(JarFile jar, String name) throws IOException {
        var entry = jar.getJarEntry(name);
        if (entry == null) {
            throw new IOException("Missing service descriptor: " + name);
        }
        try (var input = jar.getInputStream(entry)) {
            Set<String> result = new HashSet<>();
            new String(input.readAllBytes(), StandardCharsets.UTF_8).lines()
                    .map(line -> line.split("#", 2)[0].trim())
                    .filter(line -> !line.isEmpty()).forEach(result::add);
            return result;
        }
    }
}
