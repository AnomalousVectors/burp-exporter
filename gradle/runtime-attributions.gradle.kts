import groovy.json.JsonOutput
import java.io.InputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale
import java.util.jar.JarFile
import javax.inject.Inject
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.file.FileSystemOperations
import org.gradle.jvm.tasks.Jar

// Legal texts retain their original bytes and owner; dependency reports are not application inventories.
val legalName = Regex("(?i)^(licen[sc]e|notice|copying|copyright|dependencies|third[-_ .]?party)([._-].*)?$|^about\\.html$")
val legalDirectory = Regex("(?i)^(META-INF/)?(licenses?|notices?|legal|about_files|third[-_]party)/")
fun isAttributionResource(path: String): Boolean = !path.endsWith(".class") &&
    (legalName.matches(path.substringAfterLast('/')) || legalDirectory.containsMatchIn(path))

abstract class AttributionCopyServices {
    @get:Inject
    abstract val files: FileSystemOperations
}

val copyServices = objects.newInstance<AttributionCopyServices>()
val applicationVersion = project.version.toString()

fun sha256(input: InputStream): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(8192)
    var count = input.read(buffer)
    while (count != -1) {
        digest.update(buffer, 0, count)
        count = input.read(buffer)
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

fun componentId(artifact: ResolvedArtifactResult): ModuleComponentIdentifier =
    artifact.id.componentIdentifier as? ModuleComponentIdentifier
        ?: throw GradleException("Runtime attributions require Maven coordinates: ${artifact.id.displayName}")

fun coordinate(artifact: ResolvedArtifactResult): String = componentId(artifact).let {
    "${it.group}:${it.module}:${it.version}"
}

fun artifactRoot(artifact: ResolvedArtifactResult): String {
    val id = componentId(artifact)
    val segments = listOf(id.group, id.module, id.version, artifact.file.name)
    require(segments.all { it.matches(Regex("[A-Za-z0-9_.+\\-]+")) && it != "." && it != ".." }) {
        "Unsafe runtime artifact path: ${coordinate(artifact)}"
    }
    return "META-INF/burp-exporter/third-party/" + segments.joinToString("/")
}

val runtimeArtifacts by lazy {
    configurations.getByName("runtimeClasspath").incoming.artifacts.artifacts
        .sortedBy { coordinate(it) + ":" + it.file.name }
}

// Exact resolved versions avoid dynamic selection. POMs use the existing Maven repositories/cache;
// no legacy ArtifactResolutionQuery API, scanner, or added metadata repository is needed.
val runtimePoms by lazy {
    val pomDependencies = runtimeArtifacts.distinctBy { coordinate(it) }
        .map { dependencies.create("${coordinate(it)}@pom") }.toTypedArray()
    configurations.detachedConfiguration(*pomDependencies).apply { isTransitive = false }
        .incoming.artifacts.artifacts.associateBy { coordinate(it) }
}

val attributionRoot = layout.buildDirectory.dir("generated/runtime-attributions")
val generateRuntimeAttributions = tasks.register("generateRuntimeAttributions") {
    group = "build"
    description = "Inventories resolved runtime artifacts and preserves upstream legal metadata by owner."
    inputs.files(provider { runtimeArtifacts.map { it.file } }).withPropertyName("runtimeArtifacts")
    inputs.files(provider { runtimePoms.values.map { it.file } }).withPropertyName("publishedPoms")
    inputs.file(layout.projectDirectory.file("LICENSE")).withPropertyName("projectLicense")
    inputs.property("coordinates", provider { runtimeArtifacts.map { coordinate(it) + ":" + it.file.name } })
    inputs.property("applicationVersion", applicationVersion)
    outputs.dir(attributionRoot)
    doLast {
        val records = runtimeArtifacts.map { artifact ->
            val root = artifactRoot(artifact)
            val notices = JarFile(artifact.file).use { jar ->
                jar.stream().filter { !it.isDirectory && isAttributionResource(it.name) }
                    .sorted(compareBy { it.name }).map { entry ->
                        val segments = entry.name.split('/')
                        require(segments.none { it == ".." || it == "." || it.isEmpty() } && '\\' !in entry.name) {
                            "Unsafe attribution entry in ${coordinate(artifact)}: ${entry.name}"
                        }
                        mapOf(
                            "sourcePath" to entry.name,
                            "resourcePath" to "$root/notices/${entry.name}",
                            "sha256" to jar.getInputStream(entry).use { sha256(it) }
                        )
                    }.toList()
            }
            val pom = runtimePoms.getValue(coordinate(artifact)).file
            mapOf(
                "coordinate" to coordinate(artifact),
                "artifact" to artifact.file.name,
                "sha256" to artifact.file.inputStream().use { sha256(it) },
                "pom" to "$root/pom.xml",
                "pomSha256" to pom.inputStream().use { sha256(it) },
                "notices" to notices,
                "noticeCoverage" to if (notices.isEmpty()) "POM_ONLY_REVIEW_REQUIRED" else "BUNDLED_TEXTS_PRESERVED"
            )
        }
        val destinations = records.flatMap { record ->
            val artifact = runtimeArtifacts.single { coordinate(it) == record["coordinate"] && it.file.name == record["artifact"] }
            JarFile(artifact.file).use { jar ->
                jar.stream().filter { !it.isDirectory && isAttributionResource(it.name) }
                    .map { artifactRoot(artifact) + "/notices/" + it.name }.toList()
            }
        }
        require(destinations.map { it.lowercase(Locale.ROOT) }.distinct().size == destinations.size) {
            "Runtime legal resources collide on case-insensitive filesystems."
        }
        val output = attributionRoot.get().asFile.toPath().toAbsolutePath().normalize()
        val buildRoot = layout.buildDirectory.get().asFile.toPath().toAbsolutePath().normalize()
        require(output.startsWith(buildRoot) && output != buildRoot) { "Attributions must stay below build/." }
        // Sync removes stale generated owners after a dependency is removed; operator paths are not targets.
        copyServices.files.sync {
            into(output)
            includeEmptyDirs = false
            runtimeArtifacts.forEach { artifact ->
                from(zipTree(artifact.file)) {
                    include { it.isDirectory || isAttributionResource(it.relativePath.pathString) }
                    into(artifactRoot(artifact) + "/notices")
                }
                from(runtimePoms.getValue(coordinate(artifact)).file) {
                    rename { "pom.xml" }
                    into(artifactRoot(artifact))
                }
            }
            from(layout.projectDirectory.file("LICENSE")) {
                rename { "LICENSE.txt" }
                into("META-INF/burp-exporter")
            }
        }
        val metadata = output.resolve("META-INF/burp-exporter")
        Files.createDirectories(metadata)
        val inventory = mapOf("schemaVersion" to 1, "applicationVersion" to applicationVersion, "components" to records)
        Files.writeString(metadata.resolve("THIRD-PARTY.json"), JsonOutput.prettyPrint(JsonOutput.toJson(inventory)) + "\n")
        Files.writeString(metadata.resolve("THIRD-PARTY.txt"), """
            Resolved runtime artifact inventory

            THIRD-PARTY.json identifies the exact shipped runtime artifacts and SHA-256 digests.
            third-party/<group>/<module>/<version>/<artifact>/ contains that owner's published
            pom.xml and any license, notice, copying, copyright, attribution, or dependency-report
            resources supplied in its binary JAR. Files are preserved byte-for-byte, not merged.
            LICENSE.txt is Burp Exporter's license, not a license claim for its dependencies.

            POM_ONLY_REVIEW_REQUIRED means the binary contains no recognized legal text. Its POM
            is retained for review of declared or inherited licenses and referenced upstream texts.
            BUNDLED_TEXTS_PRESERVED describes preservation, not a legal-compliance certification.
            This inventory does not invent missing copyright notices or infer license compatibility.
            An upstream DEPENDENCIES file describes that component, not Burp Exporter's runtime graph.
        """.trimIndent() + "\n")
    }
}

tasks.named<Jar>("fatJar") {
    dependsOn(generateRuntimeAttributions)
    from(attributionRoot)
    // Filter only dependency inputs: application assets such as ui/notice-info.png are not notices.
    // Upstream generic filenames move to owner-qualified paths; no arbitrary first-wins license.
    from({
        configurations.getByName("runtimeClasspath")
            .filter { it.name.endsWith("jar") }
            .map { zipTree(it) }
    }) {
        // Logback's web-container integration is unrelated to the extension's SLF4J backend.
        exclude("META-INF/services/jakarta.servlet.ServletContainerInitializer")
        exclude("ch/qos/logback/classic/servlet/**")
        exclude("META-INF/services/software.amazon.awssdk.core.warmup.SdkWarmUpProvider")
        exclude { isAttributionResource(it.relativePath.pathString) }
    }
}

tasks.named<Test>("test") {
    doFirst {
        systemProperty("burp.exporter.runtimeCoordinates", runtimeArtifacts.joinToString("\n") {
            "${coordinate(it)}\t${it.file.absolutePath}"
        })
    }
}
