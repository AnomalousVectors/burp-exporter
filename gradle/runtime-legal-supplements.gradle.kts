import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.io.File
import java.io.IOException
import java.net.URI
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipFile

// Inputs are reviewed, exact-version materials, not a license detector or a license election.
fun jsonObject(file: File): Map<*, *> = JsonSlurper().parse(file) as? Map<*, *>
    ?: throw GradleException("Expected a JSON object: ${file.name}")

fun objects(value: Any?): List<Map<*, *>> = (value as? List<*>)?.map {
    it as? Map<*, *> ?: throw GradleException("Expected a JSON object in the source inventory.")
} ?: throw GradleException("Expected a JSON array in the source inventory.")

fun Map<*, *>.text(key: String): String = this[key] as? String
    ?: throw GradleException("Missing legal-inventory string: $key")

fun digest(file: File): String = file.inputStream().use { stream ->
    val hash = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(8192)
    var count = stream.read(buffer)
    while (count != -1) {
        hash.update(buffer, 0, count)
        count = stream.read(buffer)
    }
    hash.digest().joinToString("") { "%02x".format(it) }
}

fun safeRelative(path: String): String {
    require(path.isNotEmpty() && '\\' !in path && path.split('/').all {
        it.matches(Regex("[A-Za-z0-9_.+\\-]+")) && it != "." && it != ".."
    }) { "Unsafe source-material path: $path" }
    return path
}

val legalManifestFile = layout.projectDirectory.file("gradle/runtime-legal-materials.json").asFile
val legalApplicationVersion = project.version.toString()
val legalManifest by lazy { jsonObject(legalManifestFile) }
val legalMaterials by lazy { objects(legalManifest["materials"]) }
val legalComponents by lazy { objects(legalManifest["components"]) }
val legalSupplements by lazy { objects(legalManifest["supplements"]) }
val materialRoot = layout.projectDirectory.dir(".gradle/runtime-legal-materials").asFile
val legalRoot = layout.buildDirectory.dir("generated/runtime-attributions")

fun materialFile(material: Map<*, *>): File = File(materialRoot, safeRelative(material.text("path")))

fun material(id: String): Map<*, *> = legalMaterials.single { it["id"] == id }

fun verifyMaterial(file: File, expected: Map<*, *>) {
    val size = (expected["bytes"] as? Number)?.toLong()
        ?: throw GradleException("Missing source-material byte count.")
    require(size in 1..(64L * 1024 * 1024) && file.isFile && !Files.isSymbolicLink(file.toPath())
        && file.length() == size && digest(file) == expected.text("sha256")) {
        "Legal material does not match its reviewed size/digest: ${expected.text("id")}. " +
            "Review the input; do not silently replace the pinned digest."
    }
}

val prepareRuntimeLegalMaterials = tasks.register("prepareRuntimeLegalMaterials") {
    group = "build"
    description = "Obtains and verifies only the pinned inputs used for supplemental legal texts."
    inputs.file(legalManifestFile)
    outputs.files(provider { legalMaterials.map { materialFile(it) } })
    doLast {
        require(legalMaterials.map { it.text("id") }.distinct().size == legalMaterials.size)
        require(legalMaterials.map { it.text("path").lowercase(Locale.ROOT) }.distinct().size == legalMaterials.size)
        require(legalMaterials.map { it.text("id") }.toSet()
            == legalSupplements.map { it.text("material") }.toSet()) {
            "Legal inputs must be exactly those used by the supplemental notices."
        }
        legalMaterials.forEach { expected ->
            val target = materialFile(expected)
            val uri = URI(expected.text("url"))
            require(uri.scheme == "https" && uri.rawUserInfo == null && uri.rawQuery == null
                && uri.rawFragment == null && uri.host in setOf(
                    "repo.maven.apache.org", "raw.githubusercontent.com")) {
                "Legal material requires an approved public HTTPS origin."
            }
            if (!target.exists()) {
                require(!gradle.startParameter.isOffline) {
                    "Pinned source material is not cached for offline use: ${expected.text("id")}."
                }
                Files.createDirectories(target.parentFile.toPath())
                val temporary = Files.createTempFile(target.parentFile.toPath(), "source-", ".part")
                try {
                    val expectedSize = (expected["bytes"] as Number).toLong()
                    // Retry transport failures only. A size/digest disagreement still fails closed.
                    for (attempt in 1..3) {
                        try {
                            val connection = uri.toURL().openConnection().apply {
                                connectTimeout = 20000
                                readTimeout = 30000
                            }
                            connection.getInputStream().use { input ->
                                Files.newOutputStream(temporary).use { output ->
                                    val buffer = ByteArray(8192)
                                    var total = 0L
                                    var count = input.read(buffer)
                                    while (count != -1) {
                                        total += count
                                        require(total <= expectedSize) { "Legal-material download exceeded its reviewed size." }
                                        output.write(buffer, 0, count)
                                        count = input.read(buffer)
                                    }
                                }
                            }
                            break
                        } catch (failure: IOException) {
                            if (attempt == 3) throw failure
                            Thread.sleep(250L * attempt)
                        }
                    }
                    verifyMaterial(temporary.toFile(), expected)
                    Files.move(temporary, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
                } finally {
                    Files.deleteIfExists(temporary)
                }
            }
            verifyMaterial(target, expected)
        }
    }
}

// Excerpts retain the exact leading copyright/license comment bytes, including original line endings.
fun supplementBytes(supplement: Map<*, *>): ByteArray {
    val input = materialFile(material(supplement.text("material")))
    val entryName = supplement["entry"] as? String
    val bytes = if (entryName == null) input.readBytes() else ZipFile(input).use { archive ->
        val entry = archive.getEntry(safeRelative(entryName))
            ?: throw GradleException("Missing upstream legal entry: $entryName")
        require(entry.size in 1..(1024L * 1024)) { "Unexpected upstream legal-entry size." }
        archive.getInputStream(entry).use { it.readAllBytes() }
    }
    if (supplement["leadingComment"] != true) return bytes
    require(bytes.size >= 4 && bytes[0] == '/'.code.toByte() && bytes[1] == '*'.code.toByte()) {
        "A reviewed leading-comment source no longer starts with a comment."
    }
    val end = (2 until bytes.size - 1).firstOrNull {
        bytes[it] == '*'.code.toByte() && bytes[it + 1] == '/'.code.toByte()
    } ?: throw GradleException("Unterminated upstream legal comment.")
    return bytes.copyOfRange(0, end + 2)
}

tasks.named("generateRuntimeAttributions") {
    dependsOn(prepareRuntimeLegalMaterials)
    inputs.file(legalManifestFile).withPropertyName("reviewedLegalMaterials")
    inputs.files(provider { legalMaterials.map { materialFile(it) } }).withPropertyName("legalMaterialBytes")
    doLast {
        val root = legalRoot.get().asFile
        val metadata = File(root, "META-INF/burp-exporter")
        val original = jsonObject(File(metadata, "THIRD-PARTY.json"))
        val components = objects(original["components"])
        require(components.map { it.text("coordinate") }.toSet()
            == legalComponents.map { it.text("coordinate") }.toSet()
            && legalComponents.map { it.text("coordinate") }.distinct().size == legalComponents.size) {
            "Runtime dependencies changed; review the attribution inventory for the exact new graph."
        }
        val destinations = mutableSetOf<String>()
        val revised = components.map { component ->
            val owner = legalComponents.single { it["coordinate"] == component["coordinate"] }
            require(component["sha256"] == owner["binarySha256"]) {
                "Runtime bytes changed; review attributions for ${component.text("coordinate")}."
            }
            val ownerRoot = component.text("pom").removeSuffix("/pom.xml")
            val supplements = legalSupplements.filter { it["coordinate"] == component["coordinate"] }.map { item ->
                val name = "$ownerRoot/supplemental/${safeRelative(item.text("name"))}"
                require(destinations.add(name.lowercase(Locale.ROOT))) { "Supplemental legal-resource collision." }
                val target = File(root, name)
                Files.createDirectories(target.parentFile.toPath())
                Files.write(target.toPath(), supplementBytes(item))
                mapOf(
                    "resourcePath" to name, "sha256" to digest(target),
                    "material" to item.text("material"), "sourceEntry" to item["entry"],
                    "leadingComment" to (item["leadingComment"] == true)
                )
            }
            val coverage = if (objects(component["notices"]).isNotEmpty()) "BUNDLED_TEXTS_PRESERVED"
                else if (supplements.isNotEmpty()) "UPSTREAM_TEXTS_SUPPLEMENTED" else "POM_ONLY_REVIEW_REQUIRED"
            require(coverage != "POM_ONLY_REVIEW_REQUIRED") { "Missing legal-text review for ${component["coordinate"]}." }
            component.entries.associate { it.key.toString() to it.value } + mapOf(
                "supplementalNotices" to supplements, "noticeCoverage" to coverage,
                "publishedSourcesUrl" to owner.text("publishedSourcesUrl")
            )
        }
        require(legalSupplements.all { item -> components.any { it["coordinate"] == item["coordinate"] } }) {
            "A supplemental owner is absent from the runtime graph."
        }
        val inventory = mapOf("schemaVersion" to 2, "applicationVersion" to legalApplicationVersion, "components" to revised)
        Files.writeString(File(metadata, "THIRD-PARTY.json").toPath(), JsonOutput.prettyPrint(JsonOutput.toJson(inventory)) + "\n")
        Files.copy(legalManifestFile.toPath(), File(metadata, "LEGAL-MATERIALS.json").toPath(), StandardCopyOption.REPLACE_EXISTING)
        Files.writeString(File(metadata, "THIRD-PARTY.txt").toPath(), """
            Resolved runtime artifacts and upstream materials

            THIRD-PARTY.json identifies the shipped artifacts, POMs, original binary notices and
            supplemental upstream legal texts, with SHA-256 digests and owner-qualified paths.
            LEGAL-MATERIALS.json pins the provenance of the supplemental legal texts. Each
            component identifies its exact published sources URL; the extension source and build
            files are maintained in its public repository. No source archive is embedded here.
            Original files and explicitly identified leading copyright/license comments retain
            their bytes. A source excerpt is not represented as an entire upstream file.

            BUNDLED_TEXTS_PRESERVED and UPSTREAM_TEXTS_SUPPLEMENTED describe preservation,
            not a legal-compliance certification or a license election. Upstream alternatives,
            native-library licenses and file-level notices retain their separate meanings.
            LICENSE.txt is Burp Exporter's license, not its dependencies' license.
            An upstream DEPENDENCIES file is not Burp Exporter's runtime graph.
        """.trimIndent() + "\n")
    }
}

tasks.named<Test>("test") {
    doFirst {
        systemProperty("burp.exporter.legalMaterialCache", materialRoot.absolutePath)
    }
}
