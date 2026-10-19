import java.util.Collections
import java.nio.file.Files
import java.util.jar.JarFile
import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult
import org.gradle.jvm.tasks.Jar
import org.gradle.testing.jacoco.tasks.JacocoReport
import org.gradle.external.javadoc.StandardJavadocDocletOptions

import com.github.spotbugs.snom.Confidence
import com.github.spotbugs.snom.Effort
import com.github.spotbugs.snom.SpotBugsTask

plugins {
    java
    jacoco
    alias(libs.plugins.ben.manes.versions)
    alias(libs.plugins.spotless)
    alias(libs.plugins.spotbugs)
}

group = project.property("group").toString()
version = project.property("version").toString()

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

repositories {
    mavenCentral()
}

dependencies {
    // compileOnly
    compileOnly(libs.montoya)
    compileOnly(libs.logbackClassic)
    compileOnly(libs.spotbugsAnnotations)

    // implementation
    implementation(libs.jacksonCore)
    implementation(libs.jacksonDatabind)
    implementation(libs.miglayoutSwing)
    implementation(libs.jakartaJsonApi)
    // Index/mapping operations use Jackson JSON-P, not the optional JSON-B mapper.
    implementation(libs.opensearchJava) {
        exclude(group = "jakarta.json.bind", module = "jakarta.json.bind-api")
        exclude(group = "org.eclipse", module = "yasson")
        exclude(group = "org.eclipse.parsson", module = "parsson")
    }
    implementation(libs.elasticsearchRestClient)
    implementation(libs.awsSdkAuth)
    implementation(libs.awsSdkRegions)
    implementation(libs.awsSdkSts)
    implementation(libs.awsSdkSso)
    implementation(libs.awsSdkSsoOidc)
    implementation(libs.slf4jApi)
    implementation(libs.jfreechart)
    implementation(libs.brotliDec)
    implementation(libs.commonsCompress)
    implementation(libs.zstdJni)

    // testImplementation
    testImplementation(platform(libs.junitBom))
    testImplementation(libs.junitJupiter)
    testImplementation(libs.junitPlatformLauncher)
    testImplementation(libs.mockitoCore)
    testImplementation(libs.mockitoJunitJupiter)
    testImplementation(libs.assertjCore)
    testImplementation(libs.brotli4j)
    testImplementation(libs.montoya)

    // testRuntimeOnly
    testRuntimeOnly(libs.junitJupiterEngine)
    testRuntimeOnly(libs.brotli4jNativeWindows)
    testRuntimeOnly(libs.brotli4jNativeLinux)

    // runtimeOnly
    runtimeOnly(libs.logbackClassic)
    runtimeOnly(libs.parsson)
}

// Profile credentials use synchronous STS/SSO clients; retain their Apache5 transport.
configurations.configureEach {
    exclude(group = "software.amazon.awssdk", module = "netty-nio-client")
}

// Toggle with: gradlew test -PverboseTests=true
val verboseTests: Boolean =
    (project.findProperty("verboseTests")?.toString()?.toBooleanStrictOrNull()) ?: false
val excludeIntegration: Boolean = project.hasProperty("excludeIntegration")

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(
        listOf(
            "-Xlint:all",
            "-Werror",
        ),
    )
}

spotbugs {
    toolVersion.set(libs.versions.spotbugs.get())
    effort.set(Effort.MAX)
    reportLevel.set(Confidence.HIGH)
}

tasks.withType<SpotBugsTask>().configureEach {
    analyseClassFile.set(layout.buildDirectory.file("spotbugs/$name-analyse-class-file.txt"))
    reports.create("html") {
        required.set(true)
    }
}

spotless {
    java {
        target("src/main/java/**/*.java", "src/test/java/**/*.java")
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
    }
}

tasks.test {
    dependsOn("fatJar")
    inputs.file(provider { tasks.named<Jar>("fatJar").get().archiveFile.get() }).withPropertyName("packagedJar")
    inputs.property("excludeIntegration", excludeIntegration)
    useJUnitPlatform {
        if (excludeIntegration) {
            excludeTags("integration")
        }
    }

    workingDir = project.projectDir
    // Keep test spools and native temporary files separate from a running Burp instance.
    systemProperty("java.io.tmpdir", temporaryDir.absolutePath)
    doFirst {
        logger.lifecycle(if (excludeIntegration) {
            "Verification lane: CI/unit and packaged runtime; integration-tagged tests excluded."
        } else {
            "Verification lane: full; integration-tagged tests included subject to destination availability."
        })
        // A preceding clean task may remove the directory created during configuration.
        Files.createDirectories(temporaryDir.toPath())
        systemProperty("burp.exporter.packagedJar", tasks.named<Jar>("fatJar").get().archiveFile.get().asFile.absolutePath)
        systemProperty("burp.exporter.runtimeJars", configurations.runtimeClasspath.get().asPath)
    }
    systemProperty("java.awt.headless", "true")
    systemProperty("burp.exporter.version", project.version.toString())
    // Forward OpenSearch URL/creds from Gradle -P or env into the test JVM (forked process does not inherit -P)
    listOf(
        "OPENSEARCH_URL",
        "OPENSEARCH_USER",
        "OPENSEARCH_PASSWORD",
        "OPENSEARCH_CERT_PATH",
        "OPENSEARCH_CERT_KEY_PATH",
        "DATA_VOLUME_ROOT",
        "OPENSEARCH_CONTAINER",
        "OPENSEARCH_STACK_ENV",
    ).forEach { key ->
        val value = project.findProperty(key)?.toString()?.takeIf { it.isNotBlank() }
            ?: System.getenv(key)?.takeIf { it.isNotBlank() }
        if (value != null) systemProperty(key, value)
    }
    // Allow HTTPS to local/test OpenSearch with self-signed cert (same as curl -k)
    systemProperty("OPENSEARCH_INSECURE", "true")

    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = verboseTests
        showExceptions = true
        showCauses = true
        showStackTraces = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }

    val green = "\u001B[32m"
    val red = "\u001B[31m"
    val yellow = "\u001B[33m"
    val reset = "\u001B[0m"
    val failedTests = Collections.synchronizedList(mutableListOf<String>())

    addTestListener(object : TestListener {
        override fun beforeTest(descriptor: TestDescriptor) {}
        override fun beforeSuite(suite: TestDescriptor) {}

        override fun afterSuite(suite: TestDescriptor, result: TestResult) {
            if (suite.parent != null) {
                return
            }
            val total = result.testCount
            val failed = result.failedTestCount
            val skipped = result.skippedTestCount
            val passed = total - failed - skipped
            println("Test summary: total=$total, passed=$passed, failed=$failed, skipped=$skipped")
            if (failed > 0) {
                println("${red}Failed tests:${reset}")
                failedTests.forEach { println("  - $it") }
            }
        }

        override fun afterTest(descriptor: TestDescriptor, result: TestResult) {
            val label = "${descriptor.className} > ${descriptor.displayName}"
            when (result.resultType) {
                TestResult.ResultType.FAILURE -> {
                    failedTests.add(label)
                    // Gradle's test log sometimes omits the failing test on CI; always echo it here.
                    println("${red}FAILED${reset} $label")
                    result.exception?.printStackTrace(System.out)
                }
                TestResult.ResultType.SKIPPED -> if (verboseTests) {
                    println("${yellow}SKIPPED${reset} $label")
                }
                else -> if (verboseTests) {
                    println("${green}PASSED${reset} $label")
                }
            }
        }
    })
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn(tasks.test)
    reports {
        xml.required.set(false)
        csv.required.set(false)
        html.required.set(true)
    }
}

tasks.withType<Javadoc>().configureEach {
    isFailOnError = true
    (options as StandardJavadocDocletOptions).apply {
        addBooleanOption("Xdoclint:all,-missing", true)
        encoding = "UTF-8"
        charSet = "UTF-8"
        docEncoding = "UTF-8"
        locale = "en_US"
        links("https://docs.oracle.com/en/java/javase/21/docs/api/")
    }
}

// Each synchronous AWS service contributes a distinct warm-up provider at this shared path.
val sdkWarmupService = "META-INF/services/software.amazon.awssdk.core.warmup.SdkWarmUpProvider"
val mergedServiceRoot = layout.buildDirectory.dir("generated/runtime-services")
val mergeSdkWarmupService = tasks.register("mergeSdkWarmupService") {
    description = "Preserves every resolved AWS service warm-up provider in the distributable."
    inputs.files(configurations.runtimeClasspath).withPropertyName("runtimeClasspath")
    outputs.file(mergedServiceRoot.map { it.file(sdkWarmupService) })
    doLast {
        val providers = sortedSetOf<String>()
        configurations.runtimeClasspath.get().filter { it.extension == "jar" }.forEach { file ->
            JarFile(file).use { jar ->
                jar.getJarEntry(sdkWarmupService)?.let { entry ->
                    jar.getInputStream(entry).bufferedReader(Charsets.UTF_8).useLines { lines ->
                        lines.map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }
                            .forEach { providers.add(it) }
                    }
                }
            }
        }
        val output = mergedServiceRoot.get().file(sdkWarmupService).asFile
        Files.createDirectories(output.parentFile.toPath())
        Files.writeString(output.toPath(), providers.joinToString("\n", postfix = "\n"), Charsets.UTF_8)
    }
}

tasks.register<Jar>("fatJar") {
    group = "build"
    description = "Assembles a fat JAR containing compiled classes and runtime dependencies."

    archiveBaseName.set(project.property("archivesBaseName").toString())
    archiveVersion.set(project.property("version").toString())
    destinationDirectory.set(layout.buildDirectory.dir("libs"))
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version
        )
    }

    from(sourceSets.main.get().output)
    dependsOn(mergeSdkWarmupService)
    from(mergedServiceRoot)

    dependsOn(configurations.runtimeClasspath)
    // Runtime dependency expansion and owner-qualified legal metadata live in the attribution script.
}

tasks.named<Jar>("jar") {
    enabled = false
}

tasks.assemble {
    dependsOn("fatJar")
}

tasks.build {
    dependsOn("fatJar")
}

apply(from = "gradle/runtime-attributions.gradle.kts")
