plugins {
    application
}

group = "me.cxdev"
version = providers.gradleProperty("releaseVersion").get()

repositories { mavenCentral() }

dependencies {
    implementation("com.google.code.gson:gson:2.15.0")
    testImplementation(platform("org.junit:junit-bom:5.14.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

application { mainClass.set("me.cxdev.certtool.CertTool") }

sourceSets {
    test { java.setSrcDirs(listOf("test/java")) }
}

tasks.test { useJUnitPlatform() }

val copyRuntimeLibraries = tasks.register<Sync>("copyRuntimeLibraries") {
    dependsOn(tasks.jar)
    from(configurations.runtimeClasspath)
    from(tasks.jar)
    into(layout.projectDirectory.dir("lib"))
}

tasks.jar {
    archiveBaseName.set("certtool")
    manifest {
        attributes["Main-Class"] = application.mainClass.get()
        attributes["Implementation-Version"] = project.version
    }
}

tasks.register<Zip>("releaseZip") {
    dependsOn(copyRuntimeLibraries)
    archiveBaseName.set("certtool")
    archiveVersion.set(project.version.toString())
    destinationDirectory.set(layout.buildDirectory.dir("release"))
    from(layout.projectDirectory.dir("lib")) { into("lib") }
    from("bin") { into("bin") }
    from("certtool.example.json")
    from("tools/.gitkeep") { into("tools") }
    from("README.md")
    from("LICENSE")
    from("THIRD_PARTY_LICENSES.md")
}
