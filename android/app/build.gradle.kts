// LocalVault Android app module. Native framework views only: no Compose, no
// navigation, no DI, no database, no networking, no preferences, no ViewModel,
// no coroutines. Vault cryptography lives entirely in Rust (localvault-core),
// reached through the stable UniFFI Kotlin/JNA bridge.
// AGP 9.x compiles Kotlin natively; do not apply org.jetbrains.kotlin.android
// here (see build.gradle.kts at the repo-android root for why).
plugins {
    id("com.android.application")
}

// Generated-only locations that must never be committed: the cross-compiled
// bridge .so and the UniFFI-generated Kotlin binding. The PowerShell build
// script (scripts/build-android-debug.ps1) populates these before Gradle
// runs; Gradle only ever reads from them. No test fixture is packaged.
// Plain `File`s (not Gradle `Provider`s): AGP 9's legacy sourceSet API
// rejects Providers for jniLibs/kotlin srcDirs (it cannot tell whether a
// Provider points at generated vs. static content), so these are resolved
// eagerly at configuration time instead.
val generatedJniLibs = File(project.buildDir, "generated/jniLibs")
val generatedUniffiKotlin = File(project.buildDir, "generated/uniffiKotlin")

android {
    namespace = "com.localvault.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.localvault.android"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1t-b3"

        // Only used when the on-device list benchmark is built/run
        // (src/androidTest, plain android.app.Instrumentation -- no AndroidX
        // test libraries). Has no effect on the app itself.
        testInstrumentationRunner = "com.localvault.android.bench.ListRebuildBenchmark"

        // arm64-v8a only for now (no additional ABIs added for completeness).
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
    }

    // AGP 9.x compiles Kotlin natively; jvmTarget defaults to
    // targetCompatibility below.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir(generatedJniLibs)
            kotlin.srcDir(generatedUniffiKotlin)
        }
        // List-performance benchmark (not a 1T-B stage): the synthetic
        // dataset generator is shared by the plain-JVM benchmark (src/test)
        // and the on-device view-rebuild harness (src/androidTest) so both
        // measure identical data. Test-only; never part of the app.
        getByName("test") {
            kotlin.srcDir("src/benchShared/java")
        }
        getByName("androidTest") {
            kotlin.srcDir("src/benchShared/java")
        }
    }

    buildFeatures {
        buildConfig = false
    }
}

dependencies {
    // Android/JVM-side only. Never added to localvault-core or the Rust
    // bridge crate's own Cargo.toml -- JNA is how the stable UniFFI Kotlin
    // binding path talks to the native library, not a Rust dependency.
    implementation("net.java.dev.jna:jna:5.19.1@aar")

    // 1T-B5a: local (plain-JVM) unit tests for the new save/creation
    // orchestration logic (stale-source checks, recovery-snapshot bookkeeping,
    // reconciliation, grant-flag intersection). These depend only on small
    // interfaces (SafDocumentIo, RecoverySnapshotStore) and the UniFFI-
    // generated VaultSessionInterface, so a plain JUnit4 dependency is
    // sufficient -- no Robolectric/instrumentation is needed, and none is
    // added, since nothing under test touches a real ContentResolver/
    // AtomicFile directly (those concrete implementations are exercised by
    // on-device QA instead, per the accepted 1T-B5 review's test plan).
    testImplementation("junit:junit:4.13.2")
}
