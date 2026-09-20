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
    namespace = "com.localvault.android.proof"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.localvault.android.proof"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1t-b3"

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
}
