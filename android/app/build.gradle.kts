// 1T-B1b architecture-proof app module. Intentionally tiny: one Activity,
// no Compose, no navigation, no DI, no database, no networking, no
// preferences, no ViewModel, no coroutines. It exists to prove the FFI
// boundary works, not to be the real LocalVault Android UI.
// AGP 9.x compiles Kotlin natively; do not apply org.jetbrains.kotlin.android
// here (see build.gradle.kts at the repo-android root for why).
plugins {
    id("com.android.application")
}

// Generated-only locations for 1T-B1b build artifacts that must never be
// committed: the cross-compiled bridge .so, the UniFFI-generated Kotlin
// binding, and the verified copy of the canonical compat fixture. The
// PowerShell proof script (scripts/build-b1b-proof.ps1) populates these
// before Gradle runs; Gradle only ever reads from them.
// Plain `File`s (not Gradle `Provider`s): AGP 9's legacy sourceSet API
// rejects Providers for jniLibs/kotlin/assets srcDirs (it cannot tell
// whether a Provider points at generated vs. static content), so these are
// resolved eagerly at configuration time instead.
val b1bGeneratedJniLibs = File(project.buildDir, "generated/b1bJniLibs")
val b1bGeneratedKotlin = File(project.buildDir, "generated/b1bKotlin")
val b1bGeneratedAssets = File(project.buildDir, "generated/b1bAssets")

android {
    namespace = "com.localvault.android.proof"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.localvault.android.proof"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1t-b1b-proof"

        // B1b proves arm64-v8a only, matching the approved 1T-B1a/1T-B1b
        // scope (no additional ABIs are added merely for completeness).
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
    // targetCompatibility below, so no separate Kotlin compiler-options
    // block is needed for this minimal proof app.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir(b1bGeneratedJniLibs)
            kotlin.srcDir(b1bGeneratedKotlin)
            assets.srcDir(b1bGeneratedAssets)
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
