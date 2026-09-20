// 1T-B1b architecture-proof root build file. Deliberately minimal: this is
// not the real LocalVault Android app yet, just the smallest project that
// proves Kotlin -> stable UniFFI/JNA -> localvault-android-bridge ->
// localvault-core works end to end. See docs/ROADMAP.md (1T) and the
// 1T-A / 1T-A2 / 1T-B1a audits for the approved architecture this
// implements.
// AGP 9.x has built-in Kotlin support; the separate
// org.jetbrains.kotlin.android plugin is no longer applied (it is
// incompatible with AGP 9's DSL -- see
// https://developer.android.com/build/releases/agp-9-0-0-release-notes#android-gradle-plugin-built-in-kotlin).
// AGP 9.2.0 carries its own default Kotlin Gradle Plugin version; this
// buildscript override pins the exact approved Kotlin line (2.4.20) instead
// of silently floating on whatever AGP bundles.
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.20")
    }
}

plugins {
    id("com.android.application") version "9.2.0" apply false
}
