<#
.SYNOPSIS
    1T-B1b architecture-proof build script.

.DESCRIPTION
    Deliberately explicit, not a generalized build framework (see 1T-A2's
    Gradle-integration-uncertainty finding: this repository does not assume
    any particular UniFFI/Android Gradle plugin integration exists or is
    current). Performs, in order:

      1. verify expected toolchain paths;
      2. verify the canonical compat fixture's SHA256 (refuse to proceed on
         drift -- the fixture is single-sourced from
         src-tauri/tests/fixtures/compat/, never duplicated);
      3. reset the generated output directories under android/app/build/generated;
      4. cargo-ndk build the localvault-android-bridge cdylib for arm64-v8a;
      5. build the host-only uniffi-bindgen binary and generate the Kotlin
         binding in library mode directly from the cross-compiled arm64-v8a
         .so (verified during 1T-B1b implementation to produce output
         byte-identical to generating from a host-target build, confirming
         UniFFI 0.32.0's embedded metadata is architecture-agnostic here --
         not merely assumed from documentation);
      6. copy the built .so into the generated jniLibs/arm64-v8a/ source set;
      7. (Kotlin binding is written directly into the generated Kotlin
         source set by step 5);
      8. copy the hash-verified canonical fixture into the generated assets
         source set;
      9. run `gradlew assembleDebug`.

    None of the generated artifacts (the .so, the generated Kotlin, the
    copied fixture, or the APK) are committed -- android/.gitignore excludes
    app/build/ entirely. The canonical fixture at
    src-tauri/tests/fixtures/compat/schema2_baseline.envelope.json remains
    the only source of truth; this script only ever reads it and verifies
    its hash before copying.

.NOTES
    Run from anywhere; paths are resolved relative to this script's location.
    Requires the toolchain installed/pinned during 1T-B1a/1T-B1b:
      Rust target aarch64-linux-android, Android NDK 27.2.12479018 (r27c),
      cargo-ndk 4.1.2, JDK 17, Android SDK with platforms;android-36 and
      build-tools;36.0.0.
#>

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$AndroidRoot = Join-Path $RepoRoot "android"
$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
$Cargo = Join-Path $CargoBin "cargo.exe"

$AndroidSdkRoot = "C:\Users\nikita\AppData\Local\Android\Sdk"
$AndroidNdkHome = Join-Path $AndroidSdkRoot "ndk\27.2.12479018"
$JavaHome = "C:\Program Files\Java\jdk-17"

$CanonicalFixture = Join-Path $RepoRoot "src-tauri\tests\fixtures\compat\schema2_baseline.envelope.json"
$ExpectedFixtureHash = "f5bf1fcdb11115f0fa39598389a7a8ce3b9c44b78ddfd5295b57845b52155f55"

$AppGeneratedRoot = Join-Path $AndroidRoot "app\build\generated"
$JniLibsOutDir = Join-Path $AppGeneratedRoot "b1bJniLibs"
$KotlinOutDir = Join-Path $AppGeneratedRoot "b1bKotlin"
$AssetsOutDir = Join-Path $AppGeneratedRoot "b1bAssets"

Write-Host "== 1T-B1b architecture-proof build ==" -ForegroundColor Cyan

# --- 1. verify expected toolchain paths ------------------------------------
Write-Host "-- Step 1: verifying toolchain paths"
foreach ($path in @($Cargo, $AndroidSdkRoot, $AndroidNdkHome, $JavaHome)) {
    if (-not (Test-Path $path)) {
        throw "Required toolchain path missing: $path"
    }
}
$env:PATH = "$CargoBin;$env:PATH"
$env:JAVA_HOME = $JavaHome
$env:ANDROID_NDK_HOME = $AndroidNdkHome
$env:ANDROID_HOME = $AndroidSdkRoot
$env:ANDROID_SDK_ROOT = $AndroidSdkRoot
& $Cargo --version
Write-Host "   toolchain paths OK"

# --- 2. verify canonical fixture SHA256 -------------------------------------
Write-Host "-- Step 2: verifying canonical compat fixture hash"
if (-not (Test-Path $CanonicalFixture)) {
    throw "Canonical fixture missing: $CanonicalFixture"
}
$actualHash = (Get-FileHash -Algorithm SHA256 -Path $CanonicalFixture).Hash.ToLowerInvariant()
if ($actualHash -ne $ExpectedFixtureHash) {
    throw ("Canonical fixture hash mismatch.`n" +
        "  expected: $ExpectedFixtureHash`n" +
        "  actual:   $actualHash`n" +
        "Refusing to proceed -- the fixture may have drifted or this pin is stale.")
}
Write-Host "   fixture hash OK: $actualHash"

# --- 3. reset generated output directories ----------------------------------
Write-Host "-- Step 3: resetting generated output directories"
foreach ($dir in @($JniLibsOutDir, $KotlinOutDir, $AssetsOutDir)) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Host "   generated directories reset under $AppGeneratedRoot"

# --- 4. cargo-ndk build the bridge for arm64-v8a ----------------------------
Write-Host "-- Step 4: cargo-ndk build (arm64-v8a)"
Push-Location $RepoRoot
try {
    & $Cargo ndk -t arm64-v8a build -p localvault-android-bridge
    if ($LASTEXITCODE -ne 0) { throw "cargo-ndk build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}
$BuiltSo = Join-Path $RepoRoot "src-tauri\target\aarch64-linux-android\debug\liblocalvault_android_bridge.so"
if (-not (Test-Path $BuiltSo)) {
    throw "Expected built .so not found at $BuiltSo"
}
Write-Host "   built: $BuiltSo"

# --- 5. build uniffi-bindgen (host-only) and generate Kotlin bindings -------
Write-Host "-- Step 5: generating Kotlin bindings (UniFFI 0.32.0, Kotlin/JNA, library mode)"
Push-Location $RepoRoot
try {
    & $Cargo build -p localvault-android-bridge --bin uniffi-bindgen --features bindgen
    if ($LASTEXITCODE -ne 0) { throw "uniffi-bindgen host build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}
$BindgenExe = Join-Path $RepoRoot "src-tauri\target\debug\uniffi-bindgen.exe"
& $BindgenExe generate --library $BuiltSo --language kotlin --out-dir $KotlinOutDir --no-format
if ($LASTEXITCODE -ne 0) { throw "uniffi-bindgen Kotlin generation failed (exit $LASTEXITCODE)" }
Write-Host "   Kotlin bindings written under $KotlinOutDir"

# --- 6. place the .so into the generated jniLibs source set -----------------
Write-Host "-- Step 6: placing .so into generated jniLibs/arm64-v8a/"
$JniLibsAbiDir = Join-Path $JniLibsOutDir "arm64-v8a"
New-Item -ItemType Directory -Force -Path $JniLibsAbiDir | Out-Null
Copy-Item $BuiltSo (Join-Path $JniLibsAbiDir "liblocalvault_android_bridge.so") -Force
Write-Host "   done"

# --- 7. (Kotlin already placed in step 5) -----------------------------------

# --- 8. copy the verified canonical fixture into generated assets ----------
Write-Host "-- Step 8: copying hash-verified fixture into generated assets"
Copy-Item $CanonicalFixture (Join-Path $AssetsOutDir "compat_fixture.bin") -Force
Write-Host "   done"

# --- 9. run Gradle debug build -----------------------------------------------
Write-Host "-- Step 9: gradlew assembleDebug"
Push-Location $AndroidRoot
try {
    & .\gradlew.bat --no-daemon assembleDebug
    if ($LASTEXITCODE -ne 0) { throw "Gradle assembleDebug failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$Apk = Join-Path $AndroidRoot "app\build\outputs\apk\debug\app-debug.apk"
if (-not (Test-Path $Apk)) {
    throw "Expected debug APK not found at $Apk"
}

Write-Host "== BUILD PASS ==" -ForegroundColor Green
Write-Host "APK: $Apk"
