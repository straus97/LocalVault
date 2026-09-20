<#
.SYNOPSIS
    Normal LocalVault Android debug build pipeline (arm64-v8a).

.DESCRIPTION
    Deliberately explicit, not a generalized build framework. Performs, in order:

      1. verify expected toolchain paths;
      2. reset the generated output directories under android/app/build/generated;
      3. cargo-ndk build the localvault-android-bridge cdylib for arm64-v8a;
      4. build the host-only uniffi-bindgen (pinned UniFFI 0.32.0) and generate
         the Kotlin binding in library mode from the cross-compiled .so;
      5. place the .so into the generated jniLibs/arm64-v8a/ source set
         (the Kotlin binding is written directly into the generated Kotlin
         source set by step 4);
      6. run `gradlew assembleDebug`;
      7. verify the APK contains no compatibility fixture.

    Nothing generated (the .so, the generated Kotlin, the APK) is committed:
    android/.gitignore excludes app/build/ entirely. The compatibility fixtures
    under src-tauri/tests/fixtures/compat/ are used only by Rust tests and are
    never copied into the Android app.

.NOTES
    Run from anywhere; paths are resolved relative to this script's location.
    Requires: Rust target aarch64-linux-android, Android NDK 27.2.12479018
    (r27c), cargo-ndk, JDK 17, Android SDK with platforms;android-36 and
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

$AppGeneratedRoot = Join-Path $AndroidRoot "app\build\generated"
$JniLibsOutDir = Join-Path $AppGeneratedRoot "jniLibs"
$KotlinOutDir = Join-Path $AppGeneratedRoot "uniffiKotlin"

Write-Host "== LocalVault Android debug build ==" -ForegroundColor Cyan

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

# --- 2. reset generated output directories ----------------------------------
Write-Host "-- Step 2: resetting generated output directories"
if (Test-Path $AppGeneratedRoot) { Remove-Item -Recurse -Force $AppGeneratedRoot }
foreach ($dir in @($JniLibsOutDir, $KotlinOutDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Host "   generated directories reset under $AppGeneratedRoot"

# --- 3. cargo-ndk build the bridge for arm64-v8a ----------------------------
Write-Host "-- Step 3: cargo-ndk build (arm64-v8a)"
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

# --- 4. build uniffi-bindgen (host-only) and generate Kotlin bindings ------
Write-Host "-- Step 4: generating Kotlin bindings (UniFFI 0.32.0, Kotlin/JNA, library mode)"
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

# --- 5. place the .so into the generated jniLibs source set -----------------
Write-Host "-- Step 5: placing .so into generated jniLibs/arm64-v8a/"
$JniLibsAbiDir = Join-Path $JniLibsOutDir "arm64-v8a"
New-Item -ItemType Directory -Force -Path $JniLibsAbiDir | Out-Null
Copy-Item $BuiltSo (Join-Path $JniLibsAbiDir "liblocalvault_android_bridge.so") -Force
Write-Host "   done"

# --- 6. run Gradle debug build -----------------------------------------------
Write-Host "-- Step 6: gradlew assembleDebug"
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

# --- 7. verify the APK bundles no compatibility fixture ---------------------
Write-Host "-- Step 7: verifying the APK contains no compatibility fixture"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($Apk)
try {
    $bad = @($zip.Entries | Where-Object {
            $_.FullName -like "assets/*" -or $_.FullName -match "fixture|envelope|\.lvault"
        })
} finally {
    $zip.Dispose()
}
if ($bad.Count -gt 0) {
    throw ("APK unexpectedly contains asset/fixture-like entries: " +
        (($bad | ForEach-Object { $_.FullName }) -join ", "))
}
Write-Host "   APK has no assets/fixture entries"

Write-Host "== BUILD PASS ==" -ForegroundColor Green
Write-Host "APK: $Apk"
