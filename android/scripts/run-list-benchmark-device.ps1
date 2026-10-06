<#
.SYNOPSIS
    Runs the ON-DEVICE Android list view-rebuild benchmark.

.DESCRIPTION
    Builds the debug app and androidTest benchmark APK, installs both, runs
    com.localvault.android.bench.ListRebuildBenchmark, saves instrumentation
    output plus LVBench logcat, then removes only the androidTest package.

    The benchmark uses the real MainActivity with deterministic synthetic
    EntrySummary data. No real vault is opened or read and no vault data is
    written.

    The app APK is installed with `adb install -r`, so the existing debug app
    is replaced while its app data is preserved when the signing key matches.

    Keep the phone connected, unlocked and with the screen on during a run.
    This script deliberately does NOT inject wake/unlock events and does NOT
    modify Android secure/global stay-awake settings because some OEM Android
    16 builds reject those shell operations.

    Results:
      android\app\build\benchmark\list-rebuild-device.txt

.PARAMETER Serial
    ADB serial. Example: 23e9e31e

.PARAMETER Sizes
    Comma-separated entry counts.

.PARAMETER Iterations
    Measured iterations per scenario.

.PARAMETER Warmup
    Warm-up iterations per scenario.

.EXAMPLE
    .\run-list-benchmark-device.ps1 `
        -Serial 23e9e31e `
        -Sizes "1000,5000,10000,50000" `
        -Iterations 7 `
        -Warmup 2
#>

param(
    [string]$Serial = "",
    [string]$Sizes = "1000,5000,10000,50000",
    [int]$Iterations = 7,
    [int]$Warmup = 2
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$AndroidRoot = Join-Path $RepoRoot "android"

$JavaHome = "C:\Program Files\Java\jdk-17"
$AndroidSdkRoot = "C:\Users\nikita\AppData\Local\Android\Sdk"
$Adb = Join-Path $AndroidSdkRoot "platform-tools\adb.exe"

$OutDir = Join-Path $AndroidRoot "app\build\benchmark"
$OutFile = Join-Path $OutDir "list-rebuild-device.txt"

$AppApk = Join-Path $AndroidRoot "app\build\outputs\apk\debug\app-debug.apk"
$TestApk = Join-Path $AndroidRoot "app\build\outputs\apk\androidTest\debug\app-debug-androidTest.apk"

if (-not (Test-Path $Adb)) {
    throw "adb not found at $Adb"
}

$serialArgs = @()

if ($Serial -ne "") {
    $serialArgs = @("-s", $Serial)
}

$env:JAVA_HOME = $JavaHome
$env:ANDROID_HOME = $AndroidSdkRoot
$env:ANDROID_SDK_ROOT = $AndroidSdkRoot

Write-Host "-- building debug app + benchmark APK" -ForegroundColor Cyan

Push-Location $AndroidRoot

try {
    & .\gradlew.bat --no-daemon assembleDebug assembleDebugAndroidTest

    if ($LASTEXITCODE -ne 0) {
        throw "Gradle build failed (exit $LASTEXITCODE)"
    }
}
finally {
    Pop-Location
}

foreach ($apk in @($AppApk, $TestApk)) {
    if (-not (Test-Path $apk)) {
        throw "APK not found: $apk"
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "-- checking device" -ForegroundColor Cyan

& $Adb @serialArgs get-state

if ($LASTEXITCODE -ne 0) {
    throw "ADB device is not available"
}

Write-Host "-- installing app APK" -ForegroundColor Cyan

& $Adb @serialArgs install -r $AppApk

if ($LASTEXITCODE -ne 0) {
    throw "install app failed"
}

Write-Host "-- installing benchmark APK" -ForegroundColor Cyan
Write-Host "Watch the phone and approve installation if the OS asks." -ForegroundColor Yellow

& $Adb @serialArgs install -r -t $TestApk

if ($LASTEXITCODE -ne 0) {
    throw "install benchmark APK failed"
}

$testInstalled = $true

try {
    Write-Host "-- verifying instrumentation" -ForegroundColor Cyan

    $instrumentations = @(
        & $Adb @serialArgs shell pm list instrumentation
    )

    if ($LASTEXITCODE -ne 0) {
        throw "could not list instrumentation"
    }

    $expectedInstrumentation =
        "com.localvault.android.test/com.localvault.android.bench.ListRebuildBenchmark"

    if (($instrumentations -join "`n") -notmatch [regex]::Escape($expectedInstrumentation)) {
        throw "expected benchmark instrumentation is not registered"
    }

    & $Adb @serialArgs logcat -c

    if ($LASTEXITCODE -ne 0) {
        throw "logcat clear failed"
    }

    Write-Host "-- running instrumentation" -ForegroundColor Cyan
    Write-Host "Keep the phone unlocked and do not interact with it." -ForegroundColor Yellow

    $instrumentOutput = @(
        & $Adb @serialArgs shell am instrument -w `
            -e sizes $Sizes `
            -e iterations $Iterations `
            -e warmup $Warmup `
            com.localvault.android.test/com.localvault.android.bench.ListRebuildBenchmark `
            2>&1
    )

    $instrumentExit = $LASTEXITCODE

    $instrumentOutput |
        Set-Content -Path $OutFile -Encoding UTF8

    Add-Content -Path $OutFile -Value ""
    Add-Content -Path $OutFile -Value "===== LVBENCH LOGCAT ====="

    $benchLog = @(
        & $Adb @serialArgs logcat -d -s "LVBench:I" "*:S" 2>&1
    )

    $benchLog |
        Add-Content -Path $OutFile -Encoding UTF8

    $instrumentOutput

    if ($instrumentExit -ne 0) {
        throw "adb instrumentation failed (exit $instrumentExit). See $OutFile"
    }

    $instrumentText = [System.IO.File]::ReadAllText($OutFile)

    if ($instrumentText -notmatch '(?m)^DONE\s*$') {
        throw "benchmark did not emit DONE. See $OutFile"
    }

    if ($instrumentText -notmatch '(?m)^INSTRUMENTATION_CODE:\s*-1\s*$') {
        throw "benchmark did not finish with RESULT_OK. See $OutFile"
    }

    if ($instrumentText -match 'OUT_OF_MEMORY') {
        Write-Host "WARNING: benchmark reported OUT_OF_MEMORY; result is still preserved." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "== benchmark PASS ==" -ForegroundColor Green
    Write-Host "saved: $OutFile"
}
finally {
    if ($testInstalled) {
        Write-Host "-- removing benchmark APK" -ForegroundColor Cyan

        & $Adb @serialArgs uninstall com.localvault.android.test |
            Out-Null
    }
}