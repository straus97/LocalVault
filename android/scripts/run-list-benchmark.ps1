<#
.SYNOPSIS
    Runs the Android list DATA-ONLY benchmark (host JVM, no device).

.DESCRIPTION
    Runs android/app/src/test/.../bench/ListDataBenchmark.kt, which times the
    production EntryListFilter (the exact category + search filter MainActivity
    uses) over deterministic synthetic EntrySummary data at 1k / 5k / 10k / 50k
    entries. The benchmark is opt-in (LOCALVAULT_BENCH=1) so the normal JVM
    suite stays fast; this script sets that, forces the test task to re-run
    (Gradle would otherwise treat it as UP-TO-DATE), and prints the report.

    The report is written to android\app\build\benchmark\list-data-benchmark.md
    (inside the git-ignored build/ directory -- nothing to clean up, nothing to
    commit).

    Prerequisite: the generated UniFFI Kotlin binding must exist (run
    android\scripts\build-android-debug.ps1 once). No device is used.

.PARAMETER Sizes
    Comma-separated dataset sizes. Default: 1000,5000,10000,50000.
.PARAMETER Iterations
    Measured iterations per scenario (default 60).
.PARAMETER Warmup
    Warm-up iterations per scenario (default 30).

.NOTES
    Numbers are host-JVM (HotSpot, desktop CPU) timings, not phone/ART timings.
    Re-run on the same machine before and after a change to compare.
#>
param(
    [string]$Sizes = "1000,5000,10000,50000",
    [int]$Iterations = 60,
    [int]$Warmup = 30
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$AndroidRoot = Join-Path $RepoRoot "android"
$JavaHome = "C:\Program Files\Java\jdk-17"
$AndroidSdkRoot = "C:\Users\nikita\AppData\Local\Android\Sdk"
$Generated = Join-Path $AndroidRoot "app\build\generated\uniffiKotlin"

if (-not (Test-Path $Generated)) {
    throw "Generated UniFFI Kotlin binding missing at $Generated. Run android\scripts\build-android-debug.ps1 first."
}

$env:JAVA_HOME = $JavaHome
$env:ANDROID_HOME = $AndroidSdkRoot
$env:ANDROID_SDK_ROOT = $AndroidSdkRoot
$env:LOCALVAULT_BENCH = "1"
$env:LOCALVAULT_BENCH_SIZES = $Sizes
$env:LOCALVAULT_BENCH_ITERATIONS = "$Iterations"
$env:LOCALVAULT_BENCH_WARMUP = "$Warmup"

Push-Location $AndroidRoot
try {
    & .\gradlew.bat --no-daemon testDebugUnitTest --rerun --tests "com.localvault.android.bench.ListDataBenchmark"
    if ($LASTEXITCODE -ne 0) { throw "benchmark run failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
    Remove-Item Env:LOCALVAULT_BENCH, Env:LOCALVAULT_BENCH_SIZES, Env:LOCALVAULT_BENCH_ITERATIONS, Env:LOCALVAULT_BENCH_WARMUP -ErrorAction SilentlyContinue
}

$Report = Join-Path $AndroidRoot "app\build\benchmark\list-data-benchmark.md"
if (-not (Test-Path $Report)) { throw "Expected report not found: $Report" }
Write-Host ""
Write-Host "== report: $Report ==" -ForegroundColor Cyan
Get-Content $Report
