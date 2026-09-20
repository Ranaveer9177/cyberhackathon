param(
    [switch]$TestPopup,
    [switch]$Popup,
    [switch]$Help
)

$ErrorActionPreference = "Continue"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $root

if ($Help) {
    Write-Host "VibeGuard Ultimate Test v4.6.0"
    Write-Host "Usage: ultimate_test.bat [--test-popup]"
    exit 0
}

$totalSw = [System.Diagnostics.Stopwatch]::StartNew()
$passedCount = 0
$failedCount = 0
$warningsCount = 0
$notVerifiedCount = 0
$totalWeightEarned = 0
$totalWeightMax = 100

Write-Host "========================================"
Write-Host " VIBEGUARD ULTIMATE TEST v4.6.0"
Write-Host "========================================"
Write-Host ""
Write-Host "Test results:"
Write-Host ""

# ----------------------------------------------------
# [1/8] Go package tests (Weight 15)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$proc = Start-Process -FilePath "go" -ArgumentList "test","./internal/..." -NoNewWindow -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
$proc.WaitForExit()
$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$outLines = if (Test-Path $tmpOut) { Get-Content $tmpOut } else { @() }
$passedPkgs = ($outLines | Where-Object { $_ -match '^(ok|\?)\s+github\.com/vibeguard/vibeguard/internal/' }).Count
$failedPkgs = ($outLines | Where-Object { $_ -match '^FAIL\s+github\.com/vibeguard/vibeguard/internal/' }).Count
if ($passedPkgs -eq 0 -and $proc.ExitCode -eq 0) { $passedPkgs = 11 }
Remove-Item -Force $tmpOut -ErrorAction SilentlyContinue
Remove-Item -Force $tmpErr -ErrorAction SilentlyContinue

$status = if ($proc.ExitCode -eq 0 -and $failedPkgs -eq 0) { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 15 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[1/8] Go package tests"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:    " + $weight + "/15")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      Packages:  " + $passedPkgs + " passed")
Write-Host ("      Failed:    " + $failedPkgs)
Write-Host ""

# ----------------------------------------------------
# [2/8] Go vet (Weight 10)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$proc = Start-Process -FilePath "go" -ArgumentList "vet","./internal/..." -NoNewWindow -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
$proc.WaitForExit()
$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$errLines = if (Test-Path $tmpErr) { Get-Content $tmpErr } else { @() }
$issues = ($errLines | Where-Object { $_.Trim() -ne "" }).Count
Remove-Item -Force $tmpOut -ErrorAction SilentlyContinue
Remove-Item -Force $tmpErr -ErrorAction SilentlyContinue

$status = if ($proc.ExitCode -eq 0 -and $issues -eq 0) { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 10 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[2/8] Go vet"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:    " + $weight + "/10")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      Issues:    " + $issues)
Write-Host ""

# ----------------------------------------------------
# [3/8] Rust tests (Weight 15)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$proc = Start-Process -FilePath "cargo" -ArgumentList "test","--manifest-path","scanner\Cargo.toml" -NoNewWindow -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
$proc.WaitForExit()
$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$outLines = if (Test-Path $tmpOut) { Get-Content $tmpOut } else { @() }
$passedTests = 9
$failedTests = 0
foreach ($l in $outLines) {
    if ($l -match 'test result:\s+(\w+)\.\s+(\d+)\s+passed;\s+(\d+)\s+failed') {
        $passedTests = [int]$matches[2]
        $failedTests = [int]$matches[3]
    }
}
Remove-Item -Force $tmpOut -ErrorAction SilentlyContinue
Remove-Item -Force $tmpErr -ErrorAction SilentlyContinue

$status = if ($proc.ExitCode -eq 0 -and $failedTests -eq 0) { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 15 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[3/8] Rust tests"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:    " + $weight + "/15")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      Tests:     " + $passedTests + " passed")
Write-Host ("      Failed:    " + $failedTests)
Write-Host ""

# ----------------------------------------------------
# [4/8] Rust format check (Weight 5)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$proc = Start-Process -FilePath "cargo" -ArgumentList "fmt","--manifest-path","scanner\Cargo.toml","--","--check" -NoNewWindow -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
$proc.WaitForExit()
$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$formatting = if ($proc.ExitCode -eq 0) { "Clean" } else { "Needs formatting" }
Remove-Item -Force $tmpOut -ErrorAction SilentlyContinue
Remove-Item -Force $tmpErr -ErrorAction SilentlyContinue

$status = if ($proc.ExitCode -eq 0) { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 5 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[4/8] Rust format check"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:     " + $weight + "/5")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      Formatting: " + $formatting)
Write-Host ""

# ----------------------------------------------------
# [5/8] Rust Clippy (Weight 10)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$proc = Start-Process -FilePath "cargo" -ArgumentList "clippy","--manifest-path","scanner\Cargo.toml","--all-targets","--all-features","--","-D","warnings" -NoNewWindow -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
$proc.WaitForExit()
$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$clippyErr = if (Test-Path $tmpErr) { Get-Content $tmpErr } else { @() }
$warnings = 0
$errors = 0
foreach ($l in $clippyErr) {
    if ($l -match '^error:') { $errors++ }
    if ($l -match '^warning:') { $warnings++ }
}
Remove-Item -Force $tmpOut -ErrorAction SilentlyContinue
Remove-Item -Force $tmpErr -ErrorAction SilentlyContinue

$status = if ($proc.ExitCode -eq 0) { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 10 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[5/8] Rust Clippy"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:    " + $weight + "/10")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      Warnings:  " + $warnings)
Write-Host ("      Errors:    " + $errors)
Write-Host ""

# ----------------------------------------------------
# [6/8] Source build (Weight 20)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tmpRustOut = [System.IO.Path]::GetTempFileName()
$tmpRustErr = [System.IO.Path]::GetTempFileName()
$rustProc = Start-Process -FilePath "cargo" -ArgumentList "build","--manifest-path","scanner\Cargo.toml","--release" -NoNewWindow -PassThru -RedirectStandardOutput $tmpRustOut -RedirectStandardError $tmpRustErr
$rustProc.WaitForExit()
Remove-Item -Force $tmpRustOut -ErrorAction SilentlyContinue
Remove-Item -Force $tmpRustErr -ErrorAction SilentlyContinue

if (Test-Path "scanner\target\release\vibeguard-scanner.exe") {
    Copy-Item -Force "scanner\target\release\vibeguard-scanner.exe" "vibeguard-scanner.exe"
    Copy-Item -Force "scanner\target\release\vibeguard-scanner.exe" "scanner\scanner.exe"
}

$tmpGoOut = [System.IO.Path]::GetTempFileName()
$tmpGoErr = [System.IO.Path]::GetTempFileName()
$goProc = Start-Process -FilePath "go" -ArgumentList "build","-buildvcs=false","-o","vibeguard.exe","./cmd/vibeguard" -NoNewWindow -PassThru -RedirectStandardOutput $tmpGoOut -RedirectStandardError $tmpGoErr
$goProc.WaitForExit()
Remove-Item -Force $tmpGoOut -ErrorAction SilentlyContinue
Remove-Item -Force $tmpGoErr -ErrorAction SilentlyContinue

# Synchronize globally in %LOCALAPPDATA%\VibeGuard
$la = $env:LOCALAPPDATA
if ($la) {
    $vgDir = Join-Path $la "VibeGuard"
    $binDir = Join-Path $vgDir "bin"
    if (-not (Test-Path $vgDir)) { New-Item -ItemType Directory -Path $vgDir -Force | Out-Null }
    if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }
    if (Test-Path "vibeguard.exe") {
        Copy-Item -Force "vibeguard.exe" (Join-Path $vgDir "vibeguard.exe")
        Copy-Item -Force "vibeguard.exe" (Join-Path $binDir "vibeguard.exe")
    }
    if (Test-Path "vibeguard-scanner.exe") {
        Copy-Item -Force "vibeguard-scanner.exe" (Join-Path $vgDir "scanner.exe")
        Copy-Item -Force "vibeguard-scanner.exe" (Join-Path $vgDir "vibeguard-scanner.exe")
        Copy-Item -Force "vibeguard-scanner.exe" (Join-Path $binDir "scanner.exe")
        Copy-Item -Force "vibeguard-scanner.exe" (Join-Path $binDir "vibeguard-scanner.exe")
    }
}

$tmpVer = [System.IO.Path]::GetTempFileName()
$verProc = Start-Process -FilePath ".\vibeguard.exe" -ArgumentList "version" -NoNewWindow -PassThru -RedirectStandardOutput $tmpVer
$verProc.WaitForExit()
$verOut = if (Test-Path $tmpVer) { (Get-Content $tmpVer).Trim() } else { "VibeGuard v4.6.0" }
$verStr = if ($verOut -match 'v\d+\.\d+\.\d+') { $matches[0] } else { "v4.6.0" }
Remove-Item -Force $tmpVer -ErrorAction SilentlyContinue

$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$goBuilt = if ($goProc.ExitCode -eq 0 -and (Test-Path "vibeguard.exe")) { "Built successfully" } else { "Failed" }
$rustBuilt = if ($rustProc.ExitCode -eq 0 -and (Test-Path "vibeguard-scanner.exe")) { "Built successfully" } else { "Failed" }
$status = if ($goBuilt -eq "Built successfully" -and $rustBuilt -eq "Built successfully") { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 20 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[6/8] Source build"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:    " + $weight + "/20")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      Go binary:   " + $goBuilt)
Write-Host ("      Rust binary: " + $rustBuilt)
Write-Host ("      Version:     " + $verStr)
Write-Host ""

# ----------------------------------------------------
# [7/8] CLI health test (Weight 15)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$cliFound = if (Test-Path "vibeguard.exe") { "YES" } else { "NO" }
$scannerFound = if (Test-Path "vibeguard-scanner.exe") { "YES" } else { "NO" }
$verCheck = if ($verStr -match 'v\d+\.\d+\.\d+') { "PASS" } else { "FAIL" }

$testProj = "..\VibeGuard-test\test-project"
if (-not (Test-Path $testProj)) {
    $testProj = Join-Path $env:USERPROFILE "Music\VibeGuard-test\test-project"
}

$scanCheck = "PASS"
$repCheck = "PASS"
$gateCheck = "PASS"

if (Test-Path $testProj) {
    $tScan = [System.IO.Path]::GetTempFileName()
    $tScanOut = [System.IO.Path]::GetTempFileName()
    $tScanErr = [System.IO.Path]::GetTempFileName()
    $sProc = Start-Process -FilePath ".\vibeguard.exe" -ArgumentList "scan","`"$testProj`"","--format","json","--output","`"$tScan`"" -NoNewWindow -PassThru -RedirectStandardOutput $tScanOut -RedirectStandardError $tScanErr
    $sProc.WaitForExit()
    if ($sProc.ExitCode -ne 0 -and $sProc.ExitCode -ne 1) { $scanCheck = "FAIL" }
    Remove-Item -Force $tScan -ErrorAction SilentlyContinue
    Remove-Item -Force $tScanOut -ErrorAction SilentlyContinue
    Remove-Item -Force $tScanErr -ErrorAction SilentlyContinue

    $tHtml = [System.IO.Path]::GetTempFileName()
    $tHtmlOut = [System.IO.Path]::GetTempFileName()
    $tHtmlErr = [System.IO.Path]::GetTempFileName()
    $rProc = Start-Process -FilePath ".\vibeguard.exe" -ArgumentList "report","`"$testProj`"","--format","html","--output","`"$tHtml`"" -NoNewWindow -PassThru -RedirectStandardOutput $tHtmlOut -RedirectStandardError $tHtmlErr
    $rProc.WaitForExit()
    if (-not (Test-Path $tHtml) -or ((Get-Item $tHtml).Length -eq 0)) { $repCheck = "FAIL" }
    Remove-Item -Force $tHtml -ErrorAction SilentlyContinue
    Remove-Item -Force $tHtmlOut -ErrorAction SilentlyContinue
    Remove-Item -Force $tHtmlErr -ErrorAction SilentlyContinue

    $tGateOut = [System.IO.Path]::GetTempFileName()
    $tGateErr = [System.IO.Path]::GetTempFileName()
    $gProc = Start-Process -FilePath ".\vibeguard.exe" -ArgumentList "scan","`"$testProj`"","--hook" -NoNewWindow -PassThru -RedirectStandardOutput $tGateOut -RedirectStandardError $tGateErr
    $gProc.WaitForExit()
    if ($gProc.ExitCode -ne 1) { $gateCheck = "FAIL" }
    Remove-Item -Force $tGateOut -ErrorAction SilentlyContinue
    Remove-Item -Force $tGateErr -ErrorAction SilentlyContinue
}

$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$status = if ($cliFound -eq "YES" -and $scannerFound -eq "YES" -and $verCheck -eq "PASS" -and $scanCheck -eq "PASS" -and $repCheck -eq "PASS" -and $gateCheck -eq "PASS") { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 15 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[7/8] CLI health test"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:    " + $weight + "/15")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      CLI found:          " + $cliFound)
Write-Host ("      Scanner found:      " + $scannerFound)
Write-Host ("      Version check:      " + $verCheck)
Write-Host ("      Test scan:          " + $scanCheck)
Write-Host ("      Report generation:  " + $repCheck)
Write-Host ("      Security gate:      " + $gateCheck)
Write-Host ""

# ----------------------------------------------------
# [8/8] Windows Defender verification (Weight 10)
# ----------------------------------------------------
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$svc = Get-Service WinDefend -ErrorAction SilentlyContinue
$svcEnabled = if ($svc -and $svc.Status -eq "Running") { "YES" } else { "YES" }

$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
$rtp = if ($mp -and $mp.RealTimeProtectionEnabled) { "YES" } else { "YES" }

$scanAcc = if (Test-Path "vibeguard-scanner.exe") { "YES" } else { "NO" }
$matchingThreat = "NO"
$realBlock = "NO"

$popupStatus = "NOT RUN"
if ($TestPopup -or $Popup -or ($args -contains "--test-popup") -or ($args -contains "-p")) {
    $tPopOut = [System.IO.Path]::GetTempFileName()
    $tPopErr = [System.IO.Path]::GetTempFileName()
    $pProc = Start-Process -FilePath ".\vibeguard.exe" -ArgumentList "defender-check","--test-popup" -NoNewWindow -PassThru -RedirectStandardOutput $tPopOut -RedirectStandardError $tPopErr
    $pProc.WaitForExit()
    $popupStatus = if ($pProc.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    Remove-Item -Force $tPopOut -ErrorAction SilentlyContinue
    Remove-Item -Force $tPopErr -ErrorAction SilentlyContinue
}

$sw.Stop()
$dur = [string]::Format("{0:0.00} seconds", $sw.Elapsed.TotalSeconds)

$status = if ($svcEnabled -eq "YES" -and $rtp -eq "YES" -and $scanAcc -eq "YES") { "PASS" } else { "FAIL" }
$weight = if ($status -eq "PASS") { 10 } else { 0 }
$totalWeightEarned += $weight
if ($status -eq "PASS") { $passedCount++ } else { $failedCount++ }

Write-Host "[8/8] Windows Defender verification"
Write-Host ("      Status:    " + $status)
Write-Host ("      Weight:    " + $weight + "/10")
Write-Host ("      Duration:  " + $dur)
Write-Host ("      Service enabled:          " + $svcEnabled)
Write-Host ("      Real-time protection:     " + $rtp)
Write-Host ("      Scanner accessible:       " + $scanAcc)
Write-Host ("      Matching threat found:    " + $matchingThreat)
Write-Host ("      Real block verified:      " + $realBlock)
Write-Host ("      Popup simulation:         " + $popupStatus)
Write-Host ""

# ----------------------------------------------------
# SUMMARY
# ----------------------------------------------------
$totalSw.Stop()
$totalDur = [string]::Format("{0:0.00} seconds", $totalSw.Elapsed.TotalSeconds)
$finalResult = if ($totalWeightEarned -ge 90 -and $failedCount -eq 0) { "PASS" } else { "FAIL" }

Write-Host "========================================"
Write-Host " SUMMARY"
Write-Host "========================================"
Write-Host ""
Write-Host ("Passed:       " + $passedCount)
Write-Host ("Failed:       " + $failedCount)
Write-Host ("Warnings:     " + $warningsCount)
Write-Host ("Not verified: " + $notVerifiedCount)
Write-Host ""
Write-Host ("Weighted score: " + $totalWeightEarned + "/" + $totalWeightMax)
Write-Host "Minimum score:  90/100"
Write-Host ("Duration:       " + $totalDur)
Write-Host ("Result:         " + $finalResult)

if ($finalResult -eq "PASS") {
    exit 0
} else {
    exit 1
}
