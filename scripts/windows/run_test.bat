@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Health Check & Validation Script (run_test.bat)
::  Validates CLI, Scanner, Version, Scan, Report & Security Gate
:: ============================================================

:: 1. Detect project root
set "ROOT=%~dp0..\..\"
cd /d "%ROOT%"

:: Locate installed or local binary
set "CLI_BIN=%LOCALAPPDATA%\VibeGuard\vibeguard.exe"
if not exist "%CLI_BIN%" (
    set "CLI_BIN=%ROOT%vibeguard.exe"
)

set "SCANNER_BIN=%LOCALAPPDATA%\VibeGuard\scanner.exe"
if not exist "%SCANNER_BIN%" (
    if exist "%ROOT%scanner\scanner.exe" (
        set "SCANNER_BIN=%ROOT%scanner\scanner.exe"
    ) else if exist "%ROOT%vibeguard-scanner.exe" (
        set "SCANNER_BIN=%ROOT%vibeguard-scanner.exe"
    )
)

echo ========================================
echo        VIBEGUARD HEALTH TEST
echo ========================================
echo.

:: Check 1: CLI found
if not exist "%CLI_BIN%" (
    echo [FAIL] CLI binary not found.
    echo Please run setup.bat or build.bat first.
    exit /b 1
)
echo [PASS] CLI found

:: Check 2: Scanner found
if not exist "%SCANNER_BIN%" (
    echo [FAIL] Scanner binary not found.
    echo Please run setup.bat or build.bat first.
    exit /b 1
)
echo [PASS] Scanner found

:: Check 3: Version command
for /f "tokens=*" %%v in ('"%CLI_BIN%" version 2^>nul') do set "VER_OUT=%%v"
if not defined VER_OUT (
    echo [FAIL] Version command failed.
    exit /b 1
)
echo [PASS] Version command

:: Check 4: Test project scan (located in external test workspace per v4.1 rules)
set "TEST_PROJ=%ROOT%..\VibeGuard-test\test-project"
if not exist "%TEST_PROJ%" (
    set "TEST_PROJ=%USERPROFILE%\Music\VibeGuard-test\test-project"
)
if not exist "%TEST_PROJ%" (
    echo [FAIL] External test project not found in %TEST_PROJ%.
    exit /b 1
)
:: Run scan quietly to test detection logic
call "%CLI_BIN%" scan "%TEST_PROJ%" --format json --output "%TEMP%\vg-test-scan.json" >nul 2>&1
set "SCAN_EXIT=%ERRORLEVEL%"
if %SCAN_EXIT% neq 0 if %SCAN_EXIT% neq 1 (
    echo [FAIL] Test project scan returned runtime error %SCAN_EXIT%.
    exit /b %SCAN_EXIT%
)
echo [PASS] Test project scan

:: Check 5: Report generation
call "%CLI_BIN%" report "%TEST_PROJ%" --format html --output "%TEMP%\vg-test-report.html" >nul 2>&1
if not exist "%TEMP%\vg-test-report.html" (
    echo [FAIL] Report generation failed to produce output file.
    exit /b 1
)
del /f /q "%TEMP%\vg-test-report.html" >nul 2>&1
del /f /q "%TEMP%\vg-test-scan.json" >nul 2>&1
echo [PASS] Report generation

:: Check 6: Security gate policy enforcement
:: test-project has intentional vulnerabilities; gate should block (exit 1)
call "%CLI_BIN%" scan "%TEST_PROJ%" --hook >nul 2>&1
set "GATE_EXIT=%ERRORLEVEL%"
if %GATE_EXIT% equ 1 (
    echo [PASS] Security gate
) else (
    echo [FAIL] Security gate did not block vulnerable fixture: exit code %GATE_EXIT%
    exit /b 1
)

echo.
echo ========================================
echo        ALL TESTS PASSED
echo ========================================
echo.

endlocal & exit /b 0
