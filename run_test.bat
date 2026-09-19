@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Health Check & Validation Script (run_test.bat)
:: ============================================================

:: 1. Detect project root
set "ROOT=%~dp0"
cd /d "%ROOT%"

set "CLI_BIN=%ROOT%vibeguard.exe"
set "SCANNER_BIN=%ROOT%vibeguard-scanner.exe"

if not exist "%SCANNER_BIN%" (
    if exist "%ROOT%scanner\scanner.exe" (
        set "SCANNER_BIN=%ROOT%scanner\scanner.exe"
    ) else if exist "%ROOT%scanner\vibeguard-scanner.exe" (
        set "SCANNER_BIN=%ROOT%scanner\vibeguard-scanner.exe"
    )
)

echo ========================================
echo         VIBEGUARD TEST
echo ========================================
echo.

:: 2. Check CLI
if not exist "%CLI_BIN%" (
    echo [FAIL] CLI binary not found: %CLI_BIN%
    echo Please run setup.bat or build.bat first.
    exit /b 1
)
echo [OK] CLI

:: 3. Check Scanner
if not exist "%SCANNER_BIN%" (
    echo [FAIL] Scanner binary not found.
    echo Please run setup.bat or build.bat first.
    exit /b 1
)
echo [OK] Scanner

:: 4. Check Version
for /f "tokens=*" %%v in ('"%CLI_BIN%" version 2^>nul') do set "VER_OUT=%%v"
if not defined VER_OUT (
    echo [FAIL] Could not retrieve version from %CLI_BIN%
    exit /b 1
)
echo [OK] Version: !VER_OUT!

:: 5. Check Test Project
if not exist "%ROOT%test-project" (
    echo [FAIL] Test project directory not found: %ROOT%test-project
    exit /b 1
)
echo [OK] Test project

echo.
echo Running security scan...
echo.

:: 6. Run Scan on test project (fixture is intentionally vulnerable, so exit code 1 = successful detection!)
call "%CLI_BIN%" scan "%ROOT%test-project"
set "SCAN_EXIT=%ERRORLEVEL%"

echo.
echo ========================================
echo TEST COMPLETED
echo ========================================
if %SCAN_EXIT% equ 1 (
    echo Result: [PASS] Intentionally vulnerable test project correctly detected and blocked.
) else if %SCAN_EXIT% equ 0 (
    echo Result: [PASS] Scan completed with 0 findings.
) else (
    echo Result: [FAIL] Scan exited with runtime error code %SCAN_EXIT%.
    exit /b %SCAN_EXIT%
)

endlocal
