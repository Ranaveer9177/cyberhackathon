@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Automated Setup Script (setup.bat)
::  Portability: Runs on any Windows laptop using prebuilt binaries
::  Does NOT require Go, Rust, or Visual Studio Build Tools
:: ============================================================

:: 1. Detect repository root dynamically from script location
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ========================================
echo       VIBEGUARD LAPTOP SETUP
echo ========================================
echo Project Root: %ROOT%
echo.

:: 2. Prebuilt binary check
set "CLI_BIN=%ROOT%vibeguard.exe"
set "SCANNER_BIN=%ROOT%vibeguard-scanner.exe"

if not exist "%SCANNER_BIN%" (
    if exist "%ROOT%scanner\scanner.exe" (
        set "SCANNER_BIN=%ROOT%scanner\scanner.exe"
    ) else if exist "%ROOT%scanner\vibeguard-scanner.exe" (
        set "SCANNER_BIN=%ROOT%scanner\vibeguard-scanner.exe"
    )
)

if not exist "%CLI_BIN%" (
    echo [ERROR] Required VibeGuard binary was not found.
    echo.
    echo Expected:
    echo     %CLI_BIN%
    echo.
    echo Run build.bat on a developer machine or obtain the official release package.
    exit /b 1
)

echo [OK] VibeGuard CLI found: %CLI_BIN%

if not exist "%SCANNER_BIN%" (
    echo [ERROR] Required VibeGuard scanner binary was not found.
    echo.
    echo Expected:
    echo     %ROOT%vibeguard-scanner.exe or %ROOT%scanner\scanner.exe
    echo.
    echo Run build.bat on a developer machine or obtain the official release package.
    exit /b 1
)

echo [OK] Rust scanner found: %SCANNER_BIN%

:: Ensure scanner binary exists in both standard locations
if not exist "%ROOT%vibeguard-scanner.exe" (
    copy /Y "%SCANNER_BIN%" "%ROOT%vibeguard-scanner.exe" >nul 2>&1
)
if not exist "%ROOT%scanner\scanner.exe" (
    if not exist "%ROOT%scanner" mkdir "%ROOT%scanner"
    copy /Y "%SCANNER_BIN%" "%ROOT%scanner\scanner.exe" >nul 2>&1
)

:: 3. Required Directory Checks (verify or create)
echo.
echo Checking required directories...
if not exist "%ROOT%.vibeguard" (
    mkdir "%ROOT%.vibeguard"
    echo [OK] Created .vibeguard\ directory
) else (
    echo [OK] .vibeguard\ directory verified
)

if not exist "%ROOT%reports" (
    mkdir "%ROOT%reports"
    echo [OK] Created reports\ directory
) else (
    echo [OK] reports\ directory verified
)

if not exist "%ROOT%rules" (
    mkdir "%ROOT%rules"
    echo [OK] Created rules\ directory
) else (
    echo [OK] rules\ directory verified
)

if not exist "%ROOT%tests" (
    mkdir "%ROOT%tests"
    echo [OK] Created tests\ directory
) else (
    echo [OK] tests\ directory verified
)

:: 4. Verify or generate default configuration
if not exist "%ROOT%.vibeguard\config.json" (
    echo Generating default configuration...
    call "%CLI_BIN%" init >nul 2>&1
    if exist "%ROOT%.vibeguard\config.json" (
        echo [OK] Default configuration created: .vibeguard\config.json
    )
) else (
    echo [OK] Configuration verified: .vibeguard\config.json
)

:: 5. Install Git pre-push hook if inside a git repository
echo.
echo Configuring Git security gate...
if exist "%ROOT%.git" (
    call "%CLI_BIN%" init
    echo [OK] Git pre-push hook configured
) else (
    echo [INFO] No .git directory found. Skipping Git hook installation.
)

:: 6. Install VibeGuard CLI to User PATH for global execution
echo.
echo Installing VibeGuard CLI for global terminal use...
set "VIBEGUARD_HOME=%LOCALAPPDATA%\VibeGuard\bin"

if not exist "%VIBEGUARD_HOME%" (
    mkdir "%VIBEGUARD_HOME%" >nul 2>&1
)

copy /Y "%CLI_BIN%" "%VIBEGUARD_HOME%\vibeguard.exe" >nul 2>&1
copy /Y "%SCANNER_BIN%" "%VIBEGUARD_HOME%\vibeguard-scanner.exe" >nul 2>&1
copy /Y "%SCANNER_BIN%" "%VIBEGUARD_HOME%\scanner.exe" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "$u=[Environment]::GetEnvironmentVariable('Path','User'); $d=[IO.Path]::Combine($env:LOCALAPPDATA,'VibeGuard','bin'); if (($u -split ';') -notcontains $d) { [Environment]::SetEnvironmentVariable('Path', (($u.TrimEnd(';')+';'+$d).TrimStart(';')), 'User') }" >nul 2>&1

set "PATH=%VIBEGUARD_HOME%;%PATH%"

echo [OK] VibeGuard CLI installed to: %VIBEGUARD_HOME%
echo [OK] Global Command: vibeguard

:: 7. Version verification test
echo.
echo Testing VibeGuard CLI...
call "%CLI_BIN%" version
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Version verification failed.
    exit /b 1
)

echo.
echo ========================================
echo       VIBEGUARD SETUP COMPLETE
echo ========================================
echo.
echo [OK] Prebuilt binaries verified
echo [OK] Required directories verified
echo [OK] Configuration active
echo [OK] CLI ready for use
echo.
echo You can now run:
echo   vibeguard version
echo   vibeguard scan .\test-project
echo   run_test.bat
echo.
echo VibeGuard development environment ready.
endlocal & set "PATH=%LOCALAPPDATA%\VibeGuard\bin;%PATH%"
