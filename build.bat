@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Developer Build Script (build.bat)
::  Mode B: Compiles VibeGuard from source code
::  Requires: Go 1.21+, Rust 1.70+, and MSVC linker (link.exe)
:: ============================================================

:: 1. Detect project root
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ========================================
echo     VIBEGUARD SOURCE BUILD ENGINE
echo ========================================
echo Project Root: %ROOT%
echo.

:: 2. Verify Go compiler
echo Checking developer prerequisites...
where go >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go compiler go was not found.
    echo.
    echo Please install Go 1.21 or higher:
    echo   https://go.dev/dl/
    echo or run:
    echo   winget install GoLang.Go
    exit /b 1
)
for /f "tokens=3" %%v in ('go version 2^>nul') do set "GO_VER=%%v"
echo [OK] Go compiler found: %GO_VER%

:: 3. Verify Rust compiler and Cargo
where rustc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust compiler rustc was not found.
    echo.
    echo Please install Rust toolchain:
    echo   https://rustup.rs/
    echo or run:
    echo   winget install Rustlang.Rustup
    exit /b 1
)
for /f "tokens=2" %%v in ('rustc --version 2^>nul') do set "RUST_VER=%%v"
echo [OK] Rust compiler found: %RUST_VER%

where cargo >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Cargo package manager cargo was not found.
    exit /b 1
)
for /f "tokens=2" %%v in ('cargo --version 2^>nul') do set "CARGO_VER=%%v"
echo [OK] Cargo package manager found: %CARGO_VER%

:: 4. Verify Microsoft C++ linker
where link.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Microsoft C++ linker link.exe was not found.
    echo.
    echo Install:
    echo Visual Studio Build Tools
    echo -^> Desktop development with C++
    echo.
    echo Then open a new terminal and run build.bat again.
    exit /b 1
)
echo [OK] Microsoft C++ linker found: link.exe

:: 5. Build Rust Scanner Engine
echo.
echo ========================================
echo [1/2] Building Rust Scanner Engine...
echo ========================================
cd /d "%ROOT%scanner"

:: Point cargo target dir to isolated temp dir to bypass Windows media library folder locks
if not defined CARGO_TARGET_DIR (
    set "CARGO_TARGET_DIR=%TEMP%\cargo-target"
)

cargo build --release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust scanner compilation failed.
    cd /d "%ROOT%"
    exit /b 1
)

:: Locate built scanner binary
set "BUILT_SCANNER="
if exist "%CARGO_TARGET_DIR%\release\vibeguard-scanner.exe" (
    set "BUILT_SCANNER=%CARGO_TARGET_DIR%\release\vibeguard-scanner.exe"
) else if exist "%ROOT%scanner\target\release\vibeguard-scanner.exe" (
    set "BUILT_SCANNER=%ROOT%scanner\target\release\vibeguard-scanner.exe"
)

if not defined BUILT_SCANNER (
    echo [ERROR] Could not find compiled vibeguard-scanner.exe.
    cd /d "%ROOT%"
    exit /b 1
)

:: Copy scanner executable to root and scanner directories
copy /Y "%BUILT_SCANNER%" "%ROOT%vibeguard-scanner.exe" >nul
copy /Y "%BUILT_SCANNER%" "%ROOT%scanner\scanner.exe" >nul
copy /Y "%BUILT_SCANNER%" "%ROOT%scanner\vibeguard-scanner.exe" >nul
echo [OK] Rust scanner built successfully: %ROOT%vibeguard-scanner.exe

:: 6. Build Go Orchestrator CLI from repository root
cd /d "%ROOT%"
echo.
echo ========================================
echo [2/2] Building VibeGuard Go CLI...
echo ========================================
go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go CLI compilation failed.
    exit /b 1
)
echo [OK] Go CLI built successfully: %ROOT%vibeguard.exe

:: 7. Update installed copy in LocalAppData
if not exist "%LOCALAPPDATA%\VibeGuard" mkdir "%LOCALAPPDATA%\VibeGuard" >nul 2>&1
if not exist "%LOCALAPPDATA%\VibeGuard\bin" mkdir "%LOCALAPPDATA%\VibeGuard\bin" >nul 2>&1

copy /Y "%ROOT%vibeguard.exe" "%LOCALAPPDATA%\VibeGuard\vibeguard.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard.exe" "%LOCALAPPDATA%\VibeGuard\bin\vibeguard.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\scanner.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\vibeguard-scanner.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\bin\scanner.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\bin\vibeguard-scanner.exe" >nul 2>&1
if exist "%ROOT%rules" (
    if not exist "%LOCALAPPDATA%\VibeGuard\rules" mkdir "%LOCALAPPDATA%\VibeGuard\rules" >nul 2>&1
    xcopy /E /I /Y /Q "%ROOT%rules" "%LOCALAPPDATA%\VibeGuard\rules" >nul 2>&1
)
echo [OK] Updated global CLI in: %LOCALAPPDATA%\VibeGuard

:: 8. Verify generated binaries
echo.
echo Verifying built artifacts...
call "%ROOT%vibeguard.exe" version
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Verification failed.
    exit /b 1
)

echo.
echo ========================================
echo      BUILD COMPLETED SUCCESSFULLY
echo ========================================
echo Binaries produced:
echo   - %ROOT%vibeguard.exe
echo   - %ROOT%vibeguard-scanner.exe
echo   - %ROOT%scanner\scanner.exe
echo.
echo Run setup.bat to configure or run_test.bat to run health checks.
endlocal
