@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Automated Global Setup Script (setup.bat)
::  Portability: Runs on any Windows machine using prebuilt binaries
::  Installs to %LOCALAPPDATA%\VibeGuard and configures User PATH
::  Does NOT require Go, Rust, or Visual Studio Build Tools
:: ============================================================

:: Step 1 — Find repository root dynamically from script location
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ========================================
echo        VIBEGUARD SETUP
echo ========================================
echo Source Location: %ROOT%
echo.

:: Step 2 — Locate source binaries
set "CLI_SRC=%ROOT%vibeguard.exe"
set "SCANNER_SRC=%ROOT%vibeguard-scanner.exe"

if not exist "%SCANNER_SRC%" (
    if exist "%ROOT%scanner\scanner.exe" (
        set "SCANNER_SRC=%ROOT%scanner\scanner.exe"
    ) else if exist "%ROOT%scanner\vibeguard-scanner.exe" (
        set "SCANNER_SRC=%ROOT%scanner\vibeguard-scanner.exe"
    )
)

if not exist "%CLI_SRC%" (
    echo [ERROR] vibeguard.exe was not found.
    echo.
    echo Expected:
    echo     %CLI_SRC%
    echo.
    echo Run build.bat on a developer machine or obtain the official release package.
    exit /b 1
)

echo [OK] VibeGuard executable found: %CLI_SRC%

if not exist "%SCANNER_SRC%" (
    echo [ERROR] Rust scanner executable was not found.
    echo.
    echo Expected:
    echo     %ROOT%vibeguard-scanner.exe or %ROOT%scanner\scanner.exe
    echo.
    echo Run build.bat on a developer machine or obtain the official release package.
    exit /b 1
)

echo [OK] Scanner executable found: %SCANNER_SRC%

:: Step 3 — Create stable user installation directory
set "INSTALL_DIR=%LOCALAPPDATA%\VibeGuard"
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%" >nul 2>&1
)
if not exist "%INSTALL_DIR%\bin" (
    mkdir "%INSTALL_DIR%\bin" >nul 2>&1
)

:: Step 4 — Copy / update VibeGuard CLI and Rust scanner
copy /Y "%CLI_SRC%" "%INSTALL_DIR%\vibeguard.exe" >nul 2>&1
copy /Y "%CLI_SRC%" "%INSTALL_DIR%\bin\vibeguard.exe" >nul 2>&1

copy /Y "%SCANNER_SRC%" "%INSTALL_DIR%\scanner.exe" >nul 2>&1
copy /Y "%SCANNER_SRC%" "%INSTALL_DIR%\vibeguard-scanner.exe" >nul 2>&1
copy /Y "%SCANNER_SRC%" "%INSTALL_DIR%\bin\scanner.exe" >nul 2>&1
copy /Y "%SCANNER_SRC%" "%INSTALL_DIR%\bin\vibeguard-scanner.exe" >nul 2>&1

:: Also keep local copies in repo for local workflows
if not exist "%ROOT%vibeguard-scanner.exe" (
    copy /Y "%SCANNER_SRC%" "%ROOT%vibeguard-scanner.exe" >nul 2>&1
)
if not exist "%ROOT%scanner\scanner.exe" (
    if not exist "%ROOT%scanner" mkdir "%ROOT%scanner"
    copy /Y "%SCANNER_SRC%" "%ROOT%scanner\scanner.exe" >nul 2>&1
)

:: Step 5 — Copy runtime rules / configuration data
if exist "%ROOT%rules" (
    if not exist "%INSTALL_DIR%\rules" mkdir "%INSTALL_DIR%\rules" >nul 2>&1
    xcopy /E /I /Y /Q "%ROOT%rules" "%INSTALL_DIR%\rules" >nul 2>&1
)

:: Step 6 — Required directories in current repository
if not exist "%ROOT%.vibeguard" mkdir "%ROOT%.vibeguard" >nul 2>&1
if not exist "%ROOT%reports" mkdir "%ROOT%reports" >nul 2>&1
if not exist "%ROOT%rules" mkdir "%ROOT%rules" >nul 2>&1
if not exist "%ROOT%tests" mkdir "%ROOT%tests" >nul 2>&1

if not exist "%ROOT%.vibeguard\config.json" (
    call "%INSTALL_DIR%\vibeguard.exe" init >nul 2>&1
)

:: Configure Git pre-push hook if inside a git repository
if exist "%ROOT%.git" (
    call "%INSTALL_DIR%\vibeguard.exe" init >nul 2>&1
)

:: Step 7 — Add %LOCALAPPDATA%\VibeGuard to USER PATH idempotently
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$target = [IO.Path]::Combine($env:LOCALAPPDATA, 'VibeGuard'); " ^
  "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User'); " ^
  "$parts = if ($userPath) { $userPath -split ';' } else { @() }; " ^
  "$cleanParts = @(); foreach ($p in $parts) { $tp = $p.Trim(); if ($tp -and $cleanParts -notcontains $tp) { $cleanParts += $tp } }; " ^
  "$found = $false; foreach ($p in $cleanParts) { if ($p.ToLower().TrimEnd('\') -eq $target.ToLower().TrimEnd('\')) { $found = $true; break } }; " ^
  "if (-not $found) { $newPath = ($cleanParts + $target) -join ';'; [Environment]::SetEnvironmentVariable('Path', $newPath, 'User') }" >nul 2>&1

:: Also update current session PATH
set "PATH=%INSTALL_DIR%;%INSTALL_DIR%\bin;%PATH%"

:: Step 8 — Verify installation
if not exist "%INSTALL_DIR%\vibeguard.exe" (
    echo [ERROR] Installation failed: %INSTALL_DIR%\vibeguard.exe missing.
    exit /b 1
)
if not exist "%INSTALL_DIR%\scanner.exe" (
    echo [ERROR] Installation failed: %INSTALL_DIR%\scanner.exe missing.
    exit /b 1
)

echo.
echo ========================================
echo        VIBEGUARD INSTALLATION
echo ========================================
echo.
echo [OK] Installation directory
echo [OK] VibeGuard executable
echo [OK] Rust scanner
echo [OK] Runtime files
echo [OK] User PATH configured
echo.
echo Installation:
echo %INSTALL_DIR%
echo.
echo Current Session:
call "%INSTALL_DIR%\vibeguard.exe" version
echo.
echo ============================================================
echo  Please close this terminal and open a NEW CMD/PowerShell
echo  window so the updated User PATH is recognized.
echo.
echo  Then you can run from ANY directory:
echo      vibeguard version
echo      vibeguard scan ^<project-path^>
echo      vibeguard help
echo ============================================================
echo.

endlocal & set "PATH=%LOCALAPPDATA%\VibeGuard;%LOCALAPPDATA%\VibeGuard\bin;%PATH%"
