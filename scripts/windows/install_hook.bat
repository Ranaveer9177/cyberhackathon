@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Git Pre-Push Hook Installer (install_hook.bat)
:: ============================================================

set "ROOT=%~dp0..\..\"
cd /d "%ROOT%"

set "CLI_BIN=%ROOT%vibeguard.exe"

if not exist "%CLI_BIN%" (
    echo [ERROR] Required VibeGuard binary was not found: %CLI_BIN%
    echo Please run setup.bat or build.bat first.
    exit /b 1
)

if not exist "%ROOT%.git" (
    echo [ERROR] No .git directory found in %ROOT%.
    echo Please run this script inside a valid Git repository.
    exit /b 1
)

echo Installing VibeGuard Git pre-push hook...
call "%CLI_BIN%" init
if %ERRORLEVEL% equ 0 (
    echo [OK] VibeGuard Git pre-push hook installed successfully.
) else (
    echo [ERROR] Failed to install Git pre-push hook.
    exit /b %ERRORLEVEL%
)

endlocal
