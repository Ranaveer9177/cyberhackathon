@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Git Pre-Push Hook Uninstaller (uninstall_hook.bat)
:: ============================================================

set "ROOT=%~dp0..\..\"
cd /d "%ROOT%"

set "CLI_BIN=%ROOT%vibeguard.exe"

if not exist "%CLI_BIN%" (
    echo [ERROR] Required VibeGuard binary was not found: %CLI_BIN%
    exit /b 1
)

if not exist "%ROOT%.git" (
    echo [ERROR] No .git directory found in %ROOT%.
    exit /b 1
)

echo Removing VibeGuard Git pre-push hook...
call "%CLI_BIN%" uninstall
if %ERRORLEVEL% equ 0 (
    echo [OK] VibeGuard Git pre-push hook removed successfully.
) else (
    echo [ERROR] Failed to uninstall Git pre-push hook.
    exit /b %ERRORLEVEL%
)

endlocal
