@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0"
cd /d "%ROOT%"

:: Prefer modern pwsh.exe if installed, fallback to Windows PowerShell
set "PS=powershell"
where pwsh.exe >nul 2>&1
if %ERRORLEVEL% equ 0 set "PS=pwsh"

%PS% -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\windows\ultimate_test.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"

exit /b %EXIT_CODE%
