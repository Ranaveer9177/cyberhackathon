@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Automated Development Setup Script (setup.bat)
:: ============================================================

:: Configure local session PATH with standard tool directories if present
if exist "%USERPROFILE%\.cargo\bin" (
    echo !PATH! | findstr /I /C:"%USERPROFILE%\.cargo\bin" >nul 2>&1
    if !ERRORLEVEL! neq 0 set "PATH=%USERPROFILE%\.cargo\bin;!PATH!"
)
if exist "C:\Program Files\Go\bin" (
    echo !PATH! | findstr /I /C:"C:\Program Files\Go\bin" >nul 2>&1
    if !ERRORLEVEL! neq 0 set "PATH=C:\Program Files\Go\bin;!PATH!"
)
if exist "C:\Program Files\Git\cmd" (
    echo !PATH! | findstr /I /C:"C:\Program Files\Git\cmd" >nul 2>&1
    if !ERRORLEVEL! neq 0 set "PATH=C:\Program Files\Git\cmd;!PATH!"
)
if exist "C:\Program Files\nodejs" (
    echo !PATH! | findstr /I /C:"C:\Program Files\nodejs" >nul 2>&1
    if !ERRORLEVEL! neq 0 set "PATH=C:\Program Files\nodejs;!PATH!"
)
if exist "C:\Program Files\Docker\Docker\resources\bin" (
    echo !PATH! | findstr /I /C:"C:\Program Files\Docker\Docker\resources\bin" >nul 2>&1
    if !ERRORLEVEL! neq 0 set "PATH=C:\Program Files\Docker\Docker\resources\bin;!PATH!"
)

:: Step 1: Check winget package manager
where winget >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Windows Package Manager winget was not found.
    echo Please install Windows App Installer from the Microsoft Store to enable automated installs.
    echo.
)

:: Step 2: Check / Install Git
where git >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [INFO] Git not found. Installing via winget...
    winget install --id Git.Git -e --source winget --accept-source-agreements --accept-package-agreements --silent
    if exist "C:\Program Files\Git\cmd" set "PATH=C:\Program Files\Git\cmd;!PATH!"
)

:: Step 3: Check / Install Go
where go >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [INFO] Go not found. Installing via winget...
    winget install --id GoLang.Go -e --source winget --accept-source-agreements --accept-package-agreements --silent
    if exist "C:\Program Files\Go\bin" set "PATH=C:\Program Files\Go\bin;!PATH!"
)

:: Step 4: Check / Install Rust + Cargo
where rustc >nul 2>&1
set RUST_STATUS=%ERRORLEVEL%
where cargo >nul 2>&1
set CARGO_STATUS=%ERRORLEVEL%

if %RUST_STATUS% neq 0 (
    echo [INFO] Rust not found. Installing via winget...
    winget install --id Rustlang.Rustup -e --source winget --accept-source-agreements --accept-package-agreements --silent
    if exist "%USERPROFILE%\.cargo\bin" set "PATH=%USERPROFILE%\.cargo\bin;!PATH!"
) else if %CARGO_STATUS% neq 0 (
    if exist "%USERPROFILE%\.cargo\bin\cargo.exe" set "PATH=%USERPROFILE%\.cargo\bin;!PATH!"
)

:: Step 5: Check / Install Node.js
where node >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [INFO] Node.js not found. Installing via winget...
    winget install --id OpenJS.NodeJS.LTS -e --source winget --accept-source-agreements --accept-package-agreements --silent
    if exist "C:\Program Files\nodejs" set "PATH=C:\Program Files\nodejs;!PATH!"
)

:: Step 6: Check / Install Python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [INFO] Python not found. Installing via winget...
    winget install --id Python.Python.3.12 -e --source winget --accept-source-agreements --accept-package-agreements --silent
)

:: Step 7: Check / Install Docker
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "C:\Program Files\Docker\Docker\resources\bin\docker.exe" (
        set "PATH=C:\Program Files\Docker\Docker\resources\bin;!PATH!"
    )
)
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [INFO] Docker not found. Installing Docker CLI via winget...
    winget install --id Docker.DockerCLI -e --source winget --accept-source-agreements --accept-package-agreements --silent >nul 2>&1
    if exist "C:\Program Files\Docker\Docker\resources\bin\docker.exe" (
        set "PATH=C:\Program Files\Docker\Docker\resources\bin;!PATH!"
    )
)

:: Step 8: Parse installed versions for display
set "GO_VER="
where go >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=3" %%v in ('go version 2^>nul') do (
        set "RAW_GO=%%v"
        set "GO_VER=!RAW_GO:go=!"
    )
)

set "RUST_VER="
where rustc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=2" %%v in ('rustc --version 2^>nul') do (
        set "RUST_VER=%%v"
    )
)

set "CARGO_VER="
where cargo >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=2" %%v in ('cargo --version 2^>nul') do (
        set "CARGO_VER=%%v"
    )
)

:: Step 9: Print final environment status
echo ================================
echo  VibeGuard Development Setup
echo ================================
echo.

where git >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Git
) else (
    echo [FAIL] Git
)

where go >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if defined GO_VER (
        echo [OK] Go !GO_VER!
    ) else (
        echo [OK] Go
    )
) else (
    echo [FAIL] Go
)

where rustc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if defined RUST_VER (
        echo [OK] Rust !RUST_VER!
    ) else (
        echo [OK] Rust
    )
) else (
    echo [FAIL] Rust
)

where cargo >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if defined CARGO_VER (
        echo [OK] Cargo !CARGO_VER!
    ) else (
        echo [OK] Cargo
    )
) else (
    echo [FAIL] Cargo
)

where node >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Node.js
) else (
    echo [FAIL] Node.js
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Python
) else (
    echo [FAIL] Python
)

where docker >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Docker
) else (
    echo [FAIL] Docker
)

echo.
echo PATH verification:

where go >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Go
) else (
    echo [FAIL] Go
)

where rustc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Rust
) else (
    echo [FAIL] Rust
)

where cargo >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Cargo
) else (
    echo [FAIL] Cargo
)

echo.
echo VibeGuard development environment ready.
endlocal
