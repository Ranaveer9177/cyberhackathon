@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0"
cd /d "%ROOT%"

set /a TOTAL=8
set /a PASSED=0
set /a FAILED=0

echo ========================================
echo       VIBEGUARD ULTIMATE TEST
echo ========================================
echo Project Root: %ROOT%
echo.

call :run_step 1 "Go package tests" "go test ./internal/..."
call :run_step 2 "Go vet" "go vet ./internal/..."
call :run_step 3 "Rust tests" "cargo test --manifest-path scanner\Cargo.toml"
call :run_step 4 "Rust format check" "cargo fmt --manifest-path scanner\Cargo.toml -- --check"
call :run_step 5 "Rust Clippy" "cargo clippy --manifest-path scanner\Cargo.toml --all-targets --all-features -- -D warnings"
call :run_step 6 "Source build" ""
call :run_step 7 "CLI health test" ""
call :run_step 8 "Windows Defender & pop-up verification" ""

set /a PERCENT=PASSED*100/TOTAL
echo.
echo ========================================
echo          ULTIMATE TEST SUMMARY
echo ========================================
echo Passed:  %PASSED%/%TOTAL%
echo Failed:  %FAILED%/%TOTAL%
echo Score:   %PERCENT%%%

if %FAILED% equ 0 (
    echo Result:  PASS
    exit /b 0
)

echo Result:  FAIL
exit /b 1

:run_step
set "STEP=%~1"
set "LABEL=%~2"
set "COMMAND=%~3"
set /a PERCENT=STEP*100/TOTAL
echo.
echo [!STEP!/%TOTAL% - !PERCENT!%%] !LABEL!
if "!STEP!"=="6" (
    call "%ROOT%scripts\windows\build.bat"
) else if "!STEP!"=="7" (
    call "%ROOT%scripts\windows\run_test.bat"
) else if "!STEP!"=="8" (
    call "%ROOT%vibeguard.exe" defender-check
    call "%ROOT%vibeguard.exe" defender-check --test-popup
) else (
    cmd /d /c "!COMMAND!"
)
if !ERRORLEVEL! equ 0 (
    set /a PASSED+=1
    echo [PASS] !LABEL!
) else (
    set /a FAILED+=1
    echo [FAIL] !LABEL!
)
exit /b 0
