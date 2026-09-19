# VibeGuard Test Output

**Date:** 2026-09-19  
**Project:** `C:\Users\ranua\Music\cyberhackathon`  
**Version:** VibeGuard v3.0.0 (Git Secure Push Gate & Live Progress)

---

## 1. Full Go Test Suite

Command:

```powershell
go test ./...
```

Result: **PASS** (exit code `0`)

Passing packages:

- `internal/config`
- `internal/dependencies`
- `internal/gate`
- `internal/git`
- `internal/report` (includes `progress_test.go`: `TestBuildBar`, `TestProgressBarRender`, `TestProgressBarFinish`)
- `internal/risk`
- `internal/scanner`
- `tests/integration`

Packages without test files compiled successfully:

- `cmd/vibeguard`
- `internal/osv`
- `tests/sast`

---

## 2. Compile Binary

Command:

```powershell
go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
```

Result: **PASS** (exit code `0`)

---

## 3. Version Check

Command:

```powershell
.\vibeguard.exe version
```

Result: **PASS** (exit code `0`)

Output:

```text
VibeGuard v3.0.0
```

---

## 4. Status Check

Command:

```powershell
.\vibeguard.exe status
```

Result: **PASS** (exit code `0`)

Observed status:

```text
Git detected: NO
Status: INACTIVE (not a git repository)
```

---

## 5. Vulnerable Test Project Scan

Command:

```powershell
.\vibeguard.exe scan .\test-project
```

Result: **BLOCKED** (exit code `1`)

Observed summary:

```text
Deployment Status: BLOCKED
Reason: 24 critical finding(s) and 69 high-severity finding(s) detected
```

---

## 6. Clean Repository Self-Scan

Command:

```powershell
vibeguard scan scanner\src
```

Result: **PASS** (exit code `0`)

Observed summary:

```text
Security Score: 100/100 (LOW RISK)
Gate Status:    PASSED
Reason:         No blocking security findings

Code & Configuration Findings (0):
  ✓ No code, secret, or configuration issues detected.
Dependency Vulnerabilities (0 vulnerable packages, 0 total advisories):
  ✓ No known vulnerabilities found in dependencies.
```

---

## 7. Automated Health Test Suite (`run_test.bat`)

Command:

```cmd
run_test.bat
```

Result: **ALL TESTS PASSED** (exit code `0`)

Output:

```text
========================================
       VIBEGUARD HEALTH TEST
========================================

[PASS] CLI found
[PASS] Scanner found
[PASS] Version command
[PASS] Test project scan
[PASS] Report generation
[PASS] Security gate

========================================
       ALL TESTS PASSED
========================================
```

---

## Overall Result

**PASS:** The test suite, health test, binary builds, and pre-push verification succeeded. Clean projects pass with 100/100 and zero false positives; vulnerable targets are blocked with detailed, non-messy terminal reports.

