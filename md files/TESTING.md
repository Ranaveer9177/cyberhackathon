# VibeGuard — Testing & Verification Guide

> **Test Suites, Automated Tests, and Manual Verification Procedures**

---

## 1. Automated Test Suite

Run the full Go test suite:

```powershell
go test -v ./...
```

### Passing Packages:
- `internal/config`: Default configuration loading, JSON validation, and exclusion path matching.
- `internal/dependencies`: Manifest parsing (Go, npm, Python, Cargo) and exclusion filtering.
- `internal/gate`: Policy threshold evaluation and exit code mapping.
- `internal/git`: Hook installation/uninstallation, user hook preservation, ref tuple parsing, and snapshot creation.
- `internal/report`: JSON and HTML report generation, dynamic terminal progress bar rendering, and ANSI cursor control tests (`progress_test.go`).
- `internal/risk`: Deterministic mathematical risk scoring calculations.
- `internal/scanner`: Dual-engine scanner execution, exclusion skipping, and rule matching.
- `tests/integration`: End-to-end integration workflows.

---

## 2. Static Analysis Verification

```powershell
go vet ./...
```

Ensures zero suspicious constructs, correct printf formatting, and code standards compliance.

---

## 3. End-to-End Functional Verification

### 3.1 Clean Repository Self-Scan
```powershell
.\vibeguard.exe scan .
```
- **Expected Result**: `Deployment Status: PASSED`
- **Security Score**: `100/100`
- **Exit Code**: `0`
- **Findings**: `0` (internal code exclusions and tooling filters successfully applied)

### 3.2 Intentionally Vulnerable Target Scan
```powershell
.\vibeguard.exe scan .\test-project
```
- **Expected Result**: `Deployment Status: BLOCKED`
- **Exit Code**: `1`
- **Findings**: Identifies intentional secrets in `.env`, vulnerable dependencies in `requirements.txt`/`package.json`, root user in `Dockerfile`, SQL injection and command injection in `database.go`.

### 3.3 Git Pre-Push Hook Verification
```powershell
# Check status
.\vibeguard.exe status

# Reinstall hook
.\vibeguard.exe init

# Verify hook script exists
Get-Content .git/hooks/pre-push
```

### 3.4 Live Terminal Progress Indicator Verification (v3.0)
```powershell
.\vibeguard.exe scan .
```
- **File Scan Progress**: Real-time counter and file path:
  `[██████████████░░░░░░] 70%`  
  `Files: 56/80`  
  `Current: internal/scanner/runner.go`
- **Dependency Scan Progress**: Real-time package indicator:
  `[████████████████░░░░] 80%`  
  `Dependencies: 36/45`  
  `Current: lodash@4.17.20`
- **OSV Query Progress**: Real-time query counter:
  `[██████████████████░░] 90%`  
  `OSV queries: 41/45`
- **Final Completion Indicator**: Full 100% completion bar:
  `[████████████████████] 100%`  
  `Security analysis complete.`

### 3.5 Automated Health Test Suite (`run_test.bat`)
```cmd
run_test.bat
```
- **Expected Result**:
  - `[PASS] CLI found`
  - `[PASS] Scanner found`
  - `[PASS] Version command`
  - `[PASS] Test project scan`
  - `[PASS] Report generation`
  - `[PASS] Security gate`
  - All 6 tests pass with exit code `0`.

### 3.6 Fail-Closed & Multi-Ref Verification
- **Fail-Closed Test**: Rename local/global `vibeguard.exe` and invoke `git push`; pre-push hook immediately prints `[SECURITY BLOCKED]` and returns exit code `1`.
- **Multi-Ref Test**: Pushing multiple branches simultaneously validates snapshots for each ref independently.

### 3.7 False-Positive Elimination & Clean Terminal Verification
- **Doc & Coverage Test**: Scan projects containing `README.md` code snippets, `htmlcov/`, virtual environments (`venv/`), or PowerShell scripts (`start.ps1`); verify 0 false-positive findings.
- **Grouped Dependency Output**: Verify that packages with multiple advisories (e.g. Django or cryptography) are rendered in a clean table row rather than hundreds of lines of duplicated findings.


