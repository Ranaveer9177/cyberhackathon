# VibeGuard — Testing & Verification Guide

> **Test Suites, Automated Tests, and Manual Verification Procedures**

---

## 1. Automated Test Suite

Run the full Go test suite:

```powershell
go test -v ./...
```

### Passing Packages:
- `cmd/vibeguard`: CLI input validation, version (`v4.6.0`), format parsing, and exit codes.
- `internal/baseline`: Baseline loading, suppression matching, expiration, and corrupt file fail-closed logic.
- `internal/config`: Default configuration loading, JSON validation, and exclusion path matching.
- `internal/defender`: Windows Defender & AV detection, WMI product queries, Win32 error analysis, and pop-up modal logic.
- `internal/dependencies`: Manifest parsing (Go, npm, Python, Cargo) and exclusion filtering.
- `internal/errors`: Structured machine-readable error codes (`VG-E001` through `VG-E008`).
- `internal/gate`: Policy threshold evaluation and exit code mapping.
- `internal/git`: Hook installation/uninstallation, user hook preservation, ref tuple parsing, snapshot creation, and bare remote E2E tests.
- `internal/osv`: Google OSV API client, persistent SHA-256 disk cache (`.vibeguard/cache/osv/`), and offline mode.
- `internal/report`: JSON, HTML (with contextual escaping), SARIF 2.1.0 report generation, and terminal formatting.
- `internal/risk`: Deterministic mathematical risk scoring calculations.
- `internal/scanner`: Dual-engine scanner execution, finding deduplication, exclusion skipping, and context-aware secret & filename detection tests (`secrets_test.go`).
- `tests/integration`: End-to-end integration workflows.

### Rust Scanner Tests (`scanner/`):
```powershell
cargo test --manifest-path scanner/Cargo.toml
cargo clippy --manifest-path scanner/Cargo.toml -- -D warnings
```
- 9 unit tests verifying recursive scanning, sensitive filenames (`password.txt`), credential assignments (`password=123@admin`), evidence masking, and non-blocking documentation/placeholder negative cases. 100% clean Clippy.

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

### 3.2 Intentionally Vulnerable Target Scan (External Workspace)
```powershell
vibeguard scan C:\Users\ranua\Music\VibeGuard-test\test-project
```
- **Expected Result**: `Deployment Status: BLOCKED`
- **Exit Code**: `1`
- **Findings**: Identifies intentional secrets in `.env`, vulnerable dependencies in `requirements.txt`/`package.json`, root user in `Dockerfile`, SQL injection and command injection in `database.go`.

### 3.3 Git Pre-Push Hook Verification
```powershell
# Check status
vibeguard status

# Reinstall hook
vibeguard init

# Verify hook script exists
Get-Content .git/hooks/pre-push
```

### 3.4 Automated Health Test Suite (`scripts\windows\run_test.bat`)
```cmd
scripts\windows\run_test.bat
```
- **Expected Result**:
  - `[PASS] CLI found`
  - `[PASS] Scanner found`
  - `[PASS] Version command`
  - `[PASS] Test project scan`
  - `[PASS] Report generation`
  - `[PASS] Security gate`
  - `[PASS] Defender diagnostic`
  - All 7 tests pass with exit code `0`.

### 3.5 Complete Repository Test Runner (`ultimate_test.bat` v4.6.0)
```cmd
.\ultimate_test.bat
# Or with native modal alert simulation:
.\ultimate_test.bat --test-popup
```
- **Expected Result**: Executes the 8-stage weighted evaluation engine (Go package tests: 15 pts, Go vet: 10 pts, Rust tests: 15 pts, Rust format check: 5 pts, Rust Clippy: 10 pts, Source build: 20 pts, CLI health test: 15 pts, Windows Defender verification: 10 pts). Reports sub-second stopwatch timing for each stage, detailed package/test metrics, and final summary (**Score: 100/100, Minimum: 90/100, Result: PASS**).

### 3.6 Fail-Closed & Multi-Ref Verification
- **Fail-Closed Test**: Rename local/global `vibeguard.exe` and invoke `git push`; pre-push hook immediately prints `[SECURITY BLOCKED]` and returns exit code `1`.
- **Multi-Ref Test**: Pushing multiple branches simultaneously validates snapshots for each ref independently.

### 3.7 False-Positive Elimination & Clean Terminal Verification
- **Doc & Coverage Test**: Scan projects containing `README.md` code snippets, `htmlcov/`, virtual environments (`venv/`), or PowerShell scripts (`start.ps1`); verify 0 false-positive findings.
- **Grouped Dependency Output**: Verify that packages with multiple advisories (e.g. Django or cryptography) are rendered in a clean table row rather than hundreds of lines of duplicated findings.

### 3.8 Sensitive Credential Filename & Assignment Verification (v4.4)
- **Test File**: `..\VibeGuard-test\test-project\password.txt` containing `password=123@admin`
- **Command**:
  ```powershell
  vibeguard scan ..\VibeGuard-test\test-project
  ```
- **Expected Results**:
  - `VG-SECRET-FILE`: `Sensitive Credential File Detected` (`HIGH` severity, `HIGH` confidence).
  - `VG-SECRET-001`: `Hardcoded Password Detected` (`HIGH` severity, context confidence, masked evidence `password=********`).
  - `Security Score`: Penalized accordingly.
  - `Deployment Status`: `BLOCKED` with exit code `1`.
- **Negative Verification**: Verify that `README.md` containing `"Example: password=123@admin"` receives confidence penalty (-30) and does not block the gate.


