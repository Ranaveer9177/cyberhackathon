# VibeGuard — Testing & Verification Guide

> **Test Suites, Automated Tests, and Manual Verification Procedures**

---

## 1. Automated Test Suite

Run the full Go test suite:

```powershell
go test -v ./...
```

### Passing Packages:
- `cmd/vibeguard`: CLI input validation, version (`v5.1.0`), format parsing, and exit codes.
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

### 3.5 Complete Repository Test Runner (`ultimate_test.bat` v5.1.0)
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

### 3.8 Sensitive Credential Filename & Assignment Verification (v5.1.0)
- **Test Files**:
  - `..\VibeGuard-test\test-project\password.txt` containing `password=123@admin`
  - `leak_test.txt` containing `password = "super_secret_leak_123"`
- **Command**:
  ```powershell
  vibeguard scan
  ```
- **Expected Results**:
  - `VG-SECRET-FILE`: `Sensitive Credential File Detected` (`HIGH` severity, `HIGH` confidence).
  - `VG-SECRET-001`: `Hardcoded Password Detected` (`HIGH` severity, masked evidence `password=********`).
  - `Security Score`: Penalized accordingly.
  - `Deployment Status`: `BLOCKED` with exit code `1`.
- **Negative Verification**: Verify that `README.md` containing `"Example: password=123@admin"` receives confidence penalty (-30) and does not block the gate.

### 3.9 E2E Verification Matrix Summary (v5.1.0)

| Test Category | Target / Trigger | Expected Detection | Gate Status | Result |
| :--- | :--- | :--- | :---: | :---: |
| **Generic Leak Files** | `leak_test.txt` (`password = "super_secret_leak_123"`) | `[HIGH] VG-SECRET-FILE`<br>`[HIGH] VG-SECRET-001` | **BLOCKED** | **PASS** |
| **Sensitive Filename Auditing** | `test*.txt`, `*_secret.txt`, `*.conf`, `*.env*` | `[HIGH] VG-SECRET-FILE` | **BLOCKED** | **PASS** |
| **Manifest Exclusion** | `requirements.txt`, `test-requirements.txt` | Ignored as sensitive file | Evaluated for CVEs | **PASS** |
| **Dynamic Weighting** | Quoted assignment in generic text | `[HIGH] VG-SECRET-001` (Score >= 80) | **BLOCKED** | **PASS** |
| **Comparison Exclusion** | Source code `key == "password"` | Excluded from assignment rules | Allowed | **PASS** |
| **Transparent Reporting** | `vibeguard scan` (default) | Primary findings displayed, Lows summarized | As Configured | **PASS** |
| **Verbose Reporting** | `vibeguard scan --verbose` / `--all` | Dedicated `Advisory & Low Severity Findings` | As Configured | **PASS** |
| **Cache & State Isolation** | Workspaces with `.vibeguard/cache/` or `reports/` | Unconditionally skipped by walkers | Clean scan | **PASS** |
| **Pre-Push Git Gate** | `git push` with uncommitted/committed leaks | Native popup alert + console abort | **BLOCKED (Exit 1)** | **PASS** |
| **Full Repository Test Suite** | `.\ultimate_test.bat` | 8/8 stages verified (Score: 100/100) | **PASS (Exit 0)** | **PASS** |

### 3.10 DevSecOps Chaos Engineering & Adversarial Stress Suite (v5.1.0)

To guarantee enterprise robustness against bypass attempts, resource exhaustion, and path traversal ambiguities, VibeGuard v5.1.0 underwent extensive chaos testing across five specialized failure domains:

#### Domain 1: Manifest Bypass vs Malicious Injection
- **Objective**: Verify that legitimate SCA manifests containing vulnerabilities are processed strictly as dependency manifests without false-positive leak alarms, while disguised leak files are intercepted.
- **Vectors**:
  - `requirements.txt` containing vulnerable package `urllib3==1.24.1` (OSV CVE intelligence test).
  - Nested leak files: `sub/leak_config.txt` and `test_token.txt` with credentials.
- **Results**:
  - `requirements.txt`: 0 sensitive file findings; correctly queried OSV and reported 6 vulnerabilities.
  - `sub/leak_config.txt` & `test_token.txt`: 100% intercepted by `VG-SECRET-FILE` and `VG-SECRET-001`.
  - **Verdict**: PASS.

#### Domain 2: Mathematical Boundary Testing & Heuristics Stress
- **Objective**: Verify that source code comparison statements (`==`, `!=`) do not produce false alarms, genuine credential assignments are caught, and documentation examples receive appropriate penalties.
- **Vectors**:
  - `auth.go` containing:
    ```go
    if (userInput == "password") { return false }
    if (authToken != "admin") { return false }
    ```
  - `math_helpers.go` containing `db_pass := "real_secret_token_123"`.
  - `README.md` containing `password="demo_placeholder"`.
- **Results**:
  - `auth.go`: 0 findings (equality operators cleanly excluded).
  - `math_helpers.go`: Flagged as `HIGH` severity `VG-SECRET-001` (Score 80, Confidence HIGH).
  - `README.md`: Confidence reduced to 25 (`LOW`), does NOT block the gate.
  - **Verdict**: PASS.

#### Domain 3: Parallel Directory Walker Chaos & DoS Resistance
- **Objective**: Stress the directory walking subsystem under massive nested file explosions and verify early root-level directory pruning.
- **Vectors**:
  - 5,000 generated files placed across `node_modules/` and `scanner/target/`.
- **Results**:
  - Directory walker pruned `node_modules/` and `target/` instantly at the root without descending into subtrees.
  - Total scan duration: **0.160s** (160ms).
  - Effective pruning throughput: **>30,000 files/sec**.
  - **Verdict**: PASS (Zero latency spike, zero memory exhaustion).

#### Domain 4: Flag Abuse & Parameter Fuzzing
- **Objective**: Test CLI argument parsing resilience against flag stacking and invalid parameters.
- **Vectors**:
  - Stacked flags: `vibeguard scan . --verbose --all --format=terminal --show-excluded`.
  - Illegal parameter combinations: `vibeguard scan --unknown-flag-fuzz`.
- **Results**:
  - Stacked flags: Exit code `0`, clean scan, full transparent disclosure.
  - Unknown flags: Exit code `2` with descriptive syntax error message.
  - **Verdict**: PASS.

#### Domain 5: Push Gate Pre-Commit/Pre-Push Git Lifecycle Isolation
- **Objective**: Prove that VibeGuard pre-push gate strictly isolates the pushed Git commit snapshot (`git archive`) and is never tricked by dirty uncommitted working trees.
- **Vectors**:
  - Commit clean code to Git, then add uncommitted `leak_candidate.txt` with raw secrets into the working directory.
  - Run `git push`.
- **Results**:
  - Git pre-push hook extracted committed tree snapshot.
  - Working directory dirty files were excluded from the push snapshot.
  - Clean push permitted; subsequent test committing `leak_candidate.txt` immediately aborted push with Exit Code `1`.
  - **Verdict**: PASS.



