# VibeGuard Codebase — Complete Source Files
Total files: 63
---
## .gitignore

`
# Binaries and executables
*.exe
*.exe~
*.dll
*.so
*.dylib
/vibeguard
/vibeguard.exe
/vibeguard-scanner
/vibeguard-scanner.exe

# Build directories
target/
scanner/target/
bin/
dist/
build/

# Go build artifacts
*.test
*.prof

# Generated scan outputs (keep reports/ directory structure)
reports/*.json
reports/*.html
!reports/README.md

# Log files and temporary artifacts
*.log
*.tmp
.system_generated/
scratch/

# OS and IDE files
.DS_Store
Thumbs.db
.vscode/
.idea/
*.swp

`

---
## README.md

`
# VibeGuard v3.0 — Autonomous Git Pre-Push Security Gate & Code Security Scanner

> **The Autonomous Pre-Push Security Firewall for Engineering Teams**  
> *"Make security verification an automatic, non-negotiable step before code ever leaves your machine."*

---

## Overview

**VibeGuard v3.0** is an enterprise-grade security scanner and autonomous Git pre-push hook gate written in **Go** and **Rust**. It stops hardcoded secrets, dangerous code patterns (SAST), vulnerable third-party dependencies (SCA via Google OSV), Dockerfile misconfigurations, and sensitive configuration leaks *before* they are pushed to remote repositories or deployed to production.

VibeGuard operates directly in developer terminal workflows and CI/CD pipelines:
- **Clean Grouped Terminal Reporting**: Replaces 250+ lines of redundant advisory dumps with an aligned dependency table (`PACKAGE | CURRENT | SEVERITY | ADVISORIES | RECOMMENDED FIX`) and compact key advisory highlights.
- **Zero False-Positive Scanner Engine**: Automatically ignores test coverage folders (`htmlcov/`, `.coverage`), caches, virtual environments, IDE configs, and `.gitignore` patterns. Filters documentation code blocks, PowerShell parameter prompts, placeholder passwords (`"admin"`, `"password"`), loopback HTTP (`localhost`, `127.0.0.1`, `0.0.0.0`), and schema URIs.
- **Live Interactive Scan Progress**: Real-time terminal progress bars during file scanning (streamed from the Rust engine via `--progress`), dependency resolution, and OSV database queries.
- **Autonomous Git Pre-Push Gate**: Intercepts `git push` via standard pre-push hooks. Scans only the exact commits being pushed using disk-staged `git archive` snapshotting. Iterates over all pushed refs independently and fails closed if the CLI executable is missing.
- **High-Performance Concurrent OSV Engine**: Multi-goroutine worker pool with HTTP Keep-Alive and connection pooling, querying Google OSV in parallel (~400ms latency).
- **Deterministic 0–100 Security Score**: Evaluates risk using weighted mathematical severity scoring.
- **Strict Policy Enforcement**: Standardized exit codes (`0` SAFE, `1` BLOCKED, `2` ERROR, `3` CONFIG ERROR, `4` OSV UNAVAILABLE) to reliably integrate with git hooks, GitHub Actions, and deployment pipelines.
- **Zero Cloud Uploads / 100% On-Machine Privacy**: Code and files never leave your workstation. Discovered credentials are automatically masked (`sk-demo-****`).
- **Multi-Engine Speed & Precision**: High-performance Rust scanner coupled with Go orchestrator and fallback engine.


---

## Architecture

```
                    Developer Shell / Git CLI
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       git push / vibeguard push        vibeguard scan
               │                               │
               ▼                               │
        Git Pre-Push Hook                      │
  (stdin: local & remote refs)                 │
               │                               │
               ▼                               │
     Commit Tree Snapshot                      │
   (git archive -> tar reader)                 │
               │                               │
               └───────────────┬───────────────┘
                               ▼
                        VibeGuard CLI (Go)
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
      Rust Scanner Engine              OSV Vulnerability API
   (Secrets, SAST, Docker, Git)      (Real CVEs / Advisories)
               │                               │
               └───────────────┬───────────────┘
                               ▼
                         Finding Engine
                               │
                               ▼
                       Risk Scoring Engine
                               │
               ┌───────────────┼───────────────┐
               ▼               ▼               ▼
        Terminal Report   JSON Report     HTML Report
               │
               ▼
       PASS / BLOCK Gate
  (SAFE -> Push Continues | BLOCKED -> Push Aborted)
```

- **Go Orchestrator (`cmd/vibeguard`, `internal/`)**: CLI UX, Git hook lifecycle management, commit snapshot extraction, dependency detection & manifest parsing, OSV REST API communication, finding aggregation, risk scoring, report generation, and gate evaluation.
- **Rust Engine (`scanner/`)**: High-performance recursive filesystem walker, secret pattern matching with evidence masking, static analysis (SAST) rule evaluation, Dockerfile scanning, configuration auditing, and JSON IPC stream.
- **Google OSV Intelligence**: Authoritative, real-time vulnerability data for Go, npm, PyPI, and crates.io packages (no hallucinated CVEs).

---

## Repository Structure

```text
cyberhackathon/
├── cmd/
│   └── vibeguard/               # CLI application entry point
│       └── main.go              # Commands: init, status, uninstall, push, scan, report
├── internal/
│   ├── config/                  # Repository configuration (.vibeguard/config.json) & exclusions
│   │   ├── config.go
│   │   └── config_test.go
│   ├── dependencies/            # Manifest parsers (go.mod, package.json, requirements.txt, Cargo.toml)
│   │   ├── detector.go
│   │   ├── parser.go
│   │   └── parser_test.go
│   ├── gate/                    # PASS / BLOCK security gate decision engine
│   │   ├── gate.go
│   │   └── gate_test.go
│   ├── git/                     # Git integration, pre-push hook manager, snapshot scanner
│   │   ├── hooks.go
│   │   ├── hooks_test.go
│   │   ├── repo.go
│   │   └── repo_test.go
│   ├── osv/                     # Google OSV API client & batch query engine
│   │   ├── client.go
│   │   └── types.go
│   ├── report/                  # Terminal ANSI, JSON, HTML generators & live progress bars
│   │   ├── html.go
│   │   ├── json.go
│   │   ├── progress.go
│   │   ├── progress_test.go
│   │   ├── report_test.go
│   │   └── terminal.go
│   ├── risk/                    # Deterministic 0-100 risk scoring algorithm
│   │   ├── scorer.go
│   │   └── scorer_test.go
│   └── scanner/                 # Dual-engine scanner runner (Rust binary + Go fallback)
│       ├── runner.go
│       └── runner_test.go
├── scanner/                     # Rust Scanner Engine
│   ├── Cargo.toml
│   └── src/
│       ├── config.rs            # Configuration auditing (debug mode, CORS wildcard, 0.0.0.0)
│       ├── docker.rs            # Dockerfile analysis (root user, ENV secrets, COPY .)
│       ├── git.rs               # Repository sensitive file checks
│       ├── main.rs              # Scanner entry point and JSON output serializer
│       ├── rules.rs             # Built-in regex rule definitions
│       ├── sast.rs              # SAST source code scanner
│       ├── scanner.rs           # Fast recursive directory traversal with exclusion filters
│       ├── secrets.rs           # High-entropy secret detection & masking
│       └── types.rs             # Core shared data structures
├── test-project/                # Controlled intentionally vulnerable demo project
│   ├── .env                     # Demo test secrets
│   ├── Dockerfile               # Vulnerable container file (root user, ENV secrets)
│   ├── go.mod                   # Outdated dependencies
│   ├── package.json             # Outdated npm packages
│   ├── requirements.txt         # Outdated Python dependencies
│   └── src/
│       ├── auth.js              # eval(), command injection, hardcoded JWT
│       ├── config.go            # Hardcoded credentials, disabled TLS
│       └── database.go          # SQL injection, command injection, weak MD5
├── tests/                       # Test suites & fixtures
│   ├── dependencies/            # Mock manifest files
│   ├── integration/             # End-to-end integration tests
│   ├── sast/                    # Vulnerable code samples for SAST verification
│   └── secrets/                 # Test credential patterns
├── .vibeguard/
│   └── config.json              # Repository-level configuration and exclusion rules
├── reports/                     # Output directory for generated reports
├── setup.bat                    # Automated environment setup script for Windows
├── README.md                    # Project documentation
├── md files/                    # Core project documentation and blueprints
```

---

## Detection Capabilities

| Category | Checks & Rules | Default Severity |
| :--- | :--- | :---: |
| **Secrets & Keys** | AWS Access Keys (`AKIA...`), GitHub PATs (`ghp_...`), Slack Tokens (`xox...`), Private Cryptographic Keys (`BEGIN RSA/OPENSSH PRIVATE KEY`), Hardcoded Passwords & Tokens, Sensitive Files (`.env`, `*.pem`, `*.key`, `id_rsa`) | `CRITICAL` |
| **SAST — Code Analysis** | Potential OS Command Injection, Potential SQL Injection, Potential TLS Misconfiguration (`InsecureSkipVerify: true`), Potential Insecure HTTP Connection, Dangerous `eval()` / `Function()`, Weak Cryptography (`MD5`, `SHA1`, `DES`, `RC4`), Hardcoded Credentials | `HIGH` / `MEDIUM` |
| **Container & Docker** | Container running as `root` (missing non-root `USER`), Secrets stored in `ENV` instructions, Unbounded `COPY . .` without `.dockerignore` | `CRITICAL` / `HIGH` / `MEDIUM` |
| **SCA — Dependencies** | Direct & transitive package CVE lookup against live Google OSV database (`go.mod`, `package.json`, `package-lock.json`, `requirements.txt`, `Cargo.toml`, `Cargo.lock`) | `CRITICAL` to `LOW` |
| **Configuration** | Insecure CORS (`Access-Control-Allow-Origin: *`), Exposed Debug Mode (`debug: true`), Insecure host binding (`0.0.0.0`) | `MEDIUM` / `LOW` |

---

## Installation & Distribution Modes

VibeGuard supports two distinct distribution modes for zero-friction portability:

### Mode A — Demo / User Mode (No Compilers Required)
Prebuilt Windows binaries (`vibeguard.exe` and `vibeguard-scanner.exe`) are bundled directly with the repository. You **do not need Go, Rust, or Visual Studio Build Tools** to run VibeGuard:

1. **One-Command Global Setup**:
   ```cmd
   setup.bat
   ```
   *Installs VibeGuard into `%LOCALAPPDATA%\VibeGuard`, verifies the Rust scanner, installs runtime rules, configures the Git pre-push hook, and registers `%LOCALAPPDATA%\VibeGuard` in the Current User `PATH`.*

2. **Open a NEW Terminal & Verify Global Access**:
   Close your current CMD or PowerShell window and open a new one. `vibeguard` is now available globally from **any directory**:
   ```cmd
   cd %USERPROFILE%
   vibeguard version
   # Output: VibeGuard v3.0.0

   cd C:\
   vibeguard help
   ```

3. **Verify Health & Scan Test Project**:
   ```cmd
   run_test.bat
   ```
   *Executes a full self-test against the intentionally vulnerable fixture `test-project`, verifying CLI, scanner, version, scan, HTML report generation, and security gate blocking.*

4. **Hook Management Scripts**:
   ```cmd
   install_hook.bat     # Installs the pre-push hook in .git/hooks/pre-push
   uninstall_hook.bat   # Cleanly removes the pre-push hook
   ```

---

### Mode B — Developer / Source Build Mode
Developers rebuilding VibeGuard from source:

1. **Prerequisites**:
   - **Go** (1.21 or higher)
   - **Git** (2.20 or higher)
   - **Rust & Cargo** (1.70 or higher)
   - **Visual Studio Build Tools** (Desktop development with C++ for `link.exe`)

2. **One-Command Source Build**:
   ```cmd
   build.bat
   ```
   *Verifies Go, Rust, and `link.exe`, compiles the release Rust scanner (`cargo build --release`), compiles the Go orchestrator CLI (`go build ./cmd/vibeguard`), updates local binaries, and refreshes the global `%LOCALAPPDATA%\VibeGuard` installation.*

3. **Manual CLI Build**:
   ```powershell
   cd scanner
   cargo build --release
   cd ..
   go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
   ```

---

### Global Execution & Independent Target Scanning
Because VibeGuard dynamically determines its executable directory at runtime (`FindScannerExecutable()`), you can scan any external repository or project folder from anywhere on your machine:

```powershell
# Scan external projects from any directory:
vibeguard scan C:\Users\pooji\Projects\my-app
vibeguard scan D:\Repositories\backend --format html --output reports\audit.html

# Run within any Git repository:
vibeguard status
vibeguard init
vibeguard push
```

The Git pre-push hook prioritizes the trusted `%LOCALAPPDATA%\VibeGuard\vibeguard.exe` binary over untrusted repository-local executables, preventing rogue scripts from circumventing gate policies.

---

## Command Reference & Usage

### 1. `vibeguard init` — Install Git Pre-Push Hook
Installs the automatic pre-push hook into `.git/hooks/pre-push` and creates default configuration `.vibeguard/config.json`. Existing user hooks are automatically preserved and chained.
```powershell
vibeguard init
```

### 2. `vibeguard status` — Check Security Gate Status
Displays the repository status, active Git branch, remote origin, commit hash, hook installation state, and loaded security policies.
```powershell
.\vibeguard.exe status
```

### 3. `vibeguard push` — Guided Interactive Push Workflow
An interactive command that detects staged/modified files, prompts for commit message, executes the security gate verification, and pushes to remote only if the scan passes cleanly.
```powershell
.\vibeguard.exe push
```

### 4. `vibeguard scan` — Scan Repository or Target Directory
Performs security verification on any path.
```powershell
# Scan current repository
.\vibeguard.exe scan .

# Scan specific directory (e.g. intentionally vulnerable test project)
.\vibeguard.exe scan .\test-project

# Run in Git pre-push hook mode (evaluates exact pushed commits)
.\vibeguard.exe scan --hook .
```

### 5. `vibeguard report` — Generate HTML or JSON Reports
```powershell
# Interactive HTML Report (saved to reports/scan.html)
.\vibeguard.exe report .\test-project --format html

# Machine-readable JSON Report (saved to reports/scan.json)
.\vibeguard.exe report .\test-project --format json
```

### 6. `vibeguard uninstall` — Remove Git Pre-Push Hook
Cleanly removes the VibeGuard pre-push hook and restores any previous user hook backup.
```powershell
.\vibeguard.exe uninstall
```

---

## Live Scan Progress (v3.0)

During scans, VibeGuard renders terminal progress indicators with real-time feedback across all 4 stages:

### 1. File Scanning
```text
[██████████████░░░░░░] 70%
Files: 56/80
Current: internal/scanner/runner.go
```

### 2. Dependency Scanning
```text
[████████████████░░░░] 80%
Dependencies: 36/45
Current: lodash@4.17.20
```

### 3. Vulnerability Database (OSV) Lookup
```text
[██████████████████░░] 90%
OSV queries: 41/45
```

### 4. Final Completion Stage
```text
[████████████████████] 100%

Security analysis complete.
```

---

## Clean Terminal Reporting & False-Positive Elimination (v3.0)

### 1. Zero False-Positive Engine
VibeGuard eliminates the common false alarms typical of static scanners:
- **Test Coverage & Output Dirs**: Automatically excludes `htmlcov`, `.coverage`, `coverage`, `.pytest_cache`, `.mypy_cache`, `.tox`, `venv`, `env`, `.idea`, `.vscode`.
- **Automatic `.gitignore` Resolution**: Seamlessly respects local repo `.gitignore` patterns in both Rust and Go engines.
- **Documentation Safety**: Excludes `.md`, `.markdown`, `.rst`, `.txt`, and `.html` files from generic credential and password assignment rules. Real high-entropy keys (AWS, GitHub tokens, private keys) are still detected.
- **Script & Placeholder Filtering**: PowerShell parameter prompts (`Read-Host`, `param(...)`, `[securestring]`), environment variable getters (`os.getenv`, `os.environ`, `$env:`), and dummy values (`"admin"`, `"password"`, `"changeme"`, `"your_password"`) are recognized and excluded.
- **Insecure HTTP Refinement**: Ignores `http://localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, XML/JSON schemas (`w3.org`, `schemas.`, `json-schema.org`, `apache.org`, `example.com`), and dynamic template strings.

### 2. Clutter-Free Terminal Report
Instead of dumping 200+ raw, repetitive lines of advisory descriptions, VibeGuard groups findings into a clean, actionable display:

```text
========= VIBEGUARD SECURITY REPORT =========
Project:       Team-Avengers-Honeypot
Branch:        main
Commit:        93a757a
Scan Time:     245ms
Files Scanned: 69
---------------------------------------------
Security Score: 45/100 (HIGH RISK)
Gate Status:    BLOCKED
Reason:         Critical security findings detected

Severity Counts:
  Critical: 1 | High: 6 | Medium: 10 | Low: 0 | Info: 0
Category Breakdown:
  Secrets: 0 | Source Code: 0 | Dependencies: 38 | Config: 0 | Docker: 0 | Git: 0
---------------------------------------------
Code & Configuration Findings (0):
  ✓ No code, secret, or configuration issues detected.
---------------------------------------------
Dependency Vulnerabilities (6 vulnerable packages, 38 total advisories):
  PACKAGE              CURRENT      SEVERITY     ADVISORIES     RECOMMENDED FIX
  --------------------------------------------------------------------------------
  cryptography         41.0.0       CRITICAL     20 vulns       Upgrade to >= 42.0.4
  Django               3.2.0        HIGH         12 vulns       Upgrade to >= 4.2.11
  requests             2.25.1       MEDIUM       3 vulns        Upgrade to >= 2.31.0
  urllib3              1.26.5       HIGH         3 vulns        Upgrade to >= 1.26.18

  Key Advisory Highlights:
  • cryptography (41.0.0) [requirements.txt]:
    - GHSA-3ww4-gg4f-jr7f [CRITICAL]: null-dereference in PKCS12 parsing
    - GHSA-5cpq-8wj7-hf2v [HIGH]: Bleichenbacher timing oracle attack
    ... and 18 more advisories
  • Django (3.2.0) [requirements.txt]:
    - GHSA-2gwj-66ux-5946 [HIGH]: Potential denial of service in file uploads
    ... and 11 more advisories
---------------------------------------------
Deployment Status: BLOCKED
Reason: Critical security findings detected
=============================================
```

---

## Configuration (`.vibeguard/config.json`)

VibeGuard is configured via `.vibeguard/config.json` at the root of your project:

```json
{
  "block_on": [
    "critical",
    "high"
  ],
  "scan_mode": "full",
  "dependency_scan": true,
  "secret_scan": true,
  "source_scan": true,
  "report_format": "terminal",
  "fail_closed": true,
  "exclude": [
    ".git",
    ".vibeguard",
    "reports",
    "md files",
    "tests",
    "test-project",
    "code.md",
    "finalreport.md",
    "output.md",
    "output2.md",
    "test output.md",
    "test3.md"
  ]
}
```

### Configuration Options:
- `block_on`: List of severities that trigger a `BLOCK` gate decision (`"critical"`, `"high"`, `"medium"`, `"low"`).
- `scan_mode`: `"full"` scans all files; `"changed"` scans only modified/staged files.
- `fail_closed`: If `true`, aborts `git push` if the vulnerability database or scanner fails (prevents bypassing security during network failures).
- `exclude`: Subtrees, directories, and filenames excluded from security analysis.

---

## Exit Codes

| Exit Code | Classification | Meaning |
| :---: | :--- | :--- |
| `0` | **SAFE TO PUSH / PASSED** | All security checks passed; no blocking findings. Push continues. |
| `1` | **PUSH BLOCKED** | Critical or high-severity vulnerabilities detected. Git push aborted. |
| `2` | **ERROR** | Runtime or scanning error occurred. |
| `3` | **CONFIG ERROR** | Malformed or invalid `.vibeguard/config.json`. |
| `4` | **OSV UNAVAILABLE** | OSV API unreachable with `fail_closed: true`. Push aborted safely. |

---

## Security Scoring Formula

VibeGuard calculates a deterministic score from **0** to **100**:

$$\text{Score} = \max\left(0, 100 - (15 \times C + 8 \times H + 3 \times M + 1 \times L)\right)$$

- $C$ = Critical severity findings
- $H$ = High severity findings
- $M$ = Medium severity findings
- $L$ = Low severity findings

A clean project receives a score of **100/100 (`STATUS: SAFE TO PUSH`)**.

---

## Verification & Testing

Run the full test suite:

```powershell
# Run all Go package unit and integration tests
go test ./...

# Run static analysis check
go vet ./...

# Self-scan verification (must report 100/100, PASSED, Exit 0)
.\vibeguard.exe scan .

# Target verification on test fixture (must report BLOCKED, Exit 1)
.\vibeguard.exe scan .\test-project
```

---

## License & Security Policy

VibeGuard is designed for secure developer operations. It processes files locally in-memory and communicates strictly with official vulnerability advisories (OSV.dev).

`

---
## build.bat

`
@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Developer Build Script (build.bat)
::  Mode B: Compiles VibeGuard from source code
::  Requires: Go 1.21+, Rust 1.70+, and MSVC linker (link.exe)
:: ============================================================

:: 1. Detect project root
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ========================================
echo     VIBEGUARD SOURCE BUILD ENGINE
echo ========================================
echo Project Root: %ROOT%
echo.

:: 2. Verify Go compiler
echo Checking developer prerequisites...
where go >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go compiler go was not found.
    echo.
    echo Please install Go 1.21 or higher:
    echo   https://go.dev/dl/
    echo or run:
    echo   winget install GoLang.Go
    exit /b 1
)
for /f "tokens=3" %%v in ('go version 2^>nul') do set "GO_VER=%%v"
echo [OK] Go compiler found: %GO_VER%

:: 3. Verify Rust compiler and Cargo
where rustc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust compiler rustc was not found.
    echo.
    echo Please install Rust toolchain:
    echo   https://rustup.rs/
    echo or run:
    echo   winget install Rustlang.Rustup
    exit /b 1
)
for /f "tokens=2" %%v in ('rustc --version 2^>nul') do set "RUST_VER=%%v"
echo [OK] Rust compiler found: %RUST_VER%

where cargo >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Cargo package manager cargo was not found.
    exit /b 1
)
for /f "tokens=2" %%v in ('cargo --version 2^>nul') do set "CARGO_VER=%%v"
echo [OK] Cargo package manager found: %CARGO_VER%

:: 4. Verify Microsoft C++ linker
where link.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Microsoft C++ linker link.exe was not found.
    echo.
    echo Install:
    echo Visual Studio Build Tools
    echo -^> Desktop development with C++
    echo.
    echo Then open a new terminal and run build.bat again.
    exit /b 1
)
echo [OK] Microsoft C++ linker found: link.exe

:: 5. Build Rust Scanner Engine
echo.
echo ========================================
echo [1/2] Building Rust Scanner Engine...
echo ========================================
cd /d "%ROOT%scanner"

:: Point cargo target dir to isolated temp dir to bypass Windows media library folder locks
if not defined CARGO_TARGET_DIR (
    set "CARGO_TARGET_DIR=%TEMP%\cargo-target"
)

cargo build --release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust scanner compilation failed.
    cd /d "%ROOT%"
    exit /b 1
)

:: Locate built scanner binary
set "BUILT_SCANNER="
if exist "%CARGO_TARGET_DIR%\release\vibeguard-scanner.exe" (
    set "BUILT_SCANNER=%CARGO_TARGET_DIR%\release\vibeguard-scanner.exe"
) else if exist "%ROOT%scanner\target\release\vibeguard-scanner.exe" (
    set "BUILT_SCANNER=%ROOT%scanner\target\release\vibeguard-scanner.exe"
)

if not defined BUILT_SCANNER (
    echo [ERROR] Could not find compiled vibeguard-scanner.exe.
    cd /d "%ROOT%"
    exit /b 1
)

:: Copy scanner executable to root and scanner directories
copy /Y "%BUILT_SCANNER%" "%ROOT%vibeguard-scanner.exe" >nul
copy /Y "%BUILT_SCANNER%" "%ROOT%scanner\scanner.exe" >nul
copy /Y "%BUILT_SCANNER%" "%ROOT%scanner\vibeguard-scanner.exe" >nul
echo [OK] Rust scanner built successfully: %ROOT%vibeguard-scanner.exe

:: 6. Build Go Orchestrator CLI from repository root
cd /d "%ROOT%"
echo.
echo ========================================
echo [2/2] Building VibeGuard Go CLI...
echo ========================================
go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go CLI compilation failed.
    exit /b 1
)
echo [OK] Go CLI built successfully: %ROOT%vibeguard.exe

:: 7. Update installed copy in LocalAppData
if not exist "%LOCALAPPDATA%\VibeGuard" mkdir "%LOCALAPPDATA%\VibeGuard" >nul 2>&1
if not exist "%LOCALAPPDATA%\VibeGuard\bin" mkdir "%LOCALAPPDATA%\VibeGuard\bin" >nul 2>&1

copy /Y "%ROOT%vibeguard.exe" "%LOCALAPPDATA%\VibeGuard\vibeguard.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard.exe" "%LOCALAPPDATA%\VibeGuard\bin\vibeguard.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\scanner.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\vibeguard-scanner.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\bin\scanner.exe" >nul 2>&1
copy /Y "%ROOT%vibeguard-scanner.exe" "%LOCALAPPDATA%\VibeGuard\bin\vibeguard-scanner.exe" >nul 2>&1
if exist "%ROOT%rules" (
    if not exist "%LOCALAPPDATA%\VibeGuard\rules" mkdir "%LOCALAPPDATA%\VibeGuard\rules" >nul 2>&1
    xcopy /E /I /Y /Q "%ROOT%rules" "%LOCALAPPDATA%\VibeGuard\rules" >nul 2>&1
)
echo [OK] Updated global CLI in: %LOCALAPPDATA%\VibeGuard

:: 8. Verify generated binaries
echo.
echo Verifying built artifacts...
call "%ROOT%vibeguard.exe" version
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Verification failed.
    exit /b 1
)

echo.
echo ========================================
echo      BUILD COMPLETED SUCCESSFULLY
echo ========================================
echo Binaries produced:
echo   - %ROOT%vibeguard.exe
echo   - %ROOT%vibeguard-scanner.exe
echo   - %ROOT%scanner\scanner.exe
echo.
echo Run setup.bat to configure or run_test.bat to run health checks.
endlocal

`

---
## cmd/vibeguard/main.go

`
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vibeguard/vibeguard/internal/config"
	"github.com/vibeguard/vibeguard/internal/dependencies"
	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/git"
	"github.com/vibeguard/vibeguard/internal/osv"
	"github.com/vibeguard/vibeguard/internal/report"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

const version = "3.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := strings.ToLower(os.Args[1])

	switch command {
	case "init":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		handleInit(targetDir)
		os.Exit(0)

	case "uninstall":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		handleUninstall(targetDir)
		os.Exit(0)

	case "status":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		handleStatus(targetDir)
		os.Exit(0)

	case "push":
		targetDir := "."
		if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "-") {
			targetDir = os.Args[2]
		}
		exitCode := handlePush(targetDir)
		os.Exit(exitCode)

	case "scan":
		projectPath, format, outputPath, isHook := parseScanArgs(os.Args[2:], "terminal")
		if projectPath == "" {
			projectPath = "."
		}
		exitCode := runScan(projectPath, format, outputPath, isHook)
		os.Exit(exitCode)

	case "report":
		projectPath, format, outputPath, isHook := parseScanArgs(os.Args[2:], "html")
		if projectPath == "" {
			projectPath = "."
		}
		exitCode := runScan(projectPath, format, outputPath, isHook)
		os.Exit(exitCode)

	case "version", "--version", "-v":
		fmt.Printf("VibeGuard v%s\n", version)
		os.Exit(0)

	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", command)
		printUsage()
		os.Exit(2)
	}
}

func parseScanArgs(args []string, defaultFormat string) (projectPath, format, outputPath string, isHook bool) {
	format = defaultFormat
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if (arg == "--format" || arg == "-f") && i+1 < len(args) {
			format = args[i+1]
			i++
		} else if (arg == "--output" || arg == "-o") && i+1 < len(args) {
			outputPath = args[i+1]
			i++
		} else if arg == "--hook" {
			isHook = true
		} else if !strings.HasPrefix(arg, "-") && projectPath == "" {
			projectPath = arg
		}
	}
	return
}

func printUsage() {
	fmt.Printf("VibeGuard v%s — Pre-Deployment & Git Secure Push Verification CLI\n", version)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  vibeguard init [<repo-path>]                     Install Git pre-push hook & initialize .vibeguard/")
	fmt.Println("  vibeguard uninstall [<repo-path>]                Remove VibeGuard Git pre-push hook")
	fmt.Println("  vibeguard status [<repo-path>]                   Show Git repository and security gate status")
	fmt.Println("  vibeguard push [<repo-path>]                     Controlled commit + scan + push interactive workflow")
	fmt.Println("  vibeguard scan [<project-path>] [options]        Run security scan")
	fmt.Println("  vibeguard report [<project-path>] [options]      Generate HTML/JSON security report")
	fmt.Println("  vibeguard version                                Show VibeGuard version")
	fmt.Println("  vibeguard help                                   Show this help message")
	fmt.Println()
	fmt.Println("Scan Options:")
	fmt.Println("  --format, -f <fmt>     Output format: terminal (default), json, html")
	fmt.Println("  --output, -o <path>    Custom report output path (default: reports/scan.json or reports/scan.html)")
	fmt.Println("  --hook                 Apply gate policy thresholds from .vibeguard/config.json")
	fmt.Println()
	fmt.Println("Exit Codes:")
	fmt.Println("  0  PASS — Security scan passed, safe to deploy/push")
	fmt.Println("  1  BLOCK — Security policy blocked push (critical or high findings)")
	fmt.Println("  2  ERROR — Scanner or runtime error")
	fmt.Println("  3  CONFIG ERROR — Configuration file error")
	fmt.Println("  4  OSV UNAVAILABLE — Vulnerability intelligence unreachable with fail_closed enabled")
}

// handleInit: installs hook, creates default config, preserves existing user hook
func handleInit(dir string) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		os.Exit(2)
	}

	if !git.IsGitRepo(absDir) {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not inside a Git repository.\n", absDir)
		fmt.Fprintln(os.Stderr, "Run 'git init' first, then run 'vibeguard init'.")
		os.Exit(2)
	}

	root, _ := git.FindGitRoot(absDir)
	projectName := filepath.Base(root)

	fmt.Println("========================================")
	fmt.Println("    VIBEGUARD GIT SECURITY GATE INIT")
	fmt.Println("========================================")
	fmt.Printf("Repository: %s\n", projectName)
	fmt.Printf("Path:       %s\n", root)
	fmt.Println()

	// 1. Install Hook
	if err := git.InstallHook(root); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing Git pre-push hook: %v\n", err)
		os.Exit(2)
	}
	fmt.Println("✓ Git pre-push hook installed successfully (.git/hooks/pre-push)")

	// 2. Initialize .vibeguard/config.json if missing
	cfgPath := config.ConfigPath(root)
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := config.CreateDefaultConfig(root); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create default config: %v\n", err)
		} else {
			fmt.Println("✓ Initialized default configuration (.vibeguard/config.json)")
		}
	} else {
		fmt.Println("✓ Existing configuration preserved (.vibeguard/config.json)")
	}

	fmt.Println()
	fmt.Println("Every future 'git push' will automatically run VibeGuard before code leaves your machine.")
	fmt.Println("========================================")
}

// handleUninstall: removes VibeGuard hook and restores user backup if present
func handleUninstall(dir string) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		os.Exit(2)
	}

	if !git.IsGitRepo(absDir) {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not inside a Git repository.\n", absDir)
		os.Exit(2)
	}

	root, _ := git.FindGitRoot(absDir)
	if err := git.UninstallHook(root); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing Git hook: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("✓ VibeGuard Git pre-push hook removed successfully.")
}

// handleStatus: prints repository and security gate status
func handleStatus(dir string) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("========================================")
	fmt.Println("      VIBEGUARD V2 — STATUS")
	fmt.Println("========================================")

	if !git.IsGitRepo(absDir) {
		fmt.Printf("Directory:     %s\n", absDir)
		fmt.Println("Git detected:  NO")
		fmt.Println("Status:        INACTIVE (not a git repository)")
		fmt.Println("========================================")
		return
	}

	root, _ := git.FindGitRoot(absDir)
	branch := git.GetBranch(root)
	remote := git.GetRemote(root)
	commit := git.GetCommitHash(root)
	hookInstalled := git.IsHookInstalled(root)

	fmt.Printf("Repository:     %s\n", root)
	fmt.Printf("Git detected:   YES\n")
	if branch != "" {
		fmt.Printf("Branch:         %s\n", branch)
	}
	if remote != "" {
		fmt.Printf("Remote:         %s\n", remote)
	}
	if commit != "" {
		fmt.Printf("Commit:         %s\n", commit)
	}

	if hookInstalled {
		fmt.Println("Pre-push hook:  INSTALLED (.git/hooks/pre-push)")
		fmt.Println("VibeGuard Gate: ACTIVE")
	} else {
		fmt.Println("Pre-push hook:  NOT INSTALLED")
		fmt.Println("VibeGuard Gate: INACTIVE (run 'vibeguard init' to enable)")
	}

	// Configuration
	cfg, err := config.LoadConfig(root)
	if err == nil {
		fmt.Printf("Config policy:  Block on %s\n", strings.Join(cfg.BlockOn, ", "))
		fmt.Printf("Scan mode:      %s\n", cfg.ScanMode)
		fmt.Printf("Fail closed:    %v\n", cfg.FailClosed)
	}

	fmt.Println("========================================")
}

// handlePush: controlled interactive commit + scan + push workflow
func handlePush(dir string) int {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid directory: %v\n", err)
		return 2
	}

	if !git.IsGitRepo(absDir) {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not inside a Git repository.\n", absDir)
		return 2
	}

	root, _ := git.FindGitRoot(absDir)

	fmt.Println("========================================")
	fmt.Println("       VIBEGUARD SECURE PUSH")
	fmt.Println("========================================")
	fmt.Println()

	// 1. Check for staged / changed files
	changed := git.GetChangedFiles(root)
	hasStaged := git.HasStagedChanges(root)
	reader := bufio.NewReader(os.Stdin)

	if hasStaged {
		fmt.Println("Detected changes already staged in Git index.")
	} else if len(changed) == 0 {
		fmt.Println("No modified or staged files detected in repository.")
		return 0
	} else {
		fmt.Printf("Modified files (%d):\n", len(changed))
		maxShow := 5
		for i, f := range changed {
			if i < maxShow {
				fmt.Printf("  • %s\n", f)
			}
		}
		if len(changed) > maxShow {
			fmt.Printf("  ... and %d more file(s)\n", len(changed)-maxShow)
		}
		fmt.Println()

		fmt.Print("Stage these modified files for commit? [Y/n]: ")
		stageAns, _ := reader.ReadString('\n')
		stageAns = strings.TrimSpace(strings.ToLower(stageAns))
		if stageAns != "" && stageAns != "y" && stageAns != "yes" {
			fmt.Println("Aborted: files were not staged. Stage desired files manually with 'git add <file>'.")
			return 0
		}

		fmt.Println("Staging changes (git add .)...")
		if err := git.GitAdd(root); err != nil {
			fmt.Fprintf(os.Stderr, "git add failed: %v\n", err)
			return 2
		}
	}

	// 2. Prompt for commit message
	fmt.Print("Enter commit message: ")
	commitMsg, _ := reader.ReadString('\n')
	commitMsg = strings.TrimSpace(commitMsg)
	if commitMsg == "" {
		fmt.Fprintln(os.Stderr, "Aborted: commit message cannot be empty.")
		return 2
	}

	// 3. git commit -m <message>
	fmt.Println("Creating commit...")
	if err := git.GitCommit(root, commitMsg); err != nil {
		fmt.Fprintf(os.Stderr, "git commit failed: %v\n", err)
		return 2
	}

	// 5. Run full security scan using exact same push verification model
	fmt.Println()
	fmt.Println("Running VibeGuard security verification scan...")
	branch := git.GetBranch(root)
	commitHash := git.GetFullCommitHash(root)
	upstreamHash := git.GetUpstreamHash(root)
	explicitRefs := []git.PushRef{
		{
			LocalRef:  "refs/heads/" + branch,
			LocalSHA:  commitHash,
			RemoteRef: "refs/heads/" + branch,
			RemoteSHA: upstreamHash,
		},
	}
	exitCode := runScanWithRefs(root, "terminal", "", true, explicitRefs)
	if exitCode != 0 {
		fmt.Println()
		fmt.Println("========================================")
		fmt.Println("  STATUS: PUSH BLOCKED")
		fmt.Println("  Security findings detected.")
		fmt.Println("  Commit created locally, but will NOT be pushed.")
		fmt.Println("  Resolve findings and run 'git push' when ready.")
		fmt.Println("========================================")
		return 1
	}

	// 6. If PASS -> prompt "Push to GitHub? [Y/n]"
	fmt.Println()
	fmt.Println("Security scan PASSED. Code is SAFE to push.")
	fmt.Print("Push to GitHub? [Y/n]: ")
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))

	if ans == "" || ans == "y" || ans == "yes" {
		fmt.Println("Pushing to remote (git push --no-verify)...")
		if err := git.GitPushVerified(root); err != nil {
			fmt.Fprintf(os.Stderr, "git push failed: %v\n", err)
			return 2
		}
		fmt.Println("✓ Push to remote completed successfully!")
		return 0
	}

	fmt.Println("Push skipped by user. Local commit is preserved.")
	return 0
}

func determineOSVSeverity(v osv.Vulnerability) string {
	return osv.DetermineSeverity(v)
}



func runScan(projectPath string, format string, customOutput string, isHook bool) int {
	return runScanWithRefs(projectPath, format, customOutput, isHook, nil)
}

func runScanWithRefs(projectPath string, format string, customOutput string, isHook bool, explicitRefs []git.PushRef) int {
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid project path: %v\n", err)
		return 2
	}

	info, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Project path does not exist: %s\n", absPath)
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot access project path: %v\n", err)
		return 2
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Error: project path is not a directory: %s\n", absPath)
		return 2
	}

	// Load configuration
	cfg, err := config.LoadConfig(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration Error: %v\n", err)
		return 3
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration Error: %v\n", err)
		return 3
	}

	if git.IsGitRepo(absPath) && isHook {
		root, _ := git.FindGitRoot(absPath)
		pushedRefs := explicitRefs
		if len(pushedRefs) == 0 {
			pushedRefs, _ = git.ReadAllPushedRefs()
		}

		if len(pushedRefs) == 0 {
			fmt.Println("Git pre-push: everything up-to-date (no refs to push). Allowing push.")
			return 0
		}

		var activeRefs []git.PushRef
		for _, pr := range pushedRefs {
			if strings.Trim(pr.LocalSHA, "0") == "" {
				continue // branch deletion
			}
			if pr.LocalSHA == pr.RemoteSHA {
				continue // already up to date on remote
			}
			activeRefs = append(activeRefs, pr)
		}

		if len(activeRefs) == 0 {
			fmt.Println("Git pre-push: everything up-to-date (no new commits to push). Allowing push.")
			return 0
		}

		overallExitCode := 0
		failedCount := 0


		for idx, pRef := range activeRefs {
			if len(activeRefs) > 1 {
				fmt.Printf("\n========================================\n")
				fmt.Printf(" Verifying Pushed Ref [%d/%d]: %s\n", idx+1, len(activeRefs), pRef.RemoteRef)
				fmt.Printf("========================================\n")
			}

			code := scanSingleTarget(absPath, root, cfg, format, customOutput, true, &pRef)
			if code != 0 {
				overallExitCode = code
				failedCount++
			}
		}

		if len(activeRefs) > 1 {
			fmt.Println()
			fmt.Println("========================================")
			if overallExitCode == 0 {
				fmt.Printf("STATUS: ALL %d PUSHED REFS PASSED\n", len(activeRefs))
				fmt.Println("Continuing Git push...")
			} else {
				fmt.Printf("STATUS: PUSH BLOCKED (%d of %d refs failed security gate)\n", failedCount, len(activeRefs))
			}
			fmt.Println("========================================")
		}

		return overallExitCode
	}

	// Single target scan (CLI scan, report command, or working tree scan)
	return scanSingleTarget(absPath, absPath, cfg, format, customOutput, isHook, nil)
}

func scanSingleTarget(absPath string, root string, cfg *config.Config, format string, customOutput string, isHook bool, pRef *git.PushRef) int {
	projectName := filepath.Base(absPath)
	scanStart := time.Now()

	var commitHash, branchName, remoteURL string
	var pushedCommitDiff string
	var pushRange string
	var pushedFiles []string
	var filesInPushCount int
	var excludedFilesCount int
	targetScanPath := absPath
	var cleanupSnapshot func()

	if git.IsGitRepo(absPath) {
		commitHash = git.GetCommitHash(root)
		branchName = git.GetBranch(root)
		remoteName := git.GetRemoteName(root)
		remoteURL = git.GetRemoteURL(root, remoteName)

		if isHook && pRef != nil {
			commitHash = pRef.LocalSHA
			if len(commitHash) > 7 {
				commitHash = commitHash[:7]
			}
			if pRef.RemoteRef != "" {
				remoteURL = pRef.RemoteRef
			}

			locShort := pRef.LocalSHA
			if len(locShort) > 7 {
				locShort = locShort[:7]
			}
			remShort := pRef.RemoteSHA
			if len(remShort) > 7 {
				remShort = remShort[:7]
			}
			pushRange = fmt.Sprintf("%s -> %s", locShort, remShort)

			pushedFiles = git.GetPushedCommitFiles(root, pRef.RemoteSHA, pRef.LocalSHA)
			filesInPushCount = len(pushedFiles)
			for _, pf := range pushedFiles {
				if cfg.IsExcluded(pf) {
					excludedFilesCount++
				}
			}

			pushedCommitDiff = git.GetPushedCommitDiff(root, pRef.RemoteSHA, pRef.LocalSHA)

			// Create push snapshot of local commit so we scan the exact committed tree
			snapshotDir, err := git.CreatePushSnapshot(root, pRef.LocalSHA)
			if err == nil {
				targetScanPath = snapshotDir
				cleanupSnapshot = func() {
					os.RemoveAll(snapshotDir)
				}
				// Copy repo config to snapshot if absent
				snapCfgDir := filepath.Join(snapshotDir, ".vibeguard")
				_ = os.MkdirAll(snapCfgDir, 0755)
				cfgBytes, _ := os.ReadFile(config.ConfigPath(root))
				if len(cfgBytes) > 0 {
					_ = os.WriteFile(config.ConfigPath(snapshotDir), cfgBytes, 0644)
				}
			}
		}
	}
	if cleanupSnapshot != nil {
		defer cleanupSnapshot()
	}

	// Banner
	if isHook {
		fmt.Println("========================================")
		fmt.Println("       VIBEGUARD SECURITY GATE")
		fmt.Println("========================================")
		fmt.Printf("Project:        %s\n", projectName)
		if commitHash != "" {
			fmt.Printf("Commit:         %s\n", commitHash)
		}
		if branchName != "" {
			fmt.Printf("Branch:         %s\n", branchName)
		}
		if pushRange != "" {
			fmt.Printf("Push Range:     %s\n", pushRange)
		}
		if filesInPushCount > 0 {
			fmt.Printf("Files in Push:  %d (Excluded: %d)\n", filesInPushCount, excludedFilesCount)
		}
		fmt.Println()
	} else {
		fmt.Println("========================================")
		fmt.Println("       VIBEGUARD SECURITY SCANNER")
		fmt.Println("========================================")
		fmt.Printf("Project: %s\n", projectName)
		fmt.Printf("Path:    %s\n", absPath)
		if commitHash != "" {
			fmt.Printf("Commit:  %s\n", commitHash)
		}
		if branchName != "" {
			fmt.Printf("Branch:  %s\n", branchName)
		}
		fmt.Println()
	}

	// Step 1: Run security scanner
	fmt.Println("[1/4] Running security scanner...")
	pb := report.NewProgressBar(20, os.Stdout)
	scanResult, err := scanner.RunScannerWithProgress(targetScanPath, func(cur, tot int, curFile string) {
		pb.Render(cur, tot, fmt.Sprintf("Files: %d/%d", cur, tot), fmt.Sprintf("Current: %s", curFile))
	})
	pb.Reset()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Scanner error: %v\n", err)
		if cfg.FailClosed {
			fmt.Fprintln(os.Stderr, "Security policy failure: fail_closed is enabled.")
			return 2
		}
		scanResult = &scanner.ScanResult{
			Project:  projectName,
			Findings: []scanner.Finding{},
		}
	}
	for i := range scanResult.Findings {
		f := &scanResult.Findings[i]
		if rel, err := filepath.Rel(targetScanPath, f.File); err == nil && !strings.HasPrefix(rel, "..") {
			f.File = filepath.ToSlash(rel)
		}
	}
	fmt.Printf("  Files scanned: %d\n", scanResult.FilesScanned)
	fmt.Printf("  Findings from scanner: %d\n", len(scanResult.Findings))

	// Step 2: Detect and check dependencies
	var vulnResults []osv.VulnResult
	if cfg.DependencyScan {
		fmt.Println("[2/4] Checking dependencies...")
		deps, err := dependencies.DetectDependencies(targetScanPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Dependency detection error: %v\n", err)
			deps = []dependencies.Dependency{}
		}
		if len(deps) > 0 {
			for idx, d := range deps {
				pb.Render(idx+1, len(deps), fmt.Sprintf("Dependencies: %d/%d", idx+1, len(deps)), fmt.Sprintf("Current: %s@%s", d.Name, d.Version))
				time.Sleep(5 * time.Millisecond)
			}
			pb.Reset()
		}
		fmt.Printf("  Dependencies found: %d\n", len(deps))

		var osvDeps []osv.DependencyInfo
		for _, d := range deps {
			osvDeps = append(osvDeps, osv.DependencyInfo{
				Name:       d.Name,
				Version:    d.Version,
				Ecosystem:  d.Ecosystem,
				SourceFile: d.SourceFile,
			})
		}

		fmt.Println("[3/4] Querying vulnerability database (OSV)...")
		var osvErr error
		vulnResults, osvErr = osv.CheckAllDependenciesWithProgress(osvDeps, func(cur, tot int) {
			pb.Render(cur, tot, fmt.Sprintf("OSV queries: %d/%d", cur, tot), "")
		})
		pb.Reset()
		if osvErr != nil && len(osvDeps) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: OSV vulnerability database unavailable: %v\n", osvErr)
			if cfg.FailClosed {
				fmt.Fprintln(os.Stderr, "Security policy failure: OSV unavailable and fail_closed is enabled.")
				return 4
			}
		}

		totalVulns := 0
		for _, vr := range vulnResults {
			totalVulns += len(vr.Vulnerabilities)
		}
		if totalVulns > 0 {
			fmt.Printf("  Vulnerable packages: %d\n", len(vulnResults))
			fmt.Printf("  Total vulnerabilities: %d\n", totalVulns)
		} else {
			fmt.Println("  No known vulnerabilities found in dependencies")
		}
	} else {
		fmt.Println("[2/4] Skipping dependency checks (disabled in config)")
		fmt.Println("[3/4] Skipping OSV lookup")
	}

	// Combine findings
	allFindings := make([]scanner.Finding, len(scanResult.Findings))
	copy(allFindings, scanResult.Findings)

	// Scan pushed commit diff for secrets that exist in the commit history even if removed from working tree
	if pushedCommitDiff != "" && cfg.SecretScan {
		secretPatterns := []struct {
			name string
			re   *regexp.Regexp
		}{
			{"AWS Access Key in Pushed Commit", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
			{"Generic API Key in Pushed Commit", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}`)},
			{"Private Key in Pushed Commit", regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----`)},
			{"Password Assignment in Pushed Commit", regexp.MustCompile(`(?i)password\s*=\s*"[^"]+"`)},
		}

		diffLines := strings.Split(pushedCommitDiff, "\n")
		var currentFile string
		for _, dLine := range diffLines {
			if strings.HasPrefix(dLine, "diff --git a/") {
				rest := strings.TrimPrefix(dLine, "diff --git a/")
				if idx := strings.LastIndex(rest, " b/"); idx != -1 {
					currentFile = rest[:idx]
				} else {
					currentFile = rest
				}
				currentFile = strings.Trim(currentFile, "\"")
			}
			if currentFile != "" && cfg.IsExcluded(currentFile) {
				continue
			}
			if strings.HasPrefix(dLine, "+") && !strings.HasPrefix(dLine, "+++") {
				added := dLine[1:]
				for _, sp := range secretPatterns {
					if sp.name == "Password Assignment in Pushed Commit" {
						ext := strings.ToLower(filepath.Ext(currentFile))
						if ext == ".md" || ext == ".markdown" || ext == ".rst" || ext == ".txt" || ext == ".html" || ext == ".htm" || ext == ".adoc" {
							continue
						}
						lineLower := strings.ToLower(added)
						if strings.Contains(lineLower, `"admin"`) || strings.Contains(lineLower, `"password"`) || strings.Contains(lineLower, `""`) || strings.Contains(lineLower, `"..."`) || strings.Contains(lineLower, `read-host`) || strings.Contains(lineLower, `param(`) {
							continue
						}
					}
					if sp.re.MatchString(added) {
						masked := strings.TrimSpace(added)
						if len(masked) > 8 {
							masked = masked[:8] + "****"
						}
						allFindings = append(allFindings, scanner.Finding{
							ID:             fmt.Sprintf("VG-%03d", len(allFindings)+1),
							Category:       "secret",
							Severity:       "CRITICAL",
							Title:          sp.name,
							Description:    "Secret detected in the commit being pushed to remote.",
							File:           currentFile,
							Line:           0,
							Evidence:       masked,
							Recommendation: "Rewrite commit history to remove secret before pushing.",
							Confidence:     "HIGH",
						})
						break
					}
				}
			}
		}
	}

	depFindingCounter := len(allFindings) + 1
	for _, vr := range vulnResults {
		for _, v := range vr.Vulnerabilities {
			severity := determineOSVSeverity(v)

			desc := v.Summary
			if desc == "" {
				desc = v.Details
			}
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}

			fixedVersion := ""
			for _, aff := range v.Affected {
				for _, r := range aff.Ranges {
					for _, ev := range r.Events {
						if ev.Fixed != "" {
							fixedVersion = ev.Fixed
						}
					}
				}
			}

			relFile, _ := filepath.Rel(targetScanPath, vr.SourceFile)
			if relFile == "" || strings.HasPrefix(relFile, "..") {
				relFile, _ = filepath.Rel(absPath, vr.SourceFile)
				if relFile == "" {
					relFile = vr.SourceFile
				}
			}
			relFile = filepath.ToSlash(relFile)

			recommendation := fmt.Sprintf("Update %s from %s", vr.PackageName, vr.InstalledVersion)
			if fixedVersion != "" {
				recommendation += fmt.Sprintf(" to %s or later", fixedVersion)
			}

			evidence := fmt.Sprintf("Package: %s@%s, Advisory: %s", vr.PackageName, vr.InstalledVersion, v.ID)
			if len(v.Aliases) > 0 {
				evidence += fmt.Sprintf(" (%s)", strings.Join(v.Aliases, ", "))
			}

			finding := scanner.Finding{
				ID:             fmt.Sprintf("VG-%03d", depFindingCounter),
				Category:       "dependency",
				Severity:       severity,
				Title:          fmt.Sprintf("Vulnerable Dependency: %s", vr.PackageName),
				Description:    desc,
				File:           relFile,
				Line:           0,
				Evidence:       evidence,
				Recommendation: recommendation,
				Confidence:     "HIGH",
			}
			allFindings = append(allFindings, finding)
			depFindingCounter++
		}
	}

	// Filter findings to only changed files when scan_mode is "changed"
	if isHook && strings.ToLower(cfg.ScanMode) == "changed" {
		pushedMap := make(map[string]bool)
		for _, pf := range pushedFiles {
			pushedMap[filepath.ToSlash(filepath.Clean(pf))] = true
		}

		var filteredFindings []scanner.Finding
		for _, f := range allFindings {
			cleanF := filepath.ToSlash(filepath.Clean(f.File))
			if pushedMap[cleanF] {
				filteredFindings = append(filteredFindings, f)
			}
		}
		allFindings = filteredFindings
	}


	// Step 4: Calculate risk score
	fmt.Println("[4/4] Calculating risk score...")
	var findingInfos []risk.FindingInfo
	for _, f := range allFindings {
		findingInfos = append(findingInfos, risk.FindingInfo{
			Severity: f.Severity,
		})
	}
	scoreResult := risk.CalculateScore(findingInfos)

	// Final Stage: scan complete indicator
	pb.Finish("Security analysis complete.")

	// Evaluate deployment gate with config policy
	blockPolicy := []string{"critical", "high"}
	if isHook && cfg != nil && len(cfg.BlockOn) > 0 {
		blockPolicy = cfg.BlockOn
	}
	gateResult := gate.EvaluateGateWithPolicy(
		scoreResult.CriticalCount,
		scoreResult.HighCount,
		scoreResult.MediumCount,
		scoreResult.LowCount,
		blockPolicy,
	)

	// Count categories
	catCounts := report.CategoryCounts{}
	for _, f := range allFindings {
		switch strings.ToLower(f.Category) {
		case "secret":
			catCounts.Secrets++
		case "sourcecode":
			catCounts.SourceCode++
		case "dependency":
			catCounts.Dependencies++
		case "configuration":
			catCounts.Configuration++
		case "docker":
			catCounts.Docker++
		case "git":
			catCounts.Git++
		}
	}

	scanDuration := time.Since(scanStart)

	// Build the report
	r := &report.Report{
		ProjectName:    projectName,
		CommitHash:     commitHash,
		Branch:         branchName,
		Remote:         remoteURL,
		ScanTime:       scanDuration.Round(time.Millisecond).String(),
		FilesScanned:   scanResult.FilesScanned,
		Findings:       allFindings,
		Dependencies:   vulnResults,
		ScoreResult:    scoreResult,
		GateResult:     gateResult,
		CategoryCounts: catCounts,
	}

	fmt.Println()

	reportsDir := "reports"
	_ = os.MkdirAll(reportsDir, 0755)

	switch strings.ToLower(format) {
	case "json":
		jsonPath := customOutput
		if jsonPath == "" {
			jsonPath = filepath.Join(reportsDir, "scan.json")
		}
		if err := report.WriteJSONReport(r, jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON report: %v\n", err)
			return 2
		}
		fmt.Printf("JSON report saved to: %s\n", jsonPath)
		report.PrintTerminalReport(r)

	case "html":
		htmlPath := customOutput
		if htmlPath == "" {
			htmlPath = filepath.Join(reportsDir, "scan.html")
		}
		if err := report.WriteHTMLReport(r, htmlPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
			return 2
		}
		fmt.Printf("HTML report saved to: %s\n", htmlPath)
		report.PrintTerminalReport(r)

	default:
		report.PrintTerminalReport(r)
	}

	if isHook {
		fmt.Println("---------------------------------------------")
		if gateResult.Status == "PASSED" {
			fmt.Println("STATUS: SAFE TO PUSH")
			fmt.Println("Continuing Git push...")
		} else {
			fmt.Println("STATUS: PUSH BLOCKED")
			fmt.Printf("Reason: %s\n", gateResult.Reason)
			fmt.Println("Resolve the findings above before pushing.")
		}
		fmt.Println("========================================")
	}

	return gateResult.ExitCode
}

`

---
## go.mod

`
module github.com/vibeguard/vibeguard

go 1.21

`

---
## install_hook.bat

`
@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Git Pre-Push Hook Installer (install_hook.bat)
:: ============================================================

set "ROOT=%~dp0"
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

`

---
## internal/config/config.go

`
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config represents VibeGuard's project-level configuration stored in .vibeguard/config.json
type Config struct {
	BlockOn        []string `json:"block_on"`        // ["critical", "high"]
	ScanMode       string   `json:"scan_mode"`       // "full" or "changed"
	DependencyScan bool     `json:"dependency_scan"`
	SecretScan     bool     `json:"secret_scan"`
	SourceScan     bool     `json:"source_scan"`
	ReportFormat   string   `json:"report_format"`   // "terminal", "json", "html"
	FailClosed     bool     `json:"fail_closed"`     // block on scanner failure
	Exclude        []string `json:"exclude"`         // files/directories to exclude
}

// DefaultConfig returns sensible default security configuration.
func DefaultConfig() *Config {
	return &Config{
		BlockOn:        []string{"critical", "high"},
		ScanMode:       "full",
		DependencyScan: true,
		SecretScan:     true,
		SourceScan:     true,
		ReportFormat:   "terminal",
		FailClosed:     true,
		Exclude: []string{
			".git",
			".vibeguard",
			"reports",
			"md files",
			"tests",
			"code.md",
			"finalreport.md",
			"output.md",
			"output2.md",
			"test output.md",
			"test3.md",
			"test4.md",
			"test5.md",
			"NEW_LAPTOP_SETUP.md",
			"rules",
		},
	}
}

// IsExcluded evaluates whether relPath matches any configured exclusion pattern.
func (c *Config) IsExcluded(relPath string) bool {
	if relPath == "" || relPath == "." {
		return false
	}

	cleanPath := filepath.ToSlash(filepath.Clean(relPath))
	cleanPath = strings.TrimPrefix(cleanPath, "./")
	cleanPath = strings.TrimPrefix(cleanPath, "/")

	for _, pattern := range c.Exclude {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		cleanPattern := filepath.ToSlash(filepath.Clean(pattern))
		cleanPattern = strings.TrimPrefix(cleanPattern, "./")
		cleanPattern = strings.TrimPrefix(cleanPattern, "/")

		// 1. Exact match
		if cleanPath == cleanPattern {
			return true
		}

		// 2. Directory subtree match (e.g. "tests" matches "tests/sast/vulnerable.go")
		if strings.HasPrefix(cleanPath, cleanPattern+"/") {
			return true
		}

		// 3. Basename match for exact filenames (e.g. "code.md" matches "code.md")
		if filepath.Base(cleanPath) == cleanPattern {
			return true
		}
	}

	return false
}

// Validate ensures configuration values are compliant with supported options.
func (c *Config) Validate() error {
	mode := strings.ToLower(strings.TrimSpace(c.ScanMode))
	if mode != "full" && mode != "changed" {
		return fmt.Errorf("invalid scan_mode '%s': must be 'full' or 'changed'", c.ScanMode)
	}

	fmtLower := strings.ToLower(strings.TrimSpace(c.ReportFormat))
	if fmtLower != "terminal" && fmtLower != "json" && fmtLower != "html" {
		return fmt.Errorf("invalid report_format '%s': must be 'terminal', 'json', or 'html'", c.ReportFormat)
	}

	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	for _, b := range c.BlockOn {
		b = strings.ToLower(strings.TrimSpace(b))
		if !validSeverities[b] {
			return fmt.Errorf("invalid severity in block_on '%s'", b)
		}
	}

	for _, exc := range c.Exclude {
		if strings.TrimSpace(exc) == "" {
			return fmt.Errorf("exclude contains empty pattern")
		}
	}

	return nil
}

// ConfigDir returns the path to the .vibeguard directory.
func ConfigDir(projectPath string) string {
	return filepath.Join(projectPath, ".vibeguard")
}

// ConfigPath returns the path to .vibeguard/config.json.
func ConfigPath(projectPath string) string {
	return filepath.Join(ConfigDir(projectPath), "config.json")
}

// LoadConfig reads .vibeguard/config.json, falling back to defaults if not found.
func LoadConfig(projectPath string) (*Config, error) {
	cfgFile := ConfigPath(projectPath)
	data, err := os.ReadFile(cfgFile)
	if os.IsNotExist(err) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("malformed configuration file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// CreateDefaultConfig writes the default configuration file to .vibeguard/config.json.
func CreateDefaultConfig(projectPath string) error {
	dir := ConfigDir(projectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(DefaultConfig(), "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(projectPath), data, 0644)
}

// SaveConfig writes a specific configuration to .vibeguard/config.json.
func SaveConfig(projectPath string, cfg *Config) error {
	dir := ConfigDir(projectPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(projectPath), data, 0644)
}

`

---
## internal/config/config_test.go

`
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.BlockOn) != 2 {
		t.Fatalf("expected 2 block_on items, got %d", len(cfg.BlockOn))
	}
	if !cfg.DependencyScan || !cfg.SecretScan || !cfg.SourceScan {
		t.Errorf("expected all scan modules enabled by default")
	}
	if !cfg.FailClosed {
		t.Errorf("expected fail_closed to be true by default")
	}
	if cfg.ScanMode != "full" {
		t.Errorf("expected scan_mode 'full', got %s", cfg.ScanMode)
	}
}

func TestCreateDefaultConfigAndLoad(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeguard_config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create default config file
	if err := CreateDefaultConfig(tempDir); err != nil {
		t.Fatalf("CreateDefaultConfig failed: %v", err)
	}

	// Verify file existence
	cfgFile := filepath.Join(tempDir, ".vibeguard", "config.json")
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		t.Fatalf("expected %s to exist", cfgFile)
	}

	// Load config
	loaded, err := LoadConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !loaded.FailClosed {
		t.Errorf("expected loaded fail_closed to be true")
	}
	if loaded.ScanMode != "full" {
		t.Errorf("expected scan_mode 'full', got %s", loaded.ScanMode)
	}
	if len(loaded.Exclude) == 0 {
		t.Errorf("expected default exclusions to be loaded")
	}
}

func TestIsExcluded(t *testing.T) {
	cfg := DefaultConfig()

	tests := []struct {
		path     string
		expected bool
	}{
		{"tests/sast/vulnerable.go", true},
		{"md files/README.md", true},
		{"code.md", true},
		{"finalreport.md", true},
		{"reports/audit.json", true},
		{".git/config", true},
		{".vibeguard/config.json", true},
		{"output.md", true},
		{"output2.md", true},
		{"test output.md", true},
		{"test3.md", true},
		{"test4.md", true},
		{"test5.md", true},
		{"NEW_LAPTOP_SETUP.md", true},
		{"rules/README.md", true},
		{"test-project/main.go", false},
		{"src/main.rs", false},
		{"internal/scanner/runner.go", false},
		{"cmd/vibeguard/main.go", false},
		{".", false},
		{"", false},
	}

	for _, tt := range tests {
		result := cfg.IsExcluded(tt.path)
		if result != tt.expected {
			t.Errorf("IsExcluded(%q) = %v; want %v", tt.path, result, tt.expected)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig failed validation: %v", err)
	}

	// Invalid scan_mode
	badMode := DefaultConfig()
	badMode.ScanMode = "invalid"
	if err := badMode.Validate(); err == nil {
		t.Errorf("expected error for invalid scan_mode")
	}

	// Invalid report_format
	badFmt := DefaultConfig()
	badFmt.ReportFormat = "xml"
	if err := badFmt.Validate(); err == nil {
		t.Errorf("expected error for invalid report_format")
	}

	// Invalid block_on
	badBlock := DefaultConfig()
	badBlock.BlockOn = []string{"critical", "super_bad"}
	if err := badBlock.Validate(); err == nil {
		t.Errorf("expected error for invalid block_on severity")
	}

	// Empty pattern in exclude
	badExclude := DefaultConfig()
	badExclude.Exclude = []string{""}
	if err := badExclude.Validate(); err == nil {
		t.Errorf("expected error for empty pattern in exclude list")
	}
}


`

---
## internal/dependencies/detector.go

`
package dependencies

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vibeguard/vibeguard/internal/config"
)

type Dependency struct {
	Name       string
	Version    string
	Ecosystem  string
	SourceFile string
}

func DetectDependencies(projectPath string) ([]Dependency, error) {
	var deps []Dependency

	cfg, _ := config.LoadConfig(projectPath)
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(projectPath, path)
		if relPath == "" || relPath == "." {
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "vendor" || cfg.IsExcluded(relPath) {
				return filepath.SkipDir
			}
			return nil
		}

		if cfg.IsExcluded(relPath) {
			return nil
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		content := string(contentBytes)

		var fileDeps []Dependency
		switch d.Name() {
		case "go.mod":
			fileDeps = ParseGoMod(content, path)
		case "package-lock.json":
			fileDeps = ParsePackageLockJSON(content, path)
		case "package.json":
			// If package-lock.json exists in same dir, prefer the lockfile for exact installed versions
			lockFile := filepath.Join(filepath.Dir(path), "package-lock.json")
			if _, err := os.Stat(lockFile); os.IsNotExist(err) {
				fileDeps = ParsePackageJSON(content, path)
			}
		case "requirements.txt":
			fileDeps = ParseRequirementsTxt(content, path)
		case "Cargo.lock":
			fileDeps = ParseCargoLock(content, path)
		case "Cargo.toml":
			// If Cargo.lock exists in same dir, prefer the lockfile
			lockFile := filepath.Join(filepath.Dir(path), "Cargo.lock")
			if _, err := os.Stat(lockFile); os.IsNotExist(err) {
				fileDeps = ParseCargoToml(content, path)
			}
		}
		deps = append(deps, fileDeps...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return deps, nil
}

`

---
## internal/dependencies/parser.go

`
package dependencies

import (
	"encoding/json"
	"regexp"
	"strings"
)

func ParseGoMod(content string, sourceFile string) []Dependency {
	var deps []Dependency
	re := regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9.\-_/]+)\s+(v[a-zA-Z0-9.\-_+]+)(?:\s+//.*)?$`)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) == 3 && match[1] != "module" && match[1] != "go" {
			deps = append(deps, Dependency{
				Name:       match[1],
				Version:    match[2],
				Ecosystem:  "Go",
				SourceFile: sourceFile,
			})
		}
	}
	return deps
}

func ParsePackageJSON(content string, sourceFile string) []Dependency {
	var deps []Dependency
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return deps
	}

	addDeps := func(m map[string]string) {
		for name, version := range m {
			version = strings.TrimPrefix(version, "^")
			version = strings.TrimPrefix(version, "~")
			version = strings.TrimPrefix(version, ">=")
			version = strings.TrimSpace(version)
			deps = append(deps, Dependency{
				Name:       name,
				Version:    version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}
	addDeps(pkg.Dependencies)
	addDeps(pkg.DevDependencies)
	return deps
}

func ParseRequirementsTxt(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	re := regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)(?:==|>=)(.*)$`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    strings.TrimSpace(matches[2]),
				Ecosystem:  "PyPI",
				SourceFile: sourceFile,
			})
		} else {
			name := strings.Split(line, " ")[0]
			name = strings.Split(name, "=")[0]
			name = strings.Split(name, "<")[0]
			name = strings.Split(name, ">")[0]
			if name != "" && !strings.HasPrefix(name, "-") {
				deps = append(deps, Dependency{
					Name:       name,
					Version:    "unknown",
					Ecosystem:  "PyPI",
					SourceFile: sourceFile,
				})
			}
		}
	}
	return deps
}

func ParseCargoToml(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	inDeps := false
	re1 := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)\s*=\s*"([^"]+)"`)
	re2 := regexp.MustCompile(`^([a-zA-Z0-9\-_]+)\s*=\s*\{.*version\s*=\s*"([^"]+)".*}`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDeps = strings.Contains(line, "dependencies")
			continue
		}
		if !inDeps || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if matches := re1.FindStringSubmatch(line); len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    matches[2],
				Ecosystem:  "crates.io",
				SourceFile: sourceFile,
			})
		} else if matches := re2.FindStringSubmatch(line); len(matches) == 3 {
			deps = append(deps, Dependency{
				Name:       matches[1],
				Version:    matches[2],
				Ecosystem:  "crates.io",
				SourceFile: sourceFile,
			})
		}
	}
	return deps
}

// ParsePackageLockJSON parses npm package-lock.json for exact installed dependency versions.
func ParsePackageLockJSON(content string, sourceFile string) []Dependency {
	var deps []Dependency
	var lock struct {
		Packages     map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(content), &lock); err != nil {
		return deps
	}

	seen := make(map[string]bool)
	// Check npm v2/v3 packages object
	for pkgPath, info := range lock.Packages {
		if info.Version == "" {
			continue
		}
		name := strings.TrimPrefix(pkgPath, "node_modules/")
		if name != "" && name != pkgPath && !seen[name] {
			seen[name] = true
			deps = append(deps, Dependency{
				Name:       name,
				Version:    info.Version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}

	// Check npm v1 dependencies object
	for name, info := range lock.Dependencies {
		if info.Version != "" && !seen[name] {
			seen[name] = true
			deps = append(deps, Dependency{
				Name:       name,
				Version:    info.Version,
				Ecosystem:  "npm",
				SourceFile: sourceFile,
			})
		}
	}

	return deps
}

// ParseGoSum extracts dependency versions from go.sum.
func ParseGoSum(content string, sourceFile string) []Dependency {
	var deps []Dependency
	seen := make(map[string]bool)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			pkg := parts[0]
			ver := strings.TrimSuffix(parts[1], "/go.mod")
			key := pkg + "@" + ver
			if !seen[key] {
				seen[key] = true
				deps = append(deps, Dependency{
					Name:       pkg,
					Version:    ver,
					Ecosystem:  "Go",
					SourceFile: sourceFile,
				})
			}
		}
	}
	return deps
}

// ParseCargoLock parses Cargo.lock for exact locked crate versions.
func ParseCargoLock(content string, sourceFile string) []Dependency {
	var deps []Dependency
	lines := strings.Split(content, "\n")
	var currName, currVersion string
	inPackage := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if inPackage && currName != "" && currVersion != "" {
				deps = append(deps, Dependency{
					Name:       currName,
					Version:    currVersion,
					Ecosystem:  "crates.io",
					SourceFile: sourceFile,
				})
			}
			inPackage = true
			currName = ""
			currVersion = ""
			continue
		}
		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				currName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
			} else if strings.HasPrefix(line, "version = ") {
				currVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
			}
		}
	}
	if inPackage && currName != "" && currVersion != "" {
		deps = append(deps, Dependency{
			Name:       currName,
			Version:    currVersion,
			Ecosystem:  "crates.io",
			SourceFile: sourceFile,
		})
	}
	return deps
}

`

---
## internal/dependencies/parser_test.go

`
package dependencies

import (
	"testing"
)

func TestParseGoMod(t *testing.T) {
	content := `module example.com/app

go 1.21

require (
	golang.org/x/crypto v0.1.0
	github.com/gin-gonic/gin v1.9.0 // indirect
)
`
	deps := ParseGoMod(content, "go.mod")
	if len(deps) < 2 {
		t.Fatalf("expected at least 2 dependencies, got %d", len(deps))
	}

	foundCrypto := false
	for _, d := range deps {
		if d.Name == "golang.org/x/crypto" && d.Version == "v0.1.0" && d.Ecosystem == "Go" {
			foundCrypto = true
		}
	}
	if !foundCrypto {
		t.Errorf("expected to find golang.org/x/crypto v0.1.0")
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := `{
  "dependencies": {
    "lodash": "^4.17.20",
    "express": "~4.17.1"
  },
  "devDependencies": {
    "jest": "26.6.3"
  }
}`
	deps := ParsePackageJSON(content, "package.json")
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	foundLodash := false
	for _, d := range deps {
		if d.Name == "lodash" && d.Version == "4.17.20" && d.Ecosystem == "npm" {
			foundLodash = true
		}
	}
	if !foundLodash {
		t.Errorf("expected to find sanitized lodash 4.17.20")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := `
# Comment
Flask==2.0.1
requests>=2.25.1
django==3.2.0
`
	deps := ParseRequirementsTxt(content, "requirements.txt")
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	foundFlask := false
	for _, d := range deps {
		if d.Name == "Flask" && d.Version == "2.0.1" && d.Ecosystem == "PyPI" {
			foundFlask = true
		}
	}
	if !foundFlask {
		t.Errorf("expected to find Flask 2.0.1")
	}
}

func TestParseCargoToml(t *testing.T) {
	content := `[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0.104"
tokio = { version = "1.0", features = ["full"] }
`
	deps := ParseCargoToml(content, "Cargo.toml")
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	foundSerde := false
	for _, d := range deps {
		if d.Name == "serde" && d.Version == "1.0.104" && d.Ecosystem == "crates.io" {
			foundSerde = true
		}
	}
	if !foundSerde {
		t.Errorf("expected to find serde 1.0.104")
	}
}

func TestDetectDependenciesExclusions(t *testing.T) {
	root := "../../"
	deps, err := DetectDependencies(root)
	if err != nil {
		t.Fatalf("DetectDependencies failed: %v", err)
	}

	for _, d := range deps {
		cleanSource := d.SourceFile
		if cleanSource != "" && (containsSubstr(cleanSource, "tests/dependencies") || containsSubstr(cleanSource, "tests\\dependencies")) {
			t.Errorf("dependency from excluded tests/ was detected: %s (%s)", d.Name, d.SourceFile)
		}
	}
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}


`

---
## internal/gate/gate.go

`
package gate

import (
	"fmt"
	"strings"
)

type GateResult struct {
	Status   string // "PASSED" or "BLOCKED"
	ExitCode int
	Reason   string
}

// EvaluateGate evaluates deployment status blocking on critical and high severity findings.
func EvaluateGate(criticalCount, highCount int) GateResult {
	return EvaluateGateWithPolicy(criticalCount, highCount, 0, 0, []string{"critical", "high"})
}

// EvaluateGateWithPolicy evaluates deployment status against configured blocking levels.
func EvaluateGateWithPolicy(criticalCount, highCount, mediumCount, lowCount int, blockOn []string) GateResult {
	blockMap := make(map[string]bool)
	for _, b := range blockOn {
		blockMap[strings.ToLower(strings.TrimSpace(b))] = true
	}
	if len(blockMap) == 0 {
		blockMap["critical"] = true
		blockMap["high"] = true
	}

	var blockingReasons []string
	if blockMap["critical"] && criticalCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d critical finding(s)", criticalCount))
	}
	if blockMap["high"] && highCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d high-severity finding(s)", highCount))
	}
	if blockMap["medium"] && mediumCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d medium-severity finding(s)", mediumCount))
	}
	if blockMap["low"] && lowCount > 0 {
		blockingReasons = append(blockingReasons, fmt.Sprintf("%d low-severity finding(s)", lowCount))
	}

	if len(blockingReasons) > 0 {
		return GateResult{
			Status:   "BLOCKED",
			ExitCode: 1,
			Reason:   strings.Join(blockingReasons, " and ") + " detected",
		}
	}

	return GateResult{
		Status:   "PASSED",
		ExitCode: 0,
		Reason:   "No blocking security findings",
	}
}

`

---
## internal/gate/gate_test.go

`
package gate

import (
	"testing"
)

func TestEvaluateGate(t *testing.T) {
	tests := []struct {
		name         string
		critical     int
		high         int
		expectedStat string
		expectedCode int
	}{
		{
			name:         "High findings only -> BLOCKED",
			critical:     0,
			high:         5,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "One critical finding -> BLOCKED",
			critical:     1,
			high:         0,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "Multiple critical findings -> BLOCKED",
			critical:     4,
			high:         3,
			expectedStat: "BLOCKED",
			expectedCode: 1,
		},
		{
			name:         "Clean scan -> PASSED",
			critical:     0,
			high:         0,
			expectedStat: "PASSED",
			expectedCode: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := EvaluateGate(tc.critical, tc.high)
			if res.Status != tc.expectedStat {
				t.Errorf("expected status %s, got %s", tc.expectedStat, res.Status)
			}
			if res.ExitCode != tc.expectedCode {
				t.Errorf("expected exit code %d, got %d", tc.expectedCode, res.ExitCode)
			}
		})
	}
}

func TestEvaluateGateWithPolicy(t *testing.T) {
	// Only block on critical: high should pass
	res := EvaluateGateWithPolicy(0, 5, 2, 1, []string{"critical"})
	if res.Status != "PASSED" || res.ExitCode != 0 {
		t.Errorf("expected PASSED when blocking only on critical, got %s", res.Status)
	}

	// Block on medium: 1 medium should block
	res = EvaluateGateWithPolicy(0, 0, 1, 0, []string{"critical", "high", "medium"})
	if res.Status != "BLOCKED" || res.ExitCode != 1 {
		t.Errorf("expected BLOCKED when blocking on medium, got %s", res.Status)
	}
}

`

---
## internal/git/hooks.go

`
package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	HookMarker   = "# VibeGuard Security Gate — Do not edit this section"
	UserHookFile = "pre-push.user"
)

// HookScriptContent generates the shell script for .git/hooks/pre-push.
func HookScriptContent() string {
	return `#!/bin/sh
` + HookMarker + `

# 1. Run preserved user hook first if present
HOOK_DIR=$(dirname "$0")
if [ -f "$HOOK_DIR/` + UserHookFile + `" ]; then
    "$HOOK_DIR/` + UserHookFile + `" "$@"
    USER_EXIT=$?
    if [ $USER_EXIT -ne 0 ]; then
        exit $USER_EXIT
    fi
fi

# 2. Resolve repository root
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$REPO_ROOT" ]; then
    REPO_ROOT=$(pwd)
fi

# 3. Locate trusted VibeGuard binary (prioritizes global install over repo-local)
VIBEGUARD_BIN=""
if [ -n "$LOCALAPPDATA" ] && [ -f "$LOCALAPPDATA/VibeGuard/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$LOCALAPPDATA/VibeGuard/vibeguard.exe"
elif [ -n "$LOCALAPPDATA" ] && [ -f "$LOCALAPPDATA/VibeGuard/bin/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$LOCALAPPDATA/VibeGuard/bin/vibeguard.exe"
elif [ -n "$USERPROFILE" ] && [ -f "$USERPROFILE/AppData/Local/VibeGuard/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$USERPROFILE/AppData/Local/VibeGuard/vibeguard.exe"
elif command -v vibeguard.exe >/dev/null 2>&1; then
    VIBEGUARD_BIN="vibeguard.exe"
elif command -v vibeguard >/dev/null 2>&1; then
    VIBEGUARD_BIN="vibeguard"
elif [ -f "$REPO_ROOT/vibeguard.exe" ]; then
    VIBEGUARD_BIN="$REPO_ROOT/vibeguard.exe"
elif [ -f "$REPO_ROOT/vibeguard" ]; then
    VIBEGUARD_BIN="$REPO_ROOT/vibeguard"
fi

if [ -z "$VIBEGUARD_BIN" ]; then
    echo "========================================"
    echo "  VIBEGUARD SECURITY GATE: BLOCKED"
    echo "========================================"
    echo "Error: VibeGuard executable not found in %LOCALAPPDATA%\\VibeGuard, repository, or PATH."
    echo "Security policy: fail_closed is enforced. Push blocked."
    echo "Run setup.bat or ensure vibeguard is on your PATH before pushing."
    exit 1
fi

# 4. Run VibeGuard security verification gate
"$VIBEGUARD_BIN" scan "$REPO_ROOT" --hook
exit $?
`
}

// IsHookInstalled checks if the pre-push hook is installed with VibeGuard marker.
func IsHookInstalled(repoPath string) bool {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return false
	}

	hookPath := filepath.Join(root, ".git", "hooks", "pre-push")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		return false
	}

	return strings.Contains(string(content), HookMarker)
}

// InstallHook installs the pre-push hook, preserving any existing non-VibeGuard hook as pre-push.user.
func InstallHook(repoPath string) error {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return err
	}

	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-push")
	userBackupPath := filepath.Join(hooksDir, UserHookFile)

	// If hook exists
	if existingData, err := os.ReadFile(hookPath); err == nil {
		existingStr := string(existingData)
		if strings.Contains(existingStr, HookMarker) {
			// Already our hook, overwrite with latest version
			return os.WriteFile(hookPath, []byte(HookScriptContent()), 0755)
		}

		// Existing user hook found: back it up to pre-push.user
		if err := os.WriteFile(userBackupPath, existingData, 0755); err != nil {
			return fmt.Errorf("failed to backup existing user hook: %w", err)
		}
	}

	return os.WriteFile(hookPath, []byte(HookScriptContent()), 0755)
}

// UninstallHook removes the VibeGuard pre-push hook and restores user backup if present.
func UninstallHook(repoPath string) error {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return err
	}

	hooksDir := filepath.Join(root, ".git", "hooks")
	hookPath := filepath.Join(hooksDir, "pre-push")
	userBackupPath := filepath.Join(hooksDir, UserHookFile)

	data, err := os.ReadFile(hookPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// Verify it's a VibeGuard hook before deleting
	if !strings.Contains(string(data), HookMarker) {
		return fmt.Errorf("pre-push hook does not appear to be managed by VibeGuard")
	}

	// Remove hook
	if err := os.Remove(hookPath); err != nil {
		return err
	}

	// Restore backup if exists
	if _, err := os.Stat(userBackupPath); err == nil {
		return os.Rename(userBackupPath, hookPath)
	}

	return nil
}

`

---
## internal/git/hooks_test.go

`
package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookInstallUninstallAndPreserve(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	// Initially not installed
	if IsHookInstalled(repo) {
		t.Errorf("expected hook to not be installed initially")
	}

	// Install hook
	if err := InstallHook(repo); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	if !IsHookInstalled(repo) {
		t.Errorf("expected hook to be reported as installed")
	}

	hookPath := filepath.Join(repo, ".git", "hooks", "pre-push")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read hook script: %v", err)
	}
	if !strings.Contains(string(content), HookMarker) {
		t.Errorf("hook script does not contain HookMarker")
	}

	// Uninstall hook
	if err := UninstallHook(repo); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	if IsHookInstalled(repo) {
		t.Errorf("expected hook to be uninstalled")
	}
}

func TestPreserveUserHook(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	hooksDir := filepath.Join(repo, ".git", "hooks")
	os.MkdirAll(hooksDir, 0755)
	hookPath := filepath.Join(hooksDir, "pre-push")
	userScript := "#!/bin/sh\necho 'custom user hook running'\nexit 0\n"
	if err := os.WriteFile(hookPath, []byte(userScript), 0755); err != nil {
		t.Fatalf("failed to create user hook: %v", err)
	}

	// Install VibeGuard hook
	if err := InstallHook(repo); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	// Verify backup was created
	backupPath := filepath.Join(hooksDir, UserHookFile)
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed to read user hook backup: %v", err)
	}
	if string(backupData) != userScript {
		t.Errorf("backup content mismatch: got %q, want %q", string(backupData), userScript)
	}

	// Verify wrapper runs backup
	wrapperData, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read wrapper hook: %v", err)
	}
	if !strings.Contains(string(wrapperData), UserHookFile) {
		t.Errorf("wrapper hook does not reference %s", UserHookFile)
	}

	// Uninstall should restore original hook
	if err := UninstallHook(repo); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	restoredData, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read restored hook: %v", err)
	}
	if string(restoredData) != userScript {
		t.Errorf("restored hook mismatch: got %q, want %q", string(restoredData), userScript)
	}
}

`

---
## internal/git/repo.go

`
package git

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FindGitRoot locates the root of the Git repository by walking upwards.
func FindGitRoot(startDir string) (string, error) {
	curr, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}

	for {
		gitDir := filepath.Join(curr, ".git")
		if fi, err := os.Stat(gitDir); err == nil && (fi.IsDir() || !fi.IsDir()) {
			return curr, nil
		}

		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}

	return "", fmt.Errorf("not a git repository (or any of the parent directories)")
}

// IsGitRepo checks if the specified path contains a .git directory.
func IsGitRepo(path string) bool {
	gitDir := filepath.Join(path, ".git")
	fi, err := os.Stat(gitDir)
	return err == nil && (fi.IsDir() || !fi.IsDir())
}

// GetBranch returns the current active Git branch name.
func GetBranch(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetRemoteName returns the name of the first git remote (usually "origin").
func GetRemoteName(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "remote")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 && lines[0] != "" {
		return strings.TrimSpace(lines[0])
	}
	return "origin"
}

// GetRemoteURL returns the URL of the specified remote (defaults to origin).
func GetRemoteURL(path, remoteName string) string {
	if remoteName == "" {
		remoteName = "origin"
	}
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "remote", "get-url", remoteName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetRemote returns the remote URL for origin.
func GetRemote(path string) string {
	return GetRemoteURL(path, "origin")
}

// GetCommitHash returns the short commit hash of HEAD.
func GetCommitHash(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "--short", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetFullCommitHash returns the full commit hash of HEAD.
func GetFullCommitHash(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetUpstreamHash returns the commit hash of the upstream branch (@{u}).
func GetUpstreamHash(path string) string {
	root, err := FindGitRoot(path)
	if err != nil {
		return ""
	}
	out, err := runGit(root, "rev-parse", "@{u}")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetChangedFiles returns a list of files pending push or currently modified.
func GetChangedFiles(path string) []string {
	root, err := FindGitRoot(path)
	if err != nil {
		return nil
	}

	fileMap := make(map[string]bool)
	var files []string

	// 1. Files modified vs HEAD (staged or unstaged)
	if out, err := runGit(root, "diff", "--name-only", "HEAD"); err == nil && strings.TrimSpace(out) != "" {
		for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
			f = strings.TrimSpace(f)
			if f != "" && !fileMap[f] {
				fileMap[f] = true
				files = append(files, f)
			}
		}
	}

	// 2. Untracked or newly staged files from status
	if out, err := runGit(root, "status", "--porcelain"); err == nil && strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(line)
			if len(line) > 3 {
				f := strings.TrimSpace(line[3:])
				if parts := strings.Split(f, " -> "); len(parts) == 2 {
					f = parts[1]
				}
				if f != "" && !fileMap[f] {
					fileMap[f] = true
					files = append(files, f)
				}
			}
		}
	}

	// 3. Commits pending push vs upstream
	if out, err := runGit(root, "diff", "--name-only", "@{u}..HEAD"); err == nil && strings.TrimSpace(out) != "" {
		for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
			f = strings.TrimSpace(f)
			if f != "" && !fileMap[f] {
				fileMap[f] = true
				files = append(files, f)
			}
		}
	}

	return files
}

// HasStagedChanges checks if there are uncommitted staged changes in git index.
func HasStagedChanges(path string) bool {
	root, err := FindGitRoot(path)
	if err != nil {
		return false
	}
	// git diff --cached --quiet exits with 1 if there are staged changes, 0 if clean
	cmd := exec.Command("git", "diff", "--cached", "--quiet")
	cmd.Dir = root
	err = cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			return true
		}
	}
	return false
}

// GitAdd stages all changes (`git add .`).
func GitAdd(path string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	_, err = runGit(root, "add", ".")
	return err
}

// GitCommit creates a commit with the specified message (`git commit -m <message>`).
func GitCommit(path string, message string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	_, err = runGit(root, "commit", "-m", message)
	return err
}

// GitPush executes `git push`.
func GitPush(path string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "push")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// GitPushVerified executes `git push --no-verify` after VibeGuard has already completed full verification.
func GitPushVerified(path string) error {
	root, err := FindGitRoot(path)
	if err != nil {
		return err
	}
	cmd := exec.Command("git", "push", "--no-verify")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Helper to run git commands and capture stdout
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%v: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// PushRef represents a Git ref update passed via stdin to a pre-push hook.
type PushRef struct {
	LocalRef  string
	LocalSHA  string
	RemoteRef string
	RemoteSHA string
}

// ReadPrePushRefs reads standard Git pre-push ref update tuples from an io.Reader.
func ReadPrePushRefs(r io.Reader) ([]PushRef, error) {
	var refs []PushRef
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			refs = append(refs, PushRef{
				LocalRef:  parts[0],
				LocalSHA:  parts[1],
				RemoteRef: parts[2],
				RemoteSHA: parts[3],
			})
		}
	}
	return refs, scanner.Err()
}

// ReadAllPushedRefs reads standard Git pre-push ref update tuples from stdin if present.
func ReadAllPushedRefs() ([]PushRef, error) {
	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) != 0 {
		return nil, nil
	}
	return ReadPrePushRefs(os.Stdin)
}

// GetPushedRefs reads standard Git pre-push ref update tuples from stdin if present.
func GetPushedRefs() (localRef, localSha, remoteRef, remoteSha string) {
	refs, err := ReadAllPushedRefs()
	if err == nil && len(refs) > 0 {
		return refs[0].LocalRef, refs[0].LocalSHA, refs[0].RemoteRef, refs[0].RemoteSHA
	}
	return "", "", "", ""
}

// CreatePushSnapshot extracts the tree at localSha into a temporary directory using Go's archive/tar.
func CreatePushSnapshot(repoPath, localSha string) (string, error) {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return "", err
	}

	tempDir, err := os.MkdirTemp("", "vibeguard-push-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	tarPath := filepath.Join(tempDir, "commit.tar")
	cmd := exec.Command("git", "archive", "--format=tar", "-o", tarPath, localSha)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("git archive failed: %v: %s", err, string(out))
	}

	tarFile, err := os.Open(tarPath)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to open archive tar: %w", err)
	}
	defer func() {
		tarFile.Close()
		_ = os.Remove(tarPath)
	}()

	tr := tar.NewReader(tarFile)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			os.RemoveAll(tempDir)
			return "", fmt.Errorf("failed reading tar: %w", err)
		}

		target := filepath.Join(tempDir, filepath.FromSlash(header.Name))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				os.RemoveAll(tempDir)
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				os.RemoveAll(tempDir)
				return "", err
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
			if err != nil {
				os.RemoveAll(tempDir)
				return "", err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				os.RemoveAll(tempDir)
				return "", err
			}
			outFile.Close()
		}
	}

	return tempDir, nil
}

// GetPushedCommitFiles returns the list of files touched in the exact commits being pushed.
func GetPushedCommitFiles(repoPath, remoteSha, localSha string) []string {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return nil
	}

	var files []string
	seen := make(map[string]bool)

	var out string
	if remoteSha == "" || strings.Trim(remoteSha, "0") == "" {
		out, _ = runGit(root, "diff-tree", "--no-commit-id", "--name-only", "-r", localSha)
	} else {
		var diffErr error
		out, diffErr = runGit(root, "diff", "--name-only", remoteSha+".."+localSha)
		if diffErr != nil || strings.TrimSpace(out) == "" {
			// Fallback: examine the local commit directly
			out, _ = runGit(root, "diff-tree", "--no-commit-id", "--name-only", "-r", localSha)
		}
	}

	for _, f := range strings.Split(strings.TrimSpace(out), "\n") {
		f = strings.TrimSpace(f)
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	return files
}

// GetPushedCommitDiff returns the raw unified diff for the commits being pushed.
func GetPushedCommitDiff(repoPath, remoteSha, localSha string) string {
	root, err := FindGitRoot(repoPath)
	if err != nil {
		return ""
	}

	if remoteSha == "" || strings.Trim(remoteSha, "0") == "" {
		out, _ := runGit(root, "show", localSha)
		return out
	}
	out, err := runGit(root, "diff", remoteSha+".."+localSha)
	if err != nil || strings.TrimSpace(out) == "" {
		out, _ = runGit(root, "show", localSha)
	}
	return out
}


`

---
## internal/git/repo_test.go

`
package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createTestRepo(t *testing.T) string {
	dir, err := os.MkdirTemp("", "vibeguard_git_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git: %v", err)
	}

	return dir
}

func TestIsGitRepo(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	if !IsGitRepo(repo) {
		t.Errorf("expected IsGitRepo to return true for %s", repo)
	}

	nonRepo, err := os.MkdirTemp("", "non_git_repo")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(nonRepo)

	if IsGitRepo(nonRepo) {
		t.Errorf("expected IsGitRepo to return false for non-git directory %s", nonRepo)
	}

	// Test FindGitRoot from subfolder
	subDir := filepath.Join(repo, "cmd", "app")
	os.MkdirAll(subDir, 0755)
	root, err := FindGitRoot(subDir)
	if err != nil {
		t.Fatalf("FindGitRoot failed: %v", err)
	}
	if root != repo {
		t.Errorf("expected root %s, got %s", repo, root)
	}
}

func TestGetChangedFilesAndStagedChanges(t *testing.T) {
	repo := createTestRepo(t)
	defer os.RemoveAll(repo)

	// In mock directory without git init, HasStagedChanges should return false without crashing
	if HasStagedChanges(repo) {
		t.Errorf("expected HasStagedChanges to return false in empty mock repo")
	}

	files := GetChangedFiles(repo)
	if len(files) != 0 {
		t.Errorf("expected empty changed files, got %v", files)
	}
}

func TestReadPrePushRefs(t *testing.T) {
	input := `refs/heads/main 1a2b3c4d refs/heads/main 5e6f7a8b
refs/heads/feature 9999aaaa refs/heads/feature 00000000
`
	refs, err := ReadPrePushRefs(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ReadPrePushRefs failed: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}

	if refs[0].LocalRef != "refs/heads/main" || refs[0].LocalSHA != "1a2b3c4d" {
		t.Errorf("unexpected first ref: %+v", refs[0])
	}
	if refs[1].RemoteSHA != "00000000" {
		t.Errorf("unexpected second ref: %+v", refs[1])
	}
}

`

---
## internal/osv/client.go

`
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type DependencyInfo struct {
	Name       string
	Version    string
	Ecosystem  string
	SourceFile string
}

type VulnResult struct {
	PackageName      string
	InstalledVersion string
	Ecosystem        string
	SourceFile       string
	Vulnerabilities  []Vulnerability
}

// defaultHTTPClient reuses TCP connections and enables HTTP keep-alive connection pooling
var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	},
}

func QueryOSV(name, version, ecosystem string) ([]Vulnerability, error) {
	reqData := QueryRequest{
		Version: version,
		Package: Package{
			Name:      name,
			Ecosystem: ecosystem,
		},
	}
	if version == "unknown" {
		reqData.Version = ""
	}

	bodyBytes, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned HTTP %d", resp.StatusCode)
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, err
	}

	return queryResp.Vulns, nil
}

type OSVProgressFunc func(current, total int)

// CheckAllDependencies queries OSV for all dependencies, returning results.
func CheckAllDependencies(deps []DependencyInfo) []VulnResult {
	results, _ := CheckAllDependenciesWithProgress(deps, nil)
	return results
}

// CheckAllDependenciesWithStatus queries OSV and returns an error if all lookups failed due to network/API outage.
func CheckAllDependenciesWithStatus(deps []DependencyInfo) ([]VulnResult, error) {
	return CheckAllDependenciesWithProgress(deps, nil)
}

// CheckAllDependenciesWithProgress queries OSV concurrently with pooled workers and live progress callbacks.
func CheckAllDependenciesWithProgress(deps []DependencyInfo, progress OSVProgressFunc) ([]VulnResult, error) {
	total := len(deps)
	if total == 0 {
		return nil, nil
	}

	ecosystemMap := map[string]string{
		"Go":        "Go",
		"npm":       "npm",
		"PyPI":      "PyPI",
		"crates.io": "crates.io",
	}

	type depJob struct {
		index int
		dep   DependencyInfo
		eco   string
	}

	// Channel for jobs and pre-allocated results slice for deterministic ordering
	jobs := make(chan depJob, total)
	orderedResults := make([]*VulnResult, total)

	var (
		completedCount int64
		successCount   int64
		firstErrMu     sync.Mutex
		lastErr        error
		wg             sync.WaitGroup
	)

	// Concurrency level: min(10, total)
	numWorkers := 10
	if total < numWorkers {
		numWorkers = total
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				vulns, err := QueryOSV(job.dep.Name, job.dep.Version, job.eco)
				done := int(atomic.AddInt64(&completedCount, 1))
				if progress != nil {
					progress(done, total)
				}

				if err != nil {
					firstErrMu.Lock()
					lastErr = err
					firstErrMu.Unlock()
					continue
				}

				atomic.AddInt64(&successCount, 1)
				if len(vulns) > 0 {
					orderedResults[job.index] = &VulnResult{
						PackageName:      job.dep.Name,
						InstalledVersion: job.dep.Version,
						Ecosystem:        job.eco,
						SourceFile:       job.dep.SourceFile,
						Vulnerabilities:  vulns,
					}
				}
			}
		}()
	}

	// Enqueue all jobs
	for idx, d := range deps {
		eco, ok := ecosystemMap[d.Ecosystem]
		if !ok {
			eco = d.Ecosystem
		}
		jobs <- depJob{index: idx, dep: d, eco: eco}
	}
	close(jobs)

	// Wait for all workers to complete
	wg.Wait()

	// If all lookups failed due to network outage, report the error
	if total > 0 && atomic.LoadInt64(&successCount) == 0 && lastErr != nil {
		return nil, lastErr
	}

	// Collect non-nil results in original order
	var results []VulnResult
	for _, res := range orderedResults {
		if res != nil {
			results = append(results, *res)
		}
	}

	return results, nil
}

`

---
## internal/osv/severity.go

`
package osv

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	rceRegex             = regexp.MustCompile(`(?i)\b(rce|remote code execution|arbitrary code execution)\b`)
	criticalKeywordRegex = regexp.MustCompile(`(?i)\b(critical severity)\b`)
	highKeywordRegex     = regexp.MustCompile(`(?i)\b(command injection|sql injection|sqli|prototype pollution|authentication bypass|privilege escalation)\b`)
	mediumKeywordRegex   = regexp.MustCompile(`(?i)\b(cross-site scripting|xss|open redirect|directory traversal|path traversal|csrf|denial of service|dos|ssrf)\b`)
	lowKeywordRegex      = regexp.MustCompile(`(?i)\b(information disclosure|sensitive data exposure|debug information)\b`)
)

// DetermineSeverity evaluates an OSV vulnerability and maps it to CRITICAL, HIGH, MEDIUM, or LOW.
func DetermineSeverity(v Vulnerability) string {
	// 1. Check database_specific severity (e.g. GitHub Advisory GHSA severity)
	if v.DatabaseSpecific != nil {
		if rawSev, ok := v.DatabaseSpecific["severity"].(string); ok {
			switch strings.ToUpper(strings.TrimSpace(rawSev)) {
			case "CRITICAL":
				return "CRITICAL"
			case "HIGH":
				return "HIGH"
			case "MODERATE", "MEDIUM":
				return "MEDIUM"
			case "LOW":
				return "LOW"
			}
		}
	}

	// 2. Check explicit severity entries (CVSS float or CVSS vector)
	for _, s := range v.Severity {
		scoreStr := strings.ToUpper(strings.TrimSpace(s.Score))

		// Check if score is a direct float
		if val, err := strconv.ParseFloat(scoreStr, 64); err == nil {
			if val >= 9.0 {
				return "CRITICAL"
			}
			if val >= 7.0 {
				return "HIGH"
			}
			if val >= 4.0 {
				return "MEDIUM"
			}
			return "LOW"
		}

		// Check if score is a CVSS v3/v4 vector
		if strings.HasPrefix(scoreStr, "CVSS:") {
			hasNet := strings.Contains(scoreStr, "AV:N")
			hasLowComplex := strings.Contains(scoreStr, "AC:L")
			hasNoPriv := strings.Contains(scoreStr, "PR:N")
			hasNoUI := strings.Contains(scoreStr, "UI:N")
			hasAllHighImpact := strings.Contains(scoreStr, "C:H") && strings.Contains(scoreStr, "I:H") && strings.Contains(scoreStr, "A:H")

			if hasNet && hasLowComplex && hasNoPriv && hasNoUI && hasAllHighImpact {
				return "CRITICAL"
			}
			if strings.Contains(scoreStr, "C:H") || strings.Contains(scoreStr, "I:H") || strings.Contains(scoreStr, "A:H") {
				return "HIGH"
			}
			if strings.Contains(scoreStr, "C:L") || strings.Contains(scoreStr, "I:L") || strings.Contains(scoreStr, "A:L") {
				return "MEDIUM"
			}
			return "LOW"
		}

		if strings.Contains(scoreStr, "CRITICAL") {
			return "CRITICAL"
		}
		if strings.Contains(scoreStr, "HIGH") {
			return "HIGH"
		}
		if strings.Contains(scoreStr, "MEDIUM") || strings.Contains(scoreStr, "MODERATE") {
			return "MEDIUM"
		}
		if strings.Contains(scoreStr, "LOW") {
			return "LOW"
		}
	}

	// 3. Match against word boundaries in text (no substring collisions like "rce" in "source")
	combinedText := v.Summary + " " + v.Details
	if rceRegex.MatchString(combinedText) || criticalKeywordRegex.MatchString(combinedText) {
		return "CRITICAL"
	}
	if highKeywordRegex.MatchString(combinedText) {
		return "HIGH"
	}
	if mediumKeywordRegex.MatchString(combinedText) {
		return "MEDIUM"
	}
	if lowKeywordRegex.MatchString(combinedText) {
		return "LOW"
	}

	// 4. Default to MEDIUM for unclassified vulnerabilities
	return "MEDIUM"
}

`

---
## internal/osv/types.go

`
package osv

type QueryRequest struct {
	Version string  `json:"version,omitempty"`
	Package Package `json:"package"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type Vulnerability struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Aliases          []string               `json:"aliases"`
	Severity         []SeverityEntry        `json:"severity"`
	Affected         []AffectedEntry        `json:"affected"`
	References       []Reference            `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type AffectedEntry struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []Range         `json:"ranges"`
	Versions []string        `json:"versions"`
}

type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Reference struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}

`

---
## internal/report/html.go

`
package report

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

const htmlTemplateStr = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeGuard Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; color: #333; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2 { border-bottom: 1px solid #ccc; padding-bottom: 10px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .score { font-size: 24px; font-weight: bold; }
        .cards { display: flex; gap: 20px; margin: 20px 0; }
        .card { flex: 1; padding: 20px; border-radius: 5px; text-align: center; font-weight: bold; }
        .card.critical { background: #ffebee; color: #c62828; }
        .card.high { background: #fff3e0; color: #ef6c00; }
        .card.medium { background: #fffde7; color: #fbc02d; }
        .card.low { background: #e0f7fa; color: #00838f; }
        .card.info { background: #eceff1; color: #455a64; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f8f8; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; color: #fff; }
        .badge.critical { background: #c62828; }
        .badge.high { background: #ef6c00; }
        .badge.medium { background: #fbc02d; color: #333; }
        .badge.low { background: #00838f; }
        .badge.info { background: #455a64; }
        .status-banner { padding: 15px; border-radius: 5px; font-weight: bold; font-size: 18px; text-align: center; }
        .status-passed { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
        .status-blocked { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>VibeGuard Security Report</h1>
                <p><strong>Project:</strong> {{.ProjectName}} | <strong>Scanned:</strong> {{.ScanTime}} | <strong>Files:</strong> {{.FilesScanned}}</p>
            </div>
            <div class="score">Score: {{.ScoreResult.Score}}/100</div>
        </div>

        <div class="status-banner {{if eq .GateResult.Status "PASSED"}}status-passed{{else}}status-blocked{{end}}">
            Deployment Status: {{.GateResult.Status}} - {{.GateResult.Reason}}
        </div>

        <h2>Severity Summary</h2>
        <div class="cards">
            <div class="card critical">Critical<br>{{.ScoreResult.CriticalCount}}</div>
            <div class="card high">High<br>{{.ScoreResult.HighCount}}</div>
            <div class="card medium">Medium<br>{{.ScoreResult.MediumCount}}</div>
            <div class="card low">Low<br>{{.ScoreResult.LowCount}}</div>
            <div class="card info">Info<br>{{.ScoreResult.InfoCount}}</div>
        </div>

        <h2>Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>ID</th>
                <th>Title</th>
                <th>File</th>
                <th>Description</th>
                <th>Recommendation</th>
            </tr>
            {{range .Findings}}
            <tr>
                <td><span class="badge {{.Severity | js}}">{{.Severity}}</span></td>
                <td>{{.ID}}</td>
                <td>{{.Title}}</td>
                <td>{{.File}}:{{.Line}}</td>
                <td>{{.Description}}</td>
                <td>{{.Recommendation}}</td>
            </tr>
            {{end}}
        </table>

        <h2>Dependency Vulnerabilities</h2>
        <table>
            <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Ecosystem</th>
                <th>Vulnerability ID</th>
                <th>Summary</th>
            </tr>
            {{range .Dependencies}}
                {{$pkg := .PackageName}}
                {{$ver := .InstalledVersion}}
                {{$eco := .Ecosystem}}
                {{range .Vulnerabilities}}
                <tr>
                    <td>{{$pkg}}</td>
                    <td>{{$ver}}</td>
                    <td>{{$eco}}</td>
                    <td>{{.ID}}</td>
                    <td>{{.Summary}}</td>
                </tr>
                {{end}}
            {{end}}
        </table>
    </div>
</body>
</html>`

func WriteHTMLReport(r *Report, outputPath string) error {
	absPath, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		absPath = filepath.Clean(outputPath)
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"js": func(s string) string {
			switch strings.ToUpper(s) {
			case "CRITICAL":
				return "critical"
			case "HIGH":
				return "high"
			case "MEDIUM":
				return "medium"
			case "LOW":
				return "low"
			case "INFO":
				return "info"
			default:
				return "info"
			}
		},
	}).Parse(htmlTemplateStr)
	if err != nil {
		return err
	}

	var f *os.File
	f, err = os.Create(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, r)
}

`

---
## internal/report/json.go

`
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func WriteJSONReport(r *Report, outputPath string) error {
	absPath, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		absPath = filepath.Clean(outputPath)
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(absPath, data, 0644)
}

`

---
## internal/report/progress.go

`
package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// ProgressBar manages dynamic terminal progress reporting.
type ProgressBar struct {
	width        int
	out          io.Writer
	isTTY        bool
	linesPrinted int
	mu           sync.Mutex
}

// NewProgressBar creates a new progress bar renderer.
func NewProgressBar(width int, out io.Writer) *ProgressBar {
	if width <= 0 {
		width = 20
	}
	if out == nil {
		out = os.Stdout
	}

	isTTY := false
	if f, ok := out.(*os.File); ok {
		stat, err := f.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
			isTTY = true
		}
	}

	return &ProgressBar{
		width: width,
		out:   out,
		isTTY: isTTY,
	}
}

// SetTTY allows explicitly toggling TTY mode (useful for unit tests).
func (p *ProgressBar) SetTTY(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isTTY = enabled
}

// BuildBar constructs the [██████████████░░░░░░] string and percentage.
func (p *ProgressBar) BuildBar(current, total int) (string, int) {
	if total <= 0 {
		total = 1
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}

	pct := (current * 100) / total
	filled := (pct * p.width) / 100
	if filled > p.width {
		filled = p.width
	}
	empty := p.width - filled

	bar := "[" + strings.Repeat("█", filled) + strings.Repeat("░", empty) + "]"
	return bar, pct
}

// Render displays the progress bar with up to two description lines.
// Example:
// [██████████████░░░░░░] 70%
// Files: 56/80
// Current: internal/scanner/runner.go
func (p *ProgressBar) Render(current, total int, line1, line2 string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	bar, pct := p.BuildBar(current, total)

	lines := []string{
		fmt.Sprintf("%s %d%%", bar, pct),
	}
	if line1 != "" {
		lines = append(lines, line1)
	}
	if line2 != "" {
		lines = append(lines, line2)
	}

	if p.isTTY && p.linesPrinted > 0 {
		// Move cursor up by previously printed lines
		fmt.Fprintf(p.out, "\033[%dA\r", p.linesPrinted)
	}

	for _, l := range lines {
		if p.isTTY {
			// Clear line to end and print
			fmt.Fprintf(p.out, "\033[K%s\n", l)
		} else {
			fmt.Fprintf(p.out, "%s\n", l)
		}
	}

	p.linesPrinted = len(lines)
}

// Finish displays the final 100% completion bar.
// Example:
// [████████████████████] 100%
// Security analysis complete.
func (p *ProgressBar) Finish(message string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	bar := "[" + strings.Repeat("█", p.width) + "]"

	if p.isTTY && p.linesPrinted > 0 {
		fmt.Fprintf(p.out, "\033[%dA\r", p.linesPrinted)
	}

	if p.isTTY {
		fmt.Fprintf(p.out, "\033[K%s 100%%\n", bar)
		if message != "" {
			fmt.Fprintf(p.out, "\033[K\n\033[K%s\n", message)
		}
	} else {
		fmt.Fprintf(p.out, "%s 100%%\n", bar)
		if message != "" {
			fmt.Fprintf(p.out, "\n%s\n", message)
		}
	}

	p.linesPrinted = 0
}

// Reset clears the line counter.
func (p *ProgressBar) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.linesPrinted = 0
}

`

---
## internal/report/progress_test.go

`
package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildBar(t *testing.T) {
	pb := NewProgressBar(20, nil)

	// 0%
	bar, pct := pb.BuildBar(0, 100)
	if pct != 0 {
		t.Errorf("expected 0%%, got %d%%", pct)
	}
	if bar != "[░░░░░░░░░░░░░░░░░░░░]" {
		t.Errorf("unexpected bar: %s", bar)
	}

	// 70%
	bar, pct = pb.BuildBar(70, 100)
	if pct != 70 {
		t.Errorf("expected 70%%, got %d%%", pct)
	}
	if bar != "[██████████████░░░░░░]" {
		t.Errorf("unexpected bar for 70%%: %s", bar)
	}

	// 100%
	bar, pct = pb.BuildBar(100, 100)
	if pct != 100 {
		t.Errorf("expected 100%%, got %d%%", pct)
	}
	if bar != "[████████████████████]" {
		t.Errorf("unexpected bar for 100%%: %s", bar)
	}
}

func TestProgressBarRender(t *testing.T) {
	var buf bytes.Buffer
	pb := NewProgressBar(20, &buf)
	pb.SetTTY(false)

	pb.Render(56, 80, "Files: 56/80", "Current: internal/scanner/runner.go")

	output := buf.String()
	if !strings.Contains(output, "70%") {
		t.Errorf("expected 70%% in output, got: %s", output)
	}
	if !strings.Contains(output, "Files: 56/80") {
		t.Errorf("expected 'Files: 56/80' in output, got: %s", output)
	}
	if !strings.Contains(output, "Current: internal/scanner/runner.go") {
		t.Errorf("expected 'Current: internal/scanner/runner.go' in output, got: %s", output)
	}
}

func TestProgressBarFinish(t *testing.T) {
	var buf bytes.Buffer
	pb := NewProgressBar(20, &buf)
	pb.SetTTY(false)

	pb.Finish("Security analysis complete.")

	output := buf.String()
	if !strings.Contains(output, "100%") {
		t.Errorf("expected 100%% in output, got: %s", output)
	}
	if !strings.Contains(output, "Security analysis complete.") {
		t.Errorf("expected message in output, got: %s", output)
	}
}

`

---
## internal/report/report_test.go

`
package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

func TestReportGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeguard_test_reports")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	rep := &Report{
		ProjectName:  "TestApp",
		ScanTime:     "120ms",
		FilesScanned: 5,
		Findings: []scanner.Finding{
			{
				ID:             "VG-001",
				Category:       "secret",
				Severity:       "CRITICAL",
				Title:          "Hardcoded API Key",
				Description:    "Found exposed API key",
				File:           "config.go",
				Line:           10,
				Recommendation: "Revoke key",
				Confidence:     "HIGH",
			},
		},
		ScoreResult: risk.ScoreResult{
			Score:         85,
			Total:         100,
			CriticalCount: 1,
		},
		GateResult: gate.GateResult{
			Status:   "BLOCKED",
			ExitCode: 1,
			Reason:   "Critical security findings detected",
		},
		CategoryCounts: CategoryCounts{
			Secrets: 1,
		},
	}

	// Test JSON Report
	jsonPath := filepath.Join(tempDir, "scan.json")
	if err := WriteJSONReport(rep, jsonPath); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Errorf("expected json report file to exist")
	}

	// Test HTML Report
	htmlPath := filepath.Join(tempDir, "scan.html")
	if err := WriteHTMLReport(rep, htmlPath); err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}
	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		t.Errorf("expected html report file to exist")
	}
}

`

---
## internal/report/terminal.go

`
package report

import (
	"fmt"
	"strings"

	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/osv"
	"github.com/vibeguard/vibeguard/internal/risk"
	"github.com/vibeguard/vibeguard/internal/scanner"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorGray   = "\033[90m"
	ColorBold   = "\033[1m"
)

type CategoryCounts struct {
	Secrets       int
	SourceCode    int
	Dependencies  int
	Configuration int
	Docker        int
	Git           int
}

type Report struct {
	ProjectName    string
	CommitHash     string
	Branch         string
	Remote         string
	ScanTime       string
	FilesScanned   int
	Findings       []scanner.Finding
	Dependencies   []osv.VulnResult
	ScoreResult    risk.ScoreResult
	GateResult     gate.GateResult
	CategoryCounts CategoryCounts
}

func severityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func severityColor(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL", "HIGH":
		return ColorRed
	case "MEDIUM":
		return ColorYellow
	case "LOW":
		return ColorCyan
	default:
		return ColorWhite
	}
}

func getBestFixedVersion(vulns []osv.Vulnerability) string {
	var bestFix string
	for _, v := range vulns {
		for _, aff := range v.Affected {
			for _, r := range aff.Ranges {
				for _, ev := range r.Events {
					if ev.Fixed != "" {
						if bestFix == "" || ev.Fixed > bestFix {
							bestFix = ev.Fixed
						}
					}
				}
			}
		}
	}
	return bestFix
}

func PrintTerminalReport(r *Report) {
	fmt.Println("========= VIBEGUARD SECURITY REPORT =========")
	fmt.Printf("Project:       %s\n", r.ProjectName)
	if r.Branch != "" {
		fmt.Printf("Branch:        %s\n", r.Branch)
	}
	if r.CommitHash != "" {
		fmt.Printf("Commit:        %s\n", r.CommitHash)
	}
	if r.Remote != "" {
		fmt.Printf("Remote:        %s\n", r.Remote)
	}
	fmt.Printf("Scan Time:     %s\n", r.ScanTime)
	fmt.Printf("Files Scanned: %d\n", r.FilesScanned)

	fmt.Println("---------------------------------------------")
	riskLevel := "LOW RISK"
	scoreColor := ColorGreen
	if r.ScoreResult.Score < 60 {
		riskLevel = "CRITICAL RISK"
		scoreColor = ColorRed
	} else if r.ScoreResult.Score < 75 {
		riskLevel = "HIGH RISK"
		scoreColor = ColorRed
	} else if r.ScoreResult.Score < 90 {
		riskLevel = "MEDIUM RISK"
		scoreColor = ColorYellow
	}
	fmt.Printf("Security Score: %s%d/%d (%s)%s\n", scoreColor, r.ScoreResult.Score, r.ScoreResult.Total, riskLevel, ColorReset)

	statusColor := ColorGreen
	if r.GateResult.Status == "BLOCKED" {
		statusColor = ColorRed
	}
	fmt.Printf("Gate Status:    %s%s%s\n", statusColor, r.GateResult.Status, ColorReset)
	if r.GateResult.Reason != "" {
		fmt.Printf("Reason:         %s\n", r.GateResult.Reason)
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Severity Counts:\n")
	fmt.Printf("  Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		r.ScoreResult.CriticalCount,
		r.ScoreResult.HighCount,
		r.ScoreResult.MediumCount,
		r.ScoreResult.LowCount,
		r.ScoreResult.InfoCount)

	fmt.Printf("Category Breakdown:\n")
	fmt.Printf("  Secrets: %d | Source Code: %d | Dependencies: %d | Config: %d | Docker: %d | Git: %d\n",
		r.CategoryCounts.Secrets, r.CategoryCounts.SourceCode, r.CategoryCounts.Dependencies,
		r.CategoryCounts.Configuration, r.CategoryCounts.Docker, r.CategoryCounts.Git)

	// 1. Code & Secret / Configuration Findings (non-dependency)
	var codeFindings []scanner.Finding
	for _, f := range r.Findings {
		if strings.ToLower(f.Category) != "dependency" {
			codeFindings = append(codeFindings, f)
		}
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Code & Configuration Findings (%d):\n", len(codeFindings))
	if len(codeFindings) == 0 {
		fmt.Printf("  %s✓ No code, secret, or configuration issues detected.%s\n", ColorGreen, ColorReset)
	} else {
		for _, f := range codeFindings {
			c := severityColor(f.Severity)
			cat := strings.Title(strings.ToLower(f.Category))
			fmt.Printf("  %s[%s]%s %s (%s) - %s:%d\n", c, strings.ToUpper(f.Severity), ColorReset, f.ID, cat, f.File, f.Line)
			if f.Title != "" {
				fmt.Printf("    Title:          %s\n", f.Title)
			}
			if f.Description != "" && f.Description != f.Title {
				fmt.Printf("    Description:    %s\n", f.Description)
			}
			if f.Recommendation != "" {
				fmt.Printf("    Recommendation: %s\n", f.Recommendation)
			}
			fmt.Println()
		}
	}

	// 2. Dependency Vulnerabilities (Grouped by package for clean readability)
	totalVulns := 0
	for _, d := range r.Dependencies {
		totalVulns += len(d.Vulnerabilities)
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Dependency Vulnerabilities (%d vulnerable packages, %d total advisories):\n", len(r.Dependencies), totalVulns)
	if len(r.Dependencies) == 0 {
		fmt.Printf("  %s✓ No known vulnerabilities found in dependencies.%s\n", ColorGreen, ColorReset)
	} else {
		// Table Header
		fmt.Printf("  %-20s %-12s %-12s %-14s %s\n", "PACKAGE", "CURRENT", "SEVERITY", "ADVISORIES", "RECOMMENDED FIX")
		fmt.Println("  --------------------------------------------------------------------------------")

		for _, d := range r.Dependencies {
			maxSevRank := -1
			maxSevStr := "LOW"
			for _, v := range d.Vulnerabilities {
				sev := osv.DetermineSeverity(v)
				rank := severityRank(sev)
				if rank > maxSevRank {
					maxSevRank = rank
					maxSevStr = sev
				}
			}

			fixVer := getBestFixedVersion(d.Vulnerabilities)
			fixText := "Update package"
			if fixVer != "" {
				fixText = fmt.Sprintf("Upgrade to >= %s", fixVer)
			}

			sevColored := fmt.Sprintf("%s%-12s%s", severityColor(maxSevStr), maxSevStr, ColorReset)
			advCount := fmt.Sprintf("%d vulns", len(d.Vulnerabilities))

			pkgName := d.PackageName
			if len(pkgName) > 20 {
				pkgName = pkgName[:18] + ".."
			}

			instVer := d.InstalledVersion
			if len(instVer) > 12 {
				instVer = instVer[:10] + ".."
			}

			fmt.Printf("  %-20s %-12s %s %-14s %s\n", pkgName, instVer, sevColored, advCount, fixText)
		}

		// Advisory details (compact summary per package)
		fmt.Println()
		fmt.Println("  Key Advisory Highlights:")
		for _, d := range r.Dependencies {
			src := d.SourceFile
			if src != "" {
				src = fmt.Sprintf(" [%s]", src)
			}
			fmt.Printf("  • %s (%s)%s:\n", d.PackageName, d.InstalledVersion, src)

			maxShow := 2
			for idx, v := range d.Vulnerabilities {
				if idx >= maxShow {
					remaining := len(d.Vulnerabilities) - maxShow
					fmt.Printf("    %s... and %d more advisories%s\n", ColorGray, remaining, ColorReset)
					break
				}
				sev := osv.DetermineSeverity(v)
				c := severityColor(sev)
				summary := v.Summary
				if summary == "" {
					summary = v.Details
				}
				summary = strings.ReplaceAll(summary, "\n", " ")
				if len(summary) > 75 {
					summary = summary[:72] + "..."
				}
				fmt.Printf("    - %s%s%s [%s]: %s\n", c, v.ID, ColorReset, sev, summary)
			}
		}
	}

	fmt.Println("---------------------------------------------")
	fmt.Printf("Deployment Status: %s%s%s\n", statusColor, r.GateResult.Status, ColorReset)
	if r.GateResult.Reason != "" {
		fmt.Printf("Reason: %s\n", r.GateResult.Reason)
	}
	fmt.Println("=============================================")
}

`

---
## internal/risk/scorer.go

`
package risk

import "strings"

type FindingInfo struct {
	Severity string
}

type ScoreResult struct {
	Score         int
	Total         int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
}

func CalculateScore(findings []FindingInfo) ScoreResult {
	res := ScoreResult{
		Total: 100,
	}

	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			res.CriticalCount++
		case "HIGH":
			res.HighCount++
		case "MEDIUM":
			res.MediumCount++
		case "LOW":
			res.LowCount++
		case "INFO":
			res.InfoCount++
		}
	}

	deduction := (res.CriticalCount * 15) + (res.HighCount * 8) + (res.MediumCount * 3) + (res.LowCount * 1)
	res.Score = 100 - deduction
	if res.Score < 0 {
		res.Score = 0
	}

	return res
}

`

---
## internal/risk/scorer_test.go

`
package risk

import (
	"testing"
)

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name          string
		findings      []FindingInfo
		expectedScore int
		expectedCrit  int
		expectedHigh  int
	}{
		{
			name:          "Clean project",
			findings:      []FindingInfo{},
			expectedScore: 100,
			expectedCrit:  0,
			expectedHigh:  0,
		},
		{
			name: "Single critical finding",
			findings: []FindingInfo{
				{Severity: "CRITICAL"},
			},
			expectedScore: 85, // 100 - 15
			expectedCrit:  1,
			expectedHigh:  0,
		},
		{
			name: "Mixed severities",
			findings: []FindingInfo{
				{Severity: "CRITICAL"}, // -15
				{Severity: "HIGH"},     // -8
				{Severity: "MEDIUM"},   // -3
				{Severity: "LOW"},      // -1
			},
			expectedScore: 73, // 100 - 27
			expectedCrit:  1,
			expectedHigh:  1,
		},
		{
			name: "Heavily vulnerable floor at 0",
			findings: []FindingInfo{
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
				{Severity: "CRITICAL"},
			},
			expectedScore: 0,
			expectedCrit:  7,
			expectedHigh:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := CalculateScore(tc.findings)
			if res.Score != tc.expectedScore {
				t.Errorf("expected score %d, got %d", tc.expectedScore, res.Score)
			}
			if res.CriticalCount != tc.expectedCrit {
				t.Errorf("expected %d critical, got %d", tc.expectedCrit, res.CriticalCount)
			}
			if res.HighCount != tc.expectedHigh {
				t.Errorf("expected %d high, got %d", tc.expectedHigh, res.HighCount)
			}
		})
	}
}

`

---
## internal/scanner/runner.go

`
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vibeguard/vibeguard/internal/config"
)

type ScanResult struct {
	Project      string    `json:"project"`
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
	ScanTimeMs   int64     `json:"scan_time_ms"`
}

type Finding struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	File           string `json:"file"`
	Line           int    `json:"line"`
	Evidence       string `json:"evidence,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	Confidence     string `json:"confidence"`
}

// FindScannerExecutable attempts to locate the Rust scanner binary across multiple candidate paths.
// It prioritizes the running executable's directory and %LOCALAPPDATA%\VibeGuard so that
// the scanner is always found regardless of what directory the user runs VibeGuard from.
func FindScannerExecutable() (string, bool) {
	// 1. Explicit environment variable
	if envPath := os.Getenv("VIBEGUARD_SCANNER_PATH"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, true
		}
	}

	exePath, err := os.Executable()
	var exeDir string
	if err == nil {
		exeDir = filepath.Dir(exePath)
	}

	var localAppDataDir string
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		localAppDataDir = filepath.Join(la, "VibeGuard")
	} else if up := os.Getenv("USERPROFILE"); up != "" {
		localAppDataDir = filepath.Join(up, "AppData", "Local", "VibeGuard")
	}

	cwd, _ := os.Getwd()

	candidates := []string{
		// 1. In the same directory as the running VibeGuard executable
		filepath.Join(exeDir, "scanner.exe"),
		filepath.Join(exeDir, "vibeguard-scanner.exe"),
		filepath.Join(exeDir, "vibeguard-scanner"),
		filepath.Join(exeDir, "scanner", "scanner.exe"),
		filepath.Join(exeDir, "scanner", "vibeguard-scanner.exe"),

		// 2. In the global %LOCALAPPDATA%\VibeGuard installation directory
		filepath.Join(localAppDataDir, "scanner.exe"),
		filepath.Join(localAppDataDir, "vibeguard-scanner.exe"),
		filepath.Join(localAppDataDir, "bin", "scanner.exe"),
		filepath.Join(localAppDataDir, "bin", "vibeguard-scanner.exe"),

		// 3. In the current working directory / repo root
		filepath.Join(cwd, "scanner.exe"),
		filepath.Join(cwd, "vibeguard-scanner.exe"),
		filepath.Join(cwd, "vibeguard-scanner"),
		filepath.Join(cwd, "scanner", "scanner.exe"),
		filepath.Join(cwd, "scanner", "vibeguard-scanner.exe"),

		// 4. In build output directories (cargo target release/debug)
		filepath.Join(cwd, "scanner", "target", "release", "vibeguard-scanner.exe"),
		filepath.Join(cwd, "scanner", "target", "release", "scanner.exe"),
		filepath.Join(cwd, "scanner", "target", "release", "vibeguard-scanner"),
		filepath.Join(cwd, "scanner", "target", "debug", "vibeguard-scanner.exe"),
		filepath.Join(cwd, "scanner", "target", "debug", "vibeguard-scanner"),
		filepath.Join(exeDir, "..", "scanner", "target", "release", "vibeguard-scanner.exe"),
	}

	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand, true
		}
	}

	// In system PATH
	if path, err := exec.LookPath("vibeguard-scanner.exe"); err == nil {
		return path, true
	}
	if path, err := exec.LookPath("vibeguard-scanner"); err == nil {
		return path, true
	}

	return "", false
}

type ScanProgressFunc func(current, total int, currentFile string)

// RunScanner runs the Rust scanner executable if available; otherwise falls back to the built-in Go scanner.
func RunScanner(projectPath string) (*ScanResult, error) {
	return RunScannerWithProgress(projectPath, nil)
}

// RunScannerWithProgress runs the Rust scanner executable with live progress support.
// If the Rust scanner is unavailable or execution fails, it falls back to the built-in Go scanner.
func RunScannerWithProgress(projectPath string, progress ScanProgressFunc) (*ScanResult, error) {
	// Read config to check enabled modules
	secretScan := true
	sourceScan := true
	cfgFile := filepath.Join(projectPath, ".vibeguard", "config.json")
	if data, err := os.ReadFile(cfgFile); err == nil {
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err == nil {
			if v, ok := raw["secret_scan"].(bool); ok {
				secretScan = v
			}
			if v, ok := raw["source_scan"].(bool); ok {
				sourceScan = v
			}
		}
	}

	scannerExe, found := FindScannerExecutable()
	if found {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		args := []string{projectPath}
		if !secretScan {
			args = append(args, "--no-secrets")
		}
		if !sourceScan {
			args = append(args, "--no-sast")
		}
		if progress != nil {
			args = append(args, "--progress")
		}

		cmd := exec.CommandContext(ctx, scannerExe, args...)

		if progress != nil {
			var stdoutBuf bytes.Buffer
			cmd.Stdout = &stdoutBuf
			stderrPipe, err := cmd.StderrPipe()
			if err == nil {
				if err := cmd.Start(); err == nil {
					scanner := bufio.NewScanner(stderrPipe)
					for scanner.Scan() {
						line := scanner.Text()
						if strings.HasPrefix(line, "PROGRESS:") {
							parts := strings.SplitN(line[9:], ":", 3)
							if len(parts) == 3 {
								cur, _ := strconv.Atoi(parts[0])
								tot, _ := strconv.Atoi(parts[1])
								progress(cur, tot, parts[2])
							}
						}
					}
					if err := cmd.Wait(); err == nil {
						var result ScanResult
						if err := json.Unmarshal(stdoutBuf.Bytes(), &result); err == nil {
							return &result, nil
						}
					}
				}
			}
		} else {
			output, err := cmd.Output()
			if err == nil {
				var result ScanResult
				if err := json.Unmarshal(output, &result); err == nil {
					return &result, nil
				}
			}
		}
	}

	// Fallback to built-in Go scanning engine
	return RunInternalScannerWithProgress(projectPath, progress)
}

// Built-in rule definition
type internalRule struct {
	id             string
	name           string
	category       string
	severity       string
	pattern        *regexp.Regexp
	description    string
	recommendation string
}

func getInternalRules() []internalRule {
	return []internalRule{
		// Secrets
		{
			id:             "VG-SEC-001",
			name:           "AWS Access Key",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			description:    "AWS Access Key ID detected.",
			recommendation: "Revoke the key immediately and use IAM roles instead.",
		},
		{
			id:             "VG-SEC-002",
			name:           "Generic API Key",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}`),
			description:    "Generic API Key detected.",
			recommendation: "Remove the key from code and use a secret manager.",
		},
		{
			id:             "VG-SEC-003",
			name:           "GitHub Token",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
			description:    "GitHub Personal Access Token detected.",
			recommendation: "Revoke the token and generate a new one if needed.",
		},
		{
			id:             "VG-SEC-004",
			name:           "Slack Token",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`xox[bprs]-[a-zA-Z0-9-]+`),
			description:    "Slack Token detected.",
			recommendation: "Revoke and rotate the Slack token.",
		},
		{
			id:             "VG-SEC-005",
			name:           "Private Key",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----`),
			description:    "Private cryptographic key detected.",
			recommendation: "Remove private keys from the repository.",
		},
		{
			id:             "VG-SEC-006",
			name:           "Password Assignment",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]`),
			description:    "Hardcoded password assignment detected.",
			recommendation: "Use environment variables for passwords.",
		},
		{
			id:             "VG-SEC-007",
			name:           "Token/Secret Assignment",
			category:       "secret",
			severity:       "CRITICAL",
			pattern:        regexp.MustCompile(`(?i)(token|secret|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]`),
			description:    "Hardcoded token or secret assignment detected.",
			recommendation: "Move secrets to secure storage or environment variables.",
		},
		// SAST Rules
		{
			id:             "VG-SQL-001",
			name:           "Potential SQL Injection",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(fmt\.Sprintf\("SELECT|"SELECT.*"\+|query.*\+.*request|execute\("SELECT)`),
			description:    "Potential SQL injection vulnerability detected.",
			recommendation: "Use parameterized queries or prepared statements.",
		},
		{
			id:             "VG-CMD-001",
			name:           "Potential OS Command Injection",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(exec\.Command|os\.system\(|subprocess\.call\(|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec\()`),
			description:    "Potential OS command injection vulnerability detected.",
			recommendation: "Avoid executing OS commands with user input. Use safe APIs.",
		},
		{
			id:             "VG-EVAL-001",
			name:           "Dangerous Eval",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(eval\(|Function\(|exec\()`),
			description:    "Use of dangerous evaluation functions detected.",
			recommendation: "Avoid using eval or similar functions on untrusted input.",
		},
		{
			id:             "VG-TLS-001",
			name:           "Potential TLS Misconfiguration",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)(InsecureSkipVerify.*true|verify.*False|rejectUnauthorized.*false|NODE_TLS_REJECT_UNAUTHORIZED)`),
			description:    "TLS verification seems to be disabled.",
			recommendation: "Enable TLS verification for all network connections in production.",
		},
		{
			id:             "VG-CRYPTO-001",
			name:           "Weak Crypto",
			category:       "sourcecode",
			severity:       "MEDIUM",
			pattern:        regexp.MustCompile(`(?i)\b(md5|sha1|DES|RC4)\b`),
			description:    "Weak cryptographic algorithm detected.",
			recommendation: "Use strong algorithms (e.g., SHA-256, AES).",
		},
		{
			id:             "VG-HTTP-001",
			name:           "Potential Insecure HTTP Connection",
			category:       "sourcecode",
			severity:       "MEDIUM",
			pattern:        regexp.MustCompile(`http://[a-zA-Z0-9]`),
			description:    "Insecure HTTP connection detected.",
			recommendation: "Use HTTPS for all network communication.",
		},
		{
			id:             "VG-CRED-001",
			name:           "Hardcoded Credentials",
			category:       "sourcecode",
			severity:       "HIGH",
			pattern:        regexp.MustCompile(`(?i)password\s*=\s*"[^"]+"`),
			description:    "Hardcoded credentials in source code.",
			recommendation: "Use environment variables or a secret management service.",
		},
	}
}

// RunInternalScanner performs comprehensive scanning using the built-in Go engine.
func RunInternalScanner(projectPath string) (*ScanResult, error) {
	return RunInternalScannerWithProgress(projectPath, nil)
}

type candidateFile struct {
	path    string
	relPath string
	name    string
	ext     string
}

// RunInternalScannerWithProgress performs comprehensive scanning with optional live progress reporting.
func RunInternalScannerWithProgress(projectPath string, progress ScanProgressFunc) (*ScanResult, error) {
	start := time.Now()
	var findings []Finding
	counter := 0

	cfg, _ := config.LoadConfig(projectPath)
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	secretScan := cfg.SecretScan
	sourceScan := cfg.SourceScan

	allRules := getInternalRules()
	var rules []internalRule
	for _, r := range allRules {
		if r.category == "secret" && !secretScan {
			continue
		}
		if r.category == "sourcecode" && !sourceScan {
			continue
		}
		rules = append(rules, r)
	}

	skipDirs := map[string]bool{
		"node_modules":  true,
		".git":          true,
		"vendor":        true,
		"target":        true,
		"__pycache__":   true,
		".venv":         true,
		"venv":          true,
		"env":           true,
		"dist":          true,
		"build":         true,
		"htmlcov":       true,
		".coverage":     true,
		"coverage":      true,
		".pytest_cache": true,
		".mypy_cache":   true,
		".tox":          true,
		".nyc_output":   true,
		".idea":         true,
		".vscode":       true,
	}

	skipExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".zip": true, ".tar": true,
		".gz": true, ".png": true, ".jpg": true, ".gif": true,
		".mp4": true, ".pdf": true,
	}

	sourceExts := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".py": true,
		".java": true, ".rs": true, ".rb": true, ".php": true,
		".c": true, ".cpp": true, ".cs": true,
	}

	docExts := map[string]bool{
		".md": true, ".markdown": true, ".rst": true, ".txt": true,
		".adoc": true, ".html": true, ".htm": true,
	}

	var gitignorePatterns []string
	if gitignoreBytes, err := os.ReadFile(filepath.Join(projectPath, ".gitignore")); err == nil {
		lines := strings.Split(string(gitignoreBytes), "\n")
		for _, gl := range lines {
			gl = strings.TrimSpace(gl)
			if gl == "" || strings.HasPrefix(gl, "#") {
				continue
			}
			gl = strings.TrimPrefix(gl, "/")
			gl = strings.TrimSuffix(gl, "/")
			gl = filepath.ToSlash(gl)
			if gl != "" {
				gitignorePatterns = append(gitignorePatterns, gl)
			}
		}
	}

	// 1. Collect all non-skipped candidate files
	var files []candidateFile
	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(projectPath, path)
		if relPath == "" || relPath == "." {
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		for _, gp := range gitignorePatterns {
			if relPath == gp || strings.HasPrefix(relPath, gp+"/") || d.Name() == gp {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(gp, "*") && strings.HasSuffix(d.Name(), gp[1:]) {
				return nil
			}
		}

		if d.IsDir() {
			if skipDirs[d.Name()] || cfg.IsExcluded(relPath) {
				return filepath.SkipDir
			}
			return nil
		}

		if cfg.IsExcluded(relPath) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if skipExts[ext] {
			return nil
		}

		files = append(files, candidateFile{
			path:    path,
			relPath: relPath,
			name:    d.Name(),
			ext:     ext,
		})
		return nil
	})

	if err != nil {
		return nil, err
	}

	totalFiles := len(files)

	// 2. Scan each candidate file and emit progress
	for idx, f := range files {
		currentNum := idx + 1
		if progress != nil {
			progress(currentNum, totalFiles, f.relPath)
		}

		path := f.path
		relPath := f.relPath
		fileName := f.name
		ext := f.ext

		// Sensitive filename checks (excluding code source files)
		if secretScan && !sourceExts[ext] && (fileName == ".env" || fileName == "id_rsa" || fileName == "id_dsa" || ext == ".pem" || ext == ".key" ||
			strings.HasPrefix(fileName, "credentials.") || strings.HasPrefix(fileName, "secrets.")) {
			counter++
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("VG-%03d", counter),
				Category:       "secret",
				Severity:       "CRITICAL",
				Title:          "Sensitive File Detected",
				Description:    "A file commonly used to store secrets or credentials was found.",
				File:           relPath,
				Line:           1,
				Recommendation: "Ensure this file is not committed to version control and does not contain sensitive data.",
				Confidence:     "HIGH",
			})
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(contentBytes)
		lines := strings.Split(content, "\n")

		// Dockerfile checks
		if fileName == "Dockerfile" || strings.HasSuffix(fileName, ".dockerfile") {
			hasUser := false
			envSecretRe := regexp.MustCompile(`(?i)ENV\s+.*(secret|token|password|key)\s*=`)
			for lineIdx, line := range lines {
				lineNum := lineIdx + 1
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "USER ") {
					u := strings.TrimSpace(strings.TrimPrefix(trimmed, "USER "))
					if u != "root" && u != "0" {
						hasUser = true
					}
				}
				if envSecretRe.MatchString(line) {
					counter++
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("VG-%03d", counter),
						Category:       "docker",
						Severity:       "CRITICAL",
						Title:          "Secrets in ENV",
						Description:    "Environment variables in Dockerfiles can expose secrets.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Avoid setting sensitive data in ENV. Use runtime secrets.",
						Confidence:     "HIGH",
					})
				}
				if strings.Contains(trimmed, "COPY . .") {
					counter++
					findings = append(findings, Finding{
						ID:             fmt.Sprintf("VG-%03d", counter),
						Category:       "docker",
						Severity:       "MEDIUM",
						Title:          "COPY . . without caution",
						Description:    "Using COPY . . can copy unintended sensitive files into the image.",
						File:           relPath,
						Line:           lineNum,
						Evidence:       trimmed,
						Recommendation: "Use a .dockerignore file and specify explicit paths.",
						Confidence:     "MEDIUM",
					})
				}
			}
			if !hasUser {
				counter++
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("VG-%03d", counter),
					Category:       "docker",
					Severity:       "HIGH",
					Title:          "Running as root",
					Description:    "No non-root USER specified in the Dockerfile.",
					File:           relPath,
					Line:           1,
					Recommendation: "Add a non-root USER instruction.",
					Confidence:     "HIGH",
				})
			}
		}

		// Line-by-line pattern matching
		for lineIdx, line := range lines {
			lineNum := lineIdx + 1
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, ";") {
				continue
			}
			if strings.Contains(line, "regexp.MustCompile") || strings.Contains(line, "Regex::new") || strings.Contains(line, "Rule {") || strings.Contains(line, `strings.Contains(lineLower, "http`) || strings.Contains(line, `line_lower.contains("http`) {
				continue
			}

			for _, r := range rules {
				if r.category == "sourcecode" && !sourceExts[ext] {
					continue
				}

				isGenericAssignment := r.id == "VG-SEC-006" || r.id == "VG-SEC-007" || r.id == "VG-CRED-001"
				if isGenericAssignment && docExts[ext] {
					continue
				}

				if r.pattern.MatchString(line) {
					// False positive filtering for password / credential / token assignments
					if isGenericAssignment {
						lineLower := strings.ToLower(line)
						if strings.Contains(lineLower, "read-host") ||
							strings.Contains(lineLower, "param(") ||
							strings.Contains(lineLower, "[string]") ||
							strings.Contains(lineLower, "[securestring]") ||
							strings.Contains(lineLower, "os.environ") ||
							strings.Contains(lineLower, "os.getenv") ||
							strings.Contains(lineLower, "process.env") ||
							strings.Contains(lineLower, "$env:") {
							continue
						}

						dummyValues := []string{
							`""`, `''`, `"admin"`, `'admin'`, `"password"`, `'password'`,
							`"passwd"`, `'passwd'`, `"changeme"`, `'changeme'`,
							`"your_password"`, `'your_password'`, `"<password>"`, `'<password>'`,
							`"dummy"`, `'dummy'`, `"example"`, `'example'`, `"test"`, `'test'`,
							`"sample"`, `'sample'`, `"placeholder"`, `'placeholder'`,
							`"default"`, `'default'`, `"root"`, `'root'`, `"null"`, `'null'`,
							`"none"`, `'none'`, `"123456"`, `'123456'`, `"secret"`, `'secret'`,
						}
						isDummy := false
						for _, dv := range dummyValues {
							if strings.Contains(lineLower, dv) {
								isDummy = true
								break
							}
						}
						if strings.Contains(lineLower, `="$`) || strings.Contains(lineLower, `:'$`) || strings.Contains(lineLower, `="%"`) || strings.Contains(lineLower, `="${`) {
							isDummy = true
						}
						if isDummy {
							continue
						}
					}

					// Skip safe fixed tool executions for command injection
					if r.id == "VG-CMD-001" {
						if strings.Contains(line, `exec.Command("git"`) || strings.Contains(line, `exec.CommandContext`) {
							continue
						}
					}

					// Skip localhost, loopback, and schemas for Insecure HTTP rule
					if r.id == "VG-HTTP-001" {
						lineLower := strings.ToLower(line)
						if strings.Contains(lineLower, "http://localhost") ||
							strings.Contains(lineLower, "http://127.0.0.1") ||
							strings.Contains(lineLower, "http://0.0.0.0") ||
							strings.Contains(lineLower, "http://::1") ||
							strings.Contains(lineLower, "http://[::1]") ||
							strings.Contains(lineLower, "w3.org") ||
							strings.Contains(lineLower, "schemas.") ||
							strings.Contains(lineLower, "json-schema.org") ||
							strings.Contains(lineLower, "apache.org") ||
							strings.Contains(lineLower, "example.com") ||
							strings.Contains(lineLower, "example.org") ||
							strings.Contains(lineLower, "http://{") ||
							strings.Contains(lineLower, "http://${") ||
							strings.Contains(lineLower, "http://%") {
							continue
						}
					}
					counter++
					evidence := strings.TrimSpace(line)
					if r.category == "secret" {
						if len(evidence) > 8 {
							evidence = evidence[:8] + "****"
						} else {
							evidence = "****"
						}
					}

					findings = append(findings, Finding{
						ID:             fmt.Sprintf("VG-%03d", counter),
						Category:       r.category,
						Severity:       r.severity,
						Title:          r.name,
						Description:    r.description,
						File:           relPath,
						Line:           lineNum,
						Evidence:       evidence,
						Recommendation: r.recommendation,
						Confidence:     "HIGH",
					})
				}
			}
		}
	}

	projectName := filepath.Base(projectPath)
	duration := time.Since(start).Milliseconds()

	return &ScanResult{
		Project:      projectName,
		FilesScanned: totalFiles,
		Findings:     findings,
		ScanTimeMs:   duration,
	}, nil
}

`

---
## internal/scanner/runner_test.go

`
package scanner

import (
	"path/filepath"
	"testing"
)

func TestInternalScannerOnTestProject(t *testing.T) {
	testProjDir, err := filepath.Abs("../../test-project")
	if err != nil {
		t.Fatalf("failed to resolve test-project path: %v", err)
	}

	result, err := RunInternalScanner(testProjDir)
	if err != nil {
		t.Fatalf("RunInternalScanner failed: %v", err)
	}

	if result.FilesScanned == 0 {
		t.Errorf("expected files to be scanned, got 0")
	}

	if len(result.Findings) == 0 {
		t.Errorf("expected findings in vulnerable test-project, got 0")
	}

	foundSecret := false
	foundSQL := false
	foundDocker := false

	for _, f := range result.Findings {
		if f.Category == "secret" {
			foundSecret = true
		}
		if f.Title == "Potential SQL Injection" {
			foundSQL = true
		}
		if f.Category == "docker" {
			foundDocker = true
		}
	}

	if !foundSecret {
		t.Errorf("expected at least one secret finding in test-project")
	}
	if !foundSQL {
		t.Errorf("expected Potential SQL injection finding in test-project")
	}
	if !foundDocker {
		t.Errorf("expected docker finding in test-project")
	}
}

func TestInternalScannerExclusions(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to get root: %v", err)
	}

	result, err := RunInternalScanner(root)
	if err != nil {
		t.Fatalf("RunInternalScanner on root failed: %v", err)
	}

	// Verify excluded files are not reported as findings
	for _, f := range result.Findings {
		if f.File == "tests/sast/vulnerable.go" {
			t.Errorf("excluded test file %s was scanned and reported as finding", f.File)
		}
	}
}

`

---
## rules/README.md

`
# VibeGuard ? Security Rules Specification

This directory documents the built-in security detection rules enforced by the VibeGuard scanner engine.

## 1. Secret & Credential Detection Rules

| Rule ID | Name | Target Pattern / Evidence | Severity |
| :--- | :--- | :--- | :---: |
| `VG-SEC-001` | AWS Access Key | `AKIA[0-9A-Z]{16}` | `CRITICAL` |
| `VG-SEC-002` | GitHub Personal Access Token | `ghp_[a-zA-Z0-9]{36}` | `CRITICAL` |
| `VG-SEC-003` | Slack Token | `xox[bprs]-[a-zA-Z0-9-]+` | `CRITICAL` |
| `VG-SEC-004` | Private Cryptographic Key | `-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----` | `CRITICAL` |
| `VG-SEC-005` | Hardcoded Password Assignment | `(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]` | `CRITICAL` |
| `VG-SEC-006` | Hardcoded Secret / Token | `(token|secret|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]` | `CRITICAL` |
| `VG-SEC-007` | Generic Credential Assignment | `(api[_-]?key|apikey|credential)\s*[:=]\s*['"][^'"]{8,}` | `CRITICAL` |
| `VG-SEC-008` | Sensitive File in Repository | `.env`, `*.pem`, `*.key`, `id_rsa`, `id_dsa`, `credentials.*` | `CRITICAL` |

All detected credentials have their secrets automatically masked (`sk-demo-****`) in output reports.

---

## 2. Static Application Security Testing (SAST) Rules

| Rule ID | Name | Description | Severity |
| :--- | :--- | :--- | :---: |
| `VG-SAST-001` | Potential SQL Injection | Dynamic query concatenation without parameterized placeholders | `HIGH` |
| `VG-SAST-002` | Potential OS Command Injection | Untrusted shell execution via system/exec functions | `HIGH` |
| `VG-SAST-003` | Dangerous Eval Function | Dynamic code evaluation (`eval()`, `Function()`, `exec()`) | `HIGH` |
| `VG-SAST-004` | Potential TLS Misconfiguration | Disabled certificate verification (`InsecureSkipVerify: true`) | `HIGH` |
| `VG-SAST-005` | Weak Cryptography | Use of deprecated algorithms (`MD5`, `SHA1`, `DES`, `RC4`) | `MEDIUM` |
| `VG-SAST-006` | Potential Insecure HTTP Connection | Unencrypted plaintext HTTP URL in production code | `MEDIUM` |
| `VG-SAST-007` | Hardcoded Credentials | Embedded passwords in source code declarations | `HIGH` |

---

## 3. Container & Dockerfile Security Rules

| Rule ID | Name | Description | Severity |
| :--- | :--- | :--- | :---: |
| `VG-DCK-001` | Container Running as Root | Missing non-root `USER` instruction | `HIGH` |
| `VG-DCK-002` | Secret in Container Environment | Sensitive data stored in `ENV` instructions | `CRITICAL` |
| `VG-DCK-003` | Unbounded Directory Copy | `COPY . .` used without `.dockerignore` exclusion | `MEDIUM` |
| `VG-DCK-004` | Missing Healthcheck | Container lacks `HEALTHCHECK` definition | `LOW` |
| `VG-DCK-005` | Floating Container Tag | Use of `:latest` tag instead of pinned digest or version | `MEDIUM` |

---

## 4. Configuration Security Rules

| Rule ID | Name | Description | Severity |
| :--- | :--- | :--- | :---: |
| `VG-CFG-001` | Debug Mode Enabled | Debugging flags active in production configuration | `MEDIUM` |
| `VG-CFG-002` | Permissive CORS Policy | Wildcard `Access-Control-Allow-Origin: *` configured | `MEDIUM` |
| `VG-CFG-003` | Insecure Interface Binding | Server bound to all network interfaces (`0.0.0.0`) | `LOW` |

`

---
## run_test.bat

`
@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Health Check & Validation Script (run_test.bat)
::  Validates CLI, Scanner, Version, Scan, Report & Security Gate
:: ============================================================

:: 1. Detect project root
set "ROOT=%~dp0"
cd /d "%ROOT%"

:: Locate installed or local binary
set "CLI_BIN=%LOCALAPPDATA%\VibeGuard\vibeguard.exe"
if not exist "%CLI_BIN%" (
    set "CLI_BIN=%ROOT%vibeguard.exe"
)

set "SCANNER_BIN=%LOCALAPPDATA%\VibeGuard\scanner.exe"
if not exist "%SCANNER_BIN%" (
    if exist "%ROOT%scanner\scanner.exe" (
        set "SCANNER_BIN=%ROOT%scanner\scanner.exe"
    ) else if exist "%ROOT%vibeguard-scanner.exe" (
        set "SCANNER_BIN=%ROOT%vibeguard-scanner.exe"
    )
)

echo ========================================
echo        VIBEGUARD HEALTH TEST
echo ========================================
echo.

:: Check 1: CLI found
if not exist "%CLI_BIN%" (
    echo [FAIL] CLI binary not found.
    echo Please run setup.bat or build.bat first.
    exit /b 1
)
echo [PASS] CLI found

:: Check 2: Scanner found
if not exist "%SCANNER_BIN%" (
    echo [FAIL] Scanner binary not found.
    echo Please run setup.bat or build.bat first.
    exit /b 1
)
echo [PASS] Scanner found

:: Check 3: Version command
for /f "tokens=*" %%v in ('"%CLI_BIN%" version 2^>nul') do set "VER_OUT=%%v"
if not defined VER_OUT (
    echo [FAIL] Version command failed.
    exit /b 1
)
echo [PASS] Version command

:: Check 4: Test project scan
if not exist "%ROOT%test-project" (
    echo [FAIL] Test project fixture not found.
    exit /b 1
)
:: Run scan quietly to test detection logic
call "%CLI_BIN%" scan "%ROOT%test-project" --format json --output "%TEMP%\vg-test-scan.json" >nul 2>&1
set "SCAN_EXIT=%ERRORLEVEL%"
if %SCAN_EXIT% neq 0 if %SCAN_EXIT% neq 1 (
    echo [FAIL] Test project scan returned runtime error %SCAN_EXIT%.
    exit /b %SCAN_EXIT%
)
echo [PASS] Test project scan

:: Check 5: Report generation
call "%CLI_BIN%" report "%ROOT%test-project" --format html --output "%TEMP%\vg-test-report.html" >nul 2>&1
if not exist "%TEMP%\vg-test-report.html" (
    echo [FAIL] Report generation failed to produce output file.
    exit /b 1
)
del /f /q "%TEMP%\vg-test-report.html" >nul 2>&1
del /f /q "%TEMP%\vg-test-scan.json" >nul 2>&1
echo [PASS] Report generation

:: Check 6: Security gate policy enforcement
:: test-project has intentional vulnerabilities; gate should block (exit 1)
call "%CLI_BIN%" scan "%ROOT%test-project" --hook >nul 2>&1
set "GATE_EXIT=%ERRORLEVEL%"
if %GATE_EXIT% equ 1 (
    echo [PASS] Security gate
) else (
    echo [FAIL] Security gate did not block vulnerable fixture: exit code %GATE_EXIT%
    exit /b 1
)

echo.
echo ========================================
echo        ALL TESTS PASSED
echo ========================================
echo.

endlocal

`

---
## scanner/Cargo.lock

`
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "aho-corasick"
version = "1.1.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c982642fa9e8606056828ee9a8505737230110bb1099153c79efe865c59d12ba"
dependencies = [
 "memchr",
]

[[package]]
name = "itoa"
version = "1.0.18"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682"

[[package]]
name = "memchr"
version = "2.8.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98"

[[package]]
name = "proc-macro2"
version = "1.0.107"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9"
dependencies = [
 "unicode-ident",
]

[[package]]
name = "quote"
version = "1.0.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001"
dependencies = [
 "proc-macro2",
]

[[package]]
name = "regex"
version = "1.13.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f020237b6c8eed93db2e2cb53c00c60a8e1bc73da7d073199a1180401450218d"
dependencies = [
 "aho-corasick",
 "memchr",
 "regex-automata",
 "regex-syntax",
]

[[package]]
name = "regex-automata"
version = "0.4.18"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ad8553b9b26413251cbf30e620595c7a41b3887f03da04579c0e6b0d6a06b4b2"
dependencies = [
 "aho-corasick",
 "memchr",
 "regex-syntax",
]

[[package]]
name = "regex-syntax"
version = "0.8.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4"

[[package]]
name = "same-file"
version = "1.0.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "93fc1dc3aaa9bfed95e02e6eadabb4baf7e3078b0bd1b4d7b6b0b68378900502"
dependencies = [
 "winapi-util",
]

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba"
dependencies = [
 "serde_core",
 "serde_derive",
]

[[package]]
name = "serde_core"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48"
dependencies = [
 "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348"
dependencies = [
 "proc-macro2",
 "quote",
 "syn",
]

[[package]]
name = "serde_json"
version = "1.0.151"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14"
dependencies = [
 "itoa",
 "memchr",
 "serde",
 "serde_core",
 "zmij",
]

[[package]]
name = "syn"
version = "3.0.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8593e8e72159ed2257d083c7a454a85cbf854f37a0966d8d483aff8c8a3ebcee"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "unicode-ident"
version = "1.0.26"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d245f478577f809a851594d02313b640fb437e0bb33866753cff937863096954"

[[package]]
name = "vibeguard-scanner"
version = "0.1.0"
dependencies = [
 "regex",
 "serde",
 "serde_json",
 "walkdir",
]

[[package]]
name = "walkdir"
version = "2.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "29790946404f91d9c5d06f9874efddea1dc06c5efe94541a7d6863108e3a5e4b"
dependencies = [
 "same-file",
 "winapi-util",
]

[[package]]
name = "winapi-util"
version = "0.1.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c2a7b1c03c876122aa43f3020e6c3c3ee5c05081c9a00739faf7503aeba10d22"
dependencies = [
 "windows-sys",
]

[[package]]
name = "windows-link"
version = "0.2.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5"

[[package]]
name = "windows-sys"
version = "0.61.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc"
dependencies = [
 "windows-link",
]

[[package]]
name = "zmij"
version = "1.0.23"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b"

`

---
## scanner/Cargo.toml

`
[package]
name = "vibeguard-scanner"
version = "0.1.0"
edition = "2021"

[dependencies]
walkdir = "2"
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

`

---
## scanner/src/config.rs

`
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn scan_config(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let debug_re = Regex::new(r#"(?i)(debug.*true|DEBUG.*=.*1)"#).unwrap();
    let cors_re = Regex::new(r#"(?i)Access-Control-Allow-Origin.*\*"#).unwrap();
    let bind_re = Regex::new(r#"0\.0\.0\.0"#).unwrap();
    let http_re = Regex::new(r#"(?i)(endpoint|url).*http://"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        
        if debug_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Debug Mode Enabled".to_string(),
                description: "Debug mode appears to be enabled in configuration.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Disable debug mode in production environments.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if cors_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Wildcard CORS Allowed".to_string(),
                description: "CORS is configured to allow all origins (*).".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Restrict CORS origins to trusted domains.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if bind_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::LOW,
                title: "Binding to 0.0.0.0".to_string(),
                description: "Service is bound to all network interfaces (0.0.0.0).".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Ensure binding to 0.0.0.0 is intentional and properly firewalled.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
        
        if http_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Plain HTTP Endpoint".to_string(),
                description: "Configuration uses plain HTTP URLs.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Use HTTPS for all endpoints.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
    }

    findings
}

`

---
## scanner/src/docker.rs

`
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn scan_dockerfile(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let mut has_user = false;
    let mut uses_latest = false;
    let mut has_healthcheck = false;

    let env_secret_re = Regex::new(r#"(?i)ENV\s+.*(secret|token|password|key)\s*="#).unwrap();
    let copy_all_re = Regex::new(r#"COPY\s+\.\s+\."#).unwrap();
    let expose_re = Regex::new(r#"EXPOSE\s+.*"#).unwrap();
    let from_latest_re = Regex::new(r#"(?i)FROM\s+.*:latest"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        
        if line.trim().starts_with("USER ") {
            let user = line.trim().replace("USER ", "").trim().to_string();
            if user != "root" && user != "0" {
                has_user = true;
            }
        }
        
        if line.trim().starts_with("HEALTHCHECK") {
            has_healthcheck = true;
        }

        if env_secret_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::CRITICAL,
                title: "Secrets in ENV".to_string(),
                description: "Environment variables in Dockerfiles can expose secrets.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Avoid setting sensitive data in ENV. Use runtime secrets.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if copy_all_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "COPY . . without caution".to_string(),
                description: "Using COPY . . can copy unintended sensitive files into the image.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Use a .dockerignore file and specify explicit paths.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
        
        if expose_re.is_match(line) {
            let ports = line.split_whitespace().count() - 1;
            if ports > 3 {
                *finding_counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::Docker,
                    severity: Severity::LOW,
                    title: "Privileged/Many port exposure".to_string(),
                    description: "Exposing many ports could increase the attack surface.".to_string(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some("Only EXPOSE necessary ports.".to_string()),
                    confidence: "LOW".to_string(),
                });
            }
        }
        
        if from_latest_re.is_match(line) {
            uses_latest = true;
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Using latest tag".to_string(),
                description: "Base image is using the 'latest' tag.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Pin base images to specific versions.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
    }
    
    if !has_user {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Docker,
            severity: Severity::HIGH,
            title: "Running as root".to_string(),
            description: "No non-root USER specified in the Dockerfile.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Add a non-root USER instruction.".to_string()),
            confidence: "HIGH".to_string(),
        });
    }
    
    if !has_healthcheck {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Docker,
            severity: Severity::LOW,
            title: "Missing HEALTHCHECK".to_string(),
            description: "No HEALTHCHECK instruction defined.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Add a HEALTHCHECK to ensure the container is running correctly.".to_string()),
            confidence: "MEDIUM".to_string(),
        });
    }

    findings
}

`

---
## scanner/src/git.rs

`
use crate::types::{Category, Finding, Severity};
use std::path::Path;

pub fn scan_git_security(scanned_files: &[String], finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file_path in scanned_files {
        let file_name = Path::new(file_path).file_name().and_then(|n| n.to_str()).unwrap_or("");
        
        let bad_files = [".env", "id_rsa", "id_dsa", ".htpasswd"];
        let is_bad = bad_files.contains(&file_name) 
            || file_name.starts_with("credentials.") 
            || file_name.ends_with(".pem");
            
        if is_bad {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Git,
                severity: Severity::CRITICAL,
                title: "Sensitive File Tracked".to_string(),
                description: "A potentially sensitive file is present in the repository structure.".to_string(),
                file: file_path.clone(),
                line: 1,
                evidence: Some(file_name.to_string()),
                recommendation: Some("Add this file to .gitignore and remove it from tracking if necessary.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
    }
    
    findings
}

`

---
## scanner/src/main.rs

`
mod config;
mod docker;
mod git;
mod rules;
mod sast;
mod scanner;
mod secrets;
mod types;

use std::env;
use std::fs;
use std::path::Path;
use std::time::Instant;

use serde_json::json;
use types::ScanResult;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "{}",
            json!({ "error": "Usage: vibeguard-scanner <project_path> [--no-secrets] [--no-sast]" })
        );
        std::process::exit(2);
    }

    let project_path = &args[1];
    let start_time = Instant::now();

    // Check CLI flags
    let cli_no_secrets = args.iter().any(|a| a == "--no-secrets");
    let cli_no_sast = args.iter().any(|a| a == "--no-sast");
    let emit_progress = args.iter().any(|a| a == "--progress");

    // Check .vibeguard/config.json if present
    let mut enable_secrets = !cli_no_secrets;
    let mut enable_sast = !cli_no_sast;

    let cfg_file = Path::new(project_path).join(".vibeguard").join("config.json");
    if let Ok(cfg_data) = fs::read_to_string(&cfg_file) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cfg_data) {
            if let Some(sec) = parsed.get("secret_scan").and_then(|v| v.as_bool()) {
                if !sec {
                    enable_secrets = false;
                }
            }
            if let Some(src) = parsed.get("source_scan").and_then(|v| v.as_bool()) {
                if !src {
                    enable_sast = false;
                }
            }
        }
    }

    let files = scanner::scan_directory(project_path);
    let total_files = files.len();
    let mut all_findings = Vec::new();
    let mut finding_counter = 0;

    for (idx, file_path) in files.iter().enumerate() {
        if emit_progress {
            eprintln!("PROGRESS:{}:{}:{}", idx + 1, total_files, file_path);
        }

        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip files that can't be read as string (e.g. binary)
        };

        if enable_secrets {
            let mut findings = secrets::scan_secrets(file_path, &content, &mut finding_counter);
            all_findings.append(&mut findings);
        }

        if enable_sast {
            let mut findings = sast::scan_source_code(file_path, &content, &mut finding_counter);
            all_findings.append(&mut findings);
        }

        let filename = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        let ext = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        if filename == "Dockerfile" || filename.ends_with(".dockerfile") {
            let mut docker_findings = docker::scan_dockerfile(file_path, &content, &mut finding_counter);
            all_findings.append(&mut docker_findings);
        }

        let source_exts = ["go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs"];
        let config_exts = ["yaml", "yml", "toml", "ini", "conf", "cfg", "json"];
        if config_exts.contains(&ext) || (filename.starts_with("config.") && !source_exts.contains(&ext)) {
            let mut config_findings = config::scan_config(file_path, &content, &mut finding_counter);
            all_findings.append(&mut config_findings);
        }
    }

    if enable_secrets {
        let mut git_findings = git::scan_git_security(&files, &mut finding_counter);
        all_findings.append(&mut git_findings);
    }

    let project_name = Path::new(project_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let duration = start_time.elapsed().as_millis() as u64;

    let result = ScanResult {
        project: project_name,
        files_scanned: files.len(),
        findings: all_findings,
        scan_time_ms: duration,
    };

    match serde_json::to_string(&result) {
        Ok(json_out) => println!("{}", json_out),
        Err(e) => {
            eprintln!("{}", json!({ "error": format!("Serialization failed: {}", e) }));
            std::process::exit(2);
        }
    }
}

`

---
## scanner/src/rules.rs

`
use crate::types::{Category, Severity};
use regex::Regex;

pub struct Rule {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub severity: Severity,
    pub pattern: Regex,
    pub description: String,
    pub recommendation: String,
}

pub fn get_sast_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SAST-001".to_string(),
            name: "Potential SQL Injection".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(fmt\.Sprintf\("SELECT|"SELECT.*"\+|query.*\+.*request|execute\("SELECT)"#).unwrap(),
            description: "Potential SQL injection vulnerability detected.".to_string(),
            recommendation: "Use parameterized queries or prepared statements.".to_string(),
        },
        Rule {
            id: "SAST-002".to_string(),
            name: "Potential OS Command Injection".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(exec\.Command|os\.system\(|subprocess\.call\(|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec\()"#).unwrap(),
            description: "Potential OS command injection vulnerability detected.".to_string(),
            recommendation: "Avoid executing OS commands with user input. Use safe APIs.".to_string(),
        },
        Rule {
            id: "SAST-003".to_string(),
            name: "Dangerous Eval".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(eval\(|Function\(|exec\()"#).unwrap(),
            description: "Use of dangerous evaluation functions detected.".to_string(),
            recommendation: "Avoid using eval or similar functions on untrusted input.".to_string(),
        },
        Rule {
            id: "SAST-004".to_string(),
            name: "Potential TLS Misconfiguration".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(InsecureSkipVerify.*true|verify.*False|rejectUnauthorized.*false|NODE_TLS_REJECT_UNAUTHORIZED)"#).unwrap(),
            description: "TLS verification seems to be disabled.".to_string(),
            recommendation: "Enable TLS verification for all network connections in production.".to_string(),
        },
        Rule {
            id: "SAST-005".to_string(),
            name: "Weak Crypto".to_string(),
            category: Category::SourceCode,
            severity: Severity::MEDIUM,
            pattern: Regex::new(r#"(?i)\b(md5|sha1|DES|RC4|Math\.random\(\))\b"#).unwrap(),
            description: "Weak cryptographic algorithm or PRNG detected.".to_string(),
            recommendation: "Use strong algorithms (e.g., SHA-256, AES) and secure PRNGs.".to_string(),
        },
        Rule {
            id: "SAST-006".to_string(),
            name: "Potential Insecure HTTP Connection".to_string(),
            category: Category::SourceCode,
            severity: Severity::MEDIUM,
            pattern: Regex::new(r#"http://[^\s"'>]+"#).unwrap(),
            description: "Insecure HTTP connection detected.".to_string(),
            recommendation: "Use HTTPS for all network communication.".to_string(),
        },
        Rule {
            id: "SAST-007".to_string(),
            name: "Hardcoded Credentials".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)password\s*=\s*"[^"]+""#).unwrap(),
            description: "Hardcoded credentials in source code.".to_string(),
            recommendation: "Use environment variables or a secret management service.".to_string(),
        },
    ]
}

pub fn get_secret_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SEC-001".to_string(),
            name: "AWS Access Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
            description: "AWS Access Key ID detected.".to_string(),
            recommendation: "Revoke the key immediately and use IAM roles instead.".to_string(),
        },
        Rule {
            id: "SEC-002".to_string(),
            name: "Generic API Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}"#).unwrap(),
            description: "Generic API Key detected.".to_string(),
            recommendation: "Remove the key from code and use a secret manager.".to_string(),
        },
        Rule {
            id: "SEC-003".to_string(),
            name: "GitHub Token".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"ghp_[a-zA-Z0-9]{36}"#).unwrap(),
            description: "GitHub Personal Access Token detected.".to_string(),
            recommendation: "Revoke the token and generate a new one if needed.".to_string(),
        },
        Rule {
            id: "SEC-004".to_string(),
            name: "Slack Token".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"xox[bprs]-[a-zA-Z0-9-]+"#).unwrap(),
            description: "Slack Token detected.".to_string(),
            recommendation: "Revoke and rotate the Slack token.".to_string(),
        },
        Rule {
            id: "SEC-005".to_string(),
            name: "Private Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----"#).unwrap(),
            description: "Private cryptographic key detected.".to_string(),
            recommendation: "Remove private keys from the repository.".to_string(),
        },
        Rule {
            id: "SEC-006".to_string(),
            name: "Password Assignment".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]"#).unwrap(),
            description: "Hardcoded password assignment detected.".to_string(),
            recommendation: "Use environment variables for passwords.".to_string(),
        },
        Rule {
            id: "SEC-007".to_string(),
            name: "Token/Secret Assignment".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(token|secret|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]"#).unwrap(),
            description: "Hardcoded token or secret assignment detected.".to_string(),
            recommendation: "Move secrets to secure storage or environment variables.".to_string(),
        },
        Rule {
            id: "SEC-008".to_string(),
            name: "Generic Credential".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(secret|credential)\s*[:=]\s*['"][^'"]{8,}['"]"#).unwrap(),
            description: "Generic secret or credential detected.".to_string(),
            recommendation: "Securely manage all credentials outside of source control.".to_string(),
        },
    ]
}

`

---
## scanner/src/sast.rs

`
use crate::types::{Category, Finding};
use crate::rules::get_sast_rules;
use std::path::Path;

pub fn scan_source_code(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let ext = Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
    let allowed_exts = ["go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs"];
    if !allowed_exts.contains(&ext) {
        return findings;
    }

    let rules = get_sast_rules();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // Skip comment lines
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with("--") {
            continue;
        }

        for rule in &rules {
            if rule.pattern.is_match(line) {
                if line.contains("Regex::new") || line.contains("regexp.MustCompile") || line.contains("pattern:") || line.contains(r#"contains("http"#) || line.contains(r#"contains(lineLower, "http"#) {
                    continue;
                }
                if rule.id == "SAST-002" {
                    if line.contains(r#"exec.Command("git""#) || line.contains("exec.CommandContext") {
                        continue;
                    }
                }
                if rule.id == "SAST-006" {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("http://localhost")
                        || line_lower.contains("http://127.0.0.1")
                        || line_lower.contains("http://0.0.0.0")
                        || line_lower.contains("http://::1")
                        || line_lower.contains("http://[::1]")
                        || line_lower.contains("w3.org")
                        || line_lower.contains("schemas.")
                        || line_lower.contains("json-schema.org")
                        || line_lower.contains("apache.org")
                        || line_lower.contains("example.com")
                        || line_lower.contains("example.org")
                        || line_lower.contains("http://{")
                        || line_lower.contains("http://${")
                        || line_lower.contains("http://%")
                    {
                        continue;
                    }
                }
                *finding_counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::SourceCode,
                    severity: rule.severity.clone(),
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some(rule.recommendation.clone()),
                    confidence: "MEDIUM".to_string(),
                });
            }
        }
    }


    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sql_injection() {
        let mut counter = 0;
        let content = "let q = fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", input);\n";
        let findings = scan_source_code("db.go", content, &mut counter);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "Potential SQL Injection");
    }

    #[test]
    fn test_ignore_unsupported_extensions() {
        let mut counter = 0;
        let content = "fmt.Sprintf(\"SELECT * FROM users\")";
        let findings = scan_source_code("readme.md", content, &mut counter);
        assert!(findings.is_empty());
    }
}

`

---
## scanner/src/scanner.rs

`
use std::path::Path;
use walkdir::WalkDir;

pub fn scan_directory(path: &str) -> Vec<String> {
    let mut files = Vec::new();

    let skipped_dirs = [
        "node_modules", "vendor", ".git", "target", "__pycache__", ".venv", "venv", "env",
        "dist", "build", "htmlcov", ".coverage", "coverage", ".pytest_cache", ".mypy_cache",
        ".tox", ".nyc_output", ".idea", ".vscode",
    ];

    let skipped_exts = [
        "exe", "dll", "so", "dylib", "bin", "dat", "zip", "tar", "gz", "png", "jpg", "gif", "mp4",
        "pdf",
    ];

    let mut config_excludes: Vec<String> = Vec::new();
    let config_path = Path::new(path).join(".vibeguard").join("config.json");
    if config_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&config_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(arr) = val.get("exclude").and_then(|e| e.as_array()) {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            config_excludes.push(s.replace('\\', "/"));
                        }
                    }
                }
            }
        }
    }

    let gitignore_path = Path::new(path).join(".gitignore");
    if gitignore_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&gitignore_path) {
            for line in data.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let pat = trimmed.trim_start_matches('/').trim_end_matches('/').replace('\\', "/");
                if !pat.is_empty() {
                    config_excludes.push(pat);
                }
            }
        }
    }

    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();
        
        let mut skip = false;
        for component in file_path.components() {
            if let Some(comp_str) = component.as_os_str().to_str() {
                if skipped_dirs.contains(&comp_str) {
                    skip = true;
                    break;
                }
            }
        }

        let rel_path = file_path.strip_prefix(path).unwrap_or(file_path);
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let rel_clean = rel_str.trim_start_matches('/');

        for exc in &config_excludes {
            let exc_clean = exc.trim_start_matches('/');
            if exc_clean.is_empty() {
                continue;
            }
            if exc_clean.starts_with("*.") {
                let ext_pattern = &exc_clean[1..]; // e.g. ".key"
                if rel_clean.ends_with(ext_pattern) {
                    skip = true;
                    break;
                }
            }
            if rel_clean == exc_clean || rel_clean.starts_with(&format!("{}/", exc_clean)) {
                skip = true;
                break;
            }
            if let Some(file_name) = file_path.file_name().and_then(|f| f.to_str()) {
                if file_name == exc_clean {
                    skip = true;
                    break;
                }
            }
        }
        
        if let Some(ext) = file_path.extension().and_then(|s| s.to_str()) {
            if skipped_exts.contains(&ext) {
                skip = true;
            }
        }

        
        if !skip {
            if let Some(path_str) = file_path.to_str() {
                files.push(path_str.to_string());
            }
        }
    }
    
    files
}

`

---
## scanner/src/secrets.rs

`
use crate::types::{Category, Finding, Severity};
use crate::rules::get_secret_rules;

pub fn scan_secrets(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = get_secret_rules();

    let ext = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let doc_exts = ["md", "markdown", "rst", "txt", "adoc", "html", "htm"];
    let is_doc = doc_exts.contains(&ext.as_str());

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // Skip pure comments for assignment rules
        let is_comment = trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with("--");

        for rule in &rules {
            // Generic assignment rules should not run on documentation files
            if is_doc && (rule.id == "SEC-006" || rule.id == "SEC-007" || rule.id == "SEC-008") {
                continue;
            }

            if is_comment && (rule.id == "SEC-006" || rule.id == "SEC-007" || rule.id == "SEC-008") {
                continue;
            }

            if let Some(caps) = rule.pattern.captures(line) {
                // False positive filtering for password / token assignments
                if rule.id == "SEC-006" || rule.id == "SEC-007" || rule.id == "SEC-008" {
                    let matched_str = caps.get(0).map_or("", |m| m.as_str()).to_lowercase();
                    let line_lower = line.to_lowercase();

                    // Check for variable syntax or placeholders
                    if line_lower.contains("read-host")
                        || line_lower.contains("param(")
                        || line_lower.contains("[string]")
                        || line_lower.contains("[securestring]")
                        || line_lower.contains("os.environ")
                        || line_lower.contains("os.getenv")
                        || line_lower.contains("process.env")
                        || line_lower.contains("os.getenv")
                        || line_lower.contains("$env:")
                    {
                        continue;
                    }

                    // Check if the value is a dummy/placeholder/variable
                    let dummy_values = [
                        "\"\"", "''", "\"admin\"", "'admin'", "\"password\"", "'password'",
                        "\"passwd\"", "'passwd'", "\"changeme\"", "'changeme'",
                        "\"your_password\"", "'your_password'", "\"<password>\"", "'<password>'",
                        "\"dummy\"", "'dummy'", "\"example\"", "'example'", "\"test\"", "'test'",
                        "\"sample\"", "'sample'", "\"placeholder\"", "'placeholder'",
                        "\"default\"", "'default'", "\"root\"", "'root'", "\"null\"", "'null'",
                        "\"none\"", "'none'", "\"123456\"", "'123456'", "\"secret\"", "'secret'",
                    ];
                    let mut is_dummy = false;
                    for dv in &dummy_values {
                        if matched_str.contains(dv) {
                            is_dummy = true;
                            break;
                        }
                    }
                    // Variable reference in string: e.g. "$password" or "%password%" or "${password}"
                    if matched_str.contains("=\"$") || matched_str.contains(":'$") || matched_str.contains("=\"%") || matched_str.contains("=\"${") {
                        is_dummy = true;
                    }

                    if is_dummy {
                        continue;
                    }
                }

                *finding_counter += 1;
                
                let mut evidence = caps.get(0).map_or("", |m| m.as_str()).to_string();
                if evidence.len() > 8 {
                    evidence = format!("{}****", &evidence[..8]);
                } else {
                    evidence = "****".to_string();
                }

                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::Secret,
                    severity: Severity::CRITICAL,
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(evidence),
                    recommendation: Some(rule.recommendation.clone()),
                    confidence: "HIGH".to_string(),
                });
            }
        }
    }


    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let bad_filenames = [".env", "id_rsa", "id_dsa", ".htpasswd"];
    let bad_exts = ["pem", "key"];

    let ext = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
    let source_exts = ["go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs"];

    let mut is_bad_file = false;
    if !source_exts.contains(&ext) {
        is_bad_file = bad_filenames.contains(&file_name) || file_name.starts_with("credentials.") || file_name.starts_with("secrets.");
        if !is_bad_file && bad_exts.contains(&ext) {
            is_bad_file = true;
        }
    }

    if is_bad_file && findings.is_empty() {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            title: "Sensitive File Detected".to_string(),
            description: "A file commonly used to store secrets or credentials was found.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Ensure this file is not committed to version control and does not contain sensitive data.".to_string()),
            confidence: "HIGH".to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aws_key() {
        let mut counter = 0;
        let content = format!("aws_key = {}1234567890ABCDEF\n", "AKIA");
        let findings = scan_secrets("config.py", &content, &mut counter);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "AWS Access Key");
        assert_eq!(counter, 1);
        assert!(findings[0].evidence.as_ref().unwrap().contains("****"));
    }

    #[test]
    fn test_clean_file_no_secrets() {
        let mut counter = 0;
        let content = "let username = \"john_doe\";\nlet port = 8080;\n";
        let findings = scan_secrets("main.rs", content, &mut counter);
        assert!(findings.is_empty());
        assert_eq!(counter, 0);
    }
}

`

---
## scanner/src/types.rs

`
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secret,
    SourceCode,
    Dependency,
    Configuration,
    Docker,
    Git,
    File,
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub evidence: Option<String>,
    pub recommendation: Option<String>,
    pub confidence: String,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub project: String,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
    pub scan_time_ms: u64,
}

`

---
## setup.bat

`
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

`

---
## test-project/.env

`
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASSWORD=SuperSecret123!
DB_NAME=production_db

# API Keys
API_KEY=sk-demo-1234567890abcdef1234567890abcdef
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# JWT
JWT_SECRET=my-super-secret-jwt-key-that-should-not-be-here

# Stripe
STRIPE_SECRET_KEY=sk_test_fake1234567890abcdefghijklmnop

`

---
## test-project/Dockerfile

`
FROM node:latest

WORKDIR /app

ENV DATABASE_URL=postgresql://admin:password123@db:5432/production
ENV API_SECRET=hardcoded-secret-in-dockerfile
ENV NODE_ENV=production

COPY . .

RUN npm install

EXPOSE 3000
EXPOSE 8080
EXPOSE 5432

CMD ["node", "server.js"]

`

---
## test-project/README.md

`
# DemoShop — Deliberately Vulnerable Test Project

> ⚠️ **WARNING**: This project contains intentionally vulnerable code for security testing purposes only.
> All credentials are **FAKE** and should never be used in any real environment.

## Purpose

This project is used by VibeGuard to demonstrate security scanning capabilities.
It contains controlled examples of common security vulnerabilities:

- Hardcoded API keys and passwords
- SQL injection patterns
- Command injection patterns  
- Dangerous eval() usage
- Weak cryptographic algorithms (MD5)
- Disabled TLS verification
- Insecure HTTP endpoints
- Vulnerable dependencies
- Docker security misconfigurations
- Exposed .env file

## Files

| File | Vulnerabilities |
|------|----------------|
| `.env` | Exposed database credentials, API keys, JWT secret |
| `src/config.go` | Hardcoded secrets, disabled TLS, insecure HTTP |
| `src/database.go` | SQL injection, command injection, weak crypto (MD5) |
| `src/auth.js` | eval(), command injection, hardcoded JWT, insecure HTTP |
| `Dockerfile` | Root user, secrets in ENV, latest tag, no healthcheck |
| `go.mod` | Potentially vulnerable Go dependencies |
| `package.json` | Potentially vulnerable npm dependencies |
| `requirements.txt` | Potentially vulnerable Python dependencies |

## Usage

Scan with VibeGuard:
```powershell
.\vibeguard.exe scan .\test-project
```

`

---
## test-project/go.mod

`
module github.com/demo/demoshop

go 1.21

require (
	golang.org/x/crypto v0.0.0-20220314234659-1baeb1ce4c0b
	golang.org/x/text v0.3.7
)

`

---
## test-project/package.json

`
{
  "name": "demoshop-frontend",
  "version": "1.0.0",
  "description": "Demo Shop Frontend - Deliberately Vulnerable",
  "dependencies": {
    "lodash": "4.17.20",
    "express": "4.17.1",
    "jsonwebtoken": "8.5.1",
    "axios": "0.21.1"
  },
  "devDependencies": {
    "nodemon": "2.0.7"
  }
}

`

---
## test-project/requirements.txt

`
Flask==2.0.1
requests==2.25.1
PyJWT==2.3.0
cryptography==3.4.8
Django==3.2.0

`

---
## test-project/src/auth.js

`
const jwt = require('jsonwebtoken');
const http = require('http');
const { exec } = require('child_process');

// Hardcoded JWT secret
const JWT_SECRET = 'super-secret-key-do-not-share';
const API_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

// Dangerous eval usage
function processUserInput(input) {
    const result = eval(input);
    return result;
}

// Another dangerous eval
function computeFormula(formula) {
    return new Function('return ' + formula)();
}

// Command injection
function checkServer(hostname) {
    exec('ping -c 4 ' + hostname, (error, stdout) => {
        console.log(stdout);
    });
}

// Insecure HTTP request
function fetchData() {
    return fetch('http://api.payment-gateway.com/process');
}

// Weak crypto
const crypto = require('crypto');
function hashData(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// Disabled TLS verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

module.exports = { processUserInput, checkServer, fetchData, hashData };

`

---
## test-project/src/config.go

`
package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// Application configuration
var (
	APIKey      = "sk-demo-1234567890abcdef1234567890abcdef"
	DatabaseURL = "postgresql://admin:password123@localhost:5432/mydb"
	JWTSecret   = "my-hardcoded-jwt-secret-key"
	DebugMode   = true
)

func ConnectToAPI() {
	// Disabled TLS verification - INSECURE
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Using insecure HTTP
	resp, err := client.Get("http://api.example.com/data")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
}

func GetPassword() string {
	password := "admin123"
	return password
}

`

---
## test-project/src/database.go

`
package database

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"os/exec"
)

var db *sql.DB

// SQL Injection vulnerability
func GetUser(username string) (*sql.Row, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	row := db.QueryRow(query)
	return row, nil
}

// Another SQL injection
func SearchProducts(term string) (*sql.Rows, error) {
	query := "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
	return db.Query(query)
}

// Command injection vulnerability
func RunDiagnostics(host string) ([]byte, error) {
	cmd := exec.Command("ping", host)
	return cmd.Output()
}

// Weak cryptography
func HashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// Another weak hash
func GenerateToken(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

`

---
## tests/dependencies/Cargo.toml

`
[package]
name = "test-deps"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.100"
regex = "1.4.0"
tokio = { version = "1.0.0", features = ["full"] }

`

---
## tests/dependencies/go.mod

`
module test/deps

go 1.21

require (
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	github.com/gin-gonic/gin v1.6.3
)

`

---
## tests/dependencies/package.json

`
{
  "name": "test-deps",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.15",
    "minimist": "1.2.0"
  },
  "devDependencies": {
    "mocha": "^8.0.1"
  }
}

`

---
## tests/dependencies/requirements.txt

`
# Python dependencies fixture
flask==1.1.2
jinja2==2.11.2
requests>=2.20.0
# Comment line
werkzeug==1.0.1

`

---
## tests/integration/integration_test.go

`
package integration

import (
	"path/filepath"
	"testing"

	"github.com/vibeguard/vibeguard/internal/dependencies"
	"github.com/vibeguard/vibeguard/internal/gate"
	"github.com/vibeguard/vibeguard/internal/risk"
)

func TestEndToEndDependencyDetection(t *testing.T) {
	// Test against the fixtures in tests/dependencies
	fixtureDir, err := filepath.Abs("../dependencies")
	if err != nil {
		t.Fatalf("failed to get fixture path: %v", err)
	}

	deps, err := dependencies.DetectDependencies(fixtureDir)
	if err != nil {
		t.Fatalf("DetectDependencies returned error: %v", err)
	}

	if len(deps) == 0 {
		t.Errorf("expected dependencies to be discovered in fixture dir, got 0")
	}

	// Verify risk score calculation with mock findings
	mockFindings := []risk.FindingInfo{
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
	}
	score := risk.CalculateScore(mockFindings)
	gateRes := gate.EvaluateGate(score.CriticalCount, score.HighCount)

	if gateRes.Status != "BLOCKED" || gateRes.ExitCode != 1 {
		t.Errorf("expected gate to BLOCK with exit code 1, got %s (%d)", gateRes.Status, gateRes.ExitCode)
	}
}

`

---
## tests/sast/safe.go

`
package sample

import (
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"net/http"
)

func SafeOperations(db *sql.DB, userInput string) {
	// Parameterized SQL query
	_ = db.QueryRow("SELECT * FROM accounts WHERE id = ?", userInput)

	// Secure TLS
	_ = &tls.Config{InsecureSkipVerify: false}

	// HTTPS endpoint
	_, _ = http.Get("https://secure-api.internal/endpoint")

	// Strong Crypto
	_ = sha256.Sum256([]byte(userInput))
}

`

---
## tests/sast/vulnerable.go

`
package sample

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"
)

func VulnerableOperations(userInput string) {
	// SQL Injection pattern
	_ = fmt.Sprintf("SELECT * FROM accounts WHERE id = '%s'", userInput)

	// Command injection pattern
	_ = exec.Command("sh", "-c", userInput)

	// Disabled TLS verification
	_ = &tls.Config{InsecureSkipVerify: true}

	// Insecure HTTP
	_, _ = http.Get("http://insecure-api.internal/endpoint")

	// Weak Crypto
	_ = md5.Sum([]byte(userInput))
}

`

---
## tests/secrets/clean_text.txt

`
This is a standard text file with no credentials, secrets, or API keys.
It is used to verify that the scanner produces 0 false positives on clean files.
public_key_name = "guest"
account_type = "free"
welcome_message = "Hello, World!"

`

---
## tests/secrets/fake_keys.txt

`
# Test fixtures for secret detection
AWS_KEY=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_examplefakegithubtokenplaceholder00
GENERIC_API_KEY="api_key = 'abcdef1234567890abcdef1234567890'"
PASSWORD_ASSIGN="password = 'SuperSecretTestPassword!'"
SLACK_TOKEN="xoxb-mock-slack-test-token-not-real"

`

---
## uninstall_hook.bat

`
@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VibeGuard Git Pre-Push Hook Uninstaller (uninstall_hook.bat)
:: ============================================================

set "ROOT=%~dp0"
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

`

---
