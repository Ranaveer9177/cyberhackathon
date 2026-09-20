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

## 5-Stage Security Gate Verification & Interactive Push (v3.0)

When running `git push` (or `vibeguard push`), VibeGuard executes an aligned 5-stage verification gate directly inside developer terminals:

```text
========================================
       VIBEGUARD SECURITY GATE
========================================

[1/5] Detecting project ........ PASS
[2/5] Secret scan .............. PASS
[3/5] Source scan .............. PASS
[4/5] Dependency/CVE scan ...... PASS
[5/5] Security policy .......... PASS
```

Followed by the complete security report, severity summary, and interactive console prompt:

```text
----------------------------------------
Security Score: 94/100
----------------------------------------

Critical : 0
High     : 0
Medium   : 2
Low      : 3

STATUS: SAFE TO PUSH

Proceed with Git push? [Y/N]: 
```

### Guided `vibeguard push` Interactive Flow
Developers can use `vibeguard push` to stage, commit, verify, and push in a single guided command:
1. `Stage these modified files for commit? [Y/n]: `
2. `Enter commit message: `
3. Automatic commit creation & 5-stage security gate verification.
4. `Push to GitHub? [Y/n]: ` — securely pushes to remote upon passing.

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
