# VibeGuard v3.0 — Autonomous Git Pre-Push Security Gate & Code Security Scanner

> **The Autonomous Pre-Push Security Firewall for Engineering Teams**  
> *"Make security verification an automatic, non-negotiable step before code ever leaves your machine."*

---

## Overview

**VibeGuard v3.0** is an enterprise-grade security scanner and autonomous Git pre-push hook gate written in **Go** and **Rust**. It stops hardcoded secrets, dangerous code patterns (SAST), vulnerable third-party dependencies (SCA via Google OSV), Dockerfile misconfigurations, and sensitive configuration leaks *before* they are pushed to remote repositories or deployed to production.

VibeGuard operates directly in developer terminal workflows and CI/CD pipelines:
- **Live Interactive Scan Progress**: Real-time terminal progress bars during file scanning, dependency resolution, and OSV database queries.
- **Autonomous Git Pre-Push Gate**: Intercepts `git push` via standard pre-push hooks. Scans only the exact commits being pushed using pure Go `git archive` snapshotting.
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
├── CHANGELOG.md                 # Full release and version history
├── FEATURES.md                  # Comprehensive feature specification
├── LANGUAGE.md                  # Technical architecture and language decisions
├── PLAN.md                      # Development blueprint & phase tracking
└── README.md                    # Project documentation
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

## Installation & Build

### Prerequisites
- **Go** (1.21 or higher)
- **Git** (2.20 or higher)
- *(Optional)* **Rust & Cargo** (1.70 or higher) if rebuilding the Rust scanning engine

### Build Steps

1. **Clone Repository**:
   ```powershell
   git clone https://github.com/Ranaveer9177/cyberhackathon.git
   cd cyberhackathon
   ```

2. **Build the Rust Scanner Engine** *(optional, fallback Go engine included)*:
   ```powershell
   cd scanner
   cargo build --release
   cd ..
   ```

3. **Build the VibeGuard Go CLI**:
   ```powershell
   go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
   ```

4. **Verify Installation**:
   ```powershell
   .\vibeguard.exe version
   # Output: VibeGuard v2.0.0
   ```

---

## Command Reference & Usage

### 1. `vibeguard init` — Install Git Pre-Push Hook
Installs the automatic pre-push hook into `.git/hooks/pre-push` and creates default configuration `.vibeguard/config.json`. Existing user hooks are automatically preserved and chained.
```powershell
.\vibeguard.exe init
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
