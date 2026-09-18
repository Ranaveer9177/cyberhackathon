# VibeGuard — Pre-Deployment Security Verification CLI

> **Independent Pre-Deployment Security Verification System**  
> *"Make security verification a simple step between writing software and deploying software."*

---

## Overview

**VibeGuard** is a fast, developer-friendly security CLI designed to scan software projects before deployment. It discovers hardcoded secrets, dangerous source-code patterns (SAST), vulnerable open-source dependencies (SCA via OSV), Dockerfile misconfigurations, sensitive repository files, and insecure configurations.

VibeGuard acts as a definitive pre-deployment gate:
- Produces exact file paths and line numbers
- Assigns clear finding IDs (`VG-001`, `VG-002`, etc.) and severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- Calculates a deterministic Security Score (0–100)
- Delivers an automated **`DEPLOYMENT PASSED`** or **`DEPLOYMENT BLOCKED`** gate decision with standardized exit codes for CI/CD pipelines
- Generates Terminal, JSON, and standalone HTML reports

---

## Architecture

VibeGuard adopts a decoupled multi-language architecture:

```
                      Windows / Terminal
                              │
                              ▼
                     VibeGuard CLI (Go)
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
      Rust Scanner Engine            OSV Intelligence
   (Secrets, SAST, Docker, Git)    (Known CVEs & Advisories)
               │                             │
               └──────────────┬──────────────┘
                              ▼
                        Finding Engine
                              │
                              ▼
                         Risk Engine
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
            Terminal         JSON           HTML
               │
               ▼
       PASS / BLOCK Gate (Exit Codes: 0 / 1 / 2)
```

- **Go Orchestrator (`cmd/vibeguard`, `internal/`)**: CLI UX, dependency detection & manifest parsing, OSV REST API communication, finding aggregation, risk scoring, report formatting (ANSI terminal, JSON, HTML), and gate evaluation.
- **Rust Engine (`scanner/`)**: High-performance recursive filesystem walker, secret pattern matching with masking, static analysis (SAST) rule evaluation, Dockerfile scanning, configuration auditing, and JSON IPC stream.
- **OSV (Open Source Vulnerabilities)**: Real-world vulnerability data source of truth (no synthetic CVEs).

---

## Repository Structure

```text
cyberhackathon/
├── cmd/
│   └── vibeguard/               # Go CLI application entrypoint
│       └── main.go
├── internal/
│   ├── dependencies/            # Manifest parsers (go.mod, package.json, requirements.txt, Cargo.toml)
│   ├── gate/                    # PASS / BLOCK deployment decision engine
│   ├── osv/                     # OSV API client & vulnerability query types
│   ├── report/                  # Terminal, JSON, and HTML report generators
│   ├── risk/                    # Deterministic 0-100 scoring algorithm
│   └── scanner/                 # Subprocess runner for Rust scanner binary
├── scanner/
│   ├── Cargo.toml
│   └── src/
│       ├── config.rs            # Configuration auditing (debug mode, CORS, 0.0.0.0)
│       ├── docker.rs            # Dockerfile security analysis (root user, ENV secrets)
│       ├── git.rs               # Repository sensitive file checks (.env, private keys)
│       ├── main.rs              # Scanner entry point and JSON output serializer
│       ├── rules.rs             # Built-in regex rule definitions
│       ├── sast.rs              # SAST source code scanner
│       ├── scanner.rs           # Fast recursive directory traversal
│       ├── secrets.rs           # Secret detector & credential masking
│       └── types.rs             # Common data structures
├── test-project/                # Controlled intentionally vulnerable demo app
│   ├── .env                     # Fake test credentials
│   ├── Dockerfile               # Vulnerable container configuration
│   ├── go.mod                   # Outdated Go dependencies
│   ├── package.json             # Outdated npm dependencies
│   ├── requirements.txt         # Outdated Python dependencies
│   └── src/
│       ├── auth.js              # eval(), command injection, hardcoded JWT
│       ├── config.go            # Hardcoded API key, disabled TLS
│       └── database.go          # SQL injection, command injection, weak MD5
├── tests/                       # Unit & integration test fixtures
│   ├── dependencies/
│   ├── integration/
│   ├── sast/
│   └── secrets/
├── reports/                     # Output directory for generated reports
├── CHANGELOG.md                 # Complete version history
├── FEATURES.md                  # Comprehensive feature specification
├── LANGUAGE.md                  # Technical architecture and language decisions
├── PLAN.md                      # 6-Hour hackathon execution blueprint
├── PROCESSES.md                 # Development lifecycle tracking
└── README.md                    # Project documentation
```

---

## Getting Started

### Prerequisites
- **Go** (1.21+)
- **Rust & Cargo** (1.70+)
- **PowerShell 7+** / Command Prompt (Windows)

### Building the Project

1. **Build the Rust Scanner Engine**:
   ```powershell
   cd scanner
   cargo build --release
   cd ..
   ```
   *Copy or ensure `vibeguard-scanner.exe` is in the same directory as `vibeguard.exe` or in the build output.*

2. **Build the Go CLI**:
   ```powershell
   go build -o vibeguard.exe ./cmd/vibeguard
   ```

---

## Usage

### 1. Scan a Project (Terminal Output)
```powershell
.\vibeguard.exe scan .\test-project
```

### 2. Generate JSON Report
```powershell
.\vibeguard.exe scan .\test-project --format json
```
Generates `reports/scan.json` containing full machine-readable findings and metrics.

### 3. Generate HTML Report
```powershell
.\vibeguard.exe report .\test-project --format html
```
Generates an interactive, styled report at `reports/scan.html`.

### 4. Check Version
```powershell
.\vibeguard.exe version
```

---

## Exit Codes

VibeGuard returns standard exit codes suitable for CI/CD gates:

| Exit Code | Meaning | Condition |
| :---: | :--- | :--- |
| `0` | **PASS** | No critical blocking security vulnerabilities found |
| `1` | **BLOCK** | One or more `CRITICAL` findings detected |
| `2` | **ERROR** | Scanner execution error or invalid arguments |

---

## Scoring Formula

Security Score is computed deterministically from 0 to 100:
$$\text{Score} = \max\left(0, 100 - (15 \times C + 8 \times H + 3 \times M + 1 \times L)\right)$$

Where:
- $C$ = Critical count
- $H$ = High count
- $M$ = Medium count
- $L$ = Low count

---

## Security & Privacy Guarantee

- **No Source Code Uploads**: Local file scanning stays completely on-machine.
- **Credential Masking**: Discovered secrets are always truncated/masked in logs and reports (`sk-demo-****`).
- **Deterministic Truth**: OSV queries only send package name + version pairs. AI is never used to hallucinate false CVEs.
