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
- **Integrated Fallback Engine**: If the compiled Rust binary is not present in the environment, VibeGuard seamlessly activates its built-in native Go scanning engine to ensure 100% of files are analyzed without skipping checks.
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
│   └── scanner/                 # Dual-engine runner (Rust subprocess + Go fallback)
├── scanner/
│   ├── Cargo.toml
│   └── src/
│       ├── config.rs            # Configuration auditing (debug mode, CORS, 0.0.0.0)
│       ├── docker.rs            # Dockerfile security analysis (root user, ENV secrets)
│       ├── git.rs               # Repository sensitive file checks (.env, private keys)
│       ├── main.rs              # Scanner CLI and JSON output serializer
│       ├── rules.rs             # Built-in regex rule definitions
│       ├── sast.rs              # SAST source code scanner
│       ├── scanner.rs           # Fast recursive directory traversal
│       ├── secrets.rs           # Secret detector & credential masking
│       └── types.rs             # Common data structures
├── test-project/                # Controlled intentionally vulnerable demo app
│   ├── .env                     # Synthetic test credentials & keys
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
├── md files/                    # Specification and planning documentation
│   ├── ARCHITECTURE.md
│   ├── CHANGELOG.md
│   ├── FEATURES.md
│   ├── LANGUAGE.md
│   ├── PLAN.md
│   ├── PLAN1.md
│   ├── PROCESSES.md
│   ├── README.md
│   └── ROADMAP.md
└── README.md                    # Root project documentation
```

---

## V2 Git Secure Push Integration

VibeGuard V2 seamlessly integrates with Git to intercept `git push` operations and block insecure code from leaving the developer workstation.

### Commands

```powershell
# Install Git pre-push hook and initialize .vibeguard/config.json
.\vibeguard.exe init

# Check Git repository & security gate status
.\vibeguard.exe status

# Controlled interactive workflow (commit message -> scan -> push)
.\vibeguard.exe push

# Standard security scan
.\vibeguard.exe scan .\test-project

# Policy-driven hook scan (uses .vibeguard/config.json)
.\vibeguard.exe scan . --hook

# Generate JSON / HTML reports
.\vibeguard.exe scan .\test-project --format json
.\vibeguard.exe report .\test-project --format html

# Remove Git pre-push hook (restores user hook if backed up)
.\vibeguard.exe uninstall
```

---

## Exit Codes

| Exit Code | Meaning | Condition |
| :---: | :--- | :--- |
| `0` | **PASS / SAFE** | Security scan passed, code is safe to push |
| `1` | **BLOCK** | Security policy blocked push (critical or high findings) |
| `2` | **ERROR** | Scanner runtime error or invalid arguments |
| `3` | **CONFIG ERROR** | Configuration file (.vibeguard/config.json) invalid |
| `4` | **OSV UNAVAILABLE** | OSV vulnerability API unreachable with `fail_closed: true` |
