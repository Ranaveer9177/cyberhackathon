# VibeGuard v5.1.0 — Autonomous Git Pre-Push Security Gate & Code Security Scanner

[![Version](https://img.shields.io/badge/version-v5.1.0-blue.svg)](docs/CHANGELOG.md)
[![Security Gate](https://img.shields.io/badge/security_gate-PASSED_100%2F100-brightgreen.svg)](ultimate_test.bat)
[![Engines](https://img.shields.io/badge/engines-Go_1.21+_|_Rust_1.70+-orange.svg)](docs/LANGUAGE.md)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0_Compliant-purple.svg)](internal/report/sarif.go)
[![Platform](https://img.shields.io/badge/platform-Windows_10%2F11_|_Cross--Platform-lightgrey.svg)](docs/SETUP.md)

> **The Autonomous Pre-Push Security Firewall for Engineering Teams**  
> *"Make security verification an automatic, non-negotiable step before code ever leaves your machine."*

---

## Overview

**VibeGuard v5.1.0** is an enterprise-grade security scanner and autonomous Git pre-push hook gate written in **Go** and **Rust**. It stops hardcoded secrets, dangerous code patterns (SAST), vulnerable third-party dependencies (SCA via Google OSV), Dockerfile misconfigurations, and sensitive configuration leaks *before* they are pushed to remote repositories or deployed to production.

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
   (committed tree, not dirty)                  │
                │                               │
                ▼                               │
   ┌─────────────────────────────────────────┐  │
   │      VibeGuard Security Gate (Go)       │  │
   │  ┌───────────────────────────────────┐  │  │
   │  │ 1. Project Detection              │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 2. Secret Scan (Rust Engine)      │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 3. SAST Scan (Rust Engine)        │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 4. Dependency Scan (Google OSV)   │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 5. Security Policy Evaluation     │  │  │
   │  └───────────────────────────────────┘  │  │
   └────────────────────┬────────────────────┘  │
                        │                       │
           ┌────────────┴────────────┐          │
           ▼                         ▼          ▼
     Score >= 90                Score < 90 / Findings
     [PASS: Code Pushed]        [BLOCK: Push Aborted]
                                Native Desktop Pop-up
                                Terminal & HTML Report
```

---

## What's New in v5.1.0

1. **Generic Leak File & Sensitive Pattern Recognition**:
   - Expanded sensitive filename detection in both Rust and Go engines to recognize generic leak patterns: `leak*.txt` (e.g. `leak_test.txt`), `test*.txt`, `*_secret.txt`, `*.conf`, and `*.env*`.
   - Manifest files like `requirements.txt` remain protected and cleanly excluded.
2. **Dynamic Credential Weighting**:
   - High-confidence credential assignment scoring applies across any text or configuration file when exact quoted assignments (e.g., `password = "..."`) are discovered, regardless of whether the file is strictly named `password.txt`.
   - Excludes non-assignment comparison expressions (`==`, `!=`) in source files, preventing false positive alerts on variable checks.
3. **Transparent Reporting (`--verbose`, `-v`, `--all`)**:
   - Default scans focus on actionable security findings (Critical, High, Medium), while low-severity and advisory items are neatly summarized without terminal clutter.
   - Running `vibeguard scan --verbose` or `vibeguard scan --all` expands an informative `Advisory & Low Severity Findings` section with complete details.
4. **Unconditional Cache & State Isolation**:
   - Both the Rust scanner and Go fallback engine skip `.vibeguard/` and `reports/` unconditionally, ensuring zero false positives from cache or previous scan runs.

---

## Quickstart (60 Seconds)

### Option 1: Demo / User Mode (No Compilers Required)
Prebuilt Windows binaries (`vibeguard.exe` and `vibeguard-scanner.exe`) are bundled directly with the repository:

```cmd
# 1. Run global installation & register PATH:
.\scripts\windows\setup.bat

# 2. Open a NEW terminal and verify global access:
vibeguard version
# Output: VibeGuard v5.1.0

# 3. Run the comprehensive 8-stage test engine:
.\ultimate_test.bat
```

### Option 2: Developer / Source Build Mode
Compile both the Rust scanner and Go orchestrator from source:

```cmd
# Build from source and update global installation:
.\scripts\windows\build.bat
```

---

## The Ultimate Test Suite v5.0 (`ultimate_test.bat`)

Run the complete 8-stage weighted evaluation engine directly from your terminal:

```cmd
.\ultimate_test.bat
```

### Verified Execution Output

```text
========================================
 VIBEGUARD ULTIMATE TEST v4.6.0
========================================

Test results:

[1/8] Go package tests
      Status:    PASS
      Weight:    15/15
      Duration:  2.24 seconds
      Packages:  11 passed
      Failed:    0

[2/8] Go vet
      Status:    PASS
      Weight:    10/10
      Duration:  0.31 seconds
      Issues:    0

[3/8] Rust tests
      Status:    PASS
      Weight:    15/15
      Duration:  0.22 seconds
      Tests:     9 passed
      Failed:    0

[4/8] Rust format check
      Status:    PASS
      Weight:     5/5
      Duration:  0.14 seconds
      Formatting: Clean

[5/8] Rust Clippy
      Status:    PASS
      Weight:    10/10
      Duration:  0.21 seconds
      Warnings:  0
      Errors:    0

[6/8] Source build
      Status:    PASS
      Weight:    20/20
      Duration:  1.32 seconds
      Go binary:   Built successfully
      Rust binary: Built successfully
      Version:     v4.6.0

[7/8] CLI health test
      Status:    PASS
      Weight:    15/15
      Duration:  0.70 seconds
      CLI found:          YES
      Scanner found:      YES
      Version check:      PASS
      Test scan:          PASS
      Report generation:  PASS
      Security gate:      PASS

[8/8] Windows Defender verification
      Status:    PASS
      Weight:    10/10
      Duration:  1.72 seconds
      Service enabled:          YES
      Real-time protection:     YES
      Scanner accessible:       YES
      Matching threat found:    NO
      Real block verified:      NO
      Popup simulation:         NOT RUN

========================================
 SUMMARY
========================================

Passed:       8
Failed:       0
Warnings:     0
Not verified: 0

Weighted score: 100/100
Minimum score:  90/100
Duration:       6.97 seconds
Result:         PASS
```

> **Tip**: Pass `--test-popup` to verify the native desktop pop-up alert during testing:
> ```cmd
> .\ultimate_test.bat --test-popup
> ```

---

## 5-Stage Pre-Push Security Gate in Action

When you run `git push` (or `vibeguard push`), VibeGuard scans the exact committed snapshot:

```text
========================================
       VIBEGUARD SECURITY GATE
========================================

[1/5] Detecting project ........ PASS
[2/5] Secret scan .............. PASS
[3/5] Source scan .............. PASS
[4/5] Dependency/CVE scan ...... PASS
[5/5] Security policy .......... PASS

========= VIBEGUARD SECURITY REPORT =========
Project:       cyberhackathon
Branch:        main
Commit:        5c8b26f
Remote:        refs/heads/main
Scan Time:     628ms
Files Scanned: 73
---------------------------------------------
Security Score: 100/100 (LOW RISK)
Gate Status:    PASSED
Reason:         No blocking security findings
---------------------------------------------
Severity Counts:
  Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0
Category Breakdown:
  Secrets: 0 | Source Code: 0 | Dependencies: 0 | Config: 0 | Docker: 0 | Git: 0
---------------------------------------------
Code & Configuration Findings (0):
  ✓ No code, secret, or configuration issues detected.
---------------------------------------------
Dependency Vulnerabilities (0 vulnerable packages, 0 total advisories):
  ✓ No known vulnerabilities found in dependencies.
---------------------------------------------
Deployment Status: PASSED
Reason: No blocking security findings
=============================================

STATUS: SAFE TO PUSH
Continuing Git push...
```

---

## Detection Capabilities

| Category | Rules & Patterns | Default Severity | Gate Policy |
| :--- | :--- | :---: | :---: |
| **Secrets & Keys** | Sensitive filenames (`password.txt`, `credentials.txt`, `secret.txt`), Hardcoded assignments (`password=...`, `api_key=...`, `secret=...`), AWS Keys (`AKIA...`), GitHub PATs (`ghp_...`), Slack Tokens (`xox...`), Private Keys (`BEGIN RSA/OPENSSH PRIVATE KEY`), Sensitive Files (`.env`, `*.pem`) | `CRITICAL` / `HIGH` | **BLOCKS** |
| **SAST (Code)** | Potential SQL Injection, OS Command Injection, Disabled TLS (`InsecureSkipVerify: true`), Dangerous `eval()` / `Function()`, Weak Cryptography (`MD5`, `SHA1`, `DES`), Plaintext HTTP | `HIGH` / `MEDIUM` | **BLOCKS** / Advisory |
| **Containers** | Container running as `root` (missing non-root `USER`), Secrets in `ENV` instructions, Unbounded `COPY . .` without `.dockerignore` | `CRITICAL` / `HIGH` | **BLOCKS** |
| **SCA (Dependencies)** | Package CVE lookup against live Google OSV database (`go.mod`, `package.json`, `requirements.txt`, `Cargo.toml`) | `CRITICAL` to `LOW` | **BLOCKS** (Critical/High) |
| **Configuration** | Insecure CORS (`*`), Exposed Debug Mode (`debug: true`), Insecure host binding (`0.0.0.0`) | `MEDIUM` / `LOW` | Advisory |

---

## CLI Command Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `vibeguard init` | Installs `.git/hooks/pre-push` gate and generates default config | `vibeguard init` |
| `vibeguard status` | Displays active branch, hook state, remote, and security policy | `vibeguard status` |
| `vibeguard scan` | Scans any local directory or repository | `vibeguard scan .` |
| `vibeguard report` | Generates HTML, JSON, or SARIF reports | `vibeguard report . --format html` |
| `vibeguard push` | Executes security scan and pushes safely without double scanning | `vibeguard push` |
| `vibeguard defender-check` | Inspects active antivirus and tests modal pop-up alert dialog | `vibeguard defender-check --test-popup` |
| `vibeguard cache-refresh` | Purges local OSV vulnerability intelligence cache | `vibeguard cache-refresh` |
| `vibeguard uninstall` | Cleanly removes pre-push hook and restores backup user hook | `vibeguard uninstall` |
| `ultimate_test.bat` | Runs the full 8-stage weighted evaluation engine | `.\ultimate_test.bat` |

### Scan & Report Options

| Flag | Description | Default |
| :--- | :--- | :---: |
| `--format, -f <fmt>` | Output format: `terminal`, `json`, `html`, `sarif` | `terminal` |
| `--output, -o <path>` | Custom report output file path | `reports/scan.<ext>` |
| `--offline` | Query local vulnerability disk cache without network access | `false` |
| `--refresh-cache` | Purge local vulnerability cache before querying | `false` |
| `--include-tests` | Override default exclusion of test suites and fixtures | `false` |
| `--include-docs` | Override default exclusion of markdown and doc files | `false` |
| `--show-excluded` | Display count of excluded files in scan report | `false` |
| `--hook` | Enforce blocking thresholds defined in `.vibeguard/config.json` | `false` |

---

## Configuration (`.vibeguard/config.json`)

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
    "tests",
    "VibeGuard-test",
    "docs"
  ]
}
```

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

## Exit Codes

| Exit Code | Classification | Meaning |
| :---: | :--- | :--- |
| `0` | **SAFE TO PUSH / PASSED** | All security checks passed; no blocking findings. Push continues. |
| `1` | **PUSH BLOCKED** | Critical or high-severity vulnerabilities detected. Git push aborted. |
| `2` | **ERROR** | Runtime or scanning error occurred. |
| `3` | **CONFIG / FORMAT ERROR** | Malformed `.vibeguard/config.json` or unsupported format flag. |
| `4` | **OSV UNAVAILABLE** | OSV API unreachable with `fail_closed: true`. Push aborted safely. |

---

## Documentation Index

Comprehensive guides are available in the [`docs/`](docs/) directory:

- [Architecture & Design](docs/ARCHITECTURE.md) — Multi-engine architecture, data flow, and IPC protocol.
- [Changelog](docs/CHANGELOG.md) — Full release history from v0.1 to v4.6.0.
- [Feature Specifications](docs/FEATURES.md) — Complete feature specifications and capabilities.
- [Language & Technology Rationale](docs/LANGUAGE.md) — Go and Rust technical decisions.
- [Strategic Roadmap](docs/ROADMAP.md) — Milestone tracking and future horizons.
- [Security Rules Specification](docs/RULES.md) — Full catalog of secret, SAST, Docker, and config rules.
- [Global Setup & PATH Guide](docs/SETUP.md) — Portable installation and PATH setup guide.
- [Testing & Quality Assurance Guide](docs/TESTING.md) — Unit tests, integration harnesses, and test suites.
- [Canonical Test Audit Report](report.md) — Cumulative test report and historical audit logs.

---

## License & Security Policy

VibeGuard processes all files locally in-memory. Code never leaves your machine. Discovered credentials are automatically masked, and third-party intelligence queries communicate strictly with official vulnerability advisories ([OSV.dev](https://osv.dev)).
