# VibeGuard v6.6.0 — Autonomous Git Pre-Push Security Gate & Code Security Scanner

[![Version](https://img.shields.io/badge/version-v6.6.0-blue.svg)](docs/CHANGELOG.md)
[![Security Gate](https://img.shields.io/badge/security_gate-PASSED_100%2F100-brightgreen.svg)](ultimate_test.bat)
[![Engines](https://img.shields.io/badge/engines-Go_1.21+_|_Rust_1.70+-orange.svg)](docs/LANGUAGE.md)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0_Compliant-purple.svg)](internal/report/sarif.go)
[![Platform](https://img.shields.io/badge/platform-Windows_10%2F11_|_Cross--Platform-lightgrey.svg)](docs/SETUP.md)

> **The Autonomous Pre-Push Security Firewall for Engineering Teams**  
> *"Make security verification an automatic, non-negotiable step before code ever leaves your machine."*

---

## Overview

**VibeGuard v6.6.0** is an enterprise-grade security scanner and autonomous Git pre-push hook gate written in **Go** and **Rust**. It stops hardcoded secrets, dangerous code patterns (SAST with multi-language AST, semantic project modeling, deep interprocedural taint propagation, control-flow/type/value analysis, and deepened semantic security rules), vulnerable third-party dependencies (SCA via Google OSV), Docker & Docker Compose misconfigurations, and sensitive configuration leaks *before* they are pushed to remote repositories or deployed to production.

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
   │  │ 3. Lexical SAST Scan              │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 4. Multi-Language AST Analysis    │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 5. Semantic Project Model & Calls │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 6. Deep Data-Flow / Taint Engine  │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 7. Control Flow & Type Tracking   │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 8. Semantic Security Rules        │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 9. Dependency Scan (Google OSV)   │  │  │
   │  ├───────────────────────────────────┤  │  │
   │  │ 10. Security Policy Evaluation    │  │  │
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

## What's New in v6.6.0

1. **Semantic SQL Rule Engine (`scanner/rules/sql/`)**:
   - Deeply analyzes query construction across string concatenation (`+`), f-strings (`f"..."`), and `.format()` calls.
   - Detects unparameterized raw SQL and ORM raw query escape hatches (Django `.raw()`, SQLAlchemy `text()`, Prisma `$queryRaw`, Sequelize, GORM `db.Raw`).
   - Identifies dynamic table and column identifiers (`ORDER BY`, `GROUP BY`) that cannot be parameterized via bind variables.
   - Verifies secure parameterized query bindings and flags unsafe query builder raw clauses (Knex `.whereRaw`, TypeORM raw strings).

2. **Semantic Command Injection Rule Engine (`scanner/rules/command/`)**:
   - Covers `os.system`, `subprocess`, `exec`, `execFile`, `child_process.spawn`, `Runtime.getRuntime().exec`, and `ProcessBuilder`.
   - Distinguishes `shell=True` (vulnerable to metacharacters like `;`, `&`, `|`, `$()`) from `shell=False` / argv array invocation.
   - Classifies command control levels:
     - `Constant`: Compile-time constant (suppressed, zero false positives).
     - `PartiallyControlled`: Constant command with dynamic unquoted arguments.
     - `FullyControlled`: Entire command line or binary from untrusted input (CRITICAL).
     - `Sanitized`: Protected via `shlex.quote()` or validation.

3. **Semantic SSRF Rule Engine (`scanner/rules/ssrf/`)**:
   - Analyzes HTTP client calls (`requests`, `urllib.request`, `httpx`, `fetch`, `axios`, `http.Get`, `HttpClient`).
   - Verifies domain allowlists, hostname parsing, and IP address validation.
   - Checks private IP blocking (preventing calls to `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) and AWS/cloud metadata services (`169.254.169.254`).
   - Tracks redirect configuration (`allow_redirects`).

4. **Semantic Path Traversal Rule Engine (`scanner/rules/path/`)**:
   - Monitors file operations (`open`, `os.remove`, `fs.readFile`, `os.Open`, `FileInputStream`).
   - Understands relative directory traversal (`../`), absolute path overrides on POSIX and Windows, and path normalization (`realpath`, `normpath`, `filepath.Clean`).
   - Verifies canonical directory boundary containment (`startswith(base_dir)`).

5. **Semantic XSS Rule Engine (`scanner/rules/xss/`)**:
   - Analyzes unescaped inputs reaching template output or DOM sinks (`.innerHTML =`, `document.write`).
   - Detects raw HTML constructors that bypass framework auto-escaping (`Markup()`, `mark_safe()`, `render_template_string`, `dangerouslySetInnerHTML`, `v-html`).
   - Verifies HTML entity escaping (`html.escape`, `DOMPurify.sanitize`).

---

## What's New in v6.5.0

1. **Control-Flow Graph (CFG) Analysis (`scanner/analysis/cfg.rs`)**:
   - Models execution paths and branch points across `if`, `else`, `for`, `while`, `try`, `except`, `finally`, `return`.
   - Computes path reachability between untrusted sources and sensitive sinks, eliminating false positives for unreached branches and early returns.

2. **Type Tracking & Inference (`scanner/analysis/types.rs`)**:
   - Systematically tracks and infers variable types: `string`, `integer`, `boolean`, `list`, `map`, `object`, `bytes`, `unknown`.
   - Distinguishes inherently injection-safe types (such as `integer` and `boolean`) from exploitable string injection vectors, neutralizing SQL and Command injection risks on strongly typed values.

3. **Constant Propagation Engine (`scanner/analysis/constants.rs`)**:
   - Differentiates compile-time constant literals from untrusted request inputs:
     - `CMD = "safe-command"` $\longrightarrow$ Compile-time constant: verified safe, suppresses false positives.
     - `CMD = request.args["cmd"]` $\longrightarrow$ Dynamic untrusted value: tracked and flagged.
   - Constant folding for static string concatenation and formatted strings.

4. **String Transformation Propagation (`scanner/analysis/string_propagation.rs`)**:
   - Tracks taint propagation through string transformations: `+` (concatenation), `.format()`, f-strings, `.join()`, `.replace()`, `.encode()`, and `.decode()`.
   - Answers the core question: *"Can this actual value reach this actual dangerous operation?"* rather than superficial syntactic pattern matching.

---

## What's New in v6.4.0

1. **Deep Data-Flow / Taint Engine (`scanner/taint/`, `scanner/analysis/`)**:
   - **Full Taint Lifecycle Tracking**:
     $$\text{SOURCE} \longrightarrow \text{assignment} \longrightarrow \text{transformation} \longrightarrow \text{parameter} \longrightarrow \text{call} \longrightarrow \text{return} \longrightarrow \text{another file} \longrightarrow \text{SINK}$$
   - **Vulnerability-Specific Taint Typing**: Dedicated taint representations for **SQL**, **Command**, **SSRF**, **Path Traversal**, **XSS**, **Template (SSTI)**, and **Insecure Deserialization**.
   - **Strict Vulnerability-Specific Sanitizer Modeling**:
     - Accurately tracks which sanitizers neutralize which vulnerabilities.
     - `int()`, `float()`, `strconv.Atoi()` neutralize SQL injection, while HTML entity escaping (`html.escape()`, `DOMPurify`) does **not** protect against SQL injection and leaves SQL taint active.
     - Shell escapes (`shlex.quote()`) protect commands but not path traversal or SSRF.
   - **Interprocedural & Cross-File Detection**: Seamlessly tracks data flow crossing functions, modules, and files (e.g. `request` $\rightarrow$ `controller` $\rightarrow$ `service` $\rightarrow$ `repository` $\rightarrow$ `database`).
2. **Semantic Project Model & Symbol Table (`scanner/semantic/`)**:
   - Project-wide symbol table resolving functions, methods, classes, and variables.
   - Module and Function resolvers linking calls across directories.
   - Interprocedural Call Graph builder.
3. **Multi-Language AST Engine (`scanner/ast/`)**:
   - Native AST parsers for Python, JavaScript, TypeScript, Go, and Java.
4. **100% Rust & Go Parity & 100/100 Quality Gate**:
   - Clean pre-push self-scan (100/100) and full `ultimate_test.bat` pass.

---

## Quickstart (60 Seconds)

### Option 1: Demo / User Mode (No Compilers Required)
Prebuilt Windows binaries (`vibeguard.exe` and `vibeguard-scanner.exe`) are bundled directly with the repository:

```cmd
# 1. Run global installation & register PATH:
.\scripts\windows\setup.bat

# 2. Open a NEW terminal and verify global access:
vibeguard version
# Output: VibeGuard v6.0.0

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

## The Ultimate Test Suite (`ultimate_test.bat`)

Run the complete 8-stage weighted evaluation engine directly from your terminal:

```cmd
.\ultimate_test.bat
```

### Verified Execution Output

```text
========================================
 VIBEGUARD ULTIMATE TEST v6.0.0
========================================

Test results:

[1/8] Go package tests
      Status:    PASS
      Weight:    15/15
      Duration:  3.67 seconds
      Packages:  11 passed
      Failed:    0

[2/8] Go vet
      Status:    PASS
      Weight:    10/10
      Duration:  0.35 seconds
      Issues:    0

[3/8] Rust tests
      Status:    PASS
      Weight:    15/15
      Duration:  1.94 seconds
      Tests:     18 passed
      Failed:    0

[4/8] Rust format check
      Status:    PASS
      Weight:     5/5
      Duration:  0.20 seconds
      Formatting: Clean

[5/8] Rust Clippy
      Status:    PASS
      Weight:    10/10
      Duration:  0.59 seconds
      Warnings:  0
      Errors:    0

[6/8] Source build
      Status:    PASS
      Weight:    20/20
      Duration:  3.96 seconds
      Go binary:   Built successfully
      Rust binary: Built successfully
      Version:     v6.1.0

[7/8] CLI health test
      Status:    PASS
      Weight:    15/15
      Duration:  0.88 seconds
      CLI found:          YES
      Scanner found:      YES
      Version check:      PASS
      Test scan:          PASS
      Report generation:  PASS
      Security gate:      PASS

[8/8] Windows Defender verification
      Status:    PASS
      Weight:    10/10
      Duration:  3.55 seconds
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
Duration:       15.33 seconds
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
| **Secrets & Keys** | Sensitive filenames (`password.txt`, `credentials.txt`, `secret.txt`, `leak*.txt`, `test*.txt`, `*_secret.txt`, `*.conf`, `*.env*`), Hardcoded assignments (`password=...`, `api_key=...`, `secret=...`), Dynamic Credential Weighting, AWS Keys (`AKIA...`), GitHub PATs (`ghp_...`), Slack Tokens (`xox...`), Private Keys (`BEGIN RSA/OPENSSH PRIVATE KEY`), Sensitive Files (`.env`, `*.pem`) | `CRITICAL` / `HIGH` | **BLOCKS** |
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
| `--verbose, -v` | Expose low-severity findings and complete advisory details | `false` |
| `--all` | Show all findings including advisory items without abbreviation | `false` |
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

## DevSecOps Chaos & Deep Testing Suite (v5.1.0)

VibeGuard v5.1.0 includes an adversarial stress and chaos engineering validation suite across 5 core security domains:

| Domain | Adversarial Vector | VibeGuard Defense & Behavior | Gate Result |
| :--- | :--- | :--- | :---: |
| **Domain 1: Wildcards vs SCA Manifests** | Injecting CVEs in `requirements.txt` vs leak files `leak_config.txt`, `test_token.txt` | `requirements.txt` is evaluated strictly for SCA CVEs without false-positive leak alarms; leak files are intercepted immediately. | **PASS (100% Intercept)** |
| **Domain 2: Mathematical Heuristics Stress** | Code equality comparisons (`if pwd == "secret"`) vs active variable assignments (`db_pass := "..."`) | Zero false positives on comparison logic; active credential declarations flagged `HIGH`; documentation examples degraded to non-blocking `LOW`. | **PASS (0 False Positives)** |
| **Domain 3: Parallel Walker Chaos & DoS** | Massive dependency explosions (5,000 files in nested `node_modules` & `target`) | Instant directory pruning at root without subtree descent (0.160s scan time; throughput >30,000 files/sec pruning). | **PASS (Zero Latency Spike)** |
| **Domain 4: Flag Abuse & Parameter Fuzzing** | Stacked flags (`--verbose --all --format=terminal --show-excluded`) vs invalid parameters | Clean execution with granular advisory disclosure on valid flags; explicit syntax error (Exit Code 2) on illegal arguments. | **PASS (Exit Codes 0 / 2)** |
| **Domain 5: Git Push Lifecycle Isolation** | Dirty uncommitted working directory with leaks vs clean committed Git tree | Staged snapshot tar archive isolates committed ref; allows clean commit push while safely aborting if secrets are in Git history. | **PASS (Pure Tree Isolation)** |

---

## Documentation Index

Comprehensive guides are available in the [`docs/`](docs/) directory:

- [Architecture & Design](docs/ARCHITECTURE.md) — Multi-engine architecture, data flow, IPC protocol, and early pruning.
- [Changelog](docs/CHANGELOG.md) — Full release history from v0.1 to v5.1.0.
- [Feature Specifications](docs/FEATURES.md) — Complete feature specifications, transparent reporting, and capabilities.
- [Language & Technology Rationale](docs/LANGUAGE.md) — Go and Rust technical decisions.
- [Strategic Roadmap](docs/ROADMAP.md) — Milestone tracking and future horizons.
- [Security Rules Specification](docs/RULES.md) — Full catalog of secret, SAST, Docker, config rules, and dynamic weighting.
- [Global Setup & PATH Guide](docs/SETUP.md) — Portable installation and PATH setup guide.
- [Testing & Quality Assurance Guide](docs/TESTING.md) — Unit tests, integration harnesses, 8-stage test engine, and Chaos Engineering matrix.
- [Reports & Artifacts Guide](reports/README.md) — Format specifications for terminal, JSON, HTML, and SARIF reports.

---

## License & Security Policy

VibeGuard processes all files locally in-memory. Code never leaves your machine. Discovered credentials are automatically masked, and third-party intelligence queries communicate strictly with official vulnerability advisories ([OSV.dev](https://osv.dev)).

