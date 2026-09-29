# VibeGuard v7.2.0 — Autonomous Pre-Push Security Firewall & Deep Static Analyzer

[![Version](https://img.shields.io/badge/version-v7.2.0-blue.svg)](docs/CHANGELOG.md)
[![Security Gate](https://img.shields.io/badge/security_gate-PASSED_100%2F100-brightgreen.svg)](ultimate_test.bat)
[![Engines](https://img.shields.io/badge/engines-Go_1.21+_|_Rust_1.70+-orange.svg)](docs/LANGUAGE.md)
[![Benchmark](https://img.shields.io/badge/benchmark-100%25_Recall_|_100%25_Specificity-success.svg)](docs/TESTING.md)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0_Compliant-purple.svg)](internal/report/sarif.go)
[![Platform](https://img.shields.io/badge/platform-Windows_10%2F11_|_Linux_|_macOS-lightgrey.svg)](docs/SETUP.md)

> **The Autonomous Pre-Push Security Firewall for High-Velocity Engineering Teams**  
> *"Make security verification an automatic, non-negotiable step before code ever leaves your workstation."*

---

## ⚡ Quick Overview (What is VibeGuard in 30 Seconds?)

**VibeGuard** is a dual-engine security scanner and autonomous Git pre-push hook firewall built in **Go** and **Rust**. It intercepts vulnerable code, hardcoded credentials, exposed secrets, dangerous container privileges, and vulnerable open-source dependencies *before* they can be committed or pushed to remote repositories.

```
       Developer types: git push
                  │
                  ▼
   ┌──────────────────────────────┐
   │   VibeGuard Pre-Push Hook    │ ── Sub-second project scan (< 500ms)
   └──────────────┬───────────────┘
                  │
         ┌────────┴────────┐
         ▼                 ▼
   Score >= 90        Score < 90 / Blocking Findings
   [PASS: Push OK]    [BLOCKED: Push Aborted]
                      ├── Native Desktop Pop-up Alert
                      ├── Colorized Terminal Summary
                      └── Standalone Interactive HTML Report
```

### Key Highlights at a Glance

| Capability | Benefit |
| :--- | :--- |
| ⚡ **Sub-Second Execution** | Multi-threaded Rust scanner audits thousands of files in under 500 milliseconds. |
| 🔌 **100% Offline Capable** | Operates with zero required internet connectivity using an embedded local security intelligence database (`.vibeguard/database/security.db`). |
| 🎯 **Zero False-Positive Precision** | Type-aware AST inference and semantic sanitizers (`int()`, `shlex.quote`, `html.escape`, `os.path.basename`, allowlist guards) eliminate false alarms. |
| 🔗 **Interprocedural Taint Analysis** | Traces untrusted input across function calls, derivations, and module boundaries into critical sinks. |
| 🛑 **Autonomous Git Gate** | Non-invasive pre-push hook halts risky pushes automatically and provides instant actionable remediation steps. |
| 📊 **Universal Output Formats** | Generates colorized terminal summaries, machine-readable JSON, GitHub-compliant SARIF 2.1.0, and interactive HTML dashboards. |

### Quickstart in 3 Commands

```powershell
# 1. Initialize VibeGuard and install the autonomous Git pre-push hook
./vibeguard.exe init

# 2. Run a full security scan on your current workspace
./vibeguard.exe scan .

# 3. Generate a standalone, visual HTML audit report
./vibeguard.exe report . --format html --output reports/audit.html
```

### Essential CLI Commands

| Command | Action |
| :--- | :--- |
| `vibeguard scan [path]` | Runs comprehensive security scan and evaluates deployment gate status. |
| `vibeguard report [path]` | Generates standalone HTML, JSON, or SARIF 2.1.0 security reports. |
| `vibeguard benchmark [path]` | Executes quality benchmark displaying confidence breakdown, correlation, and scope metrics. |
| `vibeguard init [path]` | Installs native `.git/hooks/pre-push` hook and initializes local configuration. |
| `vibeguard push [path]` | Interactive workflow: stage changes, scan, inspect results, and safely push. |
| `vibeguard status [path]` | Checks Git hook installation and current security policy thresholds. |
| `vibeguard defender-check` | Tests Windows Defender status and native desktop security pop-up alerts. |
| `vibeguard db <status\|import>` | Manages the local offline security vulnerability intelligence database. |

---

## 🔬 Deep Technical Details & Architecture

### 20-Stage End-to-End Analysis Pipeline

VibeGuard executes a comprehensive 20-stage analysis pipeline entirely in-memory:

```
  1. File Discovery           (Walker with binary detection & smart exclusions)
         ↓
  2. Classification           (Language, manifest, container & config detection)
         ↓
  3. Lexical Analysis         (Regex patterns, Shannon entropy, secret token matching)
         ↓
  4. AST Parsing              (Multi-language ASTs: Go, Python, JS/TS, Java, Rust, PHP, Ruby)
         ↓
  5. Semantic Modeling        (Imports, exports, function boundaries & namespaces)
         ↓
  6. Symbol Table             (Variable definitions, assignments, scopes & lifetimes)
         ↓
  7. Call Graph Construction  (Direct, indirect & interprocedural invocation graphs)
         ↓
  8. Control Flow Analysis    (Branch evaluation, condition guards & exception handling)
         ↓
  9. Type & Value Inference   (Static types, constant propagation & string evaluations)
         ↓
 10. Cross-File Data Flow     (Source-to-sink derivation tracking across modules)
         ↓
 11. Taint Tracking Engine    (Untrusted user sources mapped to high-risk sinks)
         ↓
 12. Sanitizer Verification   (Type casting, entity escaping, quoting, allowlist validation)
         ↓
 13. Security Rules Engine    (Domain-specific rules: SQLi, CMDi, SSRF, Deserialization, Crypto)
         ↓
 14. Configuration Analysis   (CORS, cookies, debug flags, interface bindings)
         ↓
 15. Docker Architecture      (Root execution, broad COPY, exposed ports, volume mounts)
         ↓
 16. Local Vulnerability DB   (Offline OSV matching for Go, npm, PyPI, Crates.io)
         ↓
 17. Finding Correlation      (Logical grouping of related findings by origin and sink)
         ↓
 18. Finding Verification     (Context filtering, receiver checks, and reachability tests)
         ↓
 19. Deduplication Engine     (5-tier canonical deduplication to eliminate noise)
         ↓
 20. Confidence Scoring       (0–100 numerical confidence computation per finding)
```

---

## 🛡️ Multi-Tier Security Detection Engines

### 1. Secret & Credential Detection
- **Cloud & API Providers**: AWS Access Keys (`AKIA...`), AWS Secret Keys, Stripe Live/Secret Keys (`sk_live_...`), GitHub Personal Access Tokens (`ghp_...`), Slack Bot/User Tokens (`xoxb-...`), SendGrid Keys (`SG....`).
- **Cryptographic Keys**: PEM and OpenSSH private key blocks (RSA, DSA, EC, OPENSSH).
- **Connection Strings**: Database URIs with embedded passwords (PostgreSQL, MySQL, MongoDB), including empty-username Redis URIs (`redis://:password@host`).
- **Equality Comparison Credentials**: Secrets hardcoded in conditional statements (`if key == "MASTER_ADMIN_KEY_..."`).
- **Automatic Evidence Redaction**: Displays the first 8 characters and permanently masks the remainder (`AKIAIOSF********`) to avoid leaking secrets in CI logs or terminal screens.

### 2. Static Application Security Testing (SAST)
- **SQL Injection (CWE-89)**: Detects f-strings, concatenation (`+`), `.format()`, and string modulo formatting in unparameterized SQL queries across database drivers.
- **Command Injection (CWE-78 & CWE-88)**: Detects untrusted parameters in `os.system()`, `subprocess.run(shell=True)`, `exec.Command()`, and option/argument injection in subprocess argument lists.
- **Server-Side Request Forgery (SSRF) (CWE-918)**: Identifies user-controlled destination URLs in `requests`, `urllib`, `httpx`, and `fetch` while honoring host allowlists (`ALLOWED_HOSTS`).
- **Path Traversal (CWE-22)**: Flags dynamic file paths in `open()`, `Pathlib`, and file operations; suppresses safe code using `os.path.basename` and canonical boundaries.
- **Cross-Site Scripting & Template Injection (CWE-79 & CWE-1336)**: Detects unescaped markup passed to `Markup()` and untrusted templates compiled via `render_template_string()`.
- **Insecure Deserialization (CWE-502)**: Flags unsafe object deserializers including `pickle.loads()`, `pickle.load()`, `yaml.load(Loader=Loader)`, `yaml.unsafe_load()`, and `marshal.loads()`.
- **Cryptographic & PRNG Failures (CWE-327 & CWE-330)**: Detects broken hashes (`MD5`, `SHA-1`), weak ciphers (`DES`, `RC4` in ECB mode), and pseudo-random generators (`random.random()`, `random.choice()`) used for authentication tokens, while leaving ordinary game/simulation randomness clean.
- **Active Debug Code in Production (CWE-489)**: Flags `app.run(debug=True)` and debug flags in application source code.

### 3. Container & Orchestration Security (Docker & Compose)
- **Container Root Execution (CIS Benchmark 4.1)**: Detects Dockerfiles lacking `USER` instructions or explicitly declaring `USER root`.
- **Missing Container Healthchecks (CIS Benchmark 4.6)**: Identifies containers running without `HEALTHCHECK` monitors.
- **Unbounded Context Inclusion**: Detects broad `COPY . .` instructions that risk bundling `.env` or sensitive credentials into container images.
- **Docker Compose Misconfigurations**: Identifies exposed database ports (`5432:5432`, `3306:3306`), exposed cache ports (`6379:6379`), container privilege escalation (`privileged: true`), host volume mounts (`.:/app`), and host namespace sharing (`network_mode: host`, `pid: host`).

### 4. Software Composition Analysis (SCA) & Local Vulnerability DB
- **Multi-Ecosystem Manifest Parsers**: Native parsers for `requirements.txt` (Python), `package.json` (npm), `go.mod` (Go), and `Cargo.toml` (Rust).
- **Embedded Security Intelligence**: Queries the local `.vibeguard/database/security.db` for published CVEs, GHSAs, and vulnerability advisories with zero required internet connection.
- **Actionable Remediation Guidance**: Reports exact safe target versions (e.g. `Upgrade to >= 3.1.3`) for every vulnerable package detected.

---

## 🏆 Verified Benchmark Results

VibeGuard was rigorously benchmarked against the controlled `FastNote/vibeguard-benchmark/` matrix across 46 deterministic test fixtures:

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                   VIBEGUARD ULTIMATE SECURITY BENCHMARK SCORECARD                    ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  Total Vulnerabilities Evaluated (Ground Truth):               80                    ║
║  True Positives (Vulnerabilities Detected):                    80 (100.0% Recall)    ║
║  False Negatives (Missed Vulnerabilities):                      0 (  0.0% Miss)      ║
║  True Negatives (Safe Controls Cleared):                       18 (100.0% Specific)  ║
║  False Positives on Legitimate Code / Controls:                 0 (  0.0% FP)        ║
║  Cross-File Interprocedural Propagation Recall:             100.0% (All hops traced) ║
║  Software Composition Analysis Recall:                      100.0% (149 Advisories)  ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║  OVERALL SCANNER ACCURACY:        100.0% SENSITIVITY / 100.0% SPECIFICITY            ║
║  FINAL DEPLOYMENT GATE DECISION:  🔴 BLOCKED (High & Critical Vulnerabilities Halts) ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

### Verified Safe-Control Precision (0 False Positives)

| Safe Pattern | Implementation | Result |
| :--- | :--- | :---: |
| **Constant SQL** | `cursor.execute("SELECT * FROM users WHERE id = 10")` | **CLEAN (0 FP)** ✅ |
| **Integer Cast SQL** | `user_id = int(request.args["id"]); query = f"...{user_id}"` | **CLEAN (0 FP)** ✅ |
| **Parameterized SQL** | `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))` | **CLEAN (0 FP)** ✅ |
| **Constant System Command** | `subprocess.run(["git", "status"])` | **CLEAN (0 FP)** ✅ |
| **Quoted Subprocess Argument** | `subprocess.run(["echo", shlex.quote(user_input)])` | **CLEAN (0 FP)** ✅ |
| **Constant HTTPS Endpoint** | `requests.get("https://api.github.com/status")` | **CLEAN (0 FP)** ✅ |
| **Escaped HTML Markup** | `Markup(html.escape(user_input))` | **CLEAN (0 FP)** ✅ |
| **Cryptographically Secure PRNG** | `secrets.token_urlsafe(32)`, `uuid.uuid4()` | **CLEAN (0 FP)** ✅ |
| **Ordinary Game PRNG** | `roll = random.randint(1, 6)`, `choice(...)` in simulation | **CLEAN (0 FP)** ✅ |
| **Modern Password Hashing** | `bcrypt.hashpw(password, salt)` | **CLEAN (0 FP)** ✅ |
| **Static Filesystem Path** | `open("/var/data/config.json")` | **CLEAN (0 FP)** ✅ |
| **Basename File Isolation** | `open(os.path.join(DIR, os.path.basename(filename)))` | **CLEAN (0 FP)** ✅ |
| **SSRF Host Allowlist Guard** | `if parsed.netloc in ALLOWED_HOSTS: requests.get(url)` | **CLEAN (0 FP)** ✅ |
| **Safe Deserialization** | `json.loads(data)`, `yaml.safe_load(data)` | **CLEAN (0 FP)** ✅ |
| **Credential-Free Redis URI** | `REDIS_URL = "redis://localhost:6379"` | **CLEAN (0 FP)** ✅ |

---

## 💻 CLI Reference & Options

```
Usage:
  vibeguard <command> [<project-path>] [options]

Commands:
  scan [<path>]            Run security scan and evaluate deployment gate
  report [<path>]          Generate HTML, JSON, or SARIF security reports
  benchmark [<path>]       Run quality benchmark (confidence, correlation, scope)
  init [<path>]            Install Git pre-push hook and create .vibeguard/
  uninstall [<path>]       Remove VibeGuard Git pre-push hook
  status [<path>]          Show Git repository security gate status
  push [<path>]            Interactive commit, scan, and push workflow
  defender-check           Inspect Windows Defender status & trigger test pop-up alert
  db <status|import>       Manage local offline security intelligence database
  cache-refresh            Purge local OSV vulnerability intelligence cache
  version                  Display VibeGuard version
  help                     Show CLI help

Options:
  --format, -f <fmt>       Output format: terminal (default), json, html, sarif
  --output, -o <path>      Custom report destination path
  --offline                Query only local offline security database (zero network calls)
  --include-tests          Include test fixtures and test directories in scan
  --include-docs           Include markdown documentation in scan
  --show-excluded          Display count of files excluded by security configuration
  --verbose, -v            Show low severity findings and detailed evidence
  --all                    Show all findings including informational notices
  --hook                   Enforce gate thresholds defined in .vibeguard/config.json
```

---

## ⚙️ Configuration Schema (`.vibeguard/config.json`)

VibeGuard can be configured per repository by placing a `config.json` in `.vibeguard/`:

```json
{
  "$schema": "https://raw.githubusercontent.com/vibeguard/vibeguard/main/config.schema.json",
  "version": "7.2.0",
  "gate": {
    "block_on_critical": true,
    "block_on_high": true,
    "min_score": 90,
    "max_allowed_medium": 5
  },
  "scanners": {
    "secrets": true,
    "sast": true,
    "sca": true,
    "docker": true,
    "config": true
  },
  "exclude": [
    "vendor/**",
    "node_modules/**",
    "dist/**",
    "build/**"
  ],
  "reports": {
    "auto_generate_html": true,
    "output_dir": "reports"
  }
}
```

---

## 🚀 CI/CD Integration

### GitHub Actions Pipeline (`.github/workflows/security.yml`)

```yaml
name: VibeGuard Security Gate

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-audit:
    runs-on: windows-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build VibeGuard
        run: |
          go build -o vibeguard.exe ./cmd/vibeguard

      - name: Run VibeGuard Security Scan
        run: |
          .\vibeguard.exe scan . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 📜 Complete Documentation Reference

- **[Technical Architecture](docs/ARCHITECTURE.md)**: Process boundaries, IPC communication, and engine design.
- **[Deep Scanner Architecture](docs/DEEP_SCANNER_ARCHITECTURE.md)**: 20-stage pipeline, AST modeling, and taint propagation.
- **[Security Rules Specification](docs/RULES.md)**: Complete registry of all built-in rules, CWE mappings, and regex definitions.
- **[Language & Technology Rationale](docs/LANGUAGE.md)**: Technical rationale behind the Go + Rust architecture.
- **[Installation & Global Setup Guide](docs/SETUP.md)**: Global Windows PATH installation and zero-config deployment.
- **[Testing & Verification Guide](docs/TESTING.md)**: Test suites, control fixtures, and false-positive verification steps.
- **[Terms & Conditions](TERMS.md)**: Acceptable use policy, liability disclaimers, and privacy guarantees.
- **[Changelog & Release Notes](docs/CHANGELOG.md)**: Comprehensive release history from v0.1.0 to v7.2.0.

---

## 📄 License & Attribution

VibeGuard is free, open-source software licensed under the **[Apache License 2.0](LICENSE)**.  
Review the companion **[Terms & Conditions](TERMS.md)** for usage policies, privacy guarantees, and ethical security standards.  

Developed with ❤️ by the VibeGuard Core Security Engineering Team.
