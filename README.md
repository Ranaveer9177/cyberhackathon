# VibeGuard v7.2.0

> **Autonomous Pre-Push Security Firewall & Deep Static Analyzer**  
> *Intercept secrets, vulnerabilities, and unsafe code before they leave your workstation — automatically.*

[![Version](https://img.shields.io/badge/version-v7.2.0-blue.svg)](docs/CHANGELOG.md)
[![Security Gate](https://img.shields.io/badge/security_gate-PASSED_100%2F100-brightgreen.svg)](ultimate_test.bat)
[![Engines](https://img.shields.io/badge/engines-Go_1.21+_|_Rust_1.70+-orange.svg)](docs/LANGUAGE.md)
[![Benchmark](https://img.shields.io/badge/benchmark-100%25_Recall_|_100%25_Specificity-success.svg)](docs/TESTING.md)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0_Compliant-purple.svg)](internal/report/sarif.go)
[![Platform](https://img.shields.io/badge/platform-Windows_10%2F11-lightgrey.svg)](docs/SETUP.md)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)

---

## What is VibeGuard?

**VibeGuard** is a dual-engine security scanner built in **Go** + **Rust** that acts as an autonomous Git pre-push firewall. Before any code leaves your machine, it:

- 🔍 Scans for **hardcoded secrets, API keys, and credentials**
- 🛡️ Performs **deep static analysis** (SQLi, CMDi, SSRF, XSS, path traversal, deserialization, weak crypto)
- 📦 Audits **open-source dependencies** for known CVEs (offline-capable)
- 🐳 Validates **Docker/Compose** security configuration
- 📊 Generates **terminal, HTML, JSON, and SARIF 2.1.0** reports
- 🚫 **Blocks** the push automatically if critical or high findings are found

```
  git push
     │
     ▼
 VibeGuard Pre-Push Hook (automatic)
     │
     ├── Rust Scanner  ─── Secrets, SAST, Docker
     ├── Go Orchestrator ── Dependencies, OSV CVE lookup
     │
     ├── Score >= 90?  → [PASS]  Push proceeds
     └── Score < 90?   → [BLOCK] Push aborted + detailed report
```

---

## Running VibeGuard — Two Methods

VibeGuard can be run in **two ways**, depending on whether you have installed it globally:

---

### Method 1 — Direct `.exe` (No Installation Required)

Run `vibeguard.exe` directly from the repository root. This always uses the **latest built binary** in the project folder.

```powershell
# From the cyberhackathon repository root:

# See version
.\vibeguard.exe version

# Scan a project
.\vibeguard.exe scan .
.\vibeguard.exe scan "C:\Users\YourName\Projects\MyApp"

# Initialize the Git pre-push hook (run once per repo)
.\vibeguard.exe init

# Generate an HTML audit report
.\vibeguard.exe report . --format html --output reports/audit.html

# Interactive commit + scan + push workflow
.\vibeguard.exe push

# Show help
.\vibeguard.exe help
```

> **When to use this:** When you want to use the version in the repo directly, or when testing after a new build without re-running setup.

---

### Method 2 — Global `vibeguard` Command (After Installation)

After running `scripts\windows\setup.bat`, VibeGuard is installed globally at `%LOCALAPPDATA%\VibeGuard` and added to your User `PATH`. You can then use `vibeguard` from **any folder, any terminal**, without `.\` or a full path.

```powershell
# Works from ANY directory — no .\ needed:

vibeguard version

vibeguard scan .
vibeguard scan "C:\Users\YourName\Projects\MyApp"

vibeguard init
vibeguard push
vibeguard report . --format html
vibeguard help
```

> **When to use this:** After running `setup.bat` once. This is the recommended mode for day-to-day use — the hook installed in any repository will automatically call the globally-installed binary.

---

### How to Install Globally (One-Time Setup)

```powershell
# From the cyberhackathon repository root:
scripts\windows\setup.bat
```

**What setup.bat does:**
1. Copies `vibeguard.exe` and `vibeguard-scanner.exe` to `%LOCALAPPDATA%\VibeGuard\`
2. Adds `%LOCALAPPDATA%\VibeGuard` to your Windows User `PATH` (no admin required)
3. Initializes the `.vibeguard/` config folder and Git hook in the repo

After setup, **open a new terminal** and you'll have the `vibeguard` command available everywhere.

```powershell
# Verify global install:
vibeguard version
where vibeguard
```

---

### Difference at a Glance

| | `.\vibeguard.exe` | `vibeguard` (global) |
|:--|:--|:--|
| **Requires installation?** | No | Yes (run `setup.bat` once) |
| **Works from any folder?** | No — must be in repo root | **Yes — anywhere** |
| **Used by Git hook?** | No | **Yes** (hook calls global binary) |
| **Reflects latest build?** | Always (local exe) | After re-running `setup.bat` |
| **Best for** | Testing new builds | Day-to-day use |

---

## Quick Start

```powershell
# Step 1: Clone the repository
git clone https://github.com/Ranaveer9177/cyberhackathon.git
cd cyberhackathon

# Step 2: Install globally (one-time)
scripts\windows\setup.bat

# Step 3: Open a NEW terminal, then verify
vibeguard version

# Step 4: Initialize the hook in any Git repo you want to protect
cd C:\path\to\your\project
vibeguard init

# Step 5: That's it! Every git push is now automatically secured.
git push
```

---

## Building from Source

If you want to compile VibeGuard yourself (requires Go 1.21+ and Rust 1.70+):

```powershell
# From the cyberhackathon repository root:
scripts\windows\build.bat
```

**What build.bat does:**
1. Checks for Go, Rust, and Cargo compilers
2. Compiles the Rust scanner engine (`cargo build --release`)
3. Compiles the Go CLI orchestrator (`go build ./cmd/vibeguard`)
4. Copies both binaries to `%LOCALAPPDATA%\VibeGuard`

After building, the new binaries are live immediately in `%LOCALAPPDATA%\VibeGuard`.

```powershell
# Verify the new build:
vibeguard version       # global (updated by build.bat)
.\vibeguard.exe version  # local repo copy
```

---

## All Commands Reference

```
vibeguard <command> [<project-path>] [options]

Commands:
  scan [<path>]              Run full security scan and evaluate deployment gate
  report [<path>]            Generate HTML, JSON, or SARIF 2.1.0 security reports
  benchmark [<path>]         Run precision/recall quality benchmark
  init [<path>]              Install Git pre-push hook and create .vibeguard/ config
  uninstall [<path>]         Remove VibeGuard Git pre-push hook
  status [<path>]            Show Git repository and security gate status
  push [<path>]              Interactive: stage changes → scan → push safely
  defender-check             Inspect Windows Defender status and test desktop alert
  db <status|import|export>  Manage the local offline security vulnerability database
  cache-refresh              Clear local OSV vulnerability intelligence cache
  version                    Show VibeGuard version
  help                       Show this help message

Options:
  --format, -f <fmt>     Output format: terminal (default), json, html, sarif
  --output, -o <path>    Custom report output path
  --offline              Use only local database — zero internet required
  --include-tests        Include test directories in scan
  --include-docs         Include markdown/documentation files in scan
  --verbose, -v          Show low severity findings and detailed evidence
  --all                  Show all findings including informational notices
  --hook                 Apply gate policy from .vibeguard/config.json

Exit Codes:
  0  PASS   — Security scan passed, safe to push
  1  BLOCK  — Critical or high findings found, push blocked
  2  ERROR  — Scanner or runtime error
  3  CONFIG — Format or configuration error
  4  OFFLINE — Vulnerability DB unreachable with fail_closed enabled
```

---

## What VibeGuard Detects

### Secrets & Credentials
- AWS Access Keys (`AKIA...`) and Secret Keys
- GitHub Personal Access Tokens (`ghp_...`)
- Stripe Live/Secret Keys (`sk_live_...`)
- Slack Tokens (`xoxb-...`), SendGrid Keys (`SG....`)
- Private key PEM blocks (RSA, EC, OPENSSH)
- Database connection strings with embedded passwords (PostgreSQL, MySQL, Redis, MongoDB)
- Hardcoded passwords in equality comparisons (`if key == "MASTER_ADMIN_KEY_..."`)
- Evidence auto-masked: shows first 8 characters then `****`

### Static Analysis (SAST)
| Vulnerability | CWE | Detection Method |
|:--|:--|:--|
| SQL Injection | CWE-89 | f-strings, concatenation, `.format()` in SQL |
| Command Injection | CWE-78 | `os.system()`, `subprocess(shell=True)`, `exec.Command()` |
| Argument Injection | CWE-88 | User input in subprocess argument lists |
| SSRF | CWE-918 | User-controlled URLs in `requests`, `urllib`, `httpx` |
| Path Traversal | CWE-22 | Dynamic paths in `open()`, `pathlib` |
| XSS / Template Injection | CWE-79 | `Markup()`, `render_template_string()` |
| Insecure Deserialization | CWE-502 | `pickle.loads()`, `yaml.unsafe_load()`, `marshal.loads()` |
| Weak Crypto | CWE-327 | MD5, SHA-1, DES, RC4 for security operations |
| Insecure PRNG | CWE-330 | `random.random()`, `random.choice()` for auth tokens |
| Debug in Production | CWE-489 | `app.run(debug=True)` |

### Container Security (Docker & Compose)
- Container running as root (no `USER` instruction)
- Missing `HEALTHCHECK` directive
- Broad `COPY . .` bundling sensitive files
- Exposed database/cache ports (`5432`, `3306`, `6379`)
- `privileged: true`, host mounts, `network_mode: host`

### Software Composition Analysis (SCA)
- Parses `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`
- Checks against local offline database (`security.db`) — no internet needed
- Reports exact safe upgrade versions for every vulnerable package

---

## Safe Controls — Zero False Positives

VibeGuard's semantic analysis clears these patterns correctly:

| Pattern | Result |
|:--|:---:|
| `cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))` | ✅ CLEAN |
| `user_id = int(request.args["id"])` then used in query | ✅ CLEAN |
| `subprocess.run(["git", "status"])` — constant args | ✅ CLEAN |
| `subprocess.run(["echo", shlex.quote(user_input)])` | ✅ CLEAN |
| `requests.get("https://api.github.com/status")` | ✅ CLEAN |
| `Markup(html.escape(user_input))` | ✅ CLEAN |
| `secrets.token_urlsafe(32)`, `uuid.uuid4()` | ✅ CLEAN |
| `random.randint(1, 6)` in game/simulation code | ✅ CLEAN |
| `json.loads(data)`, `yaml.safe_load(data)` | ✅ CLEAN |
| `open(os.path.join(DIR, os.path.basename(filename)))` | ✅ CLEAN |
| `if parsed.netloc in ALLOWED_HOSTS: requests.get(url)` | ✅ CLEAN |
| `REDIS_URL = "redis://localhost:6379"` (no password) | ✅ CLEAN |

---

## Benchmark Results

Verified against the `FastNote/vibeguard-benchmark/` matrix — 46 deterministic test fixtures:

```
╔═══════════════════════════════════════════════════════════════╗
║          VIBEGUARD BENCHMARK SCORECARD (v7.2.0)               ║
╠═══════════════════════════════════════════════════════════════╣
║  True Positives (Detected):       80 / 80   → 100.0% Recall  ║
║  False Negatives (Missed):         0 / 80   →   0.0% Miss    ║
║  True Negatives (Safe & Clean):   18 / 18   → 100.0% Specific║
║  False Positives on Safe Code:     0 / 18   →   0.0% FP      ║
║  Cross-File Taint Propagation:    100.0%    (all hops traced) ║
╠═══════════════════════════════════════════════════════════════╣
║  ACCURACY: 100.0% Sensitivity / 100.0% Specificity            ║
║  GATE:     🔴 BLOCKED (High & Critical findings halted)        ║
╚═══════════════════════════════════════════════════════════════╝
```

Self-scan of the VibeGuard repository:

```
Security Score: 100/100 (LOW RISK)
Gate Status:    PASSED
Files Scanned:  117
Findings:       0 Critical, 0 High, 0 Medium, 0 Low
```

---

## Configuration (`.vibeguard/config.json`)

```json
{
  "version": "7.2.0",
  "gate": {
    "block_on_critical": true,
    "block_on_high": true,
    "min_score": 90
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
  ]
}
```

---

## Offline Mode (Air-Gapped)

VibeGuard ships with an **embedded local vulnerability database** that works with zero internet:

```powershell
# Import vulnerability data into local database
vibeguard db import path\to\osv-data.json

# Check local database status
vibeguard db status

# Run scan using only local database (no internet calls)
vibeguard scan . --offline
```

The local database is stored at `.vibeguard\database\security.db` and supports Go, npm, PyPI, and Crates.io ecosystems.

---

## CI/CD Integration (GitHub Actions)

```yaml
name: VibeGuard Security Gate

on: [push, pull_request]

jobs:
  security:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build VibeGuard
        run: go build -o vibeguard.exe ./cmd/vibeguard

      - name: Run Security Scan (SARIF)
        run: .\vibeguard.exe scan . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## Project Structure

```
cyberhackathon/
├── vibeguard.exe              ← Go CLI (run directly with .\vibeguard.exe)
├── vibeguard-scanner.exe      ← Rust scanner binary
├── ultimate_test.bat          ← Full 8-stage test suite
│
├── cmd/vibeguard/             ← Go CLI source code
├── internal/                  ← Go packages (scanner, report, gate, risk, osv)
├── scanner/                   ← Rust scanner engine source
│   └── src/
│       ├── rules/             ← Detection rules (SQLi, SSRF, SAST, secrets…)
│       ├── taint/             ← Taint propagation engine
│       └── ast/               ← AST parsers (Python, Go, JS, Rust…)
│
├── scripts/windows/
│   ├── setup.bat              ← Global install script (run once)
│   ├── build.bat              ← Build from source (needs Go + Rust)
│   ├── run_test.bat           ← Health check suite
│   ├── install_hook.bat       ← Install Git pre-push hook
│   └── uninstall_hook.bat     ← Remove Git pre-push hook
│
├── docs/                      ← Full documentation
│   ├── ARCHITECTURE.md
│   ├── RULES.md
│   ├── SETUP.md
│   ├── TESTING.md
│   └── CHANGELOG.md
│
├── .vibeguard/                ← Per-repo config (auto-created by vibeguard init)
│   ├── config.json
│   └── database/security.db  ← Local offline vulnerability database
│
└── VibeGuard Document/        ← Academic submission documents (PDF)
```

---

## Scripts Reference

| Script | Purpose | Prerequisites |
|:--|:--|:--|
| `scripts\windows\setup.bat` | Install prebuilt binaries globally, configure PATH | None (no compilers) |
| `scripts\windows\build.bat` | Compile from source, update global install | Go 1.21+, Rust 1.70+ |
| `scripts\windows\run_test.bat` | Health check: CLI, scanner, version, report, gate | Installed VibeGuard |
| `scripts\windows\install_hook.bat` | Install `.git/hooks/pre-push` in current repo | Installed VibeGuard |
| `scripts\windows\uninstall_hook.bat` | Remove pre-push hook from current repo | None |
| `ultimate_test.bat` | 8-stage weighted test: vet, clippy, build, CLI health | Go 1.21+, Rust 1.70+ |

---

## Documentation

| Document | Description |
|:--|:--|
| [SETUP.md](docs/SETUP.md) | Global installation, PATH config, setup details |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, IPC, engine boundaries |
| [DEEP_SCANNER_ARCHITECTURE.md](docs/DEEP_SCANNER_ARCHITECTURE.md) | 20-stage pipeline, AST modeling, taint propagation |
| [RULES.md](docs/RULES.md) | All built-in rules, CWE mappings, regex definitions |
| [LANGUAGE.md](docs/LANGUAGE.md) | Why Go + Rust: rationale and technical decisions |
| [TESTING.md](docs/TESTING.md) | Test suites, benchmark fixtures, verification steps |
| [CHANGELOG.md](docs/CHANGELOG.md) | Release history from v0.1.0 → v7.2.0 |
| [TERMS.md](TERMS.md) | Acceptable use, privacy guarantees, disclaimers |

---

## Team

**Team SPARK** — Sreenidhi Institute of Science and Technology  
CyberHackathon 2.0

| Name | Roll Number |
|:--|:--|
| B. Poojitha | 24311A6201 |
| Y. Bhavya Sri | 24311A6203 |
| A. Ranaveer | 24311A6211 |
| M. Gagan Sai | 24311A6212 |

---

## License

VibeGuard is open-source software licensed under the **[Apache License 2.0](LICENSE)**.  
See [TERMS.md](TERMS.md) for usage policies, privacy guarantees, and ethical security standards.

---

*Developed with ❤️ by Team SPARK — VibeGuard Core Security Engineering.*
