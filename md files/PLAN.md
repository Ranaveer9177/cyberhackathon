# VibeGuard — Unified Master Development Plan

> **Comprehensive Engineering Blueprint & Phase-by-Phase Execution Plan**  
> *Merged from PLAN.md and PLAN1.md — Covering v0.1 Prototype through v2.0 Git Secure Push Gate & Future Horizons.*

---

## 1. Product Definition & Objectives

**VibeGuard** is an autonomous, on-machine pre-deployment security verification CLI and Git pre-push security firewall. It scans software projects, detects security vulnerabilities, verifies dependency integrity against real-world vulnerability intelligence (Google OSV), calculates a deterministic 0–100 Security Score, generates multi-format reports, and enforces an automated **PASS / BLOCK** gate decision before code can be deployed or pushed to remote repositories.

### Primary Goals:
1. **Autonomous Git Pre-Push Gate**: Intercept `git push` automatically via standard Git hooks; snapshot exact committed content and abort pushes if high or critical vulnerabilities exist.
2. **Deterministic Risk Scoring**: Provide an objective, reproducible 0–100 security score using mathematical severity weighting.
3. **Realistic SAST & Zero Tooling False Positives**: Differentiate true application vulnerabilities (dynamic SQL string concatenation, shell invocations, disabled TLS) from internal CLI calls and scanner rule definitions.
4. **Authoritative Dependency Vulnerability Intelligence**: Link directly to Google OSV database without synthetic CVE generation or AI hallucinations.
5. **Configurable Policy & Exclusions**: Empower developers to configure blocking thresholds and excluded subtrees in `.vibeguard/config.json`.
6. **100% On-Machine Privacy**: Local code and files never leave the machine. Discovered secrets are masked in logs and reports.

---

## 2. Technology Stack & Responsibilities

| Component | Technology | Primary Responsibilities |
| :--- | :--- | :--- |
| **CLI & Orchestrator** | **Go (1.21+)** | Command-line UX, Git hook management, push commit snapshot extraction, dependency manifest parsing, OSV REST API communication, finding aggregation, scoring, report generation, deployment gate decision. |
| **Security Scanner** | **Rust (2021 edition)** | High-speed recursive directory walk with exclusion filtering, secret pattern regex matching with evidence masking, static code analysis (SAST), Dockerfile auditing, configuration checking, JSON IPC stream. |
| **Fallback Scanner** | **Go (Built-in)** | Native Go scanner engine mirroring all Rust rules to ensure seamless scanning in environments without a Rust compiler installed. |
| **Vulnerability DB** | **Google OSV API** | Real-time vulnerability intelligence for Go, npm, PyPI, and crates.io packages (no hallucinated CVEs). |
| **Git Integration** | **Git Hooks & Pure Go Tar** | Pre-push hook lifecycle management (`pre-push`), ref update tuple parsing via stdin, commit tree snapshotting via `git archive` and `archive/tar`. |
| **Data Exchange** | **JSON** | Inter-process communication between Rust scanner and Go CLI; machine-readable reports. |
| **Target Shells** | **PowerShell 7+, CMD, Bash, Zsh** | Cross-platform compatibility on Windows, Linux, and macOS. |

---

## 3. Architecture

```text
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

---

## 4. Repository Structure

```text
cyberhackathon/
├── cmd/
│   └── vibeguard/               # Go CLI application entrypoint
│       └── main.go              # Commands: init, status, push, scan, report, uninstall, version
├── internal/
│   ├── config/                  # Configuration loader, validator, and exclusion matcher
│   ├── dependencies/            # Manifest parsers (go.mod, package.json, requirements.txt, Cargo.toml)
│   ├── gate/                    # PASS / BLOCK deployment decision engine
│   ├── git/                     # Git pre-push hook manager, ref parser, and commit snapshot extractor
│   ├── osv/                     # Google OSV client, batch query engine, and severity mapping
│   ├── report/                  # Terminal ANSI, JSON, and standalone HTML report generators
│   ├── risk/                    # Deterministic 0-100 scoring algorithm
│   └── scanner/                 # Subprocess runner for Rust scanner binary with Go fallback
├── scanner/                     # Rust Scanner Engine
│   ├── Cargo.toml
│   └── src/
│       ├── config.rs            # Configuration file analysis (debug mode, CORS, 0.0.0.0)
│       ├── docker.rs            # Dockerfile security analysis (root user, ENV secrets)
│       ├── git.rs               # Repository sensitive file checks (.env, private keys)
│       ├── main.rs              # Scanner entry point and JSON output serializer
│       ├── rules.rs             # Built-in regex rule definitions
│       ├── sast.rs              # SAST source code scanner
│       ├── scanner.rs           # Fast recursive directory traversal with exclusion filters
│       ├── secrets.rs           # High-entropy secret detection & masking
│       └── types.rs             # Common data structures
├── test-project/                # Controlled intentionally vulnerable test fixture
├── tests/                       # Test suites (dependencies, integration, sast, secrets)
├── .vibeguard/
│   └── config.json              # Repository-level configuration and exclusion rules
├── reports/                     # Output directory for generated reports
├── CHANGELOG.md                 # Full version history
├── FEATURES.md                  # Detailed feature documentation
├── LANGUAGE.md                  # Technical architecture and language decisions
├── PLAN.md                      # Unified Master Development Plan
├── PROCESSES.md                 # Development lifecycle and verification processes
└── README.md                    # Project overview and quickstart guide
```

---

## 5. Development Rules & Engineering Principles

1. **Build the Smallest Working Version First**: Follow incremental development with verifiable milestones.
2. **Comprehensive Test Coverage**: Add unit and integration tests for every completed capability.
3. **Always Runnable**: Keep every commit buildable, testable, and cleanly passing `go vet` and `go test`.
4. **Deterministic Vulnerability Intelligence**: Never invent or hallucinate CVE/advisory data; Google OSV is the definitive source of truth.
5. **Safe Test Fixtures**: Never commit real credentials; use fake, non-functional keys in test fixtures.
6. **No Security Bypasses on Error**: Enforce `fail_closed` policy so network or scanner failures block deployment rather than allowing untested code into production.
7. **Privacy by Default**: Keep code analysis completely local; mask secrets in terminal output, JSON, and HTML.

---

## 6. Version Progression Matrix

| Version | Milestone | Key Capabilities Delivered |
| :---: | :--- | :--- |
| **v0.1** | Foundation & IPC | Go CLI skeleton, Rust scanner skeleton, JSON IPC communication. |
| **v0.2** | Filesystem Traversal | Recursive directory walker, binary file filtering, directory exclusions. |
| **v0.3** | Secret Detection | AWS, GitHub, Slack tokens, private keys, password assignments, credential masking. |
| **v0.4** | SAST Rules Engine | Potential SQL injection, OS command injection, disabled TLS, weak crypto, eval. |
| **v0.5** | Dependency Security | Go, npm, Python, Rust manifest parsers, Google OSV batch queries. |
| **v0.6** | Security Finding Engine | Normalized finding IDs (`VG-001`), severity classification, category grouping. |
| **v0.7** | Reports & Score | Deterministic 0–100 score, colored ANSI terminal, JSON, and standalone HTML reports. |
| **v0.8** | Deployment Gate | PASS / BLOCK logic, exit codes (`0` Pass, `1` Block, `2` Error). |
| **v0.9** | Container & Git Checks | Dockerfile security (root user, ENV secrets), sensitive Git files (.env, keys). |
| **v1.0** | Stable Multi-CLI MVP | Full cross-platform verification, end-to-end integration tests, documentation. |
| **v2.0** | Git Secure Push Gate | Git pre-push hook integration, `vibeguard push`, `vibeguard init`, `.vibeguard/config.json`. |
| **v2.1 / v3** | Scoped Push & Exclusions | Pure Go `git archive` snapshot scanning, exclusion rules (`exclude: [...]`), refined SAST, zero double-scanning. |

---

## 7. Detailed Phase-by-Phase Implementation Plan

### Phase 1 — Project Foundation (v0.1)
- **Step 1**: Initialize Go module `github.com/vibeguard/vibeguard` and project directory structure.
- **Step 2**: Create basic Go CLI entrypoint in `cmd/vibeguard/main.go`.
- **Step 3**: Initialize Rust scanner package in `scanner/` with `Cargo.toml`.
- **Step 4**: Implement JSON IPC communication protocol between Go orchestrator and Rust scanner subprocess.
- **Step 5**: Create basic directory scan execution workflow.
- **Test**: Run Go binary, verify invocation of scanner, parse JSON output.
- **Deploy**: Build and verify `vibeguard` v0.1.

### Phase 2 — Project & File Scanner (v0.2)
- **Step 1**: Implement recursive filesystem traversal using Rust's `walkdir`.
- **Step 2**: Detect files, directory types, and source extensions.
- **Step 3**: Filter out binary executables, media, and archive files (.exe, .dll, .so, .png, .zip).
- **Step 4**: Implement directory skips (`node_modules`, `vendor`, `.git`, `target`, `dist`, `build`).
- **Step 5**: Return structured scanned file count and path lists.
- **Test**: Run scanner on mixed directory hierarchies with binaries and source files.
- **Deploy**: Integrate fast traversal into core scanning pipeline.

### Phase 3 — Secret Detection (v0.3)
- **Step 1**: Build regex pattern engine for high-entropy secrets in `scanner/src/secrets.rs`.
- **Step 2**: Add patterns for AWS keys (`AKIA[0-9A-Z]{16}`), GitHub tokens (`ghp_[a-zA-Z0-9]{36}`), Slack tokens (`xox[bprs]-...`).
- **Step 3**: Add patterns for private keys (`BEGIN RSA/OPENSSH PRIVATE KEY`), passwords, and generic API keys.
- **Step 4**: Add sensitive filename detection (`.env`, `id_rsa`, `*.pem`, `*.key`, `credentials.*`, `secrets.*`).
- **Step 5**: Implement secret masking (preserve first 8 characters, mask remainder with `****`).
- **Test**: Verify detection and masking against `tests/secrets/` fixtures.
- **Deploy**: Integrate secret scanner into scan pipeline.

### Phase 4 — Source Code Security (SAST) (v0.4)
- **Step 1**: Create static code analysis rule definitions in `scanner/src/rules.rs` and `scanner/src/sast.rs`.
- **Step 2**: Implement Potential SQL Injection detection (string concatenation and dynamic formatting).
- **Step 3**: Implement Potential OS Command Injection detection (`exec.Command`, `os.system`, `child_process.exec`).
- **Step 4**: Implement Dangerous Evaluation detection (`eval()`, `Function()`).
- **Step 5**: Implement Potential TLS Misconfiguration detection (`InsecureSkipVerify: true`, `rejectUnauthorized: false`).
- **Step 6**: Implement Weak Cryptography detection (`md5`, `sha1`, `DES`, `RC4`).
- **Step 7**: Implement Potential Insecure HTTP Connection detection (excluding `localhost` and `127.0.0.1`).
- **Step 8**: Extract exact line numbers and code evidence for all findings.
- **Test**: Run against `tests/sast/vulnerable.go` and ensure accurate line reporting.
- **Deploy**: Integrate SAST module into scan pipeline.

### Phase 5 — Dependency Security (SCA) (v0.5)
- **Step 1**: Implement manifest parsers in `internal/dependencies/` for:
  - Go: `go.mod`
  - Node.js: `package.json` and `package-lock.json`
  - Python: `requirements.txt`
  - Rust: `Cargo.toml` and `Cargo.lock`
- **Step 2**: Sanitize package version strings (strip caret `^`, tilde `~`, comparison operators `>=`).
- **Step 3**: Connect to Google OSV REST API (`https://api.osv.dev/v1/querybatch`) in `internal/osv/`.
- **Step 4**: Extract advisory summaries, CVE aliases, affected versions, and fixed upgrade versions.
- **Step 5**: Map CVSS v3/v4 vectors and database severities into normalized VibeGuard severity levels.
- **Test**: Verify known vulnerable dependencies (`lodash@4.17.20`, `django@3.2.0`, `flask@2.0.1`).
- **Deploy**: Integrate dependency vulnerability scanner into scan pipeline.

### Phase 6 — Security Finding Engine (v0.6)
- **Step 1**: Merge findings from Secrets, SAST, Dependencies, Docker, and Configuration modules.
- **Step 2**: Generate sequential, normalized finding IDs (`VG-001`, `VG-002`, etc.).
- **Step 3**: Assign standardized severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Step 4**: Attach actionable remediation recommendations to each finding.
- **Step 5**: Group findings by category and compute aggregate counts.
- **Test**: Verify finding collation across multi-vulnerability projects.
- **Deploy**: Establish central Finding Engine.

### Phase 7 — Risk Scoring & Reporting (v0.7)
- **Step 1**: Implement deterministic 0–100 mathematical risk scoring formula:
  $$\text{Score} = \max\left(0, 100 - (15 \times C + 8 \times H + 3 \times M + 1 \times L)\right)$$
- **Step 2**: Create colored ANSI terminal report with severity banners and finding summaries.
- **Step 3**: Create structured JSON report generator (`reports/scan.json`).
- **Step 4**: Create responsive, standalone HTML report generator (`reports/scan.html`) with CSS visual badges.
- **Test**: Verify reports across both clean (100/100) and vulnerable test fixtures.
- **Deploy**: Enable `--format terminal|json|html` CLI options.

### Phase 8 — Deployment Gate & Exit Codes (v0.8)
- **Step 1**: Implement gate evaluation in `internal/gate/`:
  - `PASSED`: No blocking findings present.
  - `BLOCKED`: One or more blocking findings present.
- **Step 2**: Establish standardized process exit codes:
  - `0`: PASS / SAFE
  - `1`: BLOCK / VULNERABILITIES FOUND
  - `2`: RUNTIME ERROR
  - `3`: CONFIG ERROR
  - `4`: OSV UNAVAILABLE (with fail_closed enabled)
- **Test**: Verify CI/CD pipeline automation triggers and exit code returns.
- **Deploy**: Standardize CLI exit behavior across all commands.

### Phase 9 — Docker, Git & Configuration Auditing (v0.9)
- **Step 1**: Implement Dockerfile scanner in `scanner/src/docker.rs` (root user check, ENV secret check, COPY . .).
- **Step 2**: Implement Git repository checker in `scanner/src/git.rs` (untracked sensitive credential files).
- **Step 3**: Implement configuration auditor in `scanner/src/config.rs` (debug mode, wildcard CORS, 0.0.0.0 host binding).
- **Test**: Verify detection in Dockerfile and configuration fixtures.
- **Deploy**: Integrate into comprehensive scan.

### Phase 10 — Multi-Shell Verification & MVP Release (v1.0)
- **Step 1**: Verify seamless execution across PowerShell 7+, CMD, Git Bash, and Linux shells.
- **Step 2**: Package release binaries and complete v1.0 documentation.
- **Test**: Execute full test suite (`go test ./...`) and end-to-end integration tests.
- **Deploy**: VibeGuard v1.0 Release.

### Phase 11 — Git Pre-Push Hook Architecture (v2.0)
- **Step 1**: Implement Git repository detection and inspection in `internal/git/repo.go`.
- **Step 2**: Implement pre-push hook installer in `internal/git/hooks.go` (`.git/hooks/pre-push`).
- **Step 3**: Implement user hook preservation: back up existing hooks to `pre-push.user` and chain execution.
- **Step 4**: Implement `vibeguard init`: install hook and generate `.vibeguard/config.json`.
- **Step 5**: Implement `vibeguard status`: inspect Git repository, branch, remote, hook, and policies.
- **Step 6**: Implement `vibeguard uninstall`: cleanly remove hook and restore user backup.
- **Step 7**: Implement `vibeguard push`: interactive staging, commit creation, security scan, and remote push.
- **Test**: Verify hook installation, preservation, execution, and uninstallation.
- **Deploy**: VibeGuard v2.0 Release.

### Phase 12 — Scoped Pre-Push Snapshot & Exact Commit Scanning (v2.1 / v3)
- **Step 1**: Parse pre-push stdin ref update tuples (`<local_ref> <local_sha> <remote_ref> <remote_sha>`).
- **Step 2**: Detect branch deletions (`strings.Trim(localSha, "0") == ""`) and allow immediately.
- **Step 3**: Extract exact commit tree snapshot using pure Go `git archive` and `archive/tar`.
- **Step 4**: Scope pre-push scan strictly to the committed snapshot, preventing dirty working directory changes from polluting pre-push decisions.
- **Step 5**: Automatically clean up temporary snapshot directory via `defer`.
- **Test**: Verify pre-push hook scans exact committed tree.
- **Deploy**: Integrated into `runScan` hook workflow.

### Phase 13 — Configurable Repository Exclusions & Policy Schema (v2.1 / v3)
- **Step 1**: Add `Exclude []string` field to `Config` struct in `internal/config/config.go`.
- **Step 2**: Implement `IsExcluded(relPath string) bool` matching exact paths, directory subtrees, and basenames.
- **Step 3**: Update `.vibeguard/config.json` with default exclusions (`.git`, `.vibeguard`, `reports`, `md files`, `tests`, `code.md`, `finalreport.md`, etc.).
- **Step 4**: Update Go scanner `RunInternalScanner` to skip excluded subtrees during filesystem walk.
- **Step 5**: Update Rust scanner `scan_directory` to load `.vibeguard/config.json` and skip matching exclusions.
- **Step 6**: Update dependency detector `DetectDependencies` to skip excluded manifest files.
- **Test**: Verify self-scan reports 0 findings, while `test-project` still reports full findings.
- **Deploy**: Universal exclusion filtering across all engines.

### Phase 14 — SAST Realism & Double-Scan Elimination (v2.1 / v3)
- **Step 1**: Update SAST rule titles to precise terminology:
  - `Potential OS Command Injection`
  - `Potential SQL Injection`
  - `Potential TLS Misconfiguration`
  - `Potential Insecure HTTP Connection`
- **Step 2**: Eliminate false positives on internal CLI tooling: ignore safe fixed commands like `exec.Command("git", ...)` and `exec.CommandContext`.
- **Step 3**: Skip comments and regex compilation definitions (`regexp.MustCompile`, `Regex::new`) during code scanning.
- **Step 4**: Implement `GitPushVerified` executing `git push --no-verify` inside `vibeguard push` to eliminate duplicate scanning.
- **Step 5**: Enhance pre-push hook script to dynamically resolve `vibeguard.exe` from repository root or PATH.
- **Test**: Verify self-scan passes 100/100, and `vibeguard push` scans cleanly exactly once.
- **Deploy**: Complete double-scan elimination and realistic SAST.

### Phase 15 — Live Terminal Scan Progress Indicators (v3.0)
- **Step 1**: Implement dynamic terminal progress engine in `internal/report/progress.go` (`ProgressBar`, `BuildBar`, `Render`, `Finish`, `Reset`, ANSI in-place cursor handling `\033[%dA\r`).
- **Step 2**: Add `ScanProgressFunc` in `internal/scanner/runner.go` with candidate discovery upfront to report files scanned / total files and active file path.
- **Step 3**: Add `OSVProgressFunc` in `internal/osv/client.go` to report live OSV queries completed / total queries.
- **Step 4**: Integrate progress indicators into `cmd/vibeguard/main.go` across File Scan, Dependency Scan, OSV Querying, and 100% final completion stage.
- **Step 5**: Fix commit diff parser in `main.go` to handle file paths with spaces and honor repository exclusions.
- **Test**: Unit tests in `internal/report/progress_test.go`, full test suite `go test ./...`, self-scan test `vibeguard scan .`, and pre-push hook execution.
- **Deploy**: VibeGuard v3.0 Release with Live Scan Progress.

### Phase 16 — Automated Environment Setup & Global CLI (`setup.bat`) (v3.1)
- **Step 1**: Implement automated batch script (`setup.bat`) for Windows development environments.
- **Step 2**: Check package manager availability (`winget`).
- **Step 3**: Check whether each dependency is already installed before attempting download:
  - Git
  - Go
  - Rust + Cargo
  - Node.js
  - Python
  - Docker (Docker CLI / Docker Desktop)
- **Step 4**: Perform automated installation via `winget` only for missing prerequisites.
- **Step 5**: Permanently install `vibeguard.exe` and `vibeguard-scanner.exe` into `%LOCALAPPDATA%\VibeGuard\bin`.
- **Step 6**: Add `%LOCALAPPDATA%\VibeGuard\bin` permanently to Windows User `PATH` via PowerShell.
- **Step 7**: Configure session PATH and verify tool directories (`%LOCALAPPDATA%\VibeGuard\bin`, `.cargo\bin`, `Go\bin`, `Git\cmd`, `nodejs`).
- **Step 8**: Verify PATH for Go, Rust, Cargo, and VibeGuard and print structured confirmation status.
- **Test**: Run `setup.bat` on clean and pre-configured workstations to verify zero-redundant installations and instant environment validation.
- **Deploy**: Production-ready `setup.bat` with permanent global CLI distribution.


---

## 8. Future Roadmap & Horizons

### Phase 17 — Optional AI Remediation Layer
- Interface with developer-selected AI models (Local Ollama, Anthropic, OpenAI, or Gemini).
- Generate contextual code diff patches for identified vulnerabilities.
- Keep core vulnerability detection 100% deterministic and non-dependent on AI.

### Phase 18 — Native CI/CD Actions
- GitHub Action: `uses: vibeguard/vibeguard-action@v1`.
- GitLab CI template and pre-commit framework integration (`.pre-commit-hooks.yaml`).

### Phase 19 — IDE Sidecar & Real-Time LSP
- Lightweight language server protocol (LSP) plugin for VS Code, JetBrains, and Neovim to highlight security issues in real-time as code is typed.
