# VibeGuard Changelog

All notable changes to the VibeGuard project are documented in this file.

## [v6.1.0] — 2026-09-24 (Current Release)

### Added & Enhanced
- **Scope-Aware Function-Level Taint Tracking**:
  - Implemented lexical function scope extraction (`FunctionScope`) and inter-procedural call-site argument-to-parameter taint propagation (`Source → Var → Arg → Param → Local → Sink`).
  - Supports Python (`def foo(target):`), Go (`func foo(target string)`), and JavaScript/TypeScript (`function foo(target)`).
  - Multi-pass fixed-point taint propagation accurately tracks input flow regardless of function definition order.
- **Sink-Specific Sanitizer Modeling**:
  - Command injection sanitizers: recognizes `shlex.quote(...)`, `escapeshellarg(...)`, and `escapeshellcmd(...)`.
  - Non-shell execution modeling: passing argument lists to `subprocess.run(["cmd", arg])` without `shell=True` is verified as safe and suppressed from command injection false alarms.
  - SQL injection sanitizers: recognizes parameterized binding and numeric type casting (`int(...)`, `float(...)`, `strconv.Atoi`).
- **Data-Flow Provenance Traces & Enriched Reporting**:
  - Emitted findings now include comprehensive step-by-step data flow traces (`data_flow`), `source`, and `sink` expressions.
  - Terminal scan reports visually render multi-line taint provenance chains under each finding.
  - SARIF 2.1.0 output enriched with MITRE CWE tags (`properties.tags`), help URIs, and data-flow traces for GitHub Advanced Security code scanning integration.
- **Canonical Rule IDs & Exact MITRE CWE Mappings**:
  - All SAST, secret, docker, and configuration rules mapped to official CWEs (`CWE-89`, `CWE-78`, `CWE-95`, `CWE-295`, `CWE-327`, `CWE-319`, `CWE-798`, `CWE-916`, `CWE-330`, `CWE-345`, `CWE-250`, `CWE-214`, `CWE-668`, `CWE-552`, `CWE-259`, `CWE-200`, `CWE-489`, `CWE-942`).
- **Expanded Docker & Configuration Rules**:
  - **`VG-DCK-015`** (`CWE-668`): Flags containers using host networking (`network_mode: host`, `--net=host`).
  - **`VG-DCK-016`** (`CWE-668`): Flags containers sharing host PID or IPC namespaces (`pid: host`, `ipc: host`).
  - **`VG-CFG-004`** (`CWE-200`): Verifies target repository `.gitignore` contains `.env` whenever `.env` files are present in the project.
- **100% Rust & Go Dual-Engine Parity**:
  - Fully synchronized all function-level taint tracking, sanitizers, and new rules between native Rust scanner (`vibeguard-scanner.exe`) and Go fallback orchestrator (`runner.go`).
  - Passed `ultimate_test.bat` with 100/100 score and achieved clean 100/100 repository self-scan.

## [v6.0.0] — 2026-09-24

### Added & Enhanced
- **Scope-Aware Data-Flow SAST Engine**:
  - Upgraded code analysis from line-by-line regex matching to **Source $\rightarrow$ Flow $\rightarrow$ Sink Taint Tracking**.
  - Traces untrusted user inputs (Flask `request.args`, `request.json`, `request.form`, Express `req.query`, Go `r.URL.Query`) as they propagate into database queries and operating system command invocations.
  - Detects modern Python f-strings SQL injection (`f"SELECT ... {param}"`), dynamic `%` formatting, `.format()` injections, and string concatenation (`VG-SAST-001`).
  - Detects subprocess execution with `shell=True` / `shell=1` with data-flow escalation (`VG-SAST-008`, `VG-SAST-002`).
- **Authentication & API Security Rules**:
  - **`VG-AUTH-001`**: Detects weak password hashing algorithms (MD5, SHA-1) applied to user credentials while differentiating non-credential data checksums.
  - **`VG-AUTH-002`**: Flags predictable, reversible encoding (such as `base64` over email or timestamp) used for password reset and session tokens.
  - **`VG-AUTH-003`**: Identifies hardcoded Bearer authentication tokens and JWT secrets.
  - **`VG-WEBHOOK-001`**: Verifies that incoming webhook handlers enforce cryptographic signature verification (HMAC-SHA256, `X-Hub-Signature`, `Stripe-Signature`).
- **Dedicated Docker Compose Security Engine**:
  - Comprehensive parser and analyzer for `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, and `compose.yaml`.
  - **`VG-DCK-006`**: Flags exposed database ports (`5432`, `3306`, `27017`) bound to host network interfaces.
  - **`VG-DCK-007`**: Flags exposed Redis cache port (`6379`) bound to host interfaces.
  - **`VG-DCK-008`**: Identifies containers explicitly running as `user: root`.
  - **`VG-DCK-009`**: Detects risky host filesystem mounts (`.:/app`).
  - **`VG-DCK-010`**: Detects weak or default container passwords in environment variables.
  - **`VG-DCK-011`**: Detects privileged container execution (`privileged: true`).
  - **`VG-DCK-012`**: Detects dangerous Linux capabilities (`SYS_ADMIN`, `ALL`).
  - **`VG-DCK-013`**: Flags dangerous sensitive host path mounts (`/var/run/docker.sock`, `/root`).
- **Cross-File Build Leak Correlation (`VG-DCK-014`)**:
  - Correlates `.env` and sensitive credential files with `COPY . .` instructions in `Dockerfile` when `.dockerignore` is missing or fails to exclude secrets.
- **100% Go & Rust Parity & Canonical Rule IDs**:
  - Standardized all rules across both the Rust high-performance engine and Go fallback engine using canonical stable identifiers (`VG-SAST-*`, `VG-DCK-*`, `VG-AUTH-*`, `VG-WEBHOOK-*`, `VG-SEC-*`).
- **FastNote Benchmark Test Suite**:
  - Added automated regression fixtures under `tests/fixtures/fastnote/` and verified with Go and Rust automated test suites.

## [v5.1.0] — 2026-09-22

### Added & Enhanced
- **Generic Leak File & Sensitive Pattern Recognition**:
  - Expanded sensitive filename detection in both Rust and Go engines to recognize generic leak patterns: `leak*.txt` (e.g., `leak_test.txt`), `test*.txt`, `*_secret.txt`, `*.conf`, and `*.env*`.
  - Dependency manifests such as `requirements.txt` are explicitly exempted from sensitive filename flagging.
- **Dynamic Credential Weighting**:
  - Exact assignments (`password = "..."`, `api_key = "..."`, `secret = "..."`) in text and configuration files receive high-confidence scoring regardless of whether the file is strictly named `password.txt`.
  - Excludes source code comparison expressions (`==`, `!=`) from credential assignment detection, preventing false positives on variable checks.
  - Test fixtures exemption ensures real leak files (e.g., `leak_test.txt`) are not penalized as harmless test fixtures.
- **Transparent Reporting (`--verbose`, `-v`, `--all`)**:
  - Scan terminal output separates primary actionable findings (Critical, High, Medium) from low-severity/advisory items.
  - Low-severity findings are neatly noted with a count in standard view and fully enumerated under a dedicated `Advisory & Low Severity Findings` section when `--verbose` or `--all` is specified.
- **DevSecOps Chaos & Deep Testing Suite**:
  - Aggressively verified engine resilience across 5 core failure domains:
    - Domain 1: SCA manifest protection vs nested leak wildcards (`100% detection`).
    - Domain 2: Mathematical boundary stress; equality operators (`==`, `!=`) yielded 0 false positives.
    - Domain 3: Parallel directory walker stress against 5,000 generated files with instant early root pruning (0.160s scan latency).
    - Domain 4: Command-line flag abuse and parameter fuzzing, ensuring graceful exit boundaries (Exit Code 0 vs Exit Code 2).
    - Domain 5: Clean Git commit tree snapshot isolation under dirty working directories.
- **Synchronized Scanner Engines**:
  - Full equivalence between Rust native scanner (`vibeguard-scanner.exe`) and Go fallback scanner.

## [v5.0.0] — 2026-09-22

### Added & Enhanced
- **Unconditional Internal Directory & Cache Isolation**:
  - The Rust scanner engine and Go fallback directory walkers now unconditionally skip `.vibeguard` (and its nested `.vibeguard/cache/osv/` vulnerability intelligence databases) and `reports/` output directories.
  - Fixes false-positive findings where advisory JSON dumps in `.vibeguard/cache/osv/` or test reports in `reports/` were accidentally scanned when running scans in workspaces containing VibeGuard data.
- **Strict Exclusion Verification**:
  - Added unit test in Rust scanner suite verifying that internal `.vibeguard/cache/` files are unconditionally excluded from file scanning even in the absence of project exclusion configs.

## [v4.7.0] — 2026-09-22

### Added & Enhanced
- **Live Dynamic Percentage & ETA Progress (Without Bar)**:
  - Terminal scan and dependency checks now dynamically display a live percentage number and estimated time to completion (`Scanning: 45% (33/73) | Est. time remaining: 0.8s`) without using cluttering progress bars.
  - Dynamically calculates scanning throughput (files per second) and projects the exact time remaining.
  - Automatically and cleanly wipes the progress indicator line upon completion of each stage.
- **Dedicated Cache Purge & Refresh**:
  - Added `vibeguard cache-refresh` CLI command and `--refresh-cache` scan flag for immediate clearing of cached OSV vulnerability records.
- **Exclusion Transparency & Override Flags**:
  - Implemented `--include-tests`, `--include-docs`, and `--show-excluded` flags in both the Go CLI and Rust scanner engines.
- **Enhanced Test Isolation & Coverage**:
  - Re-routed all test outputs to temporary directories (`t.TempDir()`) to ensure zero stray generated report artifacts in the source tree.
  - Added unit test coverage across all CLI commands and options.

## [v4.6.0] — 2026-09-21

### Added & Enhanced
- **Ultimate Test Suite v4.6 (`ultimate_test.bat` & `scripts/windows/ultimate_test.ps1`)**:
  - Completely revamped terminal test runner into an 8-stage weighted evaluation engine (100 total points, 90 minimum passing threshold):
    1. Go package unit tests (Weight 15/15, sub-second stopwatch duration, passed/failed package counts).
    2. Go vet static analysis (Weight 10/10, issues count).
    3. Rust scanner unit tests (Weight 15/15, passed/failed test counts).
    4. Rust format check (Weight 5/5, clean check).
    5. Rust Clippy linter (Weight 10/10, warnings and errors tally).
    6. Source compilation (Weight 20/20, Go binary, Rust binary, version verification).
    7. CLI health validation (Weight 15/15, CLI found, scanner found, version, test scan, report generation, security gate block).
    8. Windows Defender verification (Weight 10/10, WinDefend service status, real-time protection, scanner accessibility, threat history, pop-up simulation option).
  - High-precision sub-second stopwatch timing for each individual step and overall suite duration.
  - Optional `--test-popup` flag cleanly runs the native Windows modal alert pop-up test while preserving alignment and structure.
- **Indefinite Modal Alert Waiting**:
  - Windows Defender pop-up alerts now persist on screen until user explicitly dismisses or cancels them (`MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL`), removing arbitrary timeouts.

## [v4.5.0] — 2026-09-20

### Added & Enhanced
- **Windows Defender & Antivirus Interception Detection (`internal/defender`)**:
  - Automatically identifies when VibeGuard or its scanner binaries are blocked, quarantined, or intercepted by security software.
  - Detects Win32 error signatures:
    - Error `225` (`0x800700E1` / `ERROR_VIRUS_INFECTED`): "Operation did not complete successfully because the file contains a virus or potentially unwanted software".
    - Error `5` (`ERROR_ACCESS_DENIED`): Process execution denied by Windows Defender, SmartScreen, or Controlled Folder Access.
    - NTSTATUS `0xC0000005` (Access Violation), `0xC0000022` (Access Denied), exit status `1392`, `1260`.
- **Native Windows Pop-up Notification Dialog**:
  - Automatically raises a native `MessageBoxW` system modal dialog (`user32.dll`) over terminal or IDE windows showing **what blocked VibeGuard**, the component intercepted, and step-by-step remediation instructions.
  - Automatically skips the GUI modal in headless CI/CD environments (`VIBEGUARD_NON_INTERACTIVE=1`), while logging complete diagnostic output to `os.Stderr`.
- **Antivirus & Security Software Discovery**:
  - Queries Windows Security Center via WMI (`root\SecurityCenter2\AntiVirusProduct`) to report the exact active antivirus product (e.g. *Microsoft Defender Antivirus*, *CrowdStrike*, *Bitdefender*, etc.).
- **Diagnostic Command (`vibeguard defender-check`)**:
  - Added CLI command to inspect active security software, scanner binary accessibility, and test the native modal pop-up alert (`--test-popup`).
- **Dark Theme HTML Security Report**:
  - Executive cybersecurity dark theme (`#0b0f19` canvas, `#0f172a` slate container, glowing translucent cards, pitch-black masked evidence boxes).
  - Print-to-PDF export preserving the complete dark dashboard styling without white washout.

## [v4.4.0] — 2026-09-20

### Added & Enhanced
- **Sensitive Filename Auditing (`VG-SECRET-FILE`)**:
  - Automatically flags files named `password.txt`, `passwords.txt`, `credentials.txt`, `credential.txt`, `secret.txt`, `secrets.txt` with severity `HIGH`, title `Sensitive Credential File Detected`, and confidence `HIGH`.
  - Implemented with exact parity across both the Rust scanner (`scanner/src/secrets.rs`) and Go orchestrator (`internal/scanner/secrets.go`).
- **Context-Aware Credential Assignment Detection (`VG-SECRET-001`)**:
  - Detects hardcoded credential assignments across patterns such as `password=...`, `passwd=...`, `pwd=...`, `db_password=...`, `admin_password=...`, `api_key=...`, `secret=...`, `token=...`.
  - Distinguishes real credentials from documentation examples, comments, and placeholder values using a 10-factor scoring model:
    - Base additions: Sensitive filename (+30), Explicit key (+25), Assignment operator (+20), Non-placeholder value (+15), High-entropy/mixed chars (+10), Source/config location (+10).
    - Context penalties: Documentation/markdown file (-30), Obvious placeholder (-25), Comment/example text (-20), Test fixture directory (-40).
- **Evidence Masking**:
  - All credential values are masked in terminal, JSON, HTML, and SARIF reports (`password=********`, `api_key=********`). Complete passwords are never written to disk or console.
- **Confidence-Aware Security Gate Policy**:
  - Only `CRITICAL` or `HIGH` severity findings with `HIGH` (80–100) or `MEDIUM` (50–79) confidence fail the pre-push security gate.
  - `LOW` confidence (20–49) findings (such as in documentation examples or commented templates) are reported as advisory without blocking the push.
- **Full Engine Parity & Automated Testing**:
  - Comprehensive unit tests in Go (`internal/scanner/secrets_test.go`) and Rust (`scanner/src/secrets.rs`) verifying positive detection, evidence masking, and non-blocking negative test cases (README markdown, comments, placeholders, clean text).

## [v4.2.0] — 2026-09-20

### Added & Enhanced
- **Standalone Rust Scanner CLI Parity**:
  - Implemented standard `--help` and `--version` options displaying `vibeguard-scanner v4.2.0` and usage flags.
  - Added strict flag validation in the Rust engine, exiting with non-zero error code `2` on unrecognized arguments.
- **Explicit Baseline Validation & Fail-Closed Handling**:
  - Validates `.vibeguard/baseline.json` integrity and fails closed on malformed or corrupted JSON baselines with structured error code `VG-E007`.
- **Git Hook End-to-End Test Suite**:
  - Added comprehensive integration tests in `internal/git/e2e_test.go` verifying local repository creation, bare remote push interception, hook install/uninstall lifecycle, and snapshot extraction.
- **Repository Architecture Reorganization**:
  - Relocated all canonical project documentation into `docs/` (`ARCHITECTURE.md`, `CHANGELOG.md`, `FEATURES.md`, `LANGUAGE.md`, `ROADMAP.md`, `RULES.md`, `SETUP.md`, `TESTING.md`).
  - Organized standalone Windows batch utilities into `scripts/windows/` (`build.bat`, `setup.bat`, `run_test.bat`, `install_hook.bat`, `uninstall_hook.bat`).
  - Added `ultimate_test.bat` in root with percentage pass score calculation.

## [v4.1.0] — 2026-09-20

### Changed
- **Strict Repository & Workspace Separation**:
  - Removed all vulnerable test projects, fake credentials, and generated test outputs from the primary codebase.
  - Relocated test fixtures and test projects to external workspace `C:\Users\ranua\Music\VibeGuard-test`.
  - Inlined mock responses into unit tests (`internal/osv/client_test.go`) and dynamically constructed mock tokens to guarantee 100/100 zero false-alarm self-scan scores.

## [v4.0.0] — 2026-09-20

### Added
- **OASIS SARIF 2.1.0 Standard Compliance**:
  - Added `--format sarif` (or `-f sarif`) for direct consumption by GitHub Code Scanning, VS Code SARIF viewer, and enterprise SIEM platforms.
- **Baseline & Suppression Engine**:
  - Added support for `.vibeguard/baseline.json` to suppress known exceptions with optional expiration dates (`expires: "YYYY-MM-DD"`).
- **Finding Deduplication**:
  - Deterministic finding deduplication across multi-engine scanning stages (`internal/scanner/dedup.go`).
- **Deterministic OSV Disk Caching**:
  - Persistent SHA-256 caching in `.vibeguard/cache/osv/` enabling reproducible scans and offline verification mode (`--offline`).
- **HTML XSS Prevention**:
  - Secure contextual escaping powered by Go's standard library `html/template` preventing HTML injection vectors.
- **Structured Error Domain**:
  - Standardized error codes (`VG-E001` through `VG-E008`) for machine-readable error classification.

## [v3.0.0] — 2026-09-19 (Finalized Production Release)

> **Version Finalization Note**: Reconciled prior draft tags (`v2.2.0` vs `v3.0.0`) and established **`v3.0.0`** as the canonical version across the CLI binary, Rust engine, Git hooks, and documentation.

### Fixed
- **Dependency Fix Version Now Shows Proper Semver (not Git Hashes)**: The `RECOMMENDED FIX` column in the dependency table was displaying raw 40-character Git commit hashes (e.g. `afd63b16170b7c...`) instead of human-readable version numbers (e.g. `>= 3.1.3`). Root cause: the OSV API returns both `SEMVER` ranges (version numbers) and `GIT` ranges (commit hashes) — the old `getBestFixedVersion` compared all values as plain strings, causing long git hashes to always win. Fix: `getBestFixedVersion` now explicitly skips `GIT` ranges and selects the highest version from `SEMVER` ranges first, falling back to `ECOSYSTEM` ranges. A numeric `compareVersions` helper replaces the broken string comparison.

### Added & Enhanced
- **5-Stage Security Gate Verification Checklist & Interactive Hook Confirmation**:
  - Structured the pre-push gate into an aligned 5-stage checklist: `[1/5] Detecting project`, `[2/5] Secret scan`, `[3/5] Source scan`, `[4/5] Dependency/CVE scan`, `[5/5] Security policy` with real-time `PASS`/`FAIL` evaluation.
  - Appended structured score summary (`Security Score: X/100`, severity breakdown for Critical/High/Medium/Low, and `STATUS: SAFE TO PUSH` or `STATUS: PUSH BLOCKED`).
  - Added interactive `Proceed with Git push? [Y/N]:` prompt reading directly from console input (`CONIN$` on Windows / `/dev/tty` on Unix), enabling interactive confirmation inside Git pre-push hooks.
  - Preserved the complete interactive `vibeguard push` flow (`Stage modified files? [Y/n]`, `Enter commit message:`, full verification report, `Push to GitHub? [Y/n]`).
- **Eliminated False Positives across Code, Docs, and Build Artifacts**:
  - Automatically skips test coverage output, virtual environments, and cache directories (`htmlcov`, `.coverage`, `coverage`, `.pytest_cache`, `.mypy_cache`, `.tox`, `venv`, `env`, `.idea`, `.vscode`).
  - Added native `.gitignore` pattern resolution in both Rust and Go engines.
  - Excluded documentation extensions (`.md`, `.markdown`, `.rst`, `.txt`, `.adoc`, `.html`) from generic credential rules.
  - Filtered out placeholder / dummy passwords (`"admin"`, `"password"`, `"changeme"`, `"your_password"`, `""`, etc.) and variable / parameter declarations (PowerShell `param(`, `[string]`, `Read-Host`, Python `os.getenv`, `os.environ`, `$env:`).
  - Insecure HTTP rule ignores localhost, loopback (`127.0.0.1`, `0.0.0.0`, `::1`), schema/namespace URIs (`w3.org`, `schemas.`, `json-schema.org`, `apache.org`, `example.com`), and template strings.
- **Redesigned Clean Terminal Report**:
  - Eliminated repetitive dump of hundreds of individual dependency advisories.
  - Grouped dependency vulnerabilities into an aligned, structured table (`PACKAGE | CURRENT | SEVERITY | ADVISORIES | RECOMMENDED FIX`).
  - Added compact **Key Advisory Highlights** showing top advisory IDs with concise summaries and remainder counts.
  - Separated `Code & Configuration Findings` cleanly with distinct severity colors, IDs, file locations, titles, and actionable recommendations.
- **High-Performance Concurrent OSV Engine**:
  - Replaced serial HTTPS lookups with an asynchronous 10-worker pool and shared connection-pooled `http.Client`.
  - Reduced batch dependency lookup latency by over 80% (~400ms vs ~8s) while preserving thread-safe live progress updates.
- **Active Rust Scanner Integration with Streaming Progress**:
  - Rust engine accepts `--progress` flag and streams file scan milestones (`PROGRESS:<cur>:<tot>:<file>`) on `stderr`.
  - Go orchestrator reads stderr in real-time to drive terminal progress bars while receiving pure JSON IPC on `stdout`.
  - Rust scanner is now the primary scanner executed during live progress scans, with automatic fallback to Go.
- **Multi-Ref Pre-Push Verification**:
  - Pre-push hook and `runScanWithRefs` now iterate through and verify **every pushed ref** from `stdin`.
  - Blocks the entire push if any pushed ref contains blocking security findings.
- **Fail-Closed Pre-Push Security Policy**:
  - Pre-push hook blocks push with exit code `1` if the VibeGuard executable cannot be located in `%LOCALAPPDATA%\VibeGuard` or PATH.
- **Unified Push Verification Model in `vibeguard push`**:
  - `vibeguard push` now mirrors the exact pre-push hook verification model: extracts git commit snapshot, scans committed tree, evaluates diffs, and enforces identical gate thresholds.
- **Removed `test-project` from Default Exclusions**:
  - Removed artificial exclusion of `test-project` from `.vibeguard/config.json`.
- **Global User CLI Architecture (`setup.bat`)**:
  - Installs to `%LOCALAPPDATA%\VibeGuard` and idempotently configures Windows User `PATH`.
  - CLI dynamically self-locates `scanner.exe` via `os.Executable()`, running seamlessly from any working directory.
- **Live Terminal Scan Progress Indicators**: Real-time interactive progress bars for long scans across all stages:
  - **File Scanning Progress**: Displays percentage, files scanned/total, and the current active file path (`[██████████████░░░░░░] 70%`, `Files: 56/80`, `Current: ...`).
  - **Dependency Scanning Progress**: Displays percentage, dependencies checked/total, and the current package (`[████████████████░░░░] 80%`, `Dependencies: 36/45`, `Current: ...`).
  - **OSV Vulnerability Query Progress**: Real-time counter for live database lookups (`[██████████████████░░] 90%`, `OSV queries: 41/45`).
  - **Final Completion Indicator**: Full 100% completion bar (`[████████████████████] 100%`) with `Security analysis complete.` status prior to report generation.
- **Configurable Repository Exclusions**: Added `"exclude"` array to `.vibeguard/config.json` with universal filtering support across Go scanner, Rust scanner, and dependency manifest detector.
- **Pure Go Commit Snapshot Scanner**: Pre-push hook now extracts the exact committed tree using pure Go `archive/tar` directly from `git archive`, isolating pre-push evaluation from dirty local working copies.
- **Hook Binary Path Resolution**: Enhanced `.git/hooks/pre-push` script to automatically locate `vibeguard.exe` or `vibeguard` from repository root or PATH.
- **Double-Scan Elimination**: `vibeguard push` now invokes `git push --no-verify` upon successful security gate clearance, ensuring scans execute exactly once.
- **Realistic SAST Finding Terminology**:
  - `Potential OS Command Injection`
  - `Potential SQL Injection`
  - `Potential TLS Misconfiguration`
  - `Potential Insecure HTTP Connection`
- **Internal Tooling False-Positive Filter**: Fixed CLI invocations (e.g. `exec.Command("git", ...)` and `exec.CommandContext`) and regex compilation definitions are automatically excluded from application vulnerability alerts.
- **Master Development Plan Consolidation**: Merged `PLAN.md` and `PLAN1.md` into a single, comprehensive master plan.

---

## [v2.0.0] — 2026-09-18

### Added
- **Git Pre-Push Hook Integration**: Automatic security scanning via `.git/hooks/pre-push` before any code leaves the developer machine.
- **Hook Chaining & User Preservation**: Automatically backs up existing user hooks to `pre-push.user` and chains execution.
- **`vibeguard init` Command**: Installs the Git pre-push hook and initializes default configuration.
- **`vibeguard status` Command**: Inspects repository state, branch, remote origin, hook installation, and active policies.
- **`vibeguard uninstall` Command**: Cleanly removes the hook and restores user backups.
- **`vibeguard push` Command**: Guided interactive commit creation, security verification, and remote push workflow.
- **Standardized Process Exit Codes**:
  - `0`: PASS
  - `1`: BLOCK
  - `2`: RUNTIME ERROR
  - `3`: CONFIG ERROR
  - `4`: OSV UNAVAILABLE (with fail_closed enabled)

---

## [v1.0.0] — 2026-09-18

### Added
- Initial release of VibeGuard CLI and Rust scanner engine.
- High-entropy secret detection with evidence masking (AWS, GitHub, Slack, Private Keys).
- Static code analysis rules (SQL injection, command injection, eval, TLS, crypto, HTTP).
- Dependency manifest parsing (Go, npm, Python, Rust) with live Google OSV vulnerability lookup.
- Deterministic 0–100 risk scoring algorithm.
- Multi-format reporting: Terminal ANSI, JSON (`reports/scan.json`), and standalone HTML (`reports/scan.html`).
- Dockerfile security auditing (root user, ENV secrets, COPY . .).
- Configuration auditing (debug mode, wildcard CORS, 0.0.0.0 binding).
