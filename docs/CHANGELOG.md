# VibeGuard Changelog

All notable changes to the VibeGuard project are documented in this file.

## [v4.5.0] — 2026-09-20 (Current Release)

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
