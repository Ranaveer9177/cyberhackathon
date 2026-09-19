# VibeGuard Changelog

All notable changes to the VibeGuard project are documented in this file.

## [v3.0.0] — 2026-09-19 (Finalized Production Release)

> **Version Finalization Note**: Reconciled prior draft tags (`v2.2.0` vs `v3.0.0`) and established **`v3.0.0`** as the canonical version across the CLI binary, Rust engine, Git hooks, and documentation.

### Fixed
- **Dependency Fix Version Now Shows Proper Semver (not Git Hashes)**: The `RECOMMENDED FIX` column in the dependency table was displaying raw 40-character Git commit hashes (e.g. `afd63b16170b7c...`) instead of human-readable version numbers (e.g. `>= 3.1.3`). Root cause: the OSV API returns both `SEMVER` ranges (version numbers) and `GIT` ranges (commit hashes) — the old `getBestFixedVersion` compared all values as plain strings, causing long git hashes to always win. Fix: `getBestFixedVersion` now explicitly skips `GIT` ranges and selects the highest version from `SEMVER` ranges first, falling back to `ECOSYSTEM` ranges. A numeric `compareVersions` helper replaces the broken string comparison.

### Added & Enhanced
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
