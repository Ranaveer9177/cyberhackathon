# VibeGuard Changelog

All notable changes to the VibeGuard project are documented in this file.

## [v3.0.0] — 2026-09-19

### Added
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
