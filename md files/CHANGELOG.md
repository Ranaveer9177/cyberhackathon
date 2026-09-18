# VibeGuard Changelog

## v2.0.0 — Git Secure Push Integration (2026-09-18)

### Added
- Git pre-push hook integration (`.git/hooks/pre-push`) with automatic scanning before code leaves developer machine
- Preservation of existing user pre-push hooks (backs up to `pre-push.user` and chains execution)
- `vibeguard init`: Install Git pre-push hook & initialize project configuration
- `vibeguard uninstall`: Clean hook uninstallation and original user hook restoration
- `vibeguard status`: Git repository, branch, remote, hook installation, and policy inspection
- `vibeguard push`: Controlled interactive commit + scan + push workflow
- `vibeguard scan --hook`: Policy-driven scan execution for Git hooks
- Configuration support via `.vibeguard/config.json` (`block_on`, `scan_mode`, `fail_closed`, module toggles)
- Git metadata in reports (Commit hash, Branch, Remote)
- Standardized exit codes: 0 (PASS), 1 (BLOCKED), 2 (ERROR), 3 (CONFIG ERROR), 4 (OSV UNAVAILABLE with fail_closed)

## v1.0.0 — Stable MVP (2026-09-18)

### Added
- Complete Go CLI with `scan`, `report`, `version`, and `help` commands
- Rust security scanner engine with high-performance file traversal
- Secret detection: API keys, passwords, tokens, JWT secrets, private keys, sensitive files
- Source code security (SAST): SQL injection, command injection, eval, disabled TLS, weak crypto, insecure HTTP
- Dependency security: Go, npm, Python, Rust manifest parsing
- OSV vulnerability database integration for real CVE/advisory lookup
- Risk scoring engine (0–100 deterministic score)
- Deployment gate: PASS/BLOCK with exit codes (0/1/2)
- Terminal report with colored severity output
- JSON report (`reports/scan.json`)
- HTML report (`reports/scan.html`) with professional styling
- Docker security scanning (root user, ENV secrets, latest tag, HEALTHCHECK)
- Git security scanning (sensitive files detection)
- Configuration security scanning (debug mode, CORS, HTTP endpoints)
- Deliberately vulnerable test project for demonstration
- Secret masking in all outputs

## v0.7.0 — Additional Security Checks

### Added
- Docker scanner: root user, ENV secrets, COPY . ., port exposure, latest tag, HEALTHCHECK
- Git scanner: sensitive file detection (.env, private keys, credentials)
- Config scanner: debug mode, CORS wildcards, 0.0.0.0 binding, plain HTTP

## v0.6.0 — Deployment Gate

### Added
- PASS/BLOCK deployment decision based on critical findings
- Exit codes: 0 (PASS), 1 (BLOCK), 2 (ERROR)
- CI/CD compatible process exit codes

## v0.5.0 — Risk Scoring & Reporting

### Added
- Deterministic 0–100 security score
- Formula: 100 - (critical*15 + high*8 + medium*3 + low*1)
- Terminal report with ANSI colors
- JSON report generation
- HTML report with embedded CSS and severity badges

## v0.4.0 — Dependency Security

### Added
- Manifest file detection (go.mod, package.json, requirements.txt, Cargo.toml)
- Package name and version extraction
- OSV API integration for vulnerability lookup
- CVE alias and fixed version reporting
- Graceful failure handling when OSV is unreachable

## v0.3.0 — Source Code Security

### Added
- SAST rule engine with regex-based pattern matching
- SQL injection detection
- Command injection detection
- Dangerous eval detection
- Disabled TLS verification detection
- Weak cryptography detection (MD5, SHA1, DES, RC4)
- Insecure HTTP URL detection
- Exact file and line number reporting

## v0.2.0 — Secret Detection

### Added
- AWS access key detection
- GitHub token detection
- Slack token detection
- Private key header detection
- Password/token/secret assignment detection
- Sensitive filename detection (.env, id_rsa, *.pem, *.key)
- Secret masking (first 8 chars + ****)

## v0.1.0 — Foundation

### Added
- Go CLI with scan command
- Rust scanner binary with recursive directory traversal
- JSON IPC between Go and Rust via stdout
- Binary file and vendor directory filtering
- Basic terminal output

## v0.0.0 — Planning

### Added
- FEATURES.md — Complete feature specification
- LANGUAGE.md — Technology stack and architecture
- PLAN.md — Step-by-step development plan
- PLAN1.md — Strategic architecture roadmap
