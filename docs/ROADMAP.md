# VibeGuard — Strategic Roadmap

> **Product Evolution and Future Horizons**

---

## 1. Completed Milestones

- [x] **v0.1 — Foundation**: Go CLI skeleton, Rust scanner skeleton, JSON IPC protocol.
- [x] **v0.2 — Filesystem Traversal**: Recursive walker, binary filtering, directory exclusions.
- [x] **v0.3 — Secret Detection**: AWS keys, GitHub tokens, Slack tokens, private keys, evidence masking.
- [x] **v0.4 — SAST Engine**: SQL injection, command injection, TLS bypass, weak crypto, eval.
- [x] **v0.5 — SCA Engine**: Dependency manifest parsing (Go, npm, Python, Rust) with live Google OSV lookup.
- [x] **v0.6 — Finding Engine**: Normalized IDs (`VG-001`), severity classification, category grouping.
- [x] **v0.7 — Reporting & Risk**: 0–100 deterministic risk score, ANSI terminal, JSON, and standalone HTML reports.
- [x] **v0.8 — Deployment Gate**: PASS/BLOCK decision logic, exit codes (0, 1, 2, 3, 4).
- [x] **v0.9 — Container & Config**: Dockerfile security analysis, config file security audits.
- [x] **v1.0 — Stable MVP**: Multi-shell support, comprehensive test fixtures, end-to-end integration.
- [x] **v3.0 — Live Scan Progress & Scoped Pre-Push Gate**: Real-time terminal progress bars across all scanning stages (files, dependencies, OSV queries, 100% completion indicator), pure Go `git archive` snapshot scanning, `.vibeguard/config.json` exclusions, refined SAST terminology, double-scan elimination.
- [x] **v3.0.0 — Production Hardening & Global Architecture**: Intelligent Windows environment setup (`setup.bat`) installing Git, Go, Rust, Cargo, Node.js, Python, and Docker via `winget`; global CLI in `%LOCALAPPDATA%\VibeGuard`; fail-closed pre-push hook; multi-ref verification; streaming Rust engine (`--progress`); concurrent 10-worker OSV engine (~400ms); and Windows pipe-deadlock-free disk tar snapshotting.
- [x] **v4.0 — Enterprise Compliance & Baseline Engine**: OASIS SARIF 2.1.0 output, `.vibeguard/baseline.json` suppression system, finding deduplication, deterministic OSV disk caching, and HTML contextual escaping.
- [x] **v4.1 — Strict Workspace Isolation**: Relocated all vulnerable fixtures to external `VibeGuard-test` workspace, inlined mocks in tests to ensure clean 100/100 self-scan.
- [x] **v4.2 — Standalone CLI Parity & Test Harness**: Rust scanner `--help`/`--version` CLI parity, baseline validation error handling (`VG-E007`), Git hook E2E test suite, `scripts/windows/` reorganization, and `ultimate_test.bat`.
- [x] **v4.4 — Context-Aware Secret Detection & Confidence Scoring**: Sensitive filename detection (`VG-SECRET-FILE`), credential assignment detection (`VG-SECRET-001`), 10-factor mathematical confidence scoring (+30 to -40), evidence masking (`password=********`), and confidence-aware pre-push gate policy.
- [x] **v4.5 — Windows Defender & Antivirus Interception Detection**: Interception heuristics for Win32 errors (225 / 5 / 0xC0000022), active AV identification via WMI, native Windows modal pop-up alerts (`MessageBoxW`), CLI diagnostic command (`vibeguard defender-check`), and executive dark theme HTML reporting with PDF export.
- [x] **v4.6 — Ultimate Test Engine & Metrics Standardization**: 8-stage weighted test engine (100 pts, 90 min score), sub-second stopwatch timing across all phases, detailed package/test/linter metric reporting, indefinite modal alert waiting with `MB_OKCANCEL`.
- [x] **v4.7 — Live Dynamic Percentage & ETA Progress**: Dynamic live percentage number and estimated time to completion without progress bars, `vibeguard cache-refresh`, exclusion overrides (`--include-tests`, `--include-docs`, `--show-excluded`).
- [x] **v5.0 — Unconditional Internal Cache & Report Isolation**: Walker early pruning of `.vibeguard` and `reports/` directories preventing false-positive scan results from cached vulnerability dumps.
- [x] **v5.1 — Generic Leak Wildcard Recognition, Dynamic Credential Weighting, and Chaos Engineering Suite**:
  - Expanded sensitive filename detection for `leak*.txt`, `test*.txt`, `*_secret.txt`, `*.conf`, `*.env*`.
  - Dynamic credential weighting for quoted assignments across all files with comparison operator filtering (`==`, `!=`).
  - Transparent reporting with `--verbose`, `-v`, and `--all`.
  - DevSecOps Chaos Engineering validation suite across 5 adversarial stress domains (100/100 PASS).
- [x] **v6.0 — Scope-Aware Data-Flow SAST Engine & FastNote Benchmark Security Suite**:
  - Source $\rightarrow$ Flow $\rightarrow$ Sink Taint Tracking connecting untrusted user input to database and command sinks.
  - Python f-strings SQL injection (`f"SELECT ... {param}"`), dynamic formatting, concatenation detection.
  - Dedicated Docker Compose Security Engine (`VG-DCK-006` through `VG-DCK-013`): exposed database ports (5432, 6379, 3306, 27017), root user, host volume mounts (`.:/app`), weak passwords, privileged containers, dangerous capabilities, and `/var/run/docker.sock` mounts.
  - Cross-File Build Secret Correlation (`VG-DCK-014`): `.env` + `COPY . .` in Dockerfile without `.dockerignore`.
  - Authentication and API Security Rules (`VG-AUTH-001` to `003`, `VG-WEBHOOK-001`).
  - Standardized canonical rule IDs with 100% Rust and Go engine parity.
  - FastNote benchmark test suite in `tests/fixtures/fastnote/` with 100/100 ultimate test score.

---

## 2. Upcoming Horizons

### Horizon 1: AI Remediation & Patch Generation
- Optional local/cloud AI interface (Ollama, Anthropic, OpenAI, Gemini).
- Auto-generate Git patch diffs for discovered vulnerabilities.
- Explain root causes in plain language without making AI the source of truth for detection.

### Horizon 2: Native CI/CD Integration
- Official GitHub Action (`vibeguard/action@v1`).
- GitLab CI template and Bitbucket Pipelines support.
- Pre-commit framework integration (`.pre-commit-hooks.yaml`).

### Horizon 3: IDE & Real-Time Security Sidecars
- Language Server Protocol (LSP) server for real-time diagnostics in VS Code, JetBrains, and Neovim.
