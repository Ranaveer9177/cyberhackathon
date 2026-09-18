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
- [x] **v3.1 — Automated Environment Setup & Global CLI (`setup.bat`)**: Intelligent Windows environment setup verifying and installing Git, Go, Rust, Cargo, Node.js, Python, and Docker via `winget`, permanent global installation to `%LOCALAPPDATA%\VibeGuard\bin`, User PATH registry configuration, and PATH verification.

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
