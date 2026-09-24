# VibeGuard — Language & Technology Decisions

> **Architecture Rationale & Technology Evaluation for VibeGuard v6.0.0**

---

## 1. Multi-Language Design Philosophy

VibeGuard intentionally pairs **Go** and **Rust** to optimize developer ergonomics and raw scanning throughput:

| Area | Primary Language | Rationale |
| :--- | :---: | :--- |
| **CLI & User Experience** | **Go** | Rich ecosystem for command-line tooling, cross-platform compilation, fast startup time, robust standard library (`os/exec`, `net/http`, `archive/tar`), and direct shell interop. |
| **Live Progress Engine** | **Go** | Real-time terminal progress reporting with dynamic percentage and ETA calculation, ANSI cursor positioning (`\033[%dA\r`, `\033[K`), and non-TTY stream awareness. |
| **Scanner Engine** | **Rust** | Zero-cost abstractions, fearless memory safety without garbage collection pauses, blazing-fast file traversal with `walkdir`, early root pruning of ignored trees (>30k files/sec), and high-performance regex matching. |
| **Fallback Engine** | **Go** | Native Go scanner implementation maintaining 100% rule parity, ensuring VibeGuard functions out-of-the-box on developer systems where `cargo` is not installed. |
| **Vulnerability Data** | **Google OSV** | Distributed open-source vulnerability database providing machine-readable CVEs and advisories with zero hallucinations. |
| **Environment Provisioning** | **Batch / winget** | Automated Windows setup script (`setup.bat`) integrating Windows Package Manager (`winget`) with intelligent pre-checks to eliminate redundant re-downloads. |
| **Data Protocol** | **JSON** | Universal, lightweight serialization format for inter-process communication and report persistence. |

---

## 2. Core Dependencies & Libraries

### Go Ecosystem
- `net/http`: Concurrent batch queries to Google OSV API with pooled connections.
- `archive/tar`: Pure Go in-memory extraction of `git archive` snapshots without external `tar` dependencies.
- `os/exec`: Reliable subprocess invocation for Git commands and compiled Rust scanner binaries.
- `encoding/json`: Schema serialization and deserialization.
- `internal/report/terminal.go`: Transparent reporting engine separating actionable blockers from low/advisory findings.

### Rust Ecosystem
- `walkdir` (v2): Recursive directory tree traversal with root-level early pruning.
- `regex` (v1): Compiled regular expression pattern matching and credential heuristics.
- `serde` & `serde_json` (v1): Zero-overhead JSON serialization for scanner IPC.

