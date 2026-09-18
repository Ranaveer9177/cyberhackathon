# VibeGuard — Technical Architecture Documentation

> **VibeGuard v2.0 / v3 — Multi-Engine Autonomous Pre-Push Security Firewall**

---

## 1. System Overview

VibeGuard operates as a decoupled, multi-language security architecture combining the high execution speed and memory safety of **Rust** with the rich networking, CLI UX, and process orchestration capabilities of **Go**.

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

## 2. Component Subsystems

### 2.1 Git Integration & Pre-Push Hook Gate (`internal/git/`)
- **Hook Lifecycle**: Installs `.git/hooks/pre-push` during `vibeguard init`. Backs up any pre-existing user hook to `pre-push.user` and chains execution.
- **Ref Parsing**: Reads standard Git pre-push tuples (`<local_ref> <local_sha> <remote_ref> <remote_sha>`) from `stdin`.
- **Pure Go Snapshot Extraction**: Uses `git archive` and Go's `archive/tar` standard library to unpack the exact committed tree of the pushed commit into a temporary workspace.
- **Controlled Push Workflow**: `vibeguard push` runs the scan once, verifies safety, and invokes `git push --no-verify` to eliminate redundant double scans.

### 2.2 Dual-Engine Security Scanner (`scanner/` & `internal/scanner/`)
- **Primary Rust Scanner Engine (`scanner/src/`)**:
  - Traverses the filesystem using `walkdir`.
  - Filters out binaries and archive formats.
  - Reads `.vibeguard/config.json` exclusions to skip documentation and test fixtures.
  - Executes regex pattern rules for secrets and static code vulnerabilities.
  - Masks detected credentials (`sk-demo-****`) to protect secrets in logs.
- **Fallback Go Scanner Engine (`internal/scanner/runner.go`)**:
  - Automatically invoked if the compiled Rust binary is not present in the environment.
  - Implements identical rule definitions and exclusion behavior for 100% feature parity.

### 2.3 Dependency Vulnerability Engine (`internal/dependencies/` & `internal/osv/`)
- **Manifest Parsers**:
  - Go: `go.mod`
  - Node.js: `package.json` & `package-lock.json`
  - Python: `requirements.txt`
  - Rust: `Cargo.toml` & `Cargo.lock`
- **Google OSV Integration**:
  - Batch queries the OSV REST API (`https://api.osv.dev/v1/querybatch`) using `net/http` with exponential timeouts.
  - Handles non-200 responses with descriptive error propagation.
  - Adheres to `fail_closed: true` to prevent pushes when vulnerability intelligence is unreachable.

### 2.4 Risk Scoring & Gate Engine (`internal/risk/` & `internal/gate/`)
- **Scoring**: Computes deterministic score (0–100):
  $$\text{Score} = \max\left(0, 100 - (15 \times C + 8 \times H + 3 \times M + 1 \times L)\right)$$
- **Gate Evaluation**: Compares finding severities against configured `block_on` policy (default: `["critical", "high"]`).
- **Standardized Exit Codes**:
  - `0`: PASS / SAFE TO PUSH
  - `1`: BLOCK / SECURITY FINDINGS DETECTED
  - `2`: RUNTIME / SCANNER ERROR
  - `3`: CONFIG ERROR
  - `4`: OSV DATABASE UNAVAILABLE (with fail_closed enabled)

### 2.5 Report Generation Subsystem (`internal/report/`)
- **Terminal Report**: High-visibility ANSI color output with tabular breakdown and clear PASS/BLOCK banners.
- **JSON Report**: Comprehensive machine-readable output saved to `reports/scan.json` for CI/CD integration.
- **HTML Report**: Standalone, CSS-styled interactive security report saved to `reports/scan.html`.
