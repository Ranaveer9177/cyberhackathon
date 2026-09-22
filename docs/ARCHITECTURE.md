# VibeGuard — Technical Architecture Documentation

> **VibeGuard v5.1.0 — Multi-Engine Autonomous Pre-Push Security Firewall**

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
                └───────────────┬───────────────>
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
                         Live Progress Bar
                 (Files, Dependencies, OSV, 100%)
                                │
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
- **Ref Parsing & Multi-Ref Processing**: Reads all standard Git pre-push tuples (`<local_ref> <local_sha> <remote_ref> <remote_sha>`) from `stdin`. Skips branch deletions and scans each pushed ref independently.
- **Fail-Closed Security Policy**: If the `vibeguard` binary cannot be found in `%LOCALAPPDATA%\VibeGuard` or `%PATH%`, the hook exits with code `1` and blocks the push.
- **Disk-Staged Pure Go Snapshot Extraction**: Uses `git archive --format=tar -o commit.tar <localSha>` and Go's `archive/tar` standard library to unpack the exact committed tree of the pushed commit into a temporary workspace, completely preventing Windows stdout pipe buffer deadlocks.
- **Controlled Push Workflow**: `vibeguard push` runs the snapshot scan, verifies safety, and invokes `git push --no-verify` to eliminate redundant double scans.

### 2.2 Dual-Engine Security Scanner (`scanner/` & `internal/scanner/`)
- **Primary Rust Scanner Engine (`scanner/src/`)**:
  - Traverses the filesystem using `walkdir`.
  - Filters out binaries, media, archive formats, test coverage outputs (`htmlcov/`, `.coverage`), caches, virtual environments, and IDE directories.
  - Automatically parses and respects `.gitignore` rules in the scanned repository.
  - Accepts `--progress` flag and streams live file scan progress (`PROGRESS:<cur>:<tot>:<file>`) on `stderr` while delivering pure JSON results on `stdout`.
  - Executes regex pattern rules for secrets and static code vulnerabilities.
  - **Context-Aware Secret Engine (v4.4)**: Evaluates sensitive filenames (`VG-SECRET-FILE`), credential assignments (`VG-SECRET-001`), and computes mathematical confidence scores (0–100) taking into account entropy, key names, assignment operators, and penalty weights for docs, comments, and placeholders.
  - False-positive filters for documentation examples, PowerShell parameters, placeholder passwords, and loopback/schema URLs.
  - Masks detected credentials (`sk-demo-****`, `password=********`) to protect secrets in logs.
- **Fallback Go Scanner Engine (`internal/scanner/runner.go` & `internal/scanner/secrets.go`)**:
  - Automatically invoked if the compiled Rust binary is not present in the environment.
  - Implements identical rule definitions, `.gitignore` parsing, sensitive filename detection, confidence scoring algorithm, and false-positive filtering for 100% feature parity.
  - Emits real-time progress callbacks (`ScanProgressFunc`) reporting file index, total count, and current file path.

### 2.3 Dependency Vulnerability Engine (`internal/dependencies/` & `internal/osv/`)
- **Manifest Parsers**:
  - Go: `go.mod`
  - Node.js: `package.json` & `package-lock.json`
  - Python: `requirements.txt`
  - Rust: `Cargo.toml` & `Cargo.lock`
- **Google OSV Integration**:
  - Concurrently queries the OSV REST API (`https://api.osv.dev/v1/querybatch`) using a pooled 10-goroutine worker pool with HTTP Keep-Alive and connection pooling.
  - Reduces batch dependency query latency by >80% (~400ms vs ~8s).
  - Handles non-200 responses with descriptive error propagation.
  - Adheres to `fail_closed: true` to prevent pushes when vulnerability intelligence is unreachable.
  - Emits real-time progress callbacks (`OSVProgressFunc`) reporting completed OSV queries vs total packages.

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

### 2.5 Live Scan Progress Subsystem (v3.0, `internal/report/progress.go`)
- **Interactive Visual Bar**: Renders unicode progress indicators (`[██████████████░░░░░░] 70%`) with active metadata across 4 distinct scanning stages:
  1. Files scanned and current file path.
  2. Dependencies checked and active package name/version.
  3. Live Google OSV API queries completed.
  4. Final 100% completion marker with `Security analysis complete.` status.
- **ANSI Terminal Control**: In-place line rewriting using `\033[%dA\r` and line clears (`\033[K`) on character devices.
- **Graceful Stream Fallback**: Automatic non-TTY fallback for CI/CD pipelines, log files, or piped shell execution.

### 2.6 Report Generation Subsystem (`internal/report/`)
- **Terminal Report (`internal/report/terminal.go`)**:
  - High-contrast ANSI color output with tabular breakdown and clear PASS/BLOCK banners.
  - Dedicated **Code & Configuration Findings** section displaying ID, category, file:line, title, and recommendation.
  - Aligned **Dependency Vulnerabilities Table** grouping issues by package (`PACKAGE | CURRENT | SEVERITY | ADVISORIES | RECOMMENDED FIX`).
  - Compact **Key Advisory Highlights** with top 2–3 advisories per package and remainder counts.
  - Clean confirmation banners (`✓ No code, secret, or configuration issues detected.`, `✓ No known vulnerabilities found in dependencies.`) when clean.
- **JSON Report (`internal/report/json.go`)**: Comprehensive machine-readable output saved to `reports/scan.json` for CI/CD integration.
- **HTML Report (`internal/report/html.go`)**: Standalone, CSS-styled interactive security report saved to `reports/scan.html` with native contextual escaping via `html/template`.
- **SARIF 2.1.0 Report (`internal/report/sarif.go`)**: Standard OASIS SARIF report for GitHub Code Scanning and IDE integration (`--format sarif`).

### 2.7 Distribution & Repository Architecture
- **Clean Production Layout**:
  ```text
  cyberhackathon/
  ├── cmd/vibeguard/             # Go orchestrator CLI entry point
  ├── docs/                      # Canonical technical documentation
  ├── internal/                  # Modular Go libraries (baseline, osv, gate, git, report, risk, scanner)
  ├── scanner/                   # Standalone Rust scanner engine
  ├── scripts/windows/           # Windows batch utilities (build, setup, run_test, hooks)
  ├── tests/                     # Clean integration test harnesses
  ├── ultimate_test.bat          # Complete repository test runner
  ├── README.md                  # Quickstart and overview
  └── report.md                  # Comprehensive verification audit
  ```
- **Global User Installation**: Installs to `%LOCALAPPDATA%\VibeGuard\bin\`, containing `vibeguard.exe`, `scanner.exe`, and `vibeguard-scanner.exe`.
- **Idempotent User PATH Management**: Adds `%LOCALAPPDATA%\VibeGuard\bin` to the Windows User `PATH` registry environment without duplicates or admin rights, enabling `vibeguard` from any terminal session.
- **Dynamic Self-Locating Engine (`FindScannerExecutable`)**: Prioritizes `os.Executable()` directory and `%LOCALAPPDATA%\VibeGuard` before current working directory, allowing `vibeguard scan <target>` to run from any folder.
- **Hardened Git Pre-Push Hook**: Hook prioritizes trusted `%LOCALAPPDATA%\VibeGuard\vibeguard.exe` and global PATH over repository-local binaries to prevent rogue executable substitution attacks.

### 2.8 Windows Defender & Antivirus Interception Detection (`internal/defender/`)
- **Interception Heuristics**: Automatically inspects execution errors for Win32 virus/malware block codes (`ERROR_VIRUS_INFECTED` / `225` / `0x800700E1`, `ERROR_ACCESS_DENIED` / `5` / `0xC0000022`, exit status `1392`, `1260`).
- **WMI Antivirus Discovery**: Queries Windows Security Center via WMI (`root\SecurityCenter2\AntiVirusProduct`) to detect the active security software product (e.g. *Microsoft Defender Antivirus*).
- **Native Modal Alert Pop-up**: Invokes `MessageBoxW` with `MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL` to display high-visibility alerts on the desktop explaining what blocked VibeGuard with step-by-step remediation instructions.
- **Headless Environment Awareness**: Bypasses GUI modals when `VIBEGUARD_NON_INTERACTIVE=1` or `CI=true` is present, while outputting full diagnostic alerts to `stderr`.

### 2.9 Ultimate Test & Weighted Metrics Engine (`ultimate_test.bat`)
- **8-Stage Weighted Scoring**: Implements an enterprise validation runner with 100 total points and 90 minimum passing score across Go unit tests (15), Go vet (10), Rust tests (15), Rust format (5), Rust Clippy (10), source build (20), CLI health validation (15), and Defender verification (10).
- **High-Precision Stopwatch Tracking**: Measures sub-second elapsed time per stage using `System.Diagnostics.Stopwatch`.
- **Clean Process Sandboxing**: Executes background checks with segregated temporary standard output and error handles, ensuring clean formatted metrics without terminal pollution.
