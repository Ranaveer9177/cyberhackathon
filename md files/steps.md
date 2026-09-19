# VibeGuard — Development Plan

## Phase 1 — Foundation

1. Create project structure.
2. Initialize core application.
3. Initialize scanner.
4. Connect core application and scanner.
5. Create basic scan workflow.
6. Build.
7. Test.
8. Deploy.

Version: v0.1

---

## Phase 2 — Project Scanner

1. Add recursive scanning.
2. Detect files.
3. Detect directories.
4. Detect project types.
5. Detect languages.
6. Add file filtering.
7. Build.
8. Test.
9. Deploy.

Version: v0.2

---

## Phase 3 — Secret Detection

1. Create secret detection system.
2. Add API-key detection.
3. Add password detection.
4. Add token detection.
5. Add private-key detection.
6. Add sensitive-file detection.
7. Add masking.
8. Add finding IDs.
9. Add severity.
10. Build.
11. Test.
12. Deploy.

Version: v0.3

---

## Phase 4 — Source Code Security

1. Create rule engine.
2. Add SQL injection detection.
3. Add command injection detection.
4. Add dangerous function detection.
5. Add weak cryptography detection.
6. Add insecure TLS detection.
7. Add insecure HTTP detection.
8. Add line detection.
9. Build.
10. Test.
11. Deploy.

Version: v0.4

---

## Phase 5 — Dependency Security

1. Detect dependency files.
2. Extract package names.
3. Extract versions.
4. Identify ecosystem.
5. Connect vulnerability intelligence.
6. Query vulnerabilities.
7. Process advisories.
8. Process CVEs when available.
9. Process affected versions.
10. Process fixed versions.
11. Build.
12. Test.
13. Deploy.

Version: v0.5

---

## Phase 6 — Finding Engine

1. Combine scanner results.
2. Normalize findings.
3. Assign IDs.
4. Assign severity.
5. Group findings.
6. Count findings.
7. Calculate security score.
8. Build.
9. Test.
10. Deploy.

Version: v0.6

---

## Phase 7 — Reporting

1. Create terminal report.
2. Create JSON output.
3. Create HTML report.
4. Add finding details.
5. Add security score.
6. Add vulnerability information.
7. Build.
8. Test.
9. Deploy.

Version: v0.7

---

## Phase 8 — Deployment Gate

1. Define blocking conditions.
2. Implement PASS.
3. Implement BLOCK.
4. Add thresholds.
5. Add exit codes.
6. Build.
7. Test.
8. Deploy.

Version: v0.8

---

## Phase 9 — Additional Security

1. Add configuration security.
2. Add Git security.
3. Add container security.
4. Integrate findings.
5. Build.
6. Test.
7. Deploy.

Version: v0.9

---

## Phase 10 — Multi-CLI Support

1. Make the CLI shell-independent.
2. Standardize commands.
3. Test different CLI environments.
4. Test arguments.
5. Test output.
6. Test errors.
7. Test installation.
8. Build.
9. Test.
10. Deploy.

Version: v1.0

---

## Phase 11 — Git Pre-Push Hook Architecture

1. Implement Git repository detection.
2. Implement pre-push hook installer.
3. Preserve existing user hooks via chaining.
4. Add `vibeguard init`, `status`, `uninstall`.
5. Add `vibeguard push` guided workflow.
6. Build.
7. Test.
8. Deploy.

Version: v2.0

---

## Phase 12 — Scoped Snapshot & Exclusion System

1. Add pure Go `git archive` commit snapshotting.
2. Add configurable repository exclusions (`.vibeguard/config.json`).
3. Add universal exclusion matching across Go and Rust engines.
4. Refine SAST rule terminology.
5. Eliminate double scanning via `git push --no-verify`.
6. Build.
7. Test.
8. Deploy.

Version: v2.1

---

## Phase 13 — Live Terminal Scan Progress

1. Implement dynamic progress bar renderer (`internal/report/progress.go`).
2. Implement ANSI terminal cursor positioning (`\033[%dA\r`, `\033[K`).
3. Add non-TTY fallback stream mode.
4. Add file scanning progress callbacks (`ScanProgressFunc`).
5. Add dependency scanning progress loops.
6. Add live OSV database query progress callbacks (`OSVProgressFunc`).
7. Add 100% final completion indicator (`Security analysis complete.`).
8. Connect live progress to `vibeguard scan` and pre-push hook.
9. Fix commit diff secret parser for paths with spaces and honor exclusions.
10. Build.
11. Test.
12. Deploy.

Version: v3.0

---

## Phase 14 — Automated Environment Setup & Global CLI (`setup.bat`)

1. Check Windows Package Manager (`winget`).
2. Detect existing Git installation; install via `winget` if missing.
3. Detect existing Go installation; install via `winget` if missing.
4. Detect existing Rust and Cargo installation; install via `winget` if missing.
5. Detect existing Node.js installation; install via `winget` if missing.
6. Detect existing Python installation; install via `winget` if missing.
7. Detect existing Docker installation; install via `winget` if missing.
8. Install VibeGuard CLI into `%LOCALAPPDATA%\VibeGuard\bin\` (`vibeguard.exe` and `vibeguard-scanner.exe`).
9. Permanently add `%LOCALAPPDATA%\VibeGuard\bin` to Windows User `PATH` via PowerShell.
10. Verify all installations and parse versions.
11. Configure session PATH and verify PATH for Go, Rust, Cargo, and VibeGuard.
12. Print structured status output and environment readiness.

Version: v3.0

---

## Phase 15 — Core Hardening & Production Optimization

1. Remove `test-project` from default exclusions.
2. Add `--progress` flag to Rust scanner engine and stream to `stderr`.
3. Connect Go `RunScannerWithProgress` to stream Rust scanner `stderr` into terminal progress bar.
4. Process all pushed refs from `stdin` in pre-push hook and CLI.
5. Implement fail-closed security policy (exit 1 if CLI binary missing).
6. Unify `vibeguard push` verification model with pre-push hook.
7. Implement concurrent OSV worker pool (10 goroutines) with HTTP connection pooling.
8. Implement disk-staged `git archive` snapshot extraction (`commit.tar`) to eliminate Windows pipe deadlocks.
9. Finalize canonical version naming to `v3.0.0` across all code and documentation.
10. Build.
11. Test.
12. Deploy.

Version: v3.0.0



