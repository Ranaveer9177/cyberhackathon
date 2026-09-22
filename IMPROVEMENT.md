# VibeGuard Existing Project Improvement Review

**Review date:** 22 September 2026  
**Project version reviewed:** VibeGuard v4.6.0  
**Purpose:** File-by-file and folder-by-folder maintenance review of the
existing project.

This document is an improvement checklist for the current implementation. It
does not propose new product features. The focus is correctness, consistency,
test reliability, documentation accuracy, release hygiene, and maintainability
of behavior that already exists.

## 1. Current Verification Baseline

The following checks passed during the latest review:

| Check | Result |
|---|---|
| `.\ultimate_test.bat` | 8/8 stages, 100/100 |
| `go test ./...` | PASS |
| `go vet ./...` | PASS |
| `go test -race ./...` | PASS |
| `cargo test --manifest-path scanner\Cargo.toml` | 9 passed |
| `cargo fmt --manifest-path scanner\Cargo.toml -- --check` | PASS |
| Rust Clippy through the ultimate suite | 0 warnings, 0 errors |
| Clean scanner-source scan | 100/100, 0 findings |
| Vulnerable fixture scan | Correctly blocked |
| Terminal, JSON, HTML, and SARIF output | PASS |
| Git hook init/status/uninstall lifecycle | PASS |
| Offline scan and OSV cache refresh | PASS |
| Defender diagnostic | PASS |

The recommendations below are limited to improving the existing code and
project presentation. They are not required to change the product scope.

## 2. Priority Summary

| Priority | Area | Main improvement |
|---|---|---|
| P0 | Documentation accuracy | Keep version, command output, test counts, and exit-code documentation synchronized |
| P0 | Release hygiene | Keep generated binaries, reports, caches, and temporary outputs out of source releases |
| P1 | Cross-engine consistency | Keep Rust and Go fallback rules, severity mappings, exclusions, and report fields equivalent |
| P1 | Test maintenance | Keep automated, manual, and external-fixture test instructions reproducible |
| P1 | Configuration clarity | Document every exclusion and distinguish intentionally excluded paths from unscanned paths |
| P2 | Code maintainability | Keep command routing, scanning, reporting, and error handling small and testable |
| P2 | Documentation navigation | Make the README, `docs/`, `report.md`, and this review agree on the current source of truth |

## 3. Root Files

| Path | Current role | Existing-project improvement |
|---|---|---|
| `README.md` | User-facing overview and setup guide | Keep version badges, quickstart output, supported formats, exit codes, and test counts synchronized with v4.6.0 behavior. Avoid copying stale historical output into the quickstart. |
| `report.md` | Cumulative testing report | Treat Sections 18–20 as the current evidence. Keep older results explicitly historical, and record command date, environment, exit code, and fixture availability for every new retest. |
| `go.mod` | Go module manifest | Keep the declared Go version aligned with the supported build environment and run `go mod tidy` checks in release validation. |
| `ultimate_test.bat` | Entry point for the weighted Windows suite | Keep the stage count, weights, displayed version, and underlying PowerShell script synchronized. Return the actual failing stage exit code. |
| `.gitignore` | Source and artifact exclusion rules | Periodically verify that generated reports, caches, binaries, IDE files, and build directories are ignored without hiding source files or test fixtures. |
| `.vscode/settings.json` | Local editor settings | Keep workspace settings non-machine-specific and avoid committing paths or settings that only work on one developer workstation. |
| `vibeguard.exe` | Local generated Go binary | Treat as a local build artifact; do not use it as the only evidence of source behavior. Rebuild from source before release verification. |
| `vibeguard-scanner.exe` | Local generated scanner binary | Treat as a local build artifact and verify it matches the current Rust source and version. |

## 4. `cmd/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `cmd/vibeguard/main.go` | CLI routing, argument parsing, orchestration, and user output | Keep command parsing separate from execution paths, preserve documented exit codes, and ensure every new validation branch has a focused test. Keep terminal output and report metadata consistent. |
| `cmd/vibeguard/main_test.go` | CLI and argument tests | Keep tests subprocess-safe on Windows, assert exact exit-code classes, and cover the documented commands and formats without depending on a global installation. |

## 5. `internal/baseline/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `baseline.go` | Baseline loading and finding suppression | Keep malformed, expired, and missing entries fail-closed as documented. Centralize matching normalization so terminal, JSON, HTML, and SARIF counts agree. |
| `baseline_test.go` | Baseline behavior tests | Preserve coverage for valid entries, justification, expiry, malformed files, and partial matches. Use deterministic timestamps in tests. |

## 6. `internal/config/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `config.go` | Configuration loading, defaults, exclusions, and policy | Keep defaults explicit and documented. Validate severity names, scan modes, formats, and boolean policy values before scanning. Make exclusion matching case and path-separator behavior consistent on Windows. |
| `config_test.go` | Configuration tests | Keep tests for defaults, invalid JSON, invalid policy values, exclusion matching, and repository-relative paths. |
| `.vibeguard/config.json` | Repository security policy | Review the exclusion list whenever files are added. Document why each exclusion is safe; avoid excluding a directory merely to make a scan appear clean. |

## 7. `internal/defender/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `defender_windows.go` | Windows Defender/AV discovery and interception handling | Keep WMI and Win32 errors explicit, preserve non-interactive behavior, and avoid making scans depend on a desktop session. |
| `defender_other.go` | Non-Windows implementation | Keep the platform fallback buildable and predictable. Its output should clearly state which checks are unavailable rather than implying they were performed. |
| `defender_test.go` | Defender and error interpretation tests | Keep tests independent of installed antivirus products. Use injected or simulated results for error 225, access denied, headless mode, and unavailable WMI. |

## 8. `internal/dependencies/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `detector.go` | Dependency manifest discovery and vulnerability aggregation | Keep supported manifest detection deterministic, avoid duplicate manifests, and preserve package-manager names in report output. |
| `parser.go` | Go, npm, Python, and Cargo manifest parsing | Keep parsers tolerant of valid lockfile variations while returning explicit errors for malformed files. |
| `parser_test.go` | Dependency parser tests | Maintain fixtures for each supported manifest, empty manifests, malformed input, duplicate packages, and excluded paths. |

## 9. `internal/errors/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `errors.go` | Structured error codes and user-facing error mapping | Keep error codes stable, avoid swallowing underlying causes, and ensure CLI exit codes remain distinct from security-block results. |
| `errors_test.go` | Error behavior tests | Assert code, message, wrapping, and exit-code mapping separately so wording changes do not hide behavioral regressions. |

## 10. `internal/gate/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `gate.go` | Severity policy and pass/block decision | Keep policy evaluation independent of report formatting. Verify that configured severities, baseline suppression, and fail-closed OSV errors cannot be confused with a clean scan. |
| `gate_test.go` | Gate and exit-code tests | Keep boundary tests for zero findings, configured block levels, suppressed findings, runtime errors, invalid configuration, and OSV-unavailable behavior. |

## 11. `internal/git/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `hooks.go` | Pre-push hook installation and chaining | Preserve an existing user hook, make backup/restore behavior explicit, and keep generated hook paths portable across Windows shells. |
| `repo.go` | Repository detection, refs, snapshots, and Git operations | Keep multi-ref parsing, deleted-ref handling, commit snapshot extraction, and temporary-directory cleanup deterministic. Surface Git command failures with context. |
| `hooks_test.go` | Hook lifecycle tests | Keep install, reinstall, uninstall, existing-hook preservation, and missing-binary cases isolated in temporary repositories. |
| `repo_test.go` | Repository and ref tests | Keep coverage for branch, tag, deleted ref, multiple ref, detached state, and invalid repository cases. |
| `e2e_test.go` | Bare-remote push and gate tests | Keep the end-to-end suite independent of a real GitHub remote and assert both allowed and blocked push behavior. |

## 12. `internal/osv/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `client.go` | OSV batch API client and request handling | Keep timeouts, HTTP status handling, malformed responses, partial results, and fail-closed behavior explicit. Do not silently convert network failures into zero vulnerabilities. |
| `cache.go` | Local OSV cache and purge behavior | Keep cache keys deterministic, cache writes atomic where possible, and offline misses distinguishable from clean results. |
| `severity.go` | Advisory severity normalization | Keep severity conversion stable and test unknown or missing severity values explicitly. |
| `types.go` | OSV request and response models | Keep JSON tags and optional fields compatible with the API; avoid losing advisory identifiers or affected-package information. |
| `client_test.go` | OSV client and cache tests | Preserve mock-server coverage for success, empty response, malformed JSON, 400/429/500, timeout, cache hit, cache miss, offline mode, and purge. |

## 13. `internal/report/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `terminal.go` (`Report`, `CategoryCounts`) | Shared report model and terminal aggregation | Keep one canonical finding/count model for every output format. Ensure suppressed, excluded, skipped, and dependency findings are represented consistently. |
| `terminal.go` | Human-readable terminal output | Keep headings, severity counts, OSV status, score, and exit reason aligned. Preserve non-TTY output without ANSI control sequences. |
| `json.go` | Machine-readable JSON output | Keep the schema stable, mask evidence, include scan metadata, and avoid emitting success-shaped data after a failed scan. |
| `html.go` | HTML report rendering | Preserve contextual escaping for every dynamic value and test output with hostile titles, paths, evidence, and recommendations. |
| `sarif.go` | SARIF 2.1.0 rendering | Keep rule IDs, locations, levels, fingerprints, and invocation status consistent with JSON findings. |
| `progress.go` | Interactive and non-TTY progress | Keep progress optional, avoid corrupting piped output, and handle zero-file and interrupted scans cleanly. |
| `report_test.go` | Shared report tests | Assert score, counts, exclusions, skipped files, warnings, and gate state from representative results. |
| `html_test.go` | HTML escaping tests | Keep script-injection and special-character cases in the test suite. |
| `sarif_test.go` | SARIF schema/content tests | Validate required SARIF fields, rule references, locations, severity levels, and masked messages. |
| `progress_test.go` | Progress rendering tests | Keep TTY and non-TTY rendering deterministic and avoid assertions based on elapsed wall-clock timing. |

## 14. `internal/risk/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `scorer.go` | Deterministic 0–100 risk scoring | Keep weights centralized, clamp scores explicitly, and document how suppressed findings affect scoring. |
| `scorer_test.go` | Risk boundary tests | Preserve tests for zero, one finding per severity, large counts, and score floor behavior. |

## 15. `internal/scanner/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `runner.go` | Rust process execution and Go fallback | Keep executable discovery, process errors, JSON parsing, progress handling, and fallback selection explicit. Never report a clean scan when both engines failed. |
| `secrets.go` | Go secret detection and context scoring | Keep rule IDs and confidence behavior equivalent to Rust. Maintain evidence masking and documentation/placeholder false-positive filters. |
| `dedup.go` | Finding deduplication | Keep the normalized key stable and ensure deduplication does not remove distinct rules on different lines. |
| `runner_test.go` | Scanner execution tests | Keep tests for Rust success, Rust failure, fallback behavior, malformed scanner output, missing executable, and progress parsing. |
| `secrets_test.go` | Secret detection tests | Preserve positive and negative cases for provider tokens, assignments, sensitive filenames, comments, documentation, placeholders, and masking. |
| `dedup_test.go` | Deduplication tests | Keep tests for identical findings, same line/different rule, different line/same rule, and stable output ordering. |

## 16. `scanner/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `Cargo.toml` | Rust scanner manifest | Keep dependency versions reviewed and compatible with the supported Rust toolchain. |
| `Cargo.lock` | Locked Rust dependencies | Regenerate deliberately and verify tests, Clippy, and formatting after dependency changes. |
| `src/main.rs` | Rust CLI entry point | Keep argument validation, JSON stdout, progress stderr, and exit behavior compatible with the Go orchestrator. |
| `src/config.rs` | Rust scanner configuration | Keep exclusion and scan-mode semantics aligned with Go configuration. |
| `src/scanner.rs` | File traversal and scan orchestration | Keep binary filtering, `.gitignore` behavior, skipped-file reporting, and deterministic ordering stable. |
| `src/secrets.rs` | Rust secret detection | Keep rules, confidence scoring, masking, and false-positive filters synchronized with `internal/scanner/secrets.go`. |
| `src/sast.rs` | Static source pattern detection | Keep supported extensions, line reporting, and rule IDs stable; avoid panics on unusual source text. |
| `src/docker.rs` | Dockerfile checks | Keep Docker findings severity and line information consistent with reports. |
| `src/git.rs` | Git-related scanner checks | Keep repository metadata and sensitive Git-file detection separate from ordinary source scanning. |
| `src/rules.rs` | Rust rule definitions | Keep rule IDs unique, descriptions actionable, and serialized fields used; remove dead definitions only when confirmed unused. |
| `src/types.rs` | Rust result and finding types | Keep serialization compatible with Go deserialization and preserve optional metadata fields. |
| `scanner.exe`, `vibeguard-scanner.exe` | Generated scanner binaries | Do not use checked-in/generated copies as the source of truth; rebuild and version-check them during release validation. |

## 17. `scripts/windows/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `build.bat` | Windows source build | Keep tool discovery, error propagation, output paths, and version output consistent with the manifests. |
| `setup.bat` | Global installation | Keep installation idempotent and avoid overwriting user configuration or hooks without a clear backup path. |
| `install_hook.bat` | Hook installation helper | Keep behavior equivalent to `vibeguard init`; avoid maintaining two divergent installation implementations. |
| `uninstall_hook.bat` | Hook removal helper | Preserve user hooks and return a useful error when no VibeGuard hook is installed. |
| `run_test.bat` | Focused health test | Keep external-fixture discovery, output cleanup, and accepted security-block exit codes explicit. |
| `ultimate_test.ps1` | Weighted verification implementation | Keep stage weights totaling 100, metrics based on actual command output, and optional interactive checks clearly marked as not run. |

## 18. `tests/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `tests/integration/integration_test.go` | Cross-package integration coverage | Keep tests independent of developer paths and network state unless a test explicitly uses a local mock. |
| `tests/dependencies/go.mod` | Dependency test fixture manifest | Keep fixture versions intentionally vulnerable or clean as documented; do not allow live updates to change the expected purpose. |
| `tests/dependencies/Cargo.toml` | Cargo dependency fixture | Keep fixture behavior deterministic and separate from production scanner dependencies. |
| `tests/dependencies/package.json` | npm dependency fixture | Keep package metadata minimal and document why each dependency exists in the fixture. |
| `tests/dependencies/requirements.txt` | Python dependency fixture | Keep versions pinned when the test depends on a known advisory. |

## 19. `docs/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `ARCHITECTURE.md` | Component and data-flow description | Keep diagrams, package names, fallback behavior, and report formats synchronized with source. |
| `CHANGELOG.md` | Version history | Record behavior changes, test evidence, and compatibility notes without claiming checks that were not run. |
| `FEATURES.md` | Existing capability reference | Describe only implemented and tested behavior; keep command names and supported formats accurate. |
| `LANGUAGE.md` | Go/Rust responsibilities | Keep ownership boundaries and fallback parity descriptions current. |
| `ROADMAP.md` | Historical project planning | Mark completed items clearly and avoid treating planning text as current implementation evidence. |
| `RULES.md` | Scanner rule reference | Keep rule IDs, severities, examples, exclusions, and output descriptions synchronized with both engines. |
| `SETUP.md` | Installation and environment setup | Keep Windows paths, tool prerequisites, generated-binary behavior, and uninstall steps tested. |
| `TESTING.md` | Test and verification guide | Update stale counts, commands, and expected output immediately when the test suite changes. |

## 20. `reports/`

| Path | Current role | Existing-project improvement |
|---|---|---|
| `README.md` | Generated-report directory policy | Keep the policy clear that generated outputs are disposable and not source evidence. |
| `scan.json` | Generated JSON report | Regenerate when needed; do not manually edit or use an old report as current test evidence. |
| `scan.html` | Generated HTML report | Regenerate from the current binary/source and check that dynamic values remain escaped. |
| `test_scan.html` | Generated test report | Label its fixture/date if retained, otherwise remove stale generated output before release packaging. |

## 21. Review Outcome

### Working areas

- Go and Rust builds are healthy.
- Unit, integration, vet, race, formatting, and Clippy checks pass.
- Clean scans pass and vulnerable fixtures are blocked.
- Report formats and exit-code behavior are consistent across tested paths.
- Git hook lifecycle and fail-closed behavior are implemented.
- OSV online, offline, cache-refresh, and Defender diagnostic paths are
  exercised.

### Improvements to keep applying

1. Keep documentation and expected output synchronized with v4.6.0.
2. Keep generated artifacts separate from source and test evidence.
3. Keep Go fallback and Rust primary scanner behavior equivalent.
4. Keep report schemas, rule IDs, severity counts, and masking consistent.
5. Keep tests deterministic and independent of live remotes, live OSV data,
   and installed antivirus products.
6. Keep configuration exclusions visible and justified.
7. Keep every documented command covered by an automated or manual check.

**Conclusion:** The existing VibeGuard project is working across the tested
functionality. This file identifies maintenance improvements for the current
implementation; it does not request or define new product features.
