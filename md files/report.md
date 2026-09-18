# VibeGuard Test Report

**Date:** 2026-09-18
**Target:** `C:\Users\ranua\Music\cyberhackathon`
**Fixture:** `test-project`

## Summary

The Go test suite passed. The Rust scanner suite could not run to completion because its dependencies are not available in the local Cargo cache. The CLI builds and the dependency scan runs, but the Rust scanner executable is not found at runtime and JSON/HTML report generation fails even though the output directory is writable.

## Environment

- Go executable: `C:\Program Files\Go\bin\go.exe`
- Rust: `rustc 1.98.1`
- Cargo: `cargo 1.98.1`
- The workspace has no Git metadata, so Go builds require `-buildvcs=false`.

## Test Results

| Area | Command or check | Result |
|---|---|---|
| Go unit and integration tests | `go test ./...` | **PASS** |
| Go CLI build | `go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard` | **PASS** |
| CLI version | `vibeguard.exe version` | **PASS**, reports `VibeGuard v1.0.0` |
| Rust scanner tests | `cargo test` | **BLOCKED**, dependency/lockfile setup failed |
| Rust scanner offline retry | `cargo test --offline` | **BLOCKED**, `aho-corasick v1.1.5` is not cached |
| Terminal scan | `vibeguard.exe scan .\\test-project` | **PARTIAL**, dependency scan ran; Rust scanner was skipped |
| JSON report | `vibeguard.exe scan .\\test-project --format json` | **FAIL**, cannot open `reports/scan.json` |
| HTML report | `vibeguard.exe report .\\test-project --format html` | **FAIL**, cannot open `reports/scan.html` |

## Go Test Coverage Observed

All discovered Go packages passed, including:

- `internal/dependencies`
- `internal/gate`
- `internal/report`
- `internal/risk`
- `tests/integration`

Packages without test files were also compiled successfully.

## End-to-End Observations

The vulnerable fixture produced these dependency-scan results:

- 12 dependencies discovered
- 11 vulnerable dependency groups
- 185 OSV advisories returned
- 0 files scanned by the Rust engine because `vibeguard-scanner.exe` was not available
- Terminal output ended with `Deployment Status: PASSED`, despite the scanner failure and vulnerable dependencies

## Issues Requiring Follow-up

1. Build or place `vibeguard-scanner.exe` beside `vibeguard.exe`, or configure an explicit scanner path. The current fallback relies on the executable being available through `%PATH%`.
2. Investigate why the CLI report path fails with Windows error `The system cannot find the file specified` while direct writes to the same `reports` directory succeed.
3. Ensure dependency findings affect the deployment gate. The end-to-end run reported 185 advisories but still returned a passing deployment status.
4. Restore/install Rust dependencies before rerunning `cargo test` and scanner integration checks.
