# VibeGuard Test 3 Output

**Date:** 2026-09-18
**Project:** `C:\Users\ranua\Music\cyberhackathon`

## Full Go Test Suite

Command:

```powershell
go test ./...
```

Result: **PASS** (exit code `0`)

Verified packages:

- `internal/config`
- `internal/dependencies`
- `internal/gate`
- `internal/git`
- `internal/report`
- `internal/risk`
- `internal/scanner`
- `tests/integration`

Packages without test files compiled successfully:

- `cmd/vibeguard`
- `internal/osv`
- `tests/sast`

## Vulnerable Fixture Scan

Command:

```powershell
.\vibeguard.exe scan .\test-project
```

Result: **BLOCKED** (exit code `1`)

Observed summary:

```text
Deployment Status: BLOCKED
Reason: 22 critical finding(s) and 71 high-severity finding(s) detected
```

## Overall Result

**PASS:** The project test suite passed, and the security gate correctly blocked the intentionally vulnerable test project.
