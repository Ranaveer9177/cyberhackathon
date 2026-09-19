# VibeGuard Test Output

**Date:** 2026-09-18
**Project:** `C:\Users\ranua\Music\cyberhackathon`

## 1. Full Go Test Suite

Command:

```powershell
go test ./...
```

Result: **PASS** (exit code `0`)

Passing packages:

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

## 2. Compile Binary

Command:

```powershell
go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
```

Result: **PASS** (exit code `0`)

## 3. Version Check

Command:

```powershell
.\vibeguard.exe version
```

Result: **PASS** (exit code `0`)

Output:

```text
VibeGuard v2.0.0
```

## 4. Status Check

Command:

```powershell
.\vibeguard.exe status
```

Result: **PASS** (exit code `0`)

Observed status:

```text
Git detected: NO
Status: INACTIVE (not a git repository)
```

## 5. Vulnerable Test Project Scan

Command:

```powershell
.\vibeguard.exe scan .\test-project
```

Result: **BLOCKED** (exit code `1`)

Observed summary:

```text
Deployment Status: BLOCKED
Reason: 123 critical finding(s) and 80 high-severity finding(s) detected
```

## Overall Result

**PASS:** The test suite and binary build succeeded. The security gate correctly blocked the intentionally vulnerable test project.
