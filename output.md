# VibeGuard Test Output

**Date:** 2026-09-18
**Project:** `C:\Users\ranua\Music\cyberhackathon`

## Test Results

### Go Unit and Integration Tests

Command:

```powershell
go test ./...
```

Result: **PASS**

Passing packages:

- `internal/dependencies`
- `internal/gate`
- `internal/report`
- `internal/risk`
- `internal/scanner`
- `tests/integration`

Packages without test files compiled successfully:

- `cmd/vibeguard`
- `internal/osv`
- `tests/sast`

### CLI Build and Version

Commands:

```powershell
go build -buildvcs=false -o output-test.exe ./cmd/vibeguard
output-test.exe version
```

Result: **PASS**

Output:

```text
VibeGuard v1.0.0
```

## Overall Status

**PASS** - The Go test suite passed and the CLI built and reported its version successfully.
