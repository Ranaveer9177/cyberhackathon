# Test 5 - Full Validation Report

Date: 2026-09-19
Workspace: `C:\Users\ranua\Music\cyberhackathon`
Fixture: `test-project`

## Executive Result

The Go implementation passed its unit, integration, and static-analysis checks. The CLI built successfully and completed the security analysis of the intentionally vulnerable fixture. The fixture was correctly identified as unsafe.

The Rust validation could not complete because Cargo failed to create dependency files with Windows error `os error 2`. The JSON report-writing path also failed with the same filesystem error after the scan completed.

## Commands and Results

### 1. Go tests

Command:

```powershell
go test ./...
```

Result: PASS

Packages reported successful:

- `internal/config`
- `internal/dependencies`
- `internal/gate`
- `internal/git`
- `internal/report`
- `internal/risk`
- `internal/scanner`
- `tests/integration`

Packages without test files:

- `cmd/vibeguard`
- `internal/osv`
- `tests/sast`

### 2. Go static analysis

Command:

```powershell
go vet ./...
```

Result: PASS

No diagnostics were emitted.

### 3. Go CLI build

Command:

```powershell
go build -buildvcs=false -o .\vibeguard-test.exe .\cmd\vibeguard
```

Result: PASS

### 4. CLI version check

Command:

```powershell
.\vibeguard-test.exe version
```

Output:

```text
VibeGuard v3.0.0
```

Result: PASS

### 5. Rust scanner tests

Command:

```powershell
Push-Location .\scanner
cargo test -- --nocapture
Pop-Location
```

Result: BLOCKED by environment/filesystem error.

Cargo repeatedly failed while writing dependency metadata, for example:

```text
error: error writing dependencies to ...\\target\\debug\\deps\\unicode_ident-....d: The system cannot find the file specified. (os error 2)
error: could not compile `unicode-ident` (lib) due to 1 previous error
```

The same result occurred when using a fresh isolated target directory. This was not a Rust test assertion failure.

### 6. Rust type check

Command:

```powershell
Push-Location .\scanner
cargo check
Pop-Location
```

Result: BLOCKED by the same Cargo dependency-file creation error.

### 7. Security scan of the test project

Command:

```powershell
.\vibeguard-test.exe scan .\test-project
```

Result: analysis completed and the fixture was identified as vulnerable.

Scan output details:

- Files scanned: `9/9`
- Findings from scanner: `23`
- Dependencies found: `12`
- Vulnerable packages: `11`
- Total vulnerabilities: `185`
- OSV queries completed: `12/12`
- Scan phases completed: scanner, dependency checks, OSV queries, and risk scoring

The process returned security-gate exit code `1` for the vulnerable fixture when run normally. The analysis is expected to report findings because this project intentionally contains insecure code, secrets, Docker misconfigurations, and outdated dependencies.

### 8. JSON report generation

Command:

```powershell
.\vibeguard-test.exe scan .\test-project --format json --output .\reports\test5-scan.json
```

Result: FAIL during report output, after analysis completed.

Error:

```text
Error writing JSON report: open .\\reports\\test5-scan.json: The system cannot find the file specified.
```

The `reports` directory exists, so the report path handling should be investigated separately. This does not invalidate the scanner findings collected before the write failure.

## Final Status

- Go tests: PASS
- Go vet: PASS
- CLI build: PASS
- CLI version: PASS
- Fixture scan analysis: PASS, with expected security findings
- Rust tests: BLOCKED by Cargo/Windows filesystem error
- Rust check: BLOCKED by Cargo/Windows filesystem error
- JSON report persistence: FAILS for the requested output path
