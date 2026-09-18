# VibeGuard — Testing & Verification Guide

> **Test Suites, Automated Tests, and Manual Verification Procedures**

---

## 1. Automated Test Suite

Run the full Go test suite:

```powershell
go test -v ./...
```

### Passing Packages:
- `internal/config`: Default configuration loading, JSON validation, and exclusion path matching.
- `internal/dependencies`: Manifest parsing (Go, npm, Python, Cargo) and exclusion filtering.
- `internal/gate`: Policy threshold evaluation and exit code mapping.
- `internal/git`: Hook installation/uninstallation, user hook preservation, ref tuple parsing, and snapshot creation.
- `internal/report`: JSON and HTML report generation.
- `internal/risk`: Deterministic mathematical risk scoring calculations.
- `internal/scanner`: Dual-engine scanner execution, exclusion skipping, and rule matching.
- `tests/integration`: End-to-end integration workflows.

---

## 2. Static Analysis Verification

```powershell
go vet ./...
```

Ensures zero suspicious constructs, correct printf formatting, and code standards compliance.

---

## 3. End-to-End Functional Verification

### 3.1 Clean Repository Self-Scan
```powershell
.\vibeguard.exe scan .
```
- **Expected Result**: `Deployment Status: PASSED`
- **Security Score**: `100/100`
- **Exit Code**: `0`
- **Findings**: `0` (internal code exclusions and tooling filters successfully applied)

### 3.2 Intentionally Vulnerable Target Scan
```powershell
.\vibeguard.exe scan .\test-project
```
- **Expected Result**: `Deployment Status: BLOCKED`
- **Exit Code**: `1`
- **Findings**: Identifies intentional secrets in `.env`, vulnerable dependencies in `requirements.txt`/`package.json`, root user in `Dockerfile`, SQL injection and command injection in `database.go`.

### 3.3 Git Pre-Push Hook Verification
```powershell
# Check status
.\vibeguard.exe status

# Reinstall hook
.\vibeguard.exe init

# Verify hook script exists
Get-Content .git/hooks/pre-push
```
