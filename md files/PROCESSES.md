# VibeGuard — Development Processes & Verification Lifecycle

> **Engineering Operations, Build Processes, and Quality Gates**

---

## 0. Workstation Setup & Verification Lifecycle (`NEW_LAPTOP_SETUP.md`)

### 0.1 Demo & User Mode Setup (`setup.bat`)
On a fresh Windows laptop, run:
```cmd
.\setup.bat
```
- Operates 100% on prebuilt binaries (`vibeguard.exe`, `vibeguard-scanner.exe`).
- Requires zero compilers (no Go, no Rust, no Visual Studio Build Tools).
- Automatically initializes `.vibeguard\`, `reports\`, `rules\`, and `tests\`.
- Installs the Git pre-push hook.
- Registers `%LOCALAPPDATA%\VibeGuard\bin` in the User `PATH` registry environment.

### 0.2 Automated Health Check (`run_test.bat`)
Verify complete scanner and hook pipeline:
```cmd
.\run_test.bat
```
- Validates CLI and scanner binary presence.
- Executes full scan on intentionally vulnerable `test-project`.
- Confirms findings are identified and deployment is correctly BLOCKED.

### 0.3 Pre-Push Hook Control
```cmd
.\install_hook.bat     # Installs .git/hooks/pre-push
.\uninstall_hook.bat   # Cleanly removes .git/hooks/pre-push
```

---

## 1. Development & Source Build Lifecycle

### 1.1 One-Command Source Build (`build.bat`)
For developers with Go 1.21+, Rust 1.70+, and Visual Studio Build Tools (`link.exe`):
```cmd
.\build.bat
```
Automatically verifies compiler prerequisites, rebuilds the release Rust scanner, builds the Go orchestrator CLI, updates `%LOCALAPPDATA%\VibeGuard\bin`, and runs a self-verification check.

### 1.2 Automated Verification Pipeline
```powershell
# Step 1: Run Go package unit & integration tests (including progress bar tests)
go test ./...

# Step 2: Run Go static analysis
go vet ./...

# Step 3: Verify clean self-scan with real-time progress indicators (Exit 0, PASSED, 100/100)
# - Displays File Scan progress: [██████████████░░░░░░] 70%
# - Displays Dependency Scan progress: [████████████████░░░░] 80%
# - Displays OSV Query progress: [██████████████████░░] 90%
# - Displays Final 100% Completion: [████████████████████] 100%
.\vibeguard.exe scan .

# Step 4: Verify vulnerable test fixture detection (must return Exit 1, BLOCKED)
.\vibeguard.exe scan .\test-project
```

---

## 2. Git Pre-Push Hook Lifecycle

### 2.1 Initialization
Running `vibeguard init` performs:
1. Validates Git repository existence.
2. Checks for existing `.git/hooks/pre-push`. If present, backs up to `pre-push.user`.
3. Installs VibeGuard pre-push hook script.
4. Generates `.vibeguard/config.json` with default exclusions if missing.

### 2.2 Execution on `git push`
1. Git forwards ref tuples on `stdin`.
2. Hook resolves repository root and locates `vibeguard.exe`.
3. Executes `vibeguard scan . --hook`.
4. If commit is valid, extracts `git archive` snapshot to a temporary directory.
5. Scans exact committed content.
6. Returns `0` (push continues) or `1` (push aborted).

### 2.3 Interactive Push with `vibeguard push`
1. Staging prompt (`git add .`).
2. Commit message prompt (`git commit -m "..."`).
3. Single security verification scan.
4. If passed, prompts user to push.
5. Executes `git push --no-verify` to prevent duplicate scanning.
