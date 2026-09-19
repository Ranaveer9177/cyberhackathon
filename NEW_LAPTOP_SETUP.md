# VibeGuard — New Laptop Setup & Portability Plan

## Purpose

This document defines how VibeGuard must be packaged and how the setup scripts must behave on a **new Windows laptop**.

The goal is:

> Clone/copy the repository to a new Windows laptop, run one setup command, and avoid confusing build errors caused by missing Go, Rust, MSVC, PATH configuration, or incorrect working directories.

The hackathon/demo laptop should **not need Go, Rust, or Visual Studio Build Tools just to run the already-built VibeGuard application**.

---

# 1. Recommended Final Distribution

The repository should support two modes.

## Mode A — Demo / User Mode

Use prebuilt binaries.

```text
cyberhackathon/
├── vibeguard.exe
├── scanner/
│   └── scanner.exe
├── rules/
├── reports/
├── test-project/
├── .vibeguard/
├── setup.bat
├── run_test.bat
└── README.md
```

In this mode:

```cmd
setup.bat
```

should configure VibeGuard and verify the installation.

The user should then be able to run:

```cmd
vibeguard version
```

and:

```cmd
vibeguard scan .\test-project
```

No Rust compiler is required.

No Go compiler is required.

No Visual Studio Build Tools are required.

---

# 2. Mode B — Developer / Source Build Mode

Developers who want to rebuild VibeGuard from source may install:

```text
Git
Go
Rust
Visual Studio Build Tools
Desktop development with C++
```

Then the project can be rebuilt using the source-build script.

Example:

```cmd
build.bat
```

The important rule is:

> The normal setup script must not assume that a compiler is installed.

---

# 3. Required Scripts

The repository should eventually contain:

```text
setup.bat
build.bat
run_test.bat
install_hook.bat
uninstall_hook.bat
```

## setup.bat

Responsible for:

1. Detecting the repository root.
2. Checking that VibeGuard binaries exist.
3. Creating required directories.
4. Checking required files.
5. Configuring PATH if required.
6. Installing the Git pre-push hook.
7. Running a basic version test.
8. Printing clear success/failure messages.

It should NOT automatically run `cargo build` or `go build` unless explicitly requested.

---

# 4. Repository Root Detection

Every BAT script must work regardless of the directory from which it is launched.

Do NOT assume the user is already inside the repository.

Use the BAT file's own location as the project root.

Conceptually:

```bat
set "ROOT=%~dp0"
cd /d "%ROOT%"
```

This prevents errors such as:

```text
scanner\cmd\vibeguard not found
```

caused by running a root-level Go command from inside the `scanner` directory.

---

# 5. Prebuilt Binary Check

Before doing anything else, `setup.bat` should check:

```text
vibeguard.exe
scanner\scanner.exe
```

If they exist:

```text
[OK] VibeGuard CLI found
[OK] Rust scanner found
```

If one is missing:

```text
[ERROR] Required VibeGuard binary was not found.

Expected:
    <project>\vibeguard.exe

Run build.bat on a developer machine or obtain the official release package.
```

Do not silently continue.

---

# 6. Do Not Require Rust on Demo Laptop

This is critical.

The current problem was:

```text
error: linker `link.exe` not found
```

This happens because Rust was trying to compile using the Windows MSVC target but the Microsoft C++ linker was not installed.

The final demo package should avoid this entirely.

The demo laptop should run:

```text
vibeguard.exe
```

and:

```text
scanner.exe
```

instead of compiling Rust.

---

# 7. Developer Build Requirements

`build.bat` should check:

```text
go
cargo
rustc
link.exe
```

Example checks:

```bat
where go
where cargo
where rustc
where link
```

If `link.exe` is missing, show:

```text
[ERROR] Microsoft C++ linker (link.exe) was not found.

Install:
Visual Studio Build Tools
→ Desktop development with C++

Then open a new terminal and run build.bat again.
```

Do not display a long Rust compiler error when a simple prerequisite explanation is possible.

---

# 8. Correct Build Order

The source build should be:

```text
1. Detect project root
2. Check Go
3. Check Rust
4. Check MSVC linker
5. Build Rust scanner
6. Build Go CLI
7. Verify generated binaries
8. Run version test
9. Report success
```

Rust:

```cmd
cd scanner
cargo build --release
```

Return to root:

```cmd
cd ..
```

Go:

```cmd
go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard
```

The Go command MUST be executed from the repository root.

---

# 9. Never Use Documentation Comments as Commands

Do not copy lines such as:

```text
# Output: VibeGuard v3.0.0
```

into CMD.

For BAT files use:

```bat
REM Output: VibeGuard v3.0.0
```

or simply print output with:

```bat
echo Output: VibeGuard v3.0.0
```

---

# 10. PATH Configuration

VibeGuard should work from the project directory even if PATH is not modified.

Example:

```cmd
.\vibeguard.exe version
```

If global CLI usage is desired, setup may add the VibeGuard installation directory to the user's PATH.

Prefer **User PATH**, not System PATH.

After changing PATH, tell the user:

```text
PATH updated.
Please open a new terminal before using `vibeguard`.
```

Do not assume the current CMD automatically receives the newly modified PATH.

---

# 11. Git Pre-Push Hook

The project must install a Git pre-push hook.

Expected location:

```text
.git\hooks\pre-push
```

The hook should call the VibeGuard executable using an absolute/project-relative path rather than assuming `vibeguard` is globally available.

Conceptually:

```text
git push
    ↓
.git/hooks/pre-push
    ↓
vibeguard scan
    ↓
PASS → exit 0
BLOCK → exit 1
```

The hook must return a non-zero exit code when VibeGuard blocks the push.

---

# 12. Git Hook Portability

Do not hardcode a developer's personal path such as:

```text
C:\Users\ranua\...
```

Never use:

```text
C:\Users\pooji\...
```

Never use:

```text
C:\Users\ranua\...
```

The hook must determine the repository/project location dynamically.

This is essential when moving the project between laptops.

---

# 13. Required Directory Checks

`setup.bat` should verify or create:

```text
.vibeguard\
reports\
rules\
tests\
```

If a directory is required by the current implementation, it should be created automatically.

Example:

```bat
if not exist ".vibeguard" mkdir ".vibeguard"
if not exist "reports" mkdir "reports"
```

Do not overwrite existing configuration unnecessarily.

---

# 14. Test Command

Create:

```text
run_test.bat
```

It should:

1. Detect project root.
2. Check `vibeguard.exe`.
3. Check scanner executable.
4. Run the version command.
5. Scan `test-project`.
6. Display the final result.
7. Return a useful exit code.

Example:

```cmd
run_test.bat
```

Expected:

```text
========================================
        VIBEGUARD TEST
========================================

[OK] CLI
[OK] Scanner
[OK] Version
[OK] Test project

Running security scan...

========================================
TEST COMPLETED
========================================
```

---

# 15. Setup Should Be Safe to Run Multiple Times

Running:

```cmd
setup.bat
```

more than once must not break the project.

It should:

- not duplicate PATH entries
- not overwrite user configuration unnecessarily
- not create duplicate Git hooks
- not delete existing reports
- not delete source code
- not reinstall working components unnecessarily

The setup process should be **idempotent**.

---

# 16. Error Handling

Every important command should be checked.

Conceptually:

```bat
some-command
if errorlevel 1 (
    echo [ERROR] Command failed.
    exit /b 1
)
```

Do not allow setup to continue after a critical failure.

For example:

```text
Rust scanner missing
        ↓
STOP
```

rather than:

```text
Rust scanner missing
        ↓
continue
        ↓
Go build
        ↓
confusing later error
```

---

# 17. Offline Demo Consideration

The hackathon demonstration should preferably work even if Internet access is unavailable.

The core scanner should still run.

Dependency vulnerability lookup can be designed as:

```text
Online:
Project → VibeGuard → OSV API

Offline future:
Project → VibeGuard → Local vulnerability database
```

For the current MVP, if OSV cannot be reached, VibeGuard should clearly report:

```text
[WARNING] Vulnerability intelligence service unavailable.

Dependency CVE verification could not be completed.
```

Do not report:

```text
PASS
```

when the dependency vulnerability check was never performed.

The final policy should decide whether this condition blocks the push.

---

# 18. Fresh Laptop Test Procedure

Before submitting the project, test it on another Windows laptop.

### Test 1 — Clean environment

Use a laptop without:

```text
Go
Rust
Visual Studio Build Tools
```

if possible.

Copy/clone the project.

Run:

```cmd
setup.bat
```

The demo package should still work if prebuilt binaries are included.

### Test 2 — Version

```cmd
vibeguard version
```

Expected:

```text
VibeGuard v3.0.0
```

### Test 3 — Scan

```cmd
vibeguard scan .\test-project
```

### Test 4 — Git hook

Create a controlled test finding.

Run:

```cmd
git add .
git commit -m "test"
git push
```

Expected:

```text
VibeGuard Security Gate
...
STATUS: BLOCKED
```

Then remove/fix the test finding and repeat:

```cmd
git push
```

Expected:

```text
STATUS: SAFE TO PUSH
```

---

# 19. Final Packaging Rule

For the hackathon submission, prefer distributing:

```text
VibeGuard/
├── vibeguard.exe
├── scanner/
│   └── scanner.exe
├── .vibeguard/
├── rules/
├── reports/
├── tests/
├── test-project/
├── setup.bat
├── build.bat
├── run_test.bat
├── install_hook.bat
├── uninstall_hook.bat
├── README.md
└── NEW_LAPTOP_SETUP.md
```

Source code should remain available for academic/source-code submission.

The important distinction is:

```text
Source package
    ↓
For developers who want to build

Release/demo package
    ↓
For judges/users who just want to run
```

---

# 20. Final Acceptance Criteria

VibeGuard setup is considered portable when all of these are true:

- [x] No hardcoded `C:\Users\<name>` paths.
- [x] Scripts automatically find their project root.
- [x] `setup.bat` works from any current directory.
- [x] Demo laptop does not need Rust to run VibeGuard.
- [x] Demo laptop does not need Go to run VibeGuard.
- [x] Demo laptop does not need Visual Studio Build Tools to run VibeGuard.
- [x] `build.bat` detects missing developer prerequisites.
- [x] `link.exe` requirement is explained clearly for source builds.
- [x] Go build is executed from the repository root.
- [x] Rust build is executed from the scanner directory.
- [x] Required directories are created automatically.
- [x] Git pre-push hook uses portable paths.
- [x] Setup can safely be run multiple times.
- [x] `run_test.bat` provides a complete health check.
- [x] Version command works.
- [x] Test scan works.
- [x] Git push is blocked when the security policy fails.
- [x] Git push proceeds when the security policy passes.
- [x] No real credentials are included in test data.
- [x] The project can be demonstrated on a second Windows laptop.

---

# 21. Priority for Hackathon

Because the project is being demonstrated today, implement in this order:

### P0 — Required immediately

1. Build working Rust scanner.
2. Build working Go CLI.
3. Produce `vibeguard.exe`.
4. Produce Rust scanner `.exe`.
5. Update `setup.bat`.
6. Add `run_test.bat`.
7. Make Git hook portable.
8. Test on the second laptop.

### P1 — Important

9. Clear prerequisite detection.
10. Better error messages.
11. PATH handling.
12. Final README instructions.

### P2 — Future

13. Automatic vulnerability database synchronization.
14. Offline vulnerability database.
15. CI/CD integration.
16. AI provider integration.
17. Linux/macOS release packages.

---

# Final Goal

A new Windows laptop should be able to receive the VibeGuard project and reach:

```text
setup.bat
    ↓
VibeGuard ready
    ↓
vibeguard version
    ↓
vibeguard scan .
    ↓
git push
    ↓
VibeGuard Security Gate
    ↓
┌───────────────────────┐
│ SAFE TO PUSH          │
│          OR           │
│ PUSH BLOCKED          │
└───────────────────────┘
```

without requiring the user to manually understand Rust, Cargo, Go module paths, MSVC linker configuration, or the developer's original Windows username.
