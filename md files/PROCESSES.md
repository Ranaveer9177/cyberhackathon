# VibeGuard — Development Processes & Verification Lifecycle

> **Engineering Operations, Build Processes, and Quality Gates**

---

## 1. Development & Build Lifecycle

### 1.1 Local Build Process
```powershell
# 1. Build Rust Scanner (Release Mode)
cd scanner
cargo build --release
cd ..

# 2. Build Go Orchestrator Binary
go build -buildvcs=false -o vibeguard.exe ./cmd/vibeguard

# 3. Verify Version Output
.\vibeguard.exe version
```

### 1.2 Automated Verification Pipeline
```powershell
# Step 1: Run Go package unit & integration tests
go test ./...

# Step 2: Run Go static analysis
go vet ./...

# Step 3: Verify clean self-scan (must return Exit 0, PASSED, 100/100)
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
