# VibeGuard — Feature Specifications

> **Complete Feature Reference for VibeGuard v5.1.0**

---

## 1. Autonomous Git Pre-Push Security Gate

### 1.1 Automatic Pre-Push Hook (`.git/hooks/pre-push`)
- Automatically intercepts every `git push` command.
- Forwards Git ref tuples (`<local_ref> <local_sha> <remote_ref> <remote_sha>`) via standard input.
- Immediately detects remote branch deletions and exits cleanly without scanning.
- Evaluates policy against `.vibeguard/config.json`.
- Exits with `0` to allow the push, or `1` to abort the push before code leaves the machine.

### 1.2 Push Commit Tree Snapshotting
- Executes `git archive --format=tar <localSHA>` and extracts the tree in-memory using pure Go `archive/tar`.
- Scans only the exact committed files being sent to remote, ignoring dirty local working copy files.
- Automatically cleans up temporary snapshot workspaces on completion.

### 1.3 User Hook Preservation & Chaining
- If an existing user hook is present when `vibeguard init` is run, VibeGuard backs it up to `.git/hooks/pre-push.user`.
- On every push, VibeGuard executes `pre-push.user` first; if it passes, VibeGuard runs its security gate.

### 1.4 Controlled Interactive Push (`vibeguard push`)
- Detects modified and untracked files.
- Prompts developer to stage changes (`git add .`).
- Prompts for commit message and creates the commit locally.
- Runs full security gate verification.
- If verified safe, prompts for push confirmation and pushes via `git push --no-verify` to eliminate redundant duplicate scans.

---

## 2. Multi-Engine Security Scanners

### 2.1 Secret & Credential Detection (v5.1 Context-Aware Engine)
- **Sensitive Filename Auditing (`VG-SECRET-FILE`)**:
  - Automatically detects sensitive credential and leak filenames: `password.txt`, `credentials.txt`, `secret.txt`, `leak*.txt` (e.g. `leak_test.txt`), `test*.txt`, `*_secret.txt`, `*.conf`, and `*.env*` with `HIGH` severity and `HIGH` confidence.
- **Dynamic Credential Weighting (`VG-SECRET-001`, `VG-SECRET-002`, `VG-SECRET-003`)**:
  - Automatically awards high confidence to exact quoted credential assignments (`password = "..."`, `api_key = "..."`, `secret = "..."`) across text and config files, regardless of whether the file is named `password.txt`.
  - Intelligently excludes source code comparison expressions (`==`, `!=`) and comments (`//`, `#`, `/*`).
- **Entropy & Standard Credential Pattern Recognition**:
  - AWS Access Keys (`AKIA[0-9A-Z]{16}`)
  - GitHub Personal Access Tokens (`ghp_[a-zA-Z0-9]{36}`)
  - Slack Tokens (`xox[bprs]-[a-zA-Z0-9-]+`)
  - Private Cryptographic Keys (`-----BEGIN RSA/OPENSSH PRIVATE KEY-----`)
  - Repository sensitive files (`.env`, `id_rsa`, `*.pem`, `*.key`)
- **Context & Confidence Scoring Algorithm**:
  - Computes score (0–100) using positive signals (+30 filename, +25 key, +20 assignment, +15 non-placeholder, +10 entropy, +10 source/config) and penalty signals (-30 documentation, -25 obvious placeholder, -20 comments/examples, -40 test fixtures).
  - Only `HIGH` (80–100) and `MEDIUM` (50–79) confidence findings block the gate; `LOW` (20–49) confidence findings are advisory.
- **Evidence Masking**: Truncates secrets in all outputs (`password=********`, `sk-demo-****`) to ensure zero sensitive exposure in reports and terminal displays.

### 2.2 Static Application Security Testing (SAST)
- High-precision rules with zero internal tooling false positives:
  - `Potential OS Command Injection`
  - `Potential SQL Injection`
  - `Potential TLS Misconfiguration` (`InsecureSkipVerify: true`)
  - `Potential Insecure HTTP Connection` (loopback excluded)
  - `Dangerous Eval` (`eval()`, `Function()`)
  - `Weak Crypto` (`MD5`, `SHA1`, `DES`, `RC4`)
  - `Hardcoded Credentials` in source code
- Supports: `.go`, `.js`, `.ts`, `.py`, `.java`, `.rs`, `.rb`, `.php`, `.c`, `.cpp`, `.cs`.

### 2.3 Dependency Vulnerability Intelligence (SCA)
- Native parsing of package manifests:
  - Go: `go.mod`
  - Node.js: `package.json` & `package-lock.json`
  - Python: `requirements.txt`
  - Rust: `Cargo.toml` & `Cargo.lock`
- Live integration with Google OSV database (`https://api.osv.dev/v1/querybatch`).
- Version sanitization and semantic range resolution.
- Extraction of advisory summaries, CVE aliases, affected versions, and fixed upgrade versions.
- Strict `fail_closed` policy enforcement on network/lookup failures.

### 2.4 Container & Dockerfile Auditing
- Scans `Dockerfile` and `*.dockerfile`:
  - Missing non-root `USER` instruction (`HIGH`).
  - Secrets defined in `ENV` instructions (`CRITICAL`).
  - Unbounded `COPY . .` instructions (`MEDIUM`).

### 2.5 Configuration & Git Security
- Audits `.yaml`, `.json`, `.toml`, `.ini`:
  - Debug mode enabled in production configs (`MEDIUM`).
  - Wildcard CORS (`Access-Control-Allow-Origin: *`) (`MEDIUM`).
  - Binding to insecure wildcard address `0.0.0.0` (`LOW`).

### 2.6 Windows Defender & Antivirus Interception Detection (v4.5)
- **Automatic Interception Detection**:
  - Automatically identifies when VibeGuard or its scanner binaries are blocked, quarantined, or denied execution (`ERROR_VIRUS_INFECTED`, `ERROR_ACCESS_DENIED`, `0x800700E1`, `0xC0000022`).
- **Native Windows Pop-up Notification (`MessageBoxW`)**:
  - Automatically raises a native Win32 system modal dialog (`user32.dll`) over developer terminals and IDE windows explaining what blocked VibeGuard, which component was intercepted, and specific steps to unblock it.
  - Headless/CI environments (`VIBEGUARD_NON_INTERACTIVE=1`) automatically bypass GUI dialogs while printing full diagnostics to `os.Stderr`.
- **Security Software Discovery**:
  - Queries Windows Security Center via WMI (`root\SecurityCenter2`) to detect the active antivirus/EDR product name.
- **Diagnostic Command**:
  - `vibeguard defender-check [--test-popup]` allows checking active AV status and testing the modal pop-up alert dialog on demand.

---

## 3. Configuration & Exclusion Management (`.vibeguard/config.json`)

- **Configurable Exclusions (`exclude`)**: Universal filtering skipping docs, test directories, and local reports across both Go and Rust engines.
- **Customizable Gate Policy (`block_on`)**: Define blocking severities (`["critical", "high"]`).
- **Fail-Closed Enforcement (`fail_closed`)**: Aborts push if scanner or vulnerability intelligence is unavailable.
- **Scan Modes (`scan_mode`)**: `"full"` for complete audits, `"changed"` for diff analysis.

---

## 4. Live Scan Progress Feedback (v3.0)

### 4.1 Real-Time Progress Engine
- Terminal progress bars rendered dynamically during scans across all 4 stages:
  1. **File Scanning**: Percentage, files scanned / total files, and currently active file path:
     ```text
     [██████████████░░░░░░] 70%
     Files: 56/80
     Current: internal/scanner/runner.go
     ```
  2. **Dependency Scanning**: Percentage, dependencies checked / total dependencies, and current package name and version:
     ```text
     [████████████████░░░░] 80%
     Dependencies: 36/45
     Current: lodash@4.17.20
     ```
  3. **Vulnerability Database (OSV) Lookup**: Percentage of live vulnerability queries completed / total queries:
     ```text
     [██████████████████░░] 90%
     OSV queries: 41/45
     ```
  4. **Final Stage**: 100% completion bar followed by completion confirmation:
     ```text
     [████████████████████] 100%

     Security analysis complete.
     ```
- **ANSI Terminal Control**: In-place multi-line overwriting with `\033[%dA\r` and line clearing `\033[K`.
- **Non-TTY Fallback**: Clean sequential output on headless CI runners, pipes, or non-terminal redirected output streams.

---

## 5. Reporting & Scoring

- **Deterministic Scoring**:
  $$\text{Score} = \max\left(0, 100 - (15 \times C + 8 \times H + 3 \times M + 1 \times L)\right)$$
- **Terminal Report**: High-contrast ANSI colors, summary metrics, and finding evidence.
- **JSON Report**: Saved to `reports/scan.json` for CI/CD automation.
- **HTML Report**: Responsive, standalone interactive dashboard saved to `reports/scan.html`.

---

## 6. Global CLI Installation & Windows Distribution Suite (`GLOBAL_CLI_SETUP.md`)

### 6.1 Distribution Architecture
- **Global User Installation**: Self-locating CLI installed to `%LOCALAPPDATA%\VibeGuard`, added to Windows User `PATH` idempotently.
- **Mode A (Demo / User Mode)**: Runs from prebuilt binaries (`vibeguard.exe` and `scanner.exe`). Never requires Go, Rust, or MSVC Build Tools.
- **Mode B (Developer Mode)**: Full source rebuilds using `scripts\windows\build.bat`, verifying Go and Rust plus a compatible Windows linker/toolchain.
- **Dynamic Self-Locating Engine**: Prioritizes executable path and `%LOCALAPPDATA%\VibeGuard` so `vibeguard scan <path>` executes anywhere.
- **Hardened Git Pre-Push Hook**: Prefers global `%LOCALAPPDATA%\VibeGuard` installation over untrusted repository-local executables (Section 19 Security Policy).

### 6.2 Automation Scripts
1. **`scripts\windows\setup.bat` (Mode A Setup)**:
   - Dynamic repository root detection (`%~dp0`).
   - Prebuilt binary presence verification.
   - Automatically creates `.vibeguard\`, `reports\`, `rules\`, and `tests\`.
   - Generates default `.vibeguard\config.json`.
   - Installs Git pre-push hook into `.git\hooks\pre-push`.
   - Copies binaries to `%LOCALAPPDATA%\VibeGuard` and registers User `PATH`.
   - Safe, idempotent, and non-destructive.
2. **`scripts\windows\build.bat` (Mode B Source Build)**:
   - Verifies Go and Rust toolchains and reports whether `link.exe` is directly available.
   - Recompiles Rust scanner in release mode and copies binary to root and `scanner/`.
   - Recompiles Go orchestrator CLI from repository root.
   - Refreshes `%LOCALAPPDATA%\VibeGuard`.
3. **`scripts\windows\run_test.bat` (Health Check & Fixture Validation)**:
   - Validates CLI, Scanner, Version, Test Project Scan, HTML Report Generation, and Security Gate Blocking.
   - Formatted `[PASS]` status output across all 6 core criteria.
4. **`scripts\windows\install_hook.bat` & `scripts\windows\uninstall_hook.bat`**:
   - Single-command lifecycle management for the Git pre-push hook.

---

## 7. v3.0 Production Enhancements

### 7.1 Multi-Ref Pre-Push Gate
- Intercepts all ref update lines supplied via `stdin` during `git push`.
- Detects branch deletions (`0000000000000000000000000000000000000000`) and skips scanning for deleted refs.
- Evaluates each pushed ref's commit snapshot independently; any ref failing security policy aborts the entire push.

### 7.2 Fail-Closed Security Policy
- Hardened pre-push hook fails closed: if the `vibeguard` binary cannot be found in `%LOCALAPPDATA%\VibeGuard` or `%PATH%`, it terminates with exit code `1` and prints an explicit blockage notice.
- Prevents bypasses where security scans are silently skipped if files are relocated.

### 7.3 High-Performance Concurrent OSV Engine
- Replaces serial queries with an asynchronous worker pool of 10 concurrent goroutines.
- Shared `http.Client` with HTTP Keep-Alive, connection pooling, and 15-second timeouts.
- Batch advisory lookup latency reduced by >80% (~400ms vs ~8s) with real-time thread-safe progress reporting.

### 7.4 Rust Scanner `--progress` Streaming
- Rust scanner engine accepts `--progress` flag.
- Streams live file scanning milestones (`PROGRESS:<cur>:<tot>:<file>`) on `stderr`.
- Outputs clean, pure JSON payload on `stdout`.
- Go CLI runner intercepts `stderr` in real time to render terminal progress bars while collecting scan results.

### 7.5 Unified Push Verification Model
- `vibeguard push` extracts commit snapshots and applies the identical policy and diff filtering logic as native `git push` hooks.
- Guarantees 100% behavioral parity between CLI-assisted and direct Git pushes.

### 7.6 Disk-Staged Commit Tar Snapshots
- `internal/git/repo.go` writes `git archive --format=tar -o commit.tar <localSha>` directly to disk.
- Pure Go `tar.Reader` unpacks snapshot files into temporary directories.
- Completely prevents Windows stdout pipe deadlocks during git archive operations.

### 7.7 False-Positive Elimination Engine
- **Test Coverage & Artifact Filtering**: Automatically excludes test coverage directories (`htmlcov`, `.coverage`, `coverage`, `.pytest_cache`, `.mypy_cache`, `.tox`, `.nyc_output`), virtual environments (`venv`, `env`), and IDE settings (`.idea`, `.vscode`).
- **Native `.gitignore` Parsing**: Both Rust and Go scanner engines parse the repository's `.gitignore` file and skip all ignored paths.
- **Documentation Safety**: Excludes documentation extensions (`.md`, `.markdown`, `.rst`, `.txt`, `.adoc`, `.html`) from generic password and token assignment rules. Real high-entropy credentials (AWS, GitHub tokens, RSA private keys) remain active across all file types.
- **PowerShell & Environment Filter**: Filters parameter declarations and variable prompts (`Read-Host`, `param(`, `[string]`, `[securestring]`, `os.environ`, `os.getenv`, `process.env`, `$env:`).
- **Placeholder Passwords**: Ignores common dummy/placeholder values (`"admin"`, `"password"`, `"changeme"`, `"your_password"`, `""`) and variable references (`="$...`, `="${...`, `="%"`, `:'$...`).
- **Insecure HTTP Refinement**: Ignores `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, schemas (`w3.org`, `schemas.`, `json-schema.org`, `apache.org`, `example.com`), and dynamic template strings (`http://${...`, `http://{...`).

### 7.8 Clean Grouped Terminal Report Architecture
- **Eliminated Repetitive Dumps**: Deprecated 250+ lines of duplicate raw advisory dumps in terminal mode.
- **Grouped Package Table**: Aggregates dependencies per package into an aligned table showing `PACKAGE`, `CURRENT`, `SEVERITY`, `ADVISORIES`, and `RECOMMENDED FIX`.
- **Key Advisory Highlights**: Displays top 2–3 advisory IDs per package with concise summaries and remainder counts (`... and X more advisories`).
- **Distinct Code & Secrets Section**: Non-dependency issues (secrets, SAST, Docker, Git) are displayed separately with color-coded severity badges, IDs, files, lines, titles, and recommendations.
- **Zero-Issue Confirmation State**: Renders clean green checkmark states (`✓ No code, secret, or configuration issues detected.`, `✓ No known vulnerabilities found in dependencies.`).

---

## 8. v5.1 Production Enhancements

### 8.1 Generic Leak Wildcards & SCA Manifest Safeguards
- **Expanded Sensitive File Auditing**: Intercepts generic leak patterns including `leak*.txt` (e.g. `leak_test.txt`), `test*.txt`, `*_secret.txt`, `*.conf`, and `*.env*`.
- **SCA Manifest Immunity**: Legitimate package dependency manifests (e.g. `requirements.txt`, `test-requirements.txt`, `package.json`, `Cargo.toml`) are explicitly excluded from filename-based leak detection, ensuring they are evaluated strictly for CVE advisories without false-positive leak alarms.

### 8.2 Dynamic Credential Weighting & Heuristics
- **Universal Assignment Detection**: Exact quoted credential assignments (such as `password = "..."`, `api_key = "..."`, `secret = "..."`) are flagged as HIGH confidence regardless of the surrounding filename.
- **Comparison Operator Exclusions**: Source code equality checks (`==`, `!=`, `===`, `!==`) and commented code lines are filtered out to prevent false alarms during conditional authentication logic.
- **Markdown Penalty Weighting**: Documentation examples in markdown/text receive confidence penalties (-30), preventing benign README examples from blocking production pushes.

### 8.3 Transparent Terminal Reporting (`--verbose`, `-v`, `--all`)
- **Default Noise Suppression**: In standard terminal output, low-severity and advisory items are summarized by count, keeping the terminal clean and focused on blocking items (Critical, High, Medium).
- **Expanded Disclosure**: Specifying `--verbose`, `-v`, or `--all` displays a comprehensive `Advisory & Low Severity Findings` block containing full IDs, file locations, titles, and remediation advice.

### 8.4 Early Directory Pruning & Chaos Engineering Resilience
- **Root-Level Subtree Pruning**: Ignored directories (`node_modules`, `target`, `vendor`, `.git`, `.vibeguard`, `reports`) are pruned at entry point, eliminating recursive traversals and achieving >30,000 files/sec pruning rates.
- **Stress-Tested Failure Boundaries**: Verified across 5 chaos engineering domains (Manifest vs Wildcards, Math Heuristics, Walker Chaos with 5,000 files, Flag Abuse, and Git Commit Snapshot Isolation).

