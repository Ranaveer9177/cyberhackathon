# VibeGuard — Feature Specifications

> **Complete Feature Reference for VibeGuard v3.0**

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

### 2.1 Secret & Credential Detection
- High-entropy pattern recognition for:
  - AWS Access Keys (`AKIA[0-9A-Z]{16}`)
  - GitHub Personal Access Tokens (`ghp_[a-zA-Z0-9]{36}`)
  - Slack Tokens (`xox[bprs]-[a-zA-Z0-9-]+`)
  - Private Cryptographic Keys (`-----BEGIN RSA/OPENSSH PRIVATE KEY-----`)
  - Hardcoded Password & Token assignments
  - Sensitive files (`.env`, `id_rsa`, `*.pem`, `*.key`, `credentials.*`, `secrets.*`)
- **Evidence Masking**: Truncates secrets in all outputs (first 8 characters preserved, remainder replaced with `****`).

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

---

## 3. Configuration & Exclusion Management (`.vibeguard/config.json`)

- **Configurable Exclusions (`exclude`)**: Universal filtering skipping docs, test directories, and local reports across both Go and Rust engines.
- **Customizable Gate Policy (`block_on`)**: Define blocking severities (`["critical", "high"]`).
- **Fail-Closed Enforcement (`fail_closed`)**: Aborts push if scanner or vulnerability intelligence is unavailable.
- **Scan Modes (`scan_mode`)**: `"full"` for complete audits, `"changed"` for diff analysis.

---

## 4. Reporting & Scoring

- **Deterministic Scoring**:
  $$\text{Score} = \max\left(0, 100 - (15 \times C + 8 \times H + 3 \times M + 1 \times L)\right)$$
- **Terminal Report**: High-contrast ANSI colors, summary metrics, and finding evidence.
- **JSON Report**: Saved to `reports/scan.json` for CI/CD automation.
- **HTML Report**: Responsive, standalone interactive dashboard saved to `reports/scan.html`.
