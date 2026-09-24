# VibeGuard — Security Rules Specification

This document details the built-in security detection rules enforced by the VibeGuard scanner engine (Go and Rust).

---

## 1. Secret & Credential Detection Rules

| Rule ID | Name | CWE | Target Pattern / Evidence | Severity | Confidence | Gate Policy |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: |
| `VG-SECRET-FILE` | Sensitive Credential File Detected | `CWE-798` | Filename matching `password.txt`, `passwords.txt`, `credentials.txt`, `credential.txt`, `secret.txt`, `secrets.txt`, `leak*.txt`, `test*.txt`, `*_secret.txt`, `*.conf`, `*.env*` (SCA manifests exempted) | `HIGH` | `HIGH` | **BLOCKS** |
| `VG-SECRET-001` | Hardcoded Password Detected | `CWE-798` | `password=...`, `passwd=...`, `pwd=...`, `db_password=...`, `admin_password=...`, `api_key=...`, `secret=...` (Dynamic weighting for exact quoted values) | `HIGH` | Context-evaluated | **BLOCKS** (if High/Medium) |
| `VG-SEC-001` | AWS Access Key | `CWE-798` | `AKIA[0-9A-Z]{16}` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-002` | Generic API Key | `CWE-798` | `(api[_-]?key\|apikey)\s*[:=]\s*['"][^'"]{8,}` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-003` | GitHub Personal Access Token | `CWE-798` | `ghp_[a-zA-Z0-9]{36}` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-004` | Slack Token | `CWE-798` | `xox[bprs]-[a-zA-Z0-9-]+` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-005` | Private Cryptographic Key | `CWE-798` | `-----BEGIN (RSA\|DSA\|EC\|OPENSSH)? PRIVATE KEY-----` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-006` | Hardcoded Password Assignment | `CWE-798` | `(password\|passwd\|pwd)\s*[:=]\s*['"][^'"]+['"]` | `CRITICAL` | Context-evaluated | **BLOCKS** |
| `VG-SEC-007` | Hardcoded Secret / Token | `CWE-798` | `(token\|secret\|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]` | `CRITICAL` | Context-evaluated | **BLOCKS** |
| `VG-SEC-008` | Generic Credential Assignment | `CWE-798` | `(credential)\s*[:=]\s*['"][^'"]{8,}` | `CRITICAL` | Context-evaluated | **BLOCKS** |
| `VG-GIT-001` | Sensitive File Tracked in Git | `CWE-798` | `id_rsa`, `id_dsa`, `*.pem`, `*.key`, `credentials.*`, `.htpasswd` present in repository structure | `CRITICAL` | `HIGH` | **BLOCKS** |

### 1.1 Context & Confidence Scoring Model

To prevent false alarms in documentation, code comments, and test templates while guaranteeing detection of genuine secrets, VibeGuard evaluates a 10-factor mathematical confidence score (0–100):

#### Positive Factors:
- **Sensitive filename or leak wildcard** (`password.txt`, `leak*.txt`, `test*.txt`, `.env`, etc.): `+30`
- **Explicit credential key name** (`password`, `api_key`, `secret`, `token`): `+25`
- **Direct assignment operator** (`=`, `:=`, `:`): `+20`
- **Dynamic Credential Weighting** (Exact quoted assignments in any text/config file): `+15`
- **Non-placeholder value** (not empty, not `"password"`, `"admin"`, etc.): `+15`
- **High-entropy or mixed character set** (letters, numbers, special symbols like `@`, `!`, `$`): `+10`
- **Located in source code, configuration, or root directory**: `+10`

#### Penalty & Exclusion Factors:
- **Comparison operator exclusion** (`==`, `!=`, `===`, `!==`): Completely excluded from assignment rules to prevent false positives during variable equality checks.
- **Located in documentation or markdown file** (`.md`, `.rst`, `.txt` docs): `-30`
- **Matches obvious placeholder patterns** (`example`, `demo`, `changeme`, `dummy`, `placeholder`): `-25`
- **Contained in comment or example syntax** (`# password=...`, `// password=...`, `/* ... */`): `-20`
- **File path is in a test fixture or mock directory**: `-40` (real leak files in root like `leak_test.txt` exempt)

#### Confidence Buckets & Gate Action:
- **80 – 100 (`HIGH`)**: Definite secret leak. **Triggers pre-push BLOCK.**
- **50 – 79 (`MEDIUM`)**: Probable secret assignment. **Triggers pre-push BLOCK.**
- **20 – 49 (`LOW`)**: Low-confidence or documentation example. **Advisory only — Does NOT block push.**
- **< 20 (`IGNORE`)**: Benign context or clean file. Finding is dropped completely.

### 1.2 Evidence Masking
All detected credentials have their sensitive values masked in all outputs (terminal, JSON, HTML, SARIF):
- `password=123@admin` $\rightarrow$ `password=********`
- `AKIA[KEY_ID_REDACTED]` $\rightarrow$ `AKIA1234****`
- Complete secret values are **never** persisted to report files or written unmasked to stdout.

---

## 2. Static Application Security Testing (SAST) & Scope-Aware Taint Tracking

| Rule ID | Name | CWE | Description | Severity | Gate Policy |
| :--- | :--- | :---: | :--- | :---: | :---: |
| `VG-SAST-001` | Potential SQL Injection | `CWE-89` | Dynamic query construction via Python f-strings, `%` formatting, `.format()`, string concatenation, Go `fmt.Sprintf`, or template literals with untrusted data-flow tracking | `HIGH` | **BLOCKS** |
| `VG-SAST-002` | Potential OS Command Injection | `CWE-78` | Untrusted command execution via system/exec functions (`subprocess`, `os.system`, `exec.Command`, `child_process`) | `HIGH` | **BLOCKS** |
| `VG-SAST-003` | Dangerous Eval Function | `CWE-95` | Dynamic code evaluation (`eval()`, `Function()`, `exec()`) | `HIGH` | **BLOCKS** |
| `VG-SAST-004` | Potential TLS Misconfiguration | `CWE-295` | Disabled certificate verification (`InsecureSkipVerify: true`, `verify=False`, `rejectUnauthorized: false`) | `HIGH` | **BLOCKS** |
| `VG-SAST-005` | Weak Cryptography | `CWE-327` | Deprecated hashing or cipher algorithms (`MD5`, `SHA1`, `DES`, `RC4`, `Math.random()`) | `MEDIUM` | Advisory |
| `VG-SAST-006` | Potential Insecure HTTP Connection | `CWE-319` | Unencrypted plaintext HTTP URL in production code (loopback and schemas excluded) | `MEDIUM` | Advisory |
| `VG-SAST-007` | Hardcoded Credentials | `CWE-798` | Embedded passwords in source code declarations | `HIGH` | **BLOCKS** |
| `VG-SAST-008` | Shell Execution with Untrusted Input | `CWE-78` | Subprocess invocation with `shell=True` or `shell=1` enabling arbitrary shell escalation | `HIGH` | **BLOCKS** |

### 2.1 Scope-Aware Function-Level Taint Tracking (`Source → Var → Arg → Param → Local → Sink`)

VibeGuard tracks untrusted user inputs across functional boundaries:
1. **Sources**: Request parameters (`request.args.get()`, `request.form[]`, `request.get_json()`, `req.query`, `r.URL.Query()`).
2. **Variable Transformations**: Intermediate string interpolations and formatting (`cmd = f"ping {host}"`).
3. **Call-Site Parameter Propagation**: When a tainted variable is passed to a function call (`execute_command(host)`), VibeGuard resolves the target function's parameter (`target`) and tracks taint propagation within that function's scope.
4. **Data-Flow Provenance Traces**: Every finding includes step-by-step evidence:
   - `Line 6: host = request.args.get("host") [SOURCE: Untrusted user input]`
   - `Line 7: Call to 'execute_command(...)' passes tainted argument 'host' to parameter 'target'`
   - `Line 3: subprocess.run(target, shell=True) [SINK: OS command execution]`

### 2.2 Sink-Specific Sanitizer Modeling
- **Command Injection**: Sanitized via `shlex.quote(...)`, `escapeshellarg(...)`, `escapeshellcmd(...)`, or by passing command arguments as a list without invoking a shell (`subprocess.run(["ping", "-c", "1", host])`).
- **SQL Injection**: Sanitized via parameterized query bindings, prepared statements, or numeric casting (`int(var)`, `float(var)`, `strconv.Atoi`).

---

## 3. Authentication & API Security Rules

| Rule ID | Name | CWE | Description | Severity | Gate Policy |
| :--- | :--- | :---: | :--- | :---: | :---: |
| `VG-AUTH-001` | Weak Password Hashing Algorithm | `CWE-916` | Fast collision-vulnerable hashes (MD5, SHA-1) applied to user password fields instead of Argon2id/bcrypt | `HIGH` | **BLOCKS** |
| `VG-AUTH-002` | Predictable Security Token | `CWE-330` | Reversible encoding (base64, md5(email), timestamp) used as password reset or session tokens | `HIGH` | **BLOCKS** |
| `VG-AUTH-003` | Hardcoded Authentication Token | `CWE-798` | Hardcoded Bearer tokens, JWT secrets, or authorization tokens declared in source | `HIGH` | **BLOCKS** |
| `VG-WEBHOOK-001` | Missing Webhook Signature Verification | `CWE-345` | Webhook handler processes incoming payload without HMAC or signature verification header | `HIGH` | **BLOCKS** |

---

## 4. Container & Docker Security Rules

### 4.1 Dockerfile Rules
| Rule ID | Name | CWE | Description | Severity | Gate Policy |
| :--- | :--- | :---: | :--- | :---: | :---: |
| `VG-DCK-001` | Container Running as Root | `CWE-250` | Missing non-root `USER` instruction in Dockerfile | `HIGH` | **BLOCKS** |
| `VG-DCK-002` | Secret in Container Environment | `CWE-214` | Sensitive data stored in `ENV` instructions | `CRITICAL` | **BLOCKS** |
| `VG-DCK-003` | Unbounded Directory Copy | `CWE-200` | `COPY . .` used without `.dockerignore` exclusion | `MEDIUM` | Advisory |
| `VG-DCK-004` | Missing Healthcheck | — | Container lacks `HEALTHCHECK` definition | `LOW` | Advisory |
| `VG-DCK-005` | Floating Container Tag | — | Use of `:latest` tag instead of pinned digest or version | `MEDIUM` | Advisory |
| `VG-DCK-006` | Exposed Database Port | `CWE-668` | Database port (5432, 3306, 27017) explicitly exposed in Dockerfile | `HIGH` | **BLOCKS** |
| `VG-DCK-007` | Exposed Redis Port | `CWE-668` | Redis cache port (6379) explicitly exposed in Dockerfile | `HIGH` | **BLOCKS** |

### 4.2 Docker Compose Rules
| Rule ID | Name | CWE | Description | Severity | Gate Policy |
| :--- | :--- | :---: | :--- | :---: | :---: |
| `VG-DCK-006` | Exposed Database Port | `CWE-668` | Database port (5432, 3306, 27017) bound directly to host interface | `HIGH` | **BLOCKS** |
| `VG-DCK-007` | Exposed Redis Port | `CWE-668` | Redis cache port (6379) bound directly to host interface | `HIGH` | **BLOCKS** |
| `VG-DCK-008` | Root User in Compose | `CWE-250` | Service explicitly configured with `user: root` | `HIGH` | **BLOCKS** |
| `VG-DCK-009` | Host Filesystem Mount | `CWE-552` | Service mounts local host directory into container (`.:/app`) | `MEDIUM` | Advisory |
| `VG-DCK-010` | Weak Container Password | `CWE-259` | Default or weak passwords configured in environment variables | `HIGH` | **BLOCKS** |
| `VG-DCK-011` | Privileged Container Execution | `CWE-250` | Container configured with `privileged: true` | `HIGH` | **BLOCKS** |
| `VG-DCK-012` | Dangerous Docker Capability | `CWE-250` | Container granted dangerous Linux capabilities (`SYS_ADMIN`, `ALL`) | `HIGH` | **BLOCKS** |
| `VG-DCK-013` | Sensitive Host Path Mounted | `CWE-250` | Sensitive host paths (e.g. `/var/run/docker.sock`, `/root`) mounted | `CRITICAL` | **BLOCKS** |
| `VG-DCK-015` | Container Host Networking Enabled | `CWE-668` | Container configured with `network_mode: host` bypassing network isolation | `HIGH` | **BLOCKS** |
| `VG-DCK-016` | Container Host PID/IPC Namespace Shared | `CWE-668` | Container configured with `pid: host` or `ipc: host` breaking process isolation | `HIGH` | **BLOCKS** |

### 4.3 Cross-File Build Correlation Rules
| Rule ID | Name | CWE | Description | Severity | Gate Policy |
| :--- | :--- | :---: | :--- | :---: | :---: |
| `VG-DCK-014` | Secret File Included in Docker Build | `CWE-200` | Workspace contains `.env` or credential files alongside `COPY . .` in Dockerfile without `.dockerignore` exclusion | `HIGH` | **BLOCKS** |

---

## 5. Configuration Security Rules

| Rule ID | Name | CWE | Description | Severity | Gate Policy |
| :--- | :--- | :---: | :--- | :---: | :---: |
| `VG-CFG-001` | Debug Mode Enabled | `CWE-489` | Debugging flags active in production configuration | `MEDIUM` | Advisory |
| `VG-CFG-002` | Permissive CORS Policy | `CWE-942` | Wildcard `Access-Control-Allow-Origin: *` configured | `MEDIUM` | Advisory |
| `VG-CFG-003` | Insecure Interface Binding | `CWE-668` | Server bound to all network interfaces (`0.0.0.0`) | `LOW` | Advisory |
| `VG-CFG-004` | Missing .env in .gitignore | `CWE-200` | Sensitive `.env` file present in repository but missing from `.gitignore` | `HIGH` | **BLOCKS** |
| `VG-CFG-005` | Plain HTTP Endpoint | `CWE-319` | Configuration specifies unencrypted plaintext HTTP endpoint | `MEDIUM` | Advisory |

---

## 6. Configuration Exclusions & Transparency Policy

### 6.1 Default Exclusions & Rationale

VibeGuard applies explicit default exclusions defined in `.vibeguard/config.json`:

| Excluded Pattern | Category | Justification |
| :--- | :--- | :--- |
| `.git` | Version Control Metadata | Internal Git objects and commit index; not deployable code. |
| `.vibeguard` | Tool Configuration & Cache | Local tool metadata, OSV database cache, and policy configurations. |
| `reports` | Generated Artifacts | Output destination for JSON/HTML/SARIF scan reports to avoid recursive re-scanning. |
| `tests` | Test Suites & Fixtures | Contains intentionally vulnerable fixtures and mock attack payloads for scanner verification. |
| `docs` / `*.md` | Project Documentation | Setup guides and instructions containing syntax examples (e.g. sample API keys or passwords). |
| `rules` | Static Rule Definitions | Regex pattern definitions for detection engines. |

### 6.2 Exclusion Transparency & CLI Overrides

To prevent real vulnerabilities from being unintentionally hidden by broad exclusions:

1. **Exclusion Metric in Reports**: Every scan report explicitly records `Files Excluded: <N>` so developers know when files are bypassed.
2. **`--include-tests`**: Temporarily removes test directory exclusions, allowing security audits of test suites.
3. **`--include-docs`**: Temporarily removes markdown/doc file exclusions to audit documentation for leaked production credentials.
4. **`--show-excluded`**: Displays detailed counts and alerts regarding excluded paths in the terminal scan report.

