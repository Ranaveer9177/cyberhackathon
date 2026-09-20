# VibeGuard — Security Rules Specification

This document details the built-in security detection rules enforced by the VibeGuard scanner engine (Go and Rust).

---

## 1. Secret & Credential Detection Rules

| Rule ID | Name | Target Pattern / Evidence | Severity | Confidence | Gate Policy |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `VG-SECRET-FILE` | Sensitive Credential File Detected | Filename matching `password.txt`, `passwords.txt`, `credentials.txt`, `credential.txt`, `secret.txt`, `secrets.txt` | `HIGH` | `HIGH` | **BLOCKS** |
| `VG-SECRET-001` | Hardcoded Password Detected | `password=...`, `passwd=...`, `pwd=...`, `db_password=...`, `admin_password=...`, `api_key=...`, `secret=...` | `HIGH` | Context-evaluated | **BLOCKS** (if High/Medium) |
| `VG-SEC-001` | AWS Access Key | `AKIA[0-9A-Z]{16}` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-002` | GitHub Personal Access Token | `ghp_[a-zA-Z0-9]{36}` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-003` | Slack Token | `xox[bprs]-[a-zA-Z0-9-]+` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-004` | Private Cryptographic Key | `-----BEGIN (RSA\|DSA\|EC\|OPENSSH)? PRIVATE KEY-----` | `CRITICAL` | `HIGH` | **BLOCKS** |
| `VG-SEC-005` | Hardcoded Password Assignment | `(password\|passwd\|pwd)\s*[:=]\s*['"][^'"]+['"]` | `CRITICAL` | Context-evaluated | **BLOCKS** |
| `VG-SEC-006` | Hardcoded Secret / Token | `(token\|secret\|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]` | `CRITICAL` | Context-evaluated | **BLOCKS** |
| `VG-SEC-007` | Generic Credential Assignment | `(api[_-]?key\|apikey\|credential)\s*[:=]\s*['"][^'"]{8,}` | `CRITICAL` | Context-evaluated | **BLOCKS** |
| `VG-SEC-008` | Sensitive File in Repository | `.env`, `*.pem`, `*.key`, `id_rsa`, `id_dsa` | `CRITICAL` | `HIGH` | **BLOCKS** |

### 1.1 Context & Confidence Scoring Model (v4.4)

To prevent false alarms in documentation, code comments, and test templates while guaranteeing detection of genuine secrets, VibeGuard evaluates a 10-factor mathematical confidence score (0–100):

#### Positive Factors:
- **Sensitive filename** (`password.txt`, `.env`, etc.): `+30`
- **Explicit credential key name** (`password`, `api_key`, `secret`, `token`): `+25`
- **Direct assignment operator** (`=`, `:=`, `:`): `+20`
- **Non-placeholder value** (not empty, not `"password"`, `"admin"`, etc.): `+15`
- **High-entropy or mixed character set** (letters, numbers, special symbols like `@`, `!`, `$`): `+10`
- **Located in source code, configuration, or root directory**: `+10`

#### Penalty Factors:
- **Located in documentation or markdown file** (`.md`, `.rst`, `.txt` docs): `-30`
- **Matches obvious placeholder patterns** (`example`, `demo`, `changeme`, `dummy`, `placeholder`): `-25`
- **Contained in comment or example syntax** (`# password=...`, `// password=...`): `-20`
- **File path is in a test fixture or mock directory**: `-40`

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

## 2. Static Application Security Testing (SAST) Rules

| Rule ID | Name | Description | Severity | Gate Policy |
| :--- | :--- | :--- | :---: | :---: |
| `VG-SAST-001` | Potential SQL Injection | Dynamic query concatenation without parameterized placeholders | `HIGH` | **BLOCKS** |
| `VG-SAST-002` | Potential OS Command Injection | Untrusted shell execution via system/exec functions | `HIGH` | **BLOCKS** |
| `VG-SAST-003` | Dangerous Eval Function | Dynamic code evaluation (`eval()`, `Function()`, `exec()`) | `HIGH` | **BLOCKS** |
| `VG-SAST-004` | Potential TLS Misconfiguration | Disabled certificate verification (`InsecureSkipVerify: true`) | `HIGH` | **BLOCKS** |
| `VG-SAST-005` | Weak Cryptography | Deprecated hashing or cipher algorithms (`MD5`, `SHA1`, `DES`, `RC4`) | `MEDIUM` | Advisory |
| `VG-SAST-006` | Potential Insecure HTTP Connection | Unencrypted plaintext HTTP URL in production code (loopback excluded) | `MEDIUM` | Advisory |
| `VG-SAST-007` | Hardcoded Credentials | Embedded passwords in source code declarations | `HIGH` | **BLOCKS** |

---

## 3. Container & Dockerfile Security Rules

| Rule ID | Name | Description | Severity | Gate Policy |
| :--- | :--- | :--- | :---: | :---: |
| `VG-DCK-001` | Container Running as Root | Missing non-root `USER` instruction | `HIGH` | **BLOCKS** |
| `VG-DCK-002` | Secret in Container Environment | Sensitive data stored in `ENV` instructions | `CRITICAL` | **BLOCKS** |
| `VG-DCK-003` | Unbounded Directory Copy | `COPY . .` used without `.dockerignore` exclusion | `MEDIUM` | Advisory |
| `VG-DCK-004` | Missing Healthcheck | Container lacks `HEALTHCHECK` definition | `LOW` | Advisory |
| `VG-DCK-005` | Floating Container Tag | Use of `:latest` tag instead of pinned digest or version | `MEDIUM` | Advisory |

---

## 4. Configuration Security Rules

| Rule ID | Name | Description | Severity | Gate Policy |
| :--- | :--- | :--- | :---: | :---: |
| `VG-CFG-001` | Debug Mode Enabled | Debugging flags active in production configuration | `MEDIUM` | Advisory |
| `VG-CFG-002` | Permissive CORS Policy | Wildcard `Access-Control-Allow-Origin: *` configured | `MEDIUM` | Advisory |
| `VG-CFG-003` | Insecure Interface Binding | Server bound to all network interfaces (`0.0.0.0`) | `LOW` | Advisory |
