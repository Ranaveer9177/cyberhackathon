# VibeGuard ? Security Rules Specification

This directory documents the built-in security detection rules enforced by the VibeGuard scanner engine.

## 1. Secret & Credential Detection Rules

| Rule ID | Name | Target Pattern / Evidence | Severity |
| :--- | :--- | :--- | :---: |
| `VG-SEC-001` | AWS Access Key | `AKIA[0-9A-Z]{16}` | `CRITICAL` |
| `VG-SEC-002` | GitHub Personal Access Token | `ghp_[a-zA-Z0-9]{36}` | `CRITICAL` |
| `VG-SEC-003` | Slack Token | `xox[bprs]-[a-zA-Z0-9-]+` | `CRITICAL` |
| `VG-SEC-004` | Private Cryptographic Key | `-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----` | `CRITICAL` |
| `VG-SEC-005` | Hardcoded Password Assignment | `(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]` | `CRITICAL` |
| `VG-SEC-006` | Hardcoded Secret / Token | `(token|secret|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]` | `CRITICAL` |
| `VG-SEC-007` | Generic Credential Assignment | `(api[_-]?key|apikey|credential)\s*[:=]\s*['"][^'"]{8,}` | `CRITICAL` |
| `VG-SEC-008` | Sensitive File in Repository | `.env`, `*.pem`, `*.key`, `id_rsa`, `id_dsa`, `credentials.*` | `CRITICAL` |

All detected credentials have their secrets automatically masked (`sk-demo-****`) in output reports.

---

## 2. Static Application Security Testing (SAST) Rules

| Rule ID | Name | Description | Severity |
| :--- | :--- | :--- | :---: |
| `VG-SAST-001` | Potential SQL Injection | Dynamic query concatenation without parameterized placeholders | `HIGH` |
| `VG-SAST-002` | Potential OS Command Injection | Untrusted shell execution via system/exec functions | `HIGH` |
| `VG-SAST-003` | Dangerous Eval Function | Dynamic code evaluation (`eval()`, `Function()`, `exec()`) | `HIGH` |
| `VG-SAST-004` | Potential TLS Misconfiguration | Disabled certificate verification (`InsecureSkipVerify: true`) | `HIGH` |
| `VG-SAST-005` | Weak Cryptography | Use of deprecated algorithms (`MD5`, `SHA1`, `DES`, `RC4`) | `MEDIUM` |
| `VG-SAST-006` | Potential Insecure HTTP Connection | Unencrypted plaintext HTTP URL in production code | `MEDIUM` |
| `VG-SAST-007` | Hardcoded Credentials | Embedded passwords in source code declarations | `HIGH` |

---

## 3. Container & Dockerfile Security Rules

| Rule ID | Name | Description | Severity |
| :--- | :--- | :--- | :---: |
| `VG-DCK-001` | Container Running as Root | Missing non-root `USER` instruction | `HIGH` |
| `VG-DCK-002` | Secret in Container Environment | Sensitive data stored in `ENV` instructions | `CRITICAL` |
| `VG-DCK-003` | Unbounded Directory Copy | `COPY . .` used without `.dockerignore` exclusion | `MEDIUM` |
| `VG-DCK-004` | Missing Healthcheck | Container lacks `HEALTHCHECK` definition | `LOW` |
| `VG-DCK-005` | Floating Container Tag | Use of `:latest` tag instead of pinned digest or version | `MEDIUM` |

---

## 4. Configuration Security Rules

| Rule ID | Name | Description | Severity |
| :--- | :--- | :--- | :---: |
| `VG-CFG-001` | Debug Mode Enabled | Debugging flags active in production configuration | `MEDIUM` |
| `VG-CFG-002` | Permissive CORS Policy | Wildcard `Access-Control-Allow-Origin: *` configured | `MEDIUM` |
| `VG-CFG-003` | Insecure Interface Binding | Server bound to all network interfaces (`0.0.0.0`) | `LOW` |
