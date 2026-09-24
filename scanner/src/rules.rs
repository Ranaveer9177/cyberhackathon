use crate::types::{Category, Severity};
use regex::Regex;

#[allow(dead_code)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub severity: Severity,
    pub pattern: Regex,
    pub description: String,
    pub recommendation: String,
}

pub fn get_sast_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "VG-SAST-001".to_string(),
            name: "Potential SQL Injection".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            // Matches Python f-strings, concatenation, % and .format in queries, Go Sprintf, JS template literals
            pattern: Regex::new(
                r#"(?i)(f["'].*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|UNION\s+(?:ALL\s+)?SELECT)\b.*\{|["'].*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*["']\s*\+|query.*\+.*request|execute\(["'].*%\s*|execute\(["'].*\{\}.*\.format|execute\(f["']|\bfmt\.Sprintf\(["'].*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|`.*\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b.*\$\{)"#,
            ).unwrap(),
            description: "Potential SQL injection vulnerability detected via dynamic query construction.".to_string(),
            recommendation: "Use parameterized queries, prepared statements, or ORM parameter binding.".to_string(),
        },
        Rule {
            id: "VG-SAST-002".to_string(),
            name: "Potential OS Command Injection".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            // Matches Python subprocess, os.system, os.popen, Go exec.Command, JS child_process, Java Runtime
            pattern: Regex::new(
                r#"(?i)(exec\.Command\(|os\.system\(|os\.popen\(|subprocess\.(call|check_output|run|Popen)\(|child_process\.(exec|spawn)\(|Runtime\.getRuntime\(\)\.exec\()"#,
            ).unwrap(),
            description: "Potential OS command injection vulnerability detected.".to_string(),
            recommendation: "Avoid executing OS commands with untrusted input. Use safe parameter lists without a shell.".to_string(),
        },
        Rule {
            id: "VG-SAST-003".to_string(),
            name: "Dangerous Eval".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)\b(eval\(|Function\(|exec\()"#).unwrap(),
            description: "Use of dangerous dynamic code evaluation functions detected.".to_string(),
            recommendation: "Avoid using eval or dynamic code execution on untrusted input.".to_string(),
        },
        Rule {
            id: "VG-SAST-004".to_string(),
            name: "Potential TLS Misconfiguration".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)(InsecureSkipVerify.*true|verify.*False|rejectUnauthorized.*false|NODE_TLS_REJECT_UNAUTHORIZED)"#).unwrap(),
            description: "TLS certificate verification seems to be disabled.".to_string(),
            recommendation: "Enable strict TLS certificate verification in production environments.".to_string(),
        },
        Rule {
            id: "VG-SAST-005".to_string(),
            name: "Weak Crypto".to_string(),
            category: Category::SourceCode,
            severity: Severity::MEDIUM,
            pattern: Regex::new(r#"(?i)\b(md5|sha1|DES|RC4)\b|Math\.random\(\)"#).unwrap(),
            description: "Weak cryptographic algorithm or non-cryptographic PRNG detected.".to_string(),
            recommendation: "Use modern algorithms (e.g., SHA-256, AES-GCM) and cryptographically secure PRNGs.".to_string(),
        },
        Rule {
            id: "VG-SAST-006".to_string(),
            name: "Potential Insecure HTTP Connection".to_string(),
            category: Category::SourceCode,
            severity: Severity::MEDIUM,
            pattern: Regex::new(r#"http://[^\s"'>]+"#).unwrap(),
            description: "Insecure plaintext HTTP connection detected.".to_string(),
            recommendation: "Use HTTPS for all network communication.".to_string(),
        },
        Rule {
            id: "VG-SAST-007".to_string(),
            name: "Hardcoded Credentials".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)password\s*=\s*"[^"]+""#).unwrap(),
            description: "Hardcoded credentials discovered in source code.".to_string(),
            recommendation: "Use environment variables or a secret management service.".to_string(),
        },
        Rule {
            id: "VG-SAST-008".to_string(),
            name: "Shell Execution With Potentially Untrusted Input".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(r#"(?i)\b(shell\s*=\s*True|shell\s*=\s*1)\b"#).unwrap(),
            description: "Subprocess invocation with shell=True detected. If untrusted input reaches this command, it enables arbitrary shell execution.".to_string(),
            recommendation: "Set shell=False and pass command arguments as an array/list of strings.".to_string(),
        },
        Rule {
            id: "VG-AUTH-001".to_string(),
            name: "Weak Password Hashing Algorithm".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(
                r#"(?i)(hashlib\.(md5|sha1)\(.*(password|passwd|pwd)|(md5|sha1)\(.*(password|passwd|pwd))"#,
            ).unwrap(),
            description: "MD5 or SHA-1 is being used to hash passwords. These algorithms are vulnerable to high-speed collision and dictionary attacks.".to_string(),
            recommendation: "Use modern password hashing algorithms such as Argon2id, bcrypt, scrypt, or PBKDF2.".to_string(),
        },
        Rule {
            id: "VG-AUTH-002".to_string(),
            name: "Predictable Security Token".to_string(),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            pattern: Regex::new(
                r#"(?i)(base64\.(b64encode|urlsafe_b64encode)\(.*(email|user_id|username|user\.)|(email|username)\.encode\(\).*(base64|b64encode)|(token|reset_token)\s*=\s*.*(username|email).*\+.*(timestamp|time))"#,
            ).unwrap(),
            description: "Predictable or reversible encoding (such as base64 over email/user data) used as an authentication or reset token. Encoding does not provide cryptographic randomness.".to_string(),
            recommendation: "Generate password reset and session tokens using cryptographically secure random generators (e.g., secrets.token_urlsafe).".to_string(),
        },
        Rule {
            id: "VG-AUTH-003".to_string(),
            name: "Hardcoded Authentication Token".to_string(),
            category: Category::Secret,
            severity: Severity::HIGH,
            pattern: Regex::new(
                r#"(?i)(Authorization:\s*Bearer\s+[A-Za-z0-9._~+/-]{10,}|(ADMIN_TOKEN|BEARER_TOKEN|SESSION_TOKEN)\s*=\s*['"](?:Bearer\s+)?[A-Za-z0-9._~+/-]{12,}['"]|JWT_SECRET\s*[:=]\s*['"][^'"]{8,}['"])"#,
            ).unwrap(),
            description: "Hardcoded Bearer authentication token or JWT secret detected in code.".to_string(),
            recommendation: "Retrieve bearer tokens and JWT secrets at runtime from environment variables or a vault.".to_string(),
        },
    ]
}

pub fn get_secret_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "VG-SEC-001".to_string(),
            name: "AWS Access Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
            description: "AWS Access Key ID detected.".to_string(),
            recommendation: "Revoke the key immediately and use IAM roles instead.".to_string(),
        },
        Rule {
            id: "VG-SEC-002".to_string(),
            name: "Generic API Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}"#).unwrap(),
            description: "Generic API Key detected.".to_string(),
            recommendation: "Remove the key from code and use a secret manager.".to_string(),
        },
        Rule {
            id: "VG-SEC-003".to_string(),
            name: "GitHub Token".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"ghp_[a-zA-Z0-9]{36}"#).unwrap(),
            description: "GitHub Personal Access Token detected.".to_string(),
            recommendation: "Revoke the token and generate a new one if needed.".to_string(),
        },
        Rule {
            id: "VG-SEC-004".to_string(),
            name: "Slack Token".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"xox[bprs]-[a-zA-Z0-9-]+"#).unwrap(),
            description: "Slack Token detected.".to_string(),
            recommendation: "Revoke and rotate the Slack token.".to_string(),
        },
        Rule {
            id: "VG-SEC-005".to_string(),
            name: "Private Key".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----"#)
                .unwrap(),
            description: "Private cryptographic key detected.".to_string(),
            recommendation: "Remove private keys from the repository.".to_string(),
        },
        Rule {
            id: "VG-SEC-006".to_string(),
            name: "Password Assignment".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]"#).unwrap(),
            description: "Hardcoded password assignment detected.".to_string(),
            recommendation: "Use environment variables for passwords.".to_string(),
        },
        Rule {
            id: "VG-SEC-007".to_string(),
            name: "Token/Secret Assignment".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(token|secret|jwt_secret)\s*[:=]\s*['"][^'"]{8,}['"]"#)
                .unwrap(),
            description: "Hardcoded token or secret assignment detected.".to_string(),
            recommendation: "Move secrets to secure storage or environment variables.".to_string(),
        },
        Rule {
            id: "VG-SEC-008".to_string(),
            name: "Generic Credential".to_string(),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            pattern: Regex::new(r#"(?i)(secret|credential)\s*[:=]\s*['"][^'"]{8,}['"]"#).unwrap(),
            description: "Generic secret or credential detected.".to_string(),
            recommendation: "Securely manage all credentials outside of source control."
                .to_string(),
        },
    ]
}

pub fn rule_cwe(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "VG-SAST-001" => Some("CWE-89"),
        "VG-SAST-002" | "VG-SAST-008" => Some("CWE-78"),
        "VG-SAST-003" => Some("CWE-95"),
        "VG-SAST-004" => Some("CWE-295"),
        "VG-SAST-005" => Some("CWE-327"),
        "VG-SAST-006" => Some("CWE-319"),
        "VG-SAST-007" | "VG-AUTH-003" | "VG-SEC-001" | "VG-SEC-002" | "VG-SEC-003"
        | "VG-SEC-004" | "VG-SEC-005" | "VG-SEC-006" | "VG-SEC-007" | "VG-SEC-008"
        | "VG-SECRET-001" | "VG-SECRET-002" | "VG-SECRET-003" | "VG-GIT-001" => Some("CWE-798"),
        "VG-AUTH-001" => Some("CWE-916"),
        "VG-AUTH-002" => Some("CWE-330"),
        "VG-WEBHOOK-001" | "VG-DCK-005" => Some("CWE-345"),
        "VG-DCK-001" | "VG-DCK-004" | "VG-DCK-008" | "VG-DCK-011" | "VG-DCK-012" | "VG-DCK-013"
        | "VG-DCK-015" => Some("CWE-250"),
        "VG-DCK-002" => Some("CWE-214"),
        "VG-DCK-006" | "VG-DCK-007" | "VG-DCK-016" => Some("CWE-668"),
        "VG-DCK-009" => Some("CWE-552"),
        "VG-DCK-010" => Some("CWE-259"),
        "VG-DCK-003" | "VG-DCK-014" | "VG-CFG-004" | "VG-SECRET-FILE" => Some("CWE-200"),
        "VG-CFG-001" => Some("CWE-489"),
        "VG-CFG-002" => Some("CWE-942"),
        "VG-CFG-003" => Some("CWE-668"),
        "VG-CFG-005" => Some("CWE-319"),
        _ => None,
    }
}
