use crate::rules::get_secret_rules;
use crate::types::{Category, Finding, Severity};
use regex::Regex;
use std::path::Path;

pub fn is_sensitive_filename(file_path: &str) -> (bool, &'static str) {
    let path = Path::new(file_path);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if file_name == "requirements.txt" || file_name == "test-requirements.txt" {
        return (false, "");
    }

    match file_name.as_str() {
        "password.txt" | "passwords.txt" => (true, "Password credential text file"),
        "credentials.txt" | "credential.txt" => (true, "Credential storage text file"),
        "secret.txt" | "secrets.txt" => (true, "Secret storage text file"),
        ".env" => (true, "Environment configuration file"),
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" => (true, "Private SSH key file"),
        ".htpasswd" => (true, "HTTP basic auth password file"),
        _ => {
            let code_exts = [
                "go", "rs", "js", "ts", "py", "java", "c", "cpp", "cs", "rb", "php",
            ];
            if file_name.starts_with(".env") || ext == "env" {
                (true, "Environment configuration file")
            } else if file_name.starts_with("credentials.") && !code_exts.contains(&ext.as_str()) {
                (true, "Credential storage file")
            } else if file_name.starts_with("secrets.") && !code_exts.contains(&ext.as_str()) {
                (true, "Secret storage file")
            } else if ext == "pem" || ext == "key" {
                (true, "Cryptographic key file")
            } else if ext == "conf" {
                (true, "Configuration credential file")
            } else if ext == "txt" && file_name.starts_with("leak") {
                (true, "Potential credential leak file")
            } else if ext == "txt" && file_name.starts_with("test") {
                (true, "Test credential text file")
            } else if ext == "txt"
                && (file_name.ends_with("_secret.txt") || file_name.contains("secret"))
            {
                (true, "Secret storage text file")
            } else {
                (false, "")
            }
        }
    }
}

pub fn compute_secret_confidence(
    file_path: &str,
    is_sensitive_file: bool,
    line: &str,
    key: &str,
    val: &str,
) -> Option<(i32, &'static str, Severity)> {
    let line_lower = line.to_lowercase();
    let val_clean = val.trim_matches(|c| c == '\'' || c == '"');
    let val_lower = val_clean.to_lowercase();

    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let source_exts = [
        "go", "rs", "js", "ts", "py", "java", "c", "cpp", "cs", "rb", "php",
    ];
    let is_source = source_exts.contains(&ext.as_str());

    // In source code files, hardcoded credentials are string literals ("..." or '...')
    // Non-quoted values are code expressions (variables, booleans, types, etc.)
    let is_quoted = (val.starts_with('"') && val.ends_with('"'))
        || (val.starts_with('\'') && val.ends_with('\''));
    if is_source && (!is_quoted || line.contains("==") || line.contains("!=")) {
        return None;
    }

    // Ignore boolean/type/expression tokens
    let code_tokens = [
        "true",
        "false",
        "bool",
        "string",
        "int",
        "usize",
        "none",
        "null",
        "nil",
        "undefined",
        "void",
        "any",
        "err",
        "error",
        "regex",
        "scan_secrets",
    ];
    if code_tokens.contains(&val_lower.as_str())
        || val_clean.starts_with('!')
        || val_clean.starts_with('&')
        || val_clean.contains("::")
        || val_clean.contains("=>")
        || val_clean.contains('(')
        || val_clean.contains(')')
        || val_clean.contains('{')
        || val_clean.contains('}')
        || val_clean.contains('[')
        || val_clean.contains(']')
    {
        return None;
    }

    let mut score: i32 = 0;

    // 1. Filename signal (+30)
    if is_sensitive_file {
        score += 30;
    }

    // 2. Key name signal (+25)
    let key_lower = key.to_lowercase();
    if key_lower.contains("password")
        || key_lower.contains("passwd")
        || key_lower.contains("pwd")
        || key_lower.contains("api_key")
        || key_lower.contains("apikey")
        || key_lower.contains("secret")
        || key_lower.contains("token")
    {
        score += 25;
    } else {
        score += 15;
    }

    // 3. Assignment operator (+20)
    if line.contains('=') || line.contains(':') {
        score += 20;
    }

    // 4. Placeholder checks (-25)
    let is_placeholder = val_lower == "your_password_here"
        || val_lower == "your_password"
        || val_lower == "your_api_key"
        || val_lower.contains("<password>")
        || val_lower.contains("<api_key>")
        || val_lower == "changeme"
        || val_lower == "placeholder"
        || val_lower == "example"
        || val_lower == "sample"
        || val_lower == "test"
        || val_lower == "todo"
        || val_lower == "xxx"
        || val_lower == "xxxx"
        || val_lower.starts_with('$')
        || val_lower.starts_with('%')
        || val_lower.contains("${")
        || line_lower.contains("read-host")
        || line_lower.contains("param(")
        || line_lower.contains("os.getenv")
        || line_lower.contains("os.environ")
        || line_lower.contains("process.env")
        || line_lower.contains("$env:")
        || val_clean == "..."
        || val_clean.starts_with("...")
        || val_lower == "password";

    if is_placeholder {
        score -= 25;
    } else {
        // Value characteristics (+15 non-placeholder non-empty, +10 secret-like)
        if val_clean.len() >= 3 {
            score += 15;
        }
        if val_clean.contains('@')
            || val_clean.contains('-')
            || val_clean.contains('_')
            || (val_clean.chars().any(|c| c.is_ascii_digit())
                && val_clean.chars().any(|c| c.is_alphabetic()))
        {
            score += 10;
        }
    }

    // Comments and documentation context (-20)
    let trimmed = line.trim();
    let is_comment = trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("--")
        || trimmed.starts_with(';');
    if is_comment {
        score -= 20;
    }

    if line_lower.contains("example")
        || line_lower.contains("fake")
        || line_lower.contains("intentionally")
        || line_lower.contains("syntax:")
        || line_lower.contains("format:")
    {
        score -= 20;
    }

    // Dynamic Credential Weighting:
    // When an exact assignment (password = "...", etc.) is detected in any text/config file,
    // award high confidence regardless of whether filename is strictly password.txt.
    let is_exact_credential = !is_placeholder
        && !is_comment
        && val_clean.len() >= 4
        && (is_quoted
            || is_sensitive_file
            || ext == "txt"
            || ext == "conf"
            || ext == "env"
            || ext == "ini")
        && (key_lower == "password"
            || key_lower == "passwd"
            || key_lower == "pwd"
            || key_lower == "api_key"
            || key_lower == "apikey"
            || key_lower == "secret"
            || key_lower == "token");

    if is_exact_credential {
        score += 30;
    }

    // 5. File type / context (+10 source/config, -30 doc)
    let doc_exts = ["md", "markdown", "rst", "adoc"];
    if doc_exts.contains(&ext.as_str())
        || (ext == "txt" && !is_sensitive_file && !is_exact_credential)
    {
        score -= 30;
    } else {
        score += 10;
    }

    // 7. Test fixture directory / test file (-40)
    let path_lower = file_path.to_lowercase();
    let is_target_credential_file = file_path.ends_with("password.txt")
        || is_sensitive_file
        || (is_exact_credential
            && !path_lower.contains("fixtures")
            && !path_lower.contains("mock"));

    if !is_target_credential_file
        && (path_lower.contains("test")
            || path_lower.contains("fixture")
            || path_lower.contains("mock"))
    {
        score -= 40;
    }

    // Determine confidence and severity based on calibrated score
    if score >= 80 {
        Some((score, "HIGH", Severity::HIGH))
    } else if score >= 50 {
        Some((score, "MEDIUM", Severity::MEDIUM))
    } else if score >= 20 {
        Some((score, "LOW", Severity::LOW))
    } else {
        None
    }
}

pub fn scan_secrets(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (is_sensitive, desc) = is_sensitive_filename(file_path);

    // 1. Sensitive Filename Detection
    if is_sensitive {
        *finding_counter += 1;
        findings.push(Finding {
            id: "VG-SECRET-FILE".to_string(),
            category: Category::Secret,
            severity: Severity::HIGH,
            title: "Sensitive Credential File Detected".to_string(),
            description: format!("Credential-related filename detected: {}", desc),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some(
                "Ensure this file is not committed to version control and does not contain sensitive data."
                    .to_string(),
            ),
            confidence: "HIGH".to_string(),
        });
    }

    // 2. High-entropy Provider Keys (AWS, GitHub, Slack, Private Key)
    let rules = get_secret_rules();
    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        for rule in &rules {
            if rule.id == "SEC-001"
                || rule.id == "SEC-003"
                || rule.id == "SEC-004"
                || rule.id == "SEC-005"
            {
                if let Some(caps) = rule.pattern.captures(line) {
                    *finding_counter += 1;
                    let matched = caps.get(0).map_or("", |m| m.as_str());
                    let evidence = if matched.len() > 8 {
                        format!("{}****", &matched[..8])
                    } else {
                        "****".to_string()
                    };
                    findings.push(Finding {
                        id: format!("VG-{:03}", finding_counter),
                        category: Category::Secret,
                        severity: rule.severity.clone(),
                        title: rule.name.clone(),
                        description: rule.description.clone(),
                        file: file_path.to_string(),
                        line: line_num,
                        evidence: Some(evidence),
                        recommendation: Some(rule.recommendation.clone()),
                        confidence: "HIGH".to_string(),
                    });
                }
            }
        }
    }

    // 3. Credential Assignment Detection with Context + Confidence
    let assign_re = Regex::new(
        r#"(?i)(?:^|[\s,;{(])(?P<key>[a-zA-Z0-9_-]*(?:password|passwd|pwd|api[_-]?key|apikey|secret|token)[a-zA-Z0-9_-]*)\s*[:=]\s*(?P<val>['"]?[^\s'";,]{3,}['"]?)"#,
    ).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        if let Some(caps) = assign_re.captures(line) {
            let key = caps.name("key").map_or("", |m| m.as_str());
            let val = caps.name("val").map_or("", |m| m.as_str());

            if let Some((_score, conf_str, severity)) =
                compute_secret_confidence(file_path, is_sensitive, line, key, val)
            {
                *finding_counter += 1;
                let masked_evidence = format!("{}=********", key);
                let (title, rule_id) = if key.to_lowercase().contains("password")
                    || key.to_lowercase().contains("passwd")
                    || key.to_lowercase().contains("pwd")
                {
                    ("Hardcoded Password Detected", "VG-SECRET-001")
                } else if key.to_lowercase().contains("api") {
                    ("Hardcoded API Key Detected", "VG-SECRET-002")
                } else {
                    ("Hardcoded Secret Detected", "VG-SECRET-003")
                };

                findings.push(Finding {
                    id: rule_id.to_string(),
                    category: Category::Secret,
                    severity,
                    title: title.to_string(),
                    description: format!(
                        "Hardcoded credential assignment detected for key '{}'.",
                        key
                    ),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(masked_evidence),
                    recommendation: Some(
                        "Store credentials in environment variables or a secure secrets vault."
                            .to_string(),
                    ),
                    confidence: conf_str.to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aws_key() {
        let mut counter = 0;
        let content = format!("aws_key = {}1234567890ABCDEF\n", "AKIA");
        let findings = scan_secrets("config.py", &content, &mut counter);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "AWS Access Key");
        assert!(findings[0].evidence.as_ref().unwrap().contains("****"));
    }

    #[test]
    fn test_sensitive_filename_and_password_assignment() {
        let mut counter = 0;
        let content = "password=123@admin\n";
        let findings = scan_secrets("password.txt", content, &mut counter);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "VG-SECRET-FILE");
        assert_eq!(findings[0].title, "Sensitive Credential File Detected");
        assert_eq!(findings[1].id, "VG-SECRET-001");
        assert_eq!(findings[1].title, "Hardcoded Password Detected");
        assert_eq!(findings[1].evidence.as_deref(), Some("password=********"));
        assert_eq!(findings[1].confidence, "HIGH");
    }

    #[test]
    fn test_credential_assignments_detected() {
        let mut counter = 0;
        let cases = [
            ("db_password=demo123", "Hardcoded Password Detected"),
            ("admin_password=demo123", "Hardcoded Password Detected"),
            ("api_key=demo-value", "Hardcoded API Key Detected"),
            ("secret=abc123", "Hardcoded Secret Detected"),
            ("token=abc123", "Hardcoded Secret Detected"),
        ];

        for (text, expected_title) in cases {
            let findings = scan_secrets("config.env", text, &mut counter);
            assert!(
                !findings.is_empty(),
                "expected findings for text '{}', got none",
                text
            );
            let assign_finding = findings
                .iter()
                .find(|f| f.id != "VG-SECRET-FILE")
                .expect("expected credential assignment finding");
            assert_eq!(assign_finding.title, expected_title);
            assert!(assign_finding
                .evidence
                .as_ref()
                .unwrap()
                .ends_with("=********"));
        }
    }

    #[test]
    fn test_readme_example_not_blocking() {
        let mut counter = 0;
        let content = "Example: password=123@admin\n";
        let findings = scan_secrets("README.md", content, &mut counter);
        if !findings.is_empty() {
            assert_eq!(findings[0].confidence, "LOW");
            match findings[0].severity {
                Severity::LOW | Severity::INFO => {}
                _ => panic!(
                    "Expected LOW or INFO severity for README example, got {:?}",
                    findings[0].severity
                ),
            }
        }
    }

    #[test]
    fn test_placeholder_not_blocking() {
        let mut counter = 0;
        let content = "password=YOUR_PASSWORD_HERE\n";
        let findings = scan_secrets("config.example", content, &mut counter);
        for f in findings {
            assert_ne!(f.confidence, "HIGH");
        }
    }

    #[test]
    fn test_comment_not_blocking() {
        let mut counter = 0;
        let content = "# password=example\n";
        let findings = scan_secrets("main.py", content, &mut counter);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_clean_file_no_secrets() {
        let mut counter = 0;
        let content = "This document contains no credentials.\n";
        let findings = scan_secrets("clean.txt", content, &mut counter);
        assert!(findings.is_empty());
        assert_eq!(counter, 0);
    }

    #[test]
    fn test_leak_test_file_detected() {
        let mut counter = 0;
        let content = "password = \"super_secret_leak_123\"\n";
        let findings = scan_secrets("leak_test.txt", content, &mut counter);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.id == "VG-SECRET-FILE" && f.severity == Severity::HIGH));
        assert!(findings
            .iter()
            .any(|f| f.id == "VG-SECRET-001" && f.severity == Severity::HIGH));
    }

    #[test]
    fn test_generic_sensitive_filenames() {
        assert!(is_sensitive_filename("leak_data.txt").0);
        assert!(is_sensitive_filename("test_keys.txt").0);
        assert!(is_sensitive_filename("api_secret.txt").0);
        assert!(is_sensitive_filename("app.conf").0);
        assert!(is_sensitive_filename(".env.production").0);
        assert!(!is_sensitive_filename("requirements.txt").0);
        assert!(!is_sensitive_filename("clean.txt").0);
    }
}
