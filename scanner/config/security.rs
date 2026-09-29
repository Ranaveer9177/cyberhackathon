#![allow(dead_code)]

use crate::config::types::ConfigModel;
use crate::rules::rule_cwe;
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn analyze_config_security(model: &ConfigModel, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    let secret_key_re = Regex::new(
        r#"(?i)(api[_-]?key|secret|password|passwd|pwd|jwt|token|private[_-]?key|auth)"#,
    )
    .unwrap();
    let aws_key_re = Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap();
    let jwt_re = Regex::new(r#"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#).unwrap();
    let db_conn_pass_re = Regex::new(r#"(?i)[a-z0-9_-]+://[^:]*:([^@]+)@"#).unwrap();

    for entry in &model.entries {
        let key_lower = entry.key.to_lowercase();
        let val_lower = entry.value.to_lowercase();

        // 1. Debug Mode Enabled (VG-CFG-001)
        if (key_lower.contains("debug")
            && (val_lower == "true" || val_lower == "1" || val_lower == "yes" || val_lower == "on"))
            || (key_lower.contains("env")
                && (val_lower == "development" || val_lower == "dev")
                && entry.raw_line.to_lowercase().contains("debug"))
        {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-001".to_string(),
                rule_id: Some("VG-CFG-001".to_string()),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Debug Mode Enabled".to_string(),
                description: format!(
                    "Debug mode is enabled in configuration via '{}={}'. Debug endpoints may leak stack traces, environment variables, or administrative tools.",
                    entry.key, entry.value
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Disable debug mode in production environments (set to false or 0).".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-001").map(String::from),
                ..Default::default()
            });
        }

        // 2. Wildcard CORS Allowed (VG-CFG-002)
        if (key_lower.contains("cors")
            || key_lower.contains("allow_origin")
            || key_lower.contains("allowed_origin"))
            && (entry.value.trim() == "*"
                || entry.value.contains("'*'")
                || entry.value.contains("\"*\"")
                || entry.value.contains("[*]"))
        {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-002".to_string(),
                rule_id: Some("VG-CFG-002".to_string()),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Wildcard CORS Allowed".to_string(),
                description: format!(
                    "CORS configuration '{}' allows wildcard origin (*), potentially permitting arbitrary external websites to read sensitive API responses.",
                    entry.key
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Restrict CORS Access-Control-Allow-Origin to trusted domains instead of '*'.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-002").map(String::from),
                ..Default::default()
            });
        }

        // 3. Binding to 0.0.0.0 (VG-CFG-003)
        if (key_lower.contains("host")
            || key_lower.contains("bind")
            || key_lower.contains("address")
            || key_lower.contains("listen"))
            && (entry.value.contains("0.0.0.0") || entry.value.contains("::"))
        {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-003".to_string(),
                rule_id: Some("VG-CFG-003".to_string()),
                category: Category::Configuration,
                severity: Severity::LOW,
                title: "Binding to 0.0.0.0".to_string(),
                description: format!(
                    "Service binding '{}' binds to all network interfaces (0.0.0.0), exposing it beyond localhost.",
                    entry.key
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Ensure binding to 0.0.0.0 is intentional and protected by external network firewalls, or bind to 127.0.0.1 for local services.".to_string()),
                confidence: "MEDIUM".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-003").map(String::from),
                ..Default::default()
            });
        }

        // 4. Plain HTTP Endpoints (VG-CFG-005)
        if (key_lower.contains("url")
            || key_lower.contains("endpoint")
            || key_lower.contains("api_base")
            || key_lower.contains("host"))
            && (val_lower.starts_with("http://")
                && !val_lower.contains("localhost")
                && !val_lower.contains("127.0.0.1"))
        {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-005".to_string(),
                rule_id: Some("VG-CFG-005".to_string()),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Plain HTTP Endpoint".to_string(),
                description: format!(
                    "Configuration key '{}' specifies an unencrypted HTTP URL ('{}'), exposing transmission to eavesdropping or man-in-the-middle attacks.",
                    entry.key, entry.value
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Use HTTPS for all remote communication endpoints.".to_string()),
                confidence: "MEDIUM".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-005").map(String::from),
                ..Default::default()
            });
        }

        // 5. Weak Security Configuration (VG-CFG-006)
        if (key_lower.contains("cookie_secure") && val_lower == "false")
            || (key_lower.contains("session_cookie_secure") && val_lower == "false")
            || (key_lower.contains("cookie_httponly") && val_lower == "false")
            || (key_lower.contains("csrf_enabled") && (val_lower == "false" || val_lower == "0"))
            || (key_lower.contains("csrf_protection") && (val_lower == "false" || val_lower == "0"))
            || (key_lower.contains("disable_csrf") && (val_lower == "true" || val_lower == "1"))
            || (key_lower.contains("wtf_csrf_enabled")
                && (val_lower == "false" || val_lower == "0"))
            || (key_lower.contains("strict_transport_security") && val_lower == "false")
            || (key_lower.contains("samesite") && val_lower == "none")
        {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-006".to_string(),
                rule_id: Some("VG-CFG-006".to_string()),
                category: Category::Configuration,
                severity: Severity::HIGH,
                title: "Weak Security Configuration".to_string(),
                description: format!(
                    "Critical web protection '{}' is explicitly disabled ('{}'), weakening cookie or CSRF defense mechanisms.",
                    entry.key, entry.value
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Enable Secure cookies, HttpOnly attributes, and CSRF protection in application configuration.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-006").map(String::from),
                ..Default::default()
            });
        }

        // 6. TLS Disabled in Configuration (VG-CFG-007)
        let is_disabled_bool = val_lower == "false" || val_lower == "0" || val_lower == "no";
        let is_tls_key = key_lower.contains("ssl_verify")
            || key_lower.contains("tls_verify")
            || key_lower.contains("verify_ssl");
        let is_insecure_flag =
            key_lower.contains("insecure_skip") && (val_lower == "true" || val_lower == "1");
        let is_reject_flag = key_lower.contains("reject_unauthorized") && is_disabled_bool;

        if (is_tls_key && is_disabled_bool) || is_insecure_flag || is_reject_flag {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-007".to_string(),
                rule_id: Some("VG-CFG-007".to_string()),
                category: Category::Configuration,
                severity: Severity::HIGH,
                title: "TLS Verification Disabled in Configuration".to_string(),
                description: format!(
                    "TLS certificate verification is disabled via '{}={}', leaving outbound requests vulnerable to TLS spoofing and interception.",
                    entry.key, entry.value
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Always enable TLS certificate validation in production configurations.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-007").map(String::from),
                ..Default::default()
            });
        }

        // 7. Hardcoded Secrets in Config (VG-CFG-008)
        let is_secret_name = secret_key_re.is_match(&key_lower);
        let has_aws_key = aws_key_re.is_match(&entry.value);
        let has_jwt = jwt_re.is_match(&entry.value);
        let has_db_pass = if let Some(caps) = db_conn_pass_re.captures(&entry.value) {
            let pass = caps.get(1).map_or("", |m| m.as_str());
            !pass.is_empty() && pass != "password" && pass != "root" && pass != "admin"
        } else {
            false
        };

        if has_aws_key
            || has_jwt
            || has_db_pass
            || (is_secret_name
                && entry.value.len() >= 16
                && !val_lower.contains("dummy")
                && !val_lower.contains("placeholder")
                && !val_lower.contains("example"))
        {
            *finding_counter += 1;
            let masked = if entry.value.len() > 8 {
                format!("{}****", &entry.value[..8])
            } else {
                "****".to_string()
            };
            findings.push(Finding {
                id: "VG-CFG-008".to_string(),
                rule_id: Some("VG-CFG-008".to_string()),
                category: Category::Configuration,
                severity: Severity::CRITICAL,
                title: "Hardcoded Secret in Configuration File".to_string(),
                description: format!(
                    "High-entropy secret or credential value found for configuration key '{}'.",
                    entry.key
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(format!("{}={}", entry.key, masked)),
                recommendation: Some("Store secrets in a dedicated secrets manager or runtime environment variables rather than committing them in configuration files.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-008").map(String::from),
                ..Default::default()
            });
        }

        // 8. Unsafe Defaults (VG-CFG-009)
        let default_passwords = [
            "admin",
            "password",
            "password123",
            "root",
            "postgres",
            "changeme",
            "secret",
            "123456",
            "default",
        ];
        if is_secret_name && default_passwords.contains(&val_lower.as_str()) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-009".to_string(),
                rule_id: Some("VG-CFG-009".to_string()),
                category: Category::Configuration,
                severity: Severity::HIGH,
                title: "Insecure Default Password in Configuration".to_string(),
                description: format!(
                    "Configuration key '{}' uses a known insecure default credential value ('{}').",
                    entry.key, entry.value
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Change default passwords to strong, uniquely generated secrets before deployment.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-009").map(String::from),
                ..Default::default()
            });
        }

        // 9. JWT Verification Disabled / None Algorithm in Config (VG-CFG-010)
        let is_jwt_key = key_lower.contains("jwt") || key_lower.contains("token");
        let is_none_alg = key_lower.contains("algorithm") && val_lower == "none";
        let is_unverified = (key_lower.contains("verify_signature")
            && (val_lower == "false" || val_lower == "0"))
            || (key_lower.contains("allow_unverified")
                && (val_lower == "true" || val_lower == "1"))
            || (key_lower.contains("allow_none") && (val_lower == "true" || val_lower == "1"));

        if (is_jwt_key && (is_none_alg || is_unverified)) || is_none_alg {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-010".to_string(),
                rule_id: Some("VG-CFG-010".to_string()),
                category: Category::Configuration,
                severity: Severity::HIGH,
                title: "JWT Signature Verification Disabled in Configuration".to_string(),
                description: format!(
                    "JWT authentication configuration disables cryptographic verification via '{}={}'. Tokens can be forged by unauthenticated attackers.",
                    entry.key, entry.value
                ),
                file: model.file_path.clone(),
                line: entry.line,
                column: Some(1),
                evidence: Some(entry.raw_line.trim().to_string()),
                recommendation: Some("Always enforce strong cryptographic signature verification (e.g. HS256, RS256) and reject the 'none' algorithm.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-010").map(String::from),
                ..Default::default()
            });
        }
    }

    findings
}
