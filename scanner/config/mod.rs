#![allow(dead_code)]

pub mod parser;
pub mod security;
pub mod types;

pub use parser::{
    detect_format, parse_config, parse_env, parse_ini, parse_json, parse_toml, parse_yaml,
};
pub use security::analyze_config_security;
pub use types::{ConfigEntry, ConfigFormat, ConfigModel};

use crate::types::Finding;

pub fn scan_config(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let model = parse_config(file_path, content);
    let mut findings = analyze_config_security(&model, finding_counter);

    // Fallback: If no structured entries found or non-standard format, run line-based legacy checks
    if model.entries.is_empty() {
        let legacy_model = ConfigModel {
            file_path: file_path.to_string(),
            format: ConfigFormat::ApplicationConfig,
            entries: parser::parse_ini(content),
        };
        let mut legacy_findings = analyze_config_security(&legacy_model, finding_counter);
        findings.append(&mut legacy_findings);
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_env_debug_and_secret() {
        let mut counter = 0;
        let test_key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let content = format!("DEBUG=true\nAPI_KEY={}\nCORS_ORIGIN=*\n", test_key);
        let findings = scan_config(".env", &content, &mut counter);
        assert!(findings.iter().any(|f| f.id == "VG-CFG-001"));
        assert!(findings.iter().any(|f| f.id == "VG-CFG-008"));
        assert!(findings.iter().any(|f| f.id == "VG-CFG-002"));
    }

    #[test]
    fn test_scan_yaml_weak_security_and_tls() {
        let mut counter = 0;
        let yaml_content = r#"
server:
  host: 0.0.0.0
  ssl_verify: false
security:
  session_cookie_secure: false
  csrf_enabled: false
"#;
        let findings = scan_config("config.yaml", yaml_content, &mut counter);
        assert!(findings.iter().any(|f| f.id == "VG-CFG-003"));
        assert!(findings.iter().any(|f| f.id == "VG-CFG-007"));
        assert!(findings.iter().any(|f| f.id == "VG-CFG-006"));
    }

    #[test]
    fn test_scan_json_insecure_defaults() {
        let mut counter = 0;
        let json_content = r#"{
  "database": {
    "password": "password123",
    "endpoint": "http://api.internal.net"
  }
}"#;
        let findings = scan_config("appsettings.json", json_content, &mut counter);
        assert!(findings.iter().any(|f| f.id == "VG-CFG-009"));
        assert!(findings.iter().any(|f| f.id == "VG-CFG-005"));
    }

    #[test]
    fn test_scan_config_jwt_and_csrf() {
        let mut counter = 0;
        let content = "jwt_algorithm=none\ndisable_csrf=true\n";
        let findings = scan_config("security.ini", content, &mut counter);
        assert!(findings.iter().any(|f| f.id == "VG-CFG-010"));
        assert!(findings.iter().any(|f| f.id == "VG-CFG-006"));
    }
}
