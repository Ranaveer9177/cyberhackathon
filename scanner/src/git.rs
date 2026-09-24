use crate::rules::rule_cwe;
use crate::types::{Category, Finding, Severity};
use std::fs;
use std::path::Path;

pub fn scan_git_security(
    scanned_files: &[String],
    project_path: &str,
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut has_env = false;
    for file_path in scanned_files {
        let file_name = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if file_name == ".env" || file_name.starts_with(".env.") {
            has_env = true;
        }

        let bad_files = ["id_rsa", "id_dsa", ".htpasswd"];
        let is_bad = bad_files.contains(&file_name)
            || file_name.starts_with("credentials.")
            || file_name.ends_with(".pem");

        if is_bad {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-GIT-001".to_string(),
                rule_id: Some("VG-GIT-001".to_string()),
                category: Category::Git,
                severity: Severity::CRITICAL,
                title: "Sensitive File Tracked".to_string(),
                description: "A potentially sensitive cryptographic or credential file is present in the repository structure.".to_string(),
                file: file_path.clone(),
                line: 1,
                column: Some(1),
                evidence: Some(file_name.to_string()),
                recommendation: Some(
                    "Add this file to .gitignore and remove it from tracking if necessary.".to_string(),
                ),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-GIT-001").map(String::from),
                ..Default::default()
            });
        }
    }

    // Check VG-CFG-004: .env file exists and .gitignore does not ignore it
    if has_env {
        let gitignore_path = Path::new(project_path).join(".gitignore");
        let mut ignores_env = false;
        if let Ok(content) = fs::read_to_string(&gitignore_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed == ".env" || trimmed == ".env*" || trimmed == "*.env" {
                    ignores_env = true;
                    break;
                }
            }
        }
        if !ignores_env {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-CFG-004".to_string(),
                rule_id: Some("VG-CFG-004".to_string()),
                category: Category::Configuration,
                severity: Severity::HIGH,
                title: "Missing .env in .gitignore".to_string(),
                description: "A sensitive .env file exists in the repository, but .gitignore does not exclude '.env', risking accidental credential leakage.".to_string(),
                file: ".gitignore".to_string(),
                line: 1,
                column: Some(1),
                evidence: Some("Missing .env entry in .gitignore".to_string()),
                recommendation: Some("Add '.env' and '.env*' to .gitignore to prevent committing environment variables.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-CFG-004").map(String::from),
                ..Default::default()
            });
        }
    }

    findings
}
