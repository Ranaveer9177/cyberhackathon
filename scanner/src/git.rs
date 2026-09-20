use crate::types::{Category, Finding, Severity};
use std::path::Path;

pub fn scan_git_security(scanned_files: &[String], finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file_path in scanned_files {
        let file_name = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let bad_files = [".env", "id_rsa", "id_dsa", ".htpasswd"];
        let is_bad = bad_files.contains(&file_name)
            || file_name.starts_with("credentials.")
            || file_name.ends_with(".pem");

        if is_bad {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Git,
                severity: Severity::CRITICAL,
                title: "Sensitive File Tracked".to_string(),
                description: "A potentially sensitive file is present in the repository structure."
                    .to_string(),
                file: file_path.clone(),
                line: 1,
                evidence: Some(file_name.to_string()),
                recommendation: Some(
                    "Add this file to .gitignore and remove it from tracking if necessary."
                        .to_string(),
                ),
                confidence: "HIGH".to_string(),
            });
        }
    }

    findings
}
