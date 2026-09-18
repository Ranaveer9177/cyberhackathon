use crate::types::{Category, Finding, Severity};
use crate::rules::get_secret_rules;

pub fn scan_secrets(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = get_secret_rules();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;

        for rule in &rules {
            if let Some(caps) = rule.pattern.captures(line) {
                *finding_counter += 1;
                
                let mut evidence = caps.get(0).map_or("", |m| m.as_str()).to_string();
                if evidence.len() > 8 {
                    evidence = format!("{}****", &evidence[..8]);
                } else {
                    evidence = "****".to_string();
                }

                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::Secret,
                    severity: Severity::CRITICAL,
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

    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let bad_filenames = [".env", "id_rsa", "id_dsa", ".htpasswd"];
    let bad_exts = ["pem", "key"];

    let mut is_bad_file = bad_filenames.contains(&file_name) || file_name.starts_with("credentials.") || file_name.starts_with("secrets.");
    
    if !is_bad_file {
        if let Some(ext) = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()) {
            if bad_exts.contains(&ext) {
                is_bad_file = true;
            }
        }
    }

    if is_bad_file && findings.is_empty() {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            title: "Sensitive File Detected".to_string(),
            description: "A file commonly used to store secrets or credentials was found.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Ensure this file is not committed to version control and does not contain sensitive data.".to_string()),
            confidence: "HIGH".to_string(),
        });
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
        assert_eq!(counter, 1);
        assert!(findings[0].evidence.as_ref().unwrap().contains("****"));
    }

    #[test]
    fn test_clean_file_no_secrets() {
        let mut counter = 0;
        let content = "let username = \"john_doe\";\nlet port = 8080;\n";
        let findings = scan_secrets("main.rs", content, &mut counter);
        assert!(findings.is_empty());
        assert_eq!(counter, 0);
    }
}
