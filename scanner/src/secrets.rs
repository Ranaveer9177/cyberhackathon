use crate::types::{Category, Finding, Severity};
use crate::rules::get_secret_rules;

pub fn scan_secrets(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = get_secret_rules();

    let ext = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let doc_exts = ["md", "markdown", "rst", "txt", "adoc", "html", "htm"];
    let is_doc = doc_exts.contains(&ext.as_str());

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // Skip pure comments for assignment rules
        let is_comment = trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with("--");

        for rule in &rules {
            // Generic assignment rules should not run on documentation files
            if is_doc && (rule.id == "SEC-006" || rule.id == "SEC-007" || rule.id == "SEC-008") {
                continue;
            }

            if is_comment && (rule.id == "SEC-006" || rule.id == "SEC-007" || rule.id == "SEC-008") {
                continue;
            }

            if let Some(caps) = rule.pattern.captures(line) {
                // False positive filtering for password / token assignments
                if rule.id == "SEC-006" || rule.id == "SEC-007" || rule.id == "SEC-008" {
                    let matched_str = caps.get(0).map_or("", |m| m.as_str()).to_lowercase();
                    let line_lower = line.to_lowercase();

                    // Check for variable syntax or placeholders
                    if line_lower.contains("read-host")
                        || line_lower.contains("param(")
                        || line_lower.contains("[string]")
                        || line_lower.contains("[securestring]")
                        || line_lower.contains("os.environ")
                        || line_lower.contains("os.getenv")
                        || line_lower.contains("process.env")
                        || line_lower.contains("os.getenv")
                        || line_lower.contains("$env:")
                    {
                        continue;
                    }

                    // Check if the value is a dummy/placeholder/variable
                    let dummy_values = [
                        "\"\"", "''", "\"admin\"", "'admin'", "\"password\"", "'password'",
                        "\"passwd\"", "'passwd'", "\"changeme\"", "'changeme'",
                        "\"your_password\"", "'your_password'", "\"<password>\"", "'<password>'",
                        "\"dummy\"", "'dummy'", "\"example\"", "'example'", "\"test\"", "'test'",
                        "\"sample\"", "'sample'", "\"placeholder\"", "'placeholder'",
                        "\"default\"", "'default'", "\"root\"", "'root'", "\"null\"", "'null'",
                        "\"none\"", "'none'", "\"123456\"", "'123456'", "\"secret\"", "'secret'",
                    ];
                    let mut is_dummy = false;
                    for dv in &dummy_values {
                        if matched_str.contains(dv) {
                            is_dummy = true;
                            break;
                        }
                    }
                    // Variable reference in string: e.g. "$password" or "%password%" or "${password}"
                    if matched_str.contains("=\"$") || matched_str.contains(":'$") || matched_str.contains("=\"%") || matched_str.contains("=\"${") {
                        is_dummy = true;
                    }

                    if is_dummy {
                        continue;
                    }
                }

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

    let ext = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
    let source_exts = ["go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs"];

    let mut is_bad_file = false;
    if !source_exts.contains(&ext) {
        is_bad_file = bad_filenames.contains(&file_name) || file_name.starts_with("credentials.") || file_name.starts_with("secrets.");
        if !is_bad_file && bad_exts.contains(&ext) {
            is_bad_file = true;
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
