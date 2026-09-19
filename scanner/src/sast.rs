use crate::types::{Category, Finding};
use crate::rules::get_sast_rules;
use std::path::Path;

pub fn scan_source_code(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let ext = Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
    let allowed_exts = ["go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs"];
    if !allowed_exts.contains(&ext) {
        return findings;
    }

    let rules = get_sast_rules();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // Skip comment lines
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with("--") {
            continue;
        }

        for rule in &rules {
            if rule.pattern.is_match(line) {
                if line.contains("Regex::new") || line.contains("regexp.MustCompile") || line.contains("pattern:") || line.contains(r#"contains("http"#) || line.contains(r#"contains(lineLower, "http"#) {
                    continue;
                }
                if rule.id == "SAST-002" {
                    if line.contains(r#"exec.Command("git""#) || line.contains("exec.CommandContext") {
                        continue;
                    }
                }
                if rule.id == "SAST-006" {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("http://localhost")
                        || line_lower.contains("http://127.0.0.1")
                        || line_lower.contains("http://0.0.0.0")
                        || line_lower.contains("http://::1")
                        || line_lower.contains("http://[::1]")
                        || line_lower.contains("w3.org")
                        || line_lower.contains("schemas.")
                        || line_lower.contains("json-schema.org")
                        || line_lower.contains("apache.org")
                        || line_lower.contains("example.com")
                        || line_lower.contains("example.org")
                        || line_lower.contains("http://{")
                        || line_lower.contains("http://${")
                        || line_lower.contains("http://%")
                    {
                        continue;
                    }
                }
                *finding_counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::SourceCode,
                    severity: rule.severity.clone(),
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some(rule.recommendation.clone()),
                    confidence: "MEDIUM".to_string(),
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
    fn test_detect_sql_injection() {
        let mut counter = 0;
        let content = "let q = fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", input);\n";
        let findings = scan_source_code("db.go", content, &mut counter);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].title, "Potential SQL Injection");
    }

    #[test]
    fn test_ignore_unsupported_extensions() {
        let mut counter = 0;
        let content = "fmt.Sprintf(\"SELECT * FROM users\")";
        let findings = scan_source_code("readme.md", content, &mut counter);
        assert!(findings.is_empty());
    }
}
