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
        for rule in &rules {
            if rule.pattern.is_match(line) {
                if rule.id == "SAST-002" {
                    if line.contains(r#"exec.Command("git""#) || line.contains("exec.CommandContext") {
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
