use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn scan_config(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let debug_re = Regex::new(r#"(?i)(debug.*true|DEBUG.*=.*1)"#).unwrap();
    let cors_re = Regex::new(r#"(?i)Access-Control-Allow-Origin.*\*"#).unwrap();
    let bind_re = Regex::new(r#"0\.0\.0\.0"#).unwrap();
    let http_re = Regex::new(r#"(?i)(endpoint|url).*http://"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        
        if debug_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Debug Mode Enabled".to_string(),
                description: "Debug mode appears to be enabled in configuration.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Disable debug mode in production environments.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if cors_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Wildcard CORS Allowed".to_string(),
                description: "CORS is configured to allow all origins (*).".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Restrict CORS origins to trusted domains.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if bind_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::LOW,
                title: "Binding to 0.0.0.0".to_string(),
                description: "Service is bound to all network interfaces (0.0.0.0).".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Ensure binding to 0.0.0.0 is intentional and properly firewalled.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
        
        if http_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Configuration,
                severity: Severity::MEDIUM,
                title: "Plain HTTP Endpoint".to_string(),
                description: "Configuration uses plain HTTP URLs.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Use HTTPS for all endpoints.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
    }

    findings
}
