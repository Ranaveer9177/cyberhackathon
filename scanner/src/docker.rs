use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn scan_dockerfile(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let mut has_user = false;
    let mut uses_latest = false;
    let mut has_healthcheck = false;

    let env_secret_re = Regex::new(r#"(?i)ENV\s+.*(secret|token|password|key)\s*="#).unwrap();
    let copy_all_re = Regex::new(r#"COPY\s+\.\s+\."#).unwrap();
    let expose_re = Regex::new(r#"EXPOSE\s+.*"#).unwrap();
    let from_latest_re = Regex::new(r#"(?i)FROM\s+.*:latest"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        
        if line.trim().starts_with("USER ") {
            let user = line.trim().replace("USER ", "").trim().to_string();
            if user != "root" && user != "0" {
                has_user = true;
            }
        }
        
        if line.trim().starts_with("HEALTHCHECK") {
            has_healthcheck = true;
        }

        if env_secret_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::CRITICAL,
                title: "Secrets in ENV".to_string(),
                description: "Environment variables in Dockerfiles can expose secrets.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Avoid setting sensitive data in ENV. Use runtime secrets.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
        
        if copy_all_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "COPY . . without caution".to_string(),
                description: "Using COPY . . can copy unintended sensitive files into the image.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Use a .dockerignore file and specify explicit paths.".to_string()),
                confidence: "MEDIUM".to_string(),
            });
        }
        
        if expose_re.is_match(line) {
            let ports = line.split_whitespace().count() - 1;
            if ports > 3 {
                *finding_counter += 1;
                findings.push(Finding {
                    id: format!("VG-{:03}", finding_counter),
                    category: Category::Docker,
                    severity: Severity::LOW,
                    title: "Privileged/Many port exposure".to_string(),
                    description: "Exposing many ports could increase the attack surface.".to_string(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some("Only EXPOSE necessary ports.".to_string()),
                    confidence: "LOW".to_string(),
                });
            }
        }
        
        if from_latest_re.is_match(line) {
            uses_latest = true;
            *finding_counter += 1;
            findings.push(Finding {
                id: format!("VG-{:03}", finding_counter),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Using latest tag".to_string(),
                description: "Base image is using the 'latest' tag.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Pin base images to specific versions.".to_string()),
                confidence: "HIGH".to_string(),
            });
        }
    }
    
    if !has_user {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Docker,
            severity: Severity::HIGH,
            title: "Running as root".to_string(),
            description: "No non-root USER specified in the Dockerfile.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Add a non-root USER instruction.".to_string()),
            confidence: "HIGH".to_string(),
        });
    }
    
    if !has_healthcheck {
        *finding_counter += 1;
        findings.push(Finding {
            id: format!("VG-{:03}", finding_counter),
            category: Category::Docker,
            severity: Severity::LOW,
            title: "Missing HEALTHCHECK".to_string(),
            description: "No HEALTHCHECK instruction defined.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Add a HEALTHCHECK to ensure the container is running correctly.".to_string()),
            confidence: "MEDIUM".to_string(),
        });
    }

    findings
}
