#![allow(dead_code)]

use crate::docker::types::{CopyInstruction, DockerfileModel};
use crate::rules::rule_cwe;
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn parse_dockerfile(file_path: &str, content: &str) -> DockerfileModel {
    let mut model = DockerfileModel {
        file_path: file_path.to_string(),
        ..Default::default()
    };

    let from_re = Regex::new(r#"(?i)^FROM\s+([^\s:]+)(?::([^\s]+))?"#).unwrap();
    let copy_re = Regex::new(r#"(?i)^COPY\s+(?:--[a-z]+=[^\s]+\s+)*([^\s]+)\s+([^\s]+)"#).unwrap();
    let env_re = Regex::new(r#"(?i)^ENV\s+([a-zA-Z0-9_-]+)(?:\s*=\s*|\s+)(.*)$"#).unwrap();
    let arg_re = Regex::new(r#"(?i)^ARG\s+([a-zA-Z0-9_-]+)(?:=(.*))?$"#).unwrap();
    let user_re = Regex::new(r#"(?i)^USER\s+([^\s]+)"#).unwrap();
    let expose_re = Regex::new(r#"(?i)^EXPOSE\s+([^\s]+)"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(caps) = from_re.captures(trimmed) {
            let img = caps.get(1).map_or("", |m| m.as_str()).to_string();
            let tag = caps.get(2).map(|m| m.as_str().to_string());
            model.from_images.push((img, tag, line_num));
        } else if let Some(caps) = copy_re.captures(trimmed) {
            let src = caps.get(1).map_or("", |m| m.as_str()).to_string();
            let dst = caps.get(2).map_or("", |m| m.as_str()).to_string();
            model.copy_instructions.push(CopyInstruction {
                src,
                dst,
                raw: trimmed.to_string(),
                line: line_num,
            });
        } else if let Some(caps) = env_re.captures(trimmed) {
            let key = caps.get(1).map_or("", |m| m.as_str()).to_string();
            let val = caps.get(2).map_or("", |m| m.as_str()).to_string();
            model.env_vars.push((key, val, line_num));
        } else if let Some(caps) = arg_re.captures(trimmed) {
            let key = caps.get(1).map_or("", |m| m.as_str()).to_string();
            let val = caps.get(2).map(|m| m.as_str().to_string());
            model.arg_vars.push((key, val, line_num));
        } else if let Some(caps) = user_re.captures(trimmed) {
            let u = caps.get(1).map_or("", |m| m.as_str()).to_string();
            model.user = Some((u, line_num));
        } else if let Some(caps) = expose_re.captures(trimmed) {
            let raw_port = caps.get(1).map_or("", |m| m.as_str());
            if let Ok(p) = raw_port.parse::<u16>() {
                model.exposed_ports.push((p, line_num));
            }
        } else if trimmed.starts_with("HEALTHCHECK") {
            model.has_healthcheck = true;
        }
    }

    model
}

pub fn scan_dockerfile(
    file_path: &str,
    content: &str,
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let model = parse_dockerfile(file_path, content);

    let secret_name_re =
        Regex::new(r#"(?i)(secret|token|password|passwd|key|apikey|jwt)"#).unwrap();

    // 1. Container Running as Root (VG-DCK-001)
    let is_root = match &model.user {
        None => true,
        Some((u, _)) => u == "root" || u == "0",
    };

    if is_root {
        *finding_counter += 1;
        findings.push(Finding {
            id: "VG-DCK-001".to_string(),
            rule_id: Some("VG-DCK-001".to_string()),
            category: Category::Docker,
            severity: Severity::HIGH,
            title: "Container Running as Root".to_string(),
            description: "No non-root USER instruction specified in the Dockerfile. Container processes will run with root privileges.".to_string(),
            file: file_path.to_string(),
            line: model.user.as_ref().map(|(_, l)| *l).unwrap_or(1),
            column: Some(1),
            evidence: model.user.as_ref().map(|(u, _)| format!("USER {}", u)),
            recommendation: Some("Add a non-root USER instruction (e.g., 'USER appuser' or 'USER 10001').".to_string()),
            confidence: "HIGH".to_string(),
            source: None,
            sink: None,
            data_flow: None,
            cwe: rule_cwe("VG-DCK-001").map(String::from),
            ..Default::default()
        });
    }

    // 2. Secret in Container Environment (VG-DCK-002)
    for (key, val, line) in &model.env_vars {
        if secret_name_re.is_match(key) && !val.is_empty() && !val.starts_with('$') {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-002".to_string(),
                rule_id: Some("VG-DCK-002".to_string()),
                category: Category::Docker,
                severity: Severity::CRITICAL,
                title: "Secret in Container Environment".to_string(),
                description: format!(
                    "Sensitive credential '{}' discovered in Dockerfile ENV instruction.",
                    key
                ),
                file: file_path.to_string(),
                line: *line,
                column: Some(1),
                evidence: Some(format!("ENV {}={}", key, "********")),
                recommendation: Some("Avoid setting sensitive data in ENV instructions. Use Docker secrets or runtime environment injection.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-002").map(String::from),
                ..Default::default()
            });
        }
    }

    // 3. Unbounded Directory Copy (VG-DCK-003)
    for copy in &model.copy_instructions {
        if (copy.src == "." || copy.src == "./")
            && (copy.dst == "." || copy.dst == "./" || copy.dst == "/app" || copy.dst == "/app/")
        {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-003".to_string(),
                rule_id: Some("VG-DCK-003".to_string()),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Unbounded Directory Copy (COPY . .)".to_string(),
                description: "Using COPY . . copies the entire build context and can unintentionally bundle local secrets, .env files, or git metadata into the image.".to_string(),
                file: file_path.to_string(),
                line: copy.line,
                column: Some(1),
                evidence: Some(copy.raw.clone()),
                recommendation: Some("Use a .dockerignore file and specify explicit directory/file paths.".to_string()),
                confidence: "MEDIUM".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-003").map(String::from),
                ..Default::default()
            });
        }
    }

    // 4. Missing HEALTHCHECK (VG-DCK-004)
    if !model.has_healthcheck {
        *finding_counter += 1;
        findings.push(Finding {
            id: "VG-DCK-004".to_string(),
            rule_id: Some("VG-DCK-004".to_string()),
            category: Category::Docker,
            severity: Severity::LOW,
            title: "Missing HEALTHCHECK".to_string(),
            description: "No HEALTHCHECK instruction defined.".to_string(),
            file: file_path.to_string(),
            line: 1,
            column: Some(1),
            evidence: None,
            recommendation: Some(
                "Add a HEALTHCHECK to ensure container liveness can be monitored.".to_string(),
            ),
            confidence: "MEDIUM".to_string(),
            source: None,
            sink: None,
            data_flow: None,
            cwe: rule_cwe("VG-DCK-004").map(String::from),
            ..Default::default()
        });
    }

    // 5. Floating Container Tag (:latest) (VG-DCK-005)
    for (img, tag, line) in &model.from_images {
        if tag.as_deref() == Some("latest") || tag.is_none() {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-005".to_string(),
                rule_id: Some("VG-DCK-005".to_string()),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Floating Container Tag (:latest)".to_string(),
                description: format!(
                    "Base image '{}' uses the ':latest' tag or lacks a version tag, resulting in non-deterministic builds.",
                    img
                ),
                file: file_path.to_string(),
                line: *line,
                column: Some(1),
                evidence: Some(format!("FROM {}:{}", img, tag.as_deref().unwrap_or("latest"))),
                recommendation: Some("Pin base images to specific immutable version tags or SHA-256 digests.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-005").map(String::from),
                ..Default::default()
            });
        }
    }

    // 6. Exposed Database / Cache Ports in Dockerfile (VG-DCK-006 / VG-DCK-007)
    for (port, line) in &model.exposed_ports {
        if *port == 5432 || *port == 3306 || *port == 27017 {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-006".to_string(),
                rule_id: Some("VG-DCK-006".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Exposed Database Port in Dockerfile".to_string(),
                description: format!(
                    "Database port {} is explicitly exposed in Dockerfile. Databases should reside in private networks.",
                    port
                ),
                file: file_path.to_string(),
                line: *line,
                column: Some(1),
                evidence: Some(format!("EXPOSE {}", port)),
                recommendation: Some("Remove database EXPOSE instructions and connect containers via internal Docker bridge networks.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-006").map(String::from),
                ..Default::default()
            });
        } else if *port == 6379 {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-007".to_string(),
                rule_id: Some("VG-DCK-007".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Exposed Redis Port in Dockerfile".to_string(),
                description: "Redis port 6379 is explicitly exposed. Insecure Redis instances can be accessed without authentication if exposed.".to_string(),
                file: file_path.to_string(),
                line: *line,
                column: Some(1),
                evidence: Some(format!("EXPOSE {}", port)),
                recommendation: Some("Remove EXPOSE 6379 and keep cache servers inside private container networks.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-007").map(String::from),
                ..Default::default()
            });
        }
    }

    // 7. Sensitive Build-time Secret in ARG (VG-DCK-017)
    for (key, val, line) in &model.arg_vars {
        if secret_name_re.is_match(key) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-017".to_string(),
                rule_id: Some("VG-DCK-017".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Sensitive Build-Time Secret in Docker ARG".to_string(),
                description: format!(
                    "ARG instruction defines sensitive variable '{}'. Build ARGs are persisted in the image manifest and visible via 'docker history'.",
                    key
                ),
                file: file_path.to_string(),
                line: *line,
                column: Some(1),
                evidence: Some(format!("ARG {}{}", key, if val.is_some() { "=********" } else { "" })),
                recommendation: Some("Do not pass secret credentials via ARG instructions. Use BuildKit secret mounts ('--mount=type=secret') instead.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-017").map(String::from),
                ..Default::default()
            });
        }
    }

    findings
}
