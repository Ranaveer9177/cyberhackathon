#![allow(dead_code)]

use crate::docker::types::{DockerComposeModel, DockerfileModel};
use crate::rules::rule_cwe;
use crate::types::{Category, Finding, Severity};
use std::fs;
use std::path::Path;

pub fn scan_docker_relationships(
    files: &[String],
    project_path: &str,
    dockerfiles: &[DockerfileModel],
    compose_models: &[DockerComposeModel],
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Identify sensitive files present in project context
    let sensitive_files: Vec<&String> = files
        .iter()
        .filter(|f| {
            let name = Path::new(f)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            name == ".env"
                || name.starts_with(".env.")
                || name.ends_with(".key")
                || name.ends_with(".pem")
                || name.starts_with("credentials.")
                || name.starts_with("secrets.")
        })
        .collect();

    // Check .dockerignore coverage
    let dockerignore_path = Path::new(project_path).join(".dockerignore");
    let mut ignores_env = false;
    let mut ignores_keys = false;

    if let Ok(content) = fs::read_to_string(&dockerignore_path) {
        for line in content.lines() {
            let t = line.trim();
            if t == ".env" || t == ".env*" || t == "*.env" || t == "secrets*" {
                ignores_env = true;
            }
            if t == "*.key" || t == "*.pem" || t == "id_rsa*" {
                ignores_keys = true;
            }
        }
    }

    // 2. Relationship: Sensitive project files + Dockerfile COPY instructions (VG-DCK-014)
    if !sensitive_files.is_empty() && (!ignores_env || !ignores_keys) {
        for df in dockerfiles {
            for copy in &df.copy_instructions {
                let copies_all = copy.src == "." || copy.src == "./";
                let copies_sensitive = sensitive_files
                    .iter()
                    .any(|sf| copy.src.contains(sf.as_str()));

                if copies_all || copies_sensitive {
                    *finding_counter += 1;
                    findings.push(Finding {
                        id: "VG-DCK-014".to_string(),
                        rule_id: Some("VG-DCK-014".to_string()),
                        category: Category::Docker,
                        severity: Severity::HIGH,
                        title: "Potential Secret Included In Docker Image".to_string(),
                        description: format!(
                            "A sensitive credential file ({}) exists in the build context and '{}' is used without complete .dockerignore exclusion. Secrets may be permanently baked into image layers.",
                            sensitive_files[0], copy.raw
                        ),
                        file: df.file_path.clone(),
                        line: copy.line,
                        column: Some(1),
                        evidence: Some(copy.raw.clone()),
                        recommendation: Some("Add '.env', '*.key', '*.pem', and sensitive config files to .dockerignore to prevent them from entering image builds.".to_string()),
                        confidence: "HIGH".to_string(),
                        source: None,
                        sink: None,
                        data_flow: None,
                        cwe: rule_cwe("VG-DCK-014").map(String::from),
                        ..Default::default()
                    });
                    break;
                }
            }
        }
    }

    // 3. Compose Multi-Service & Volume Relationships
    for compose in compose_models {
        let has_web_service = compose.services.iter().any(|s| {
            let n = s.name.to_lowercase();
            n.contains("web")
                || n.contains("api")
                || n.contains("app")
                || n.contains("frontend")
                || n.contains("server")
        });

        for svc in &compose.services {
            let is_root = svc.user.is_none()
                || svc.user.as_deref() == Some("root")
                || svc.user.as_deref() == Some("0");
            let has_host_mount = svc.volumes.iter().any(|v| {
                v.host_path == "."
                    || v.host_path == "./"
                    || v.host_path.starts_with("./")
                    || v.host_path.starts_with('/')
            });

            // Relationship: Root user + Host filesystem mount (VG-DCK-019)
            if is_root && has_host_mount {
                *finding_counter += 1;
                let vol_line = svc.volumes.first().map(|v| v.line).unwrap_or(1);
                findings.push(Finding {
                    id: "VG-DCK-019".to_string(),
                    rule_id: Some("VG-DCK-019".to_string()),
                    category: Category::Docker,
                    severity: Severity::HIGH,
                    title: "Root Container Execution with Host Volume Mount".to_string(),
                    description: format!(
                        "Service '{}' mounts host filesystem directories into the container while running as root (default or explicit 'user: root'). A compromised container process can modify host system or project files with root privileges.",
                        svc.name
                    ),
                    file: compose.file_path.clone(),
                    line: vol_line,
                    column: Some(1),
                    evidence: Some(format!("service: {}, user: root, volume: {}", svc.name, svc.volumes[0].raw)),
                    recommendation: Some("Specify a non-root 'user: \"1000:1000\"' in docker-compose.yml when mounting host volumes.".to_string()),
                    confidence: "HIGH".to_string(),
                    source: None,
                    sink: None,
                    data_flow: None,
                    cwe: rule_cwe("VG-DCK-019").map(String::from),
                    ..Default::default()
                });
            }

            // Relationship: Inter-service exposure vs Host exposure (VG-DCK-018)
            let is_backend_db = {
                let n = svc.name.to_lowercase();
                n.contains("db")
                    || n.contains("postgres")
                    || n.contains("mysql")
                    || n.contains("redis")
                    || n.contains("mongo")
            };

            if has_web_service && is_backend_db {
                for port_map in &svc.ports {
                    // Check if database port is published to host (5432, 3306, 6379, 27017)
                    if port_map.container_port == 5432
                        || port_map.container_port == 3306
                        || port_map.container_port == 6379
                        || port_map.container_port == 27017
                    {
                        *finding_counter += 1;
                        findings.push(Finding {
                            id: "VG-DCK-018".to_string(),
                            rule_id: Some("VG-DCK-018".to_string()),
                            category: Category::Docker,
                            severity: Severity::MEDIUM,
                            title: "Unnecessary Host Exposure of Internal Backend Service".to_string(),
                            description: format!(
                                "Backend database/cache service '{}' maps port {} to the host interface. In multi-service topologies, frontend/API services connect via internal service names on the Docker network, making host port exposure redundant and increasing attack surface.",
                                svc.name, port_map.container_port
                            ),
                            file: compose.file_path.clone(),
                            line: port_map.line,
                            column: Some(1),
                            evidence: Some(format!("service: {}, port: {}", svc.name, port_map.raw)),
                            recommendation: Some("Remove host port publishing for backend services. Other compose services can reach it via internal DNS (e.g. 'http://db:5432').".to_string()),
                            confidence: "HIGH".to_string(),
                            source: None,
                            sink: None,
                            data_flow: None,
                            cwe: rule_cwe("VG-DCK-018").map(String::from),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    findings
}
