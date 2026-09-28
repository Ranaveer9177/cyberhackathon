#![allow(dead_code)]

use crate::docker::types::{ComposeServiceModel, DockerComposeModel, PortMapping, VolumeMount};
use crate::rules::rule_cwe;
use crate::types::{Category, Finding, Severity};
use regex::Regex;

pub fn parse_docker_compose(file_path: &str, content: &str) -> DockerComposeModel {
    let mut model = DockerComposeModel {
        file_path: file_path.to_string(),
        version: "3".to_string(),
        services: Vec::new(),
    };

    let mut current_service: Option<ComposeServiceModel> = None;
    let mut in_services_block = false;
    let mut current_section: Option<String> = None;

    let port_split_re = Regex::new(r#"^["']?(?:([^:]+):)?([0-9]+):([0-9]+)["']?"#).unwrap();
    let volume_split_re = Regex::new(r#"^["']?([^:]+):([^:]+)(?::([a-z]+))?["']?"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();

        if indent == 0 && trimmed.starts_with("services:") {
            in_services_block = true;
            continue;
        } else if indent == 0 && !trimmed.starts_with("services:") && trimmed.ends_with(':') {
            in_services_block = false;
        }

        if in_services_block {
            if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
                if let Some(svc) = current_service.take() {
                    model.services.push(svc);
                }
                let svc_name = trimmed[..trimmed.len() - 1].trim().to_string();
                current_service = Some(ComposeServiceModel {
                    name: svc_name,
                    ..Default::default()
                });
                current_section = None;
                continue;
            }

            if let Some(ref mut svc) = current_service {
                if indent == 4 && trimmed.ends_with(':') {
                    current_section = Some(trimmed[..trimmed.len() - 1].trim().to_string());
                    continue;
                }

                if indent == 4 {
                    if let Some(colon) = trimmed.find(':') {
                        let k = trimmed[..colon].trim();
                        let v = trimmed[colon + 1..]
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'');
                        match k {
                            "image" => svc.image = Some(v.to_string()),
                            "user" => svc.user = Some(v.to_string()),
                            "network_mode" => svc.network_mode = Some(v.to_string()),
                            "pid" => svc.pid = Some(v.to_string()),
                            "ipc" => svc.ipc = Some(v.to_string()),
                            "privileged" => svc.privileged = v == "true",
                            _ => {}
                        }
                    }
                }

                if indent >= 6 && trimmed.starts_with('-') {
                    let item = trimmed[1..].trim().trim_matches('"').trim_matches('\'');
                    if let Some(ref sec) = current_section {
                        match sec.as_str() {
                            "ports" => {
                                if let Some(caps) = port_split_re.captures(item) {
                                    let host_ip = caps.get(1).map(|m| m.as_str().to_string());
                                    let h_port = caps
                                        .get(2)
                                        .and_then(|m| m.as_str().parse::<u16>().ok())
                                        .unwrap_or(0);
                                    let c_port = caps
                                        .get(3)
                                        .and_then(|m| m.as_str().parse::<u16>().ok())
                                        .unwrap_or(0);
                                    svc.ports.push(PortMapping {
                                        host_ip,
                                        host_port: h_port,
                                        container_port: c_port,
                                        raw: item.to_string(),
                                        line: line_num,
                                    });
                                }
                            }
                            "volumes" => {
                                if let Some(caps) = volume_split_re.captures(item) {
                                    let host_path =
                                        caps.get(1).map_or("", |m| m.as_str()).to_string();
                                    let container_path =
                                        caps.get(2).map_or("", |m| m.as_str()).to_string();
                                    let ro = caps.get(3).is_some_and(|m| m.as_str() == "ro");
                                    svc.volumes.push(VolumeMount {
                                        host_path,
                                        container_path,
                                        read_only: ro,
                                        raw: item.to_string(),
                                        line: line_num,
                                    });
                                }
                            }
                            "environment" => {
                                if let Some(eq) = item.find('=') {
                                    let k = item[..eq].trim().to_string();
                                    let v = item[eq + 1..].trim().to_string();
                                    svc.environment.push((k, v, line_num));
                                }
                            }
                            "env_file" => {
                                svc.env_file.push(item.to_string());
                            }
                            "cap_add" => {
                                svc.cap_add.push(item.to_string());
                            }
                            "depends_on" => {
                                svc.depends_on.push(item.to_string());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    if let Some(svc) = current_service {
        model.services.push(svc);
    }

    model
}

pub fn scan_docker_compose(
    file_path: &str,
    content: &str,
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let db_port_re = Regex::new(r#"(?i)["']?(?:5432:5432|3306:3306|27017:27017)["']?"#).unwrap();
    let redis_port_re = Regex::new(r#"(?i)["']?6379:6379["']?"#).unwrap();
    let root_user_re = Regex::new(r#"(?i)^\s*user:\s*["']?(root|0)["']?\s*$"#).unwrap();
    let host_mount_re = Regex::new(r#"(?i)^\s*-\s*["']?(?:\.:|\./[^:]+:|/[^:]+:)"#).unwrap();
    let sensitive_mount_re =
        Regex::new(r#"(?i)(/var/run/docker\.sock|/etc:|/root:|/proc:)"#).unwrap();
    let privileged_re = Regex::new(r#"(?i)^\s*privileged:\s*true\s*$"#).unwrap();
    let dangerous_cap_re =
        Regex::new(r#"(?i)^\s*-\s*(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE)\b"#).unwrap();
    let weak_env_pass_re = Regex::new(
        r#"(?i)^\s*-\s*([A-Za-z0-9_]*PASS(?:WORD)?|SECRET|KEY)\s*=\s*["']?([^"'\s]+)["']?"#,
    )
    .unwrap();
    let host_network_re = Regex::new(r#"(?i)^\s*network_mode:\s*["']?host["']?\s*$"#).unwrap();
    let host_pid_ipc_re = Regex::new(r#"(?i)^\s*(pid|ipc):\s*["']?host["']?\s*$"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // 1. Exposed Database Port (VG-DCK-006)
        if db_port_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-006".to_string(),
                rule_id: Some("VG-DCK-006".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Exposed Database Port in Docker Compose".to_string(),
                description: "Database port (5432, 3306, or 27017) is mapped directly to the host interface. Databases should communicate via private internal networks.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove host port mapping from database service. Access databases via internal container network names.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-006").map(String::from),
                ..Default::default()
            });
        }

        // 2. Exposed Redis Port (VG-DCK-007)
        if redis_port_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-007".to_string(),
                rule_id: Some("VG-DCK-007".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Exposed Redis Port in Docker Compose".to_string(),
                description: "Redis port 6379 is mapped to the host interface without network isolation, allowing unauthorized access if binding is unauthenticated.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove port 6379 mapping to keep Redis accessible only within the internal Docker network.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-007").map(String::from),
                ..Default::default()
            });
        }

        // 3. Container Running as Root (VG-DCK-008)
        if root_user_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-008".to_string(),
                rule_id: Some("VG-DCK-008".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Container Running as Root in Docker Compose".to_string(),
                description: "Service explicitly specifies 'user: root', allowing processes full privileges inside the container.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Configure services to run as a non-privileged user (e.g. user: '1000:1000').".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-008").map(String::from),
                ..Default::default()
            });
        }

        // 4. Sensitive Host Mount (VG-DCK-013)
        if sensitive_mount_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-013".to_string(),
                rule_id: Some("VG-DCK-013".to_string()),
                category: Category::Docker,
                severity: Severity::CRITICAL,
                title: "Sensitive Host Path Mounted in Container".to_string(),
                description: "Mounting sensitive host paths (e.g. /var/run/docker.sock, /etc, /root) grants host root access or docker daemon control.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove Docker socket or root path mounts from containers.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-013").map(String::from),
                ..Default::default()
            });
        } else if host_mount_re.is_match(line) {
            // 5. General Host Filesystem Mount (VG-DCK-009)
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-009".to_string(),
                rule_id: Some("VG-DCK-009".to_string()),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Host Filesystem Mount in Docker Compose".to_string(),
                description: "Service mounts local host directory into container (e.g. '.:/app'). Host file changes or container compromises can cross boundary.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Use named volumes or copy files into production images instead of binding host working directories.".to_string()),
                confidence: "MEDIUM".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-009").map(String::from),
                ..Default::default()
            });
        }

        // 6. Privileged Container (VG-DCK-011)
        if privileged_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-011".to_string(),
                rule_id: Some("VG-DCK-011".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Privileged Container Execution".to_string(),
                description: "Container runs with 'privileged: true', disabling all Linux security capabilities and seccomp profiles.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove privileged: true and grant only explicit, minimal capabilities needed.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-011").map(String::from),
                ..Default::default()
            });
        }

        // 7. Dangerous Capabilities (VG-DCK-012)
        if dangerous_cap_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-012".to_string(),
                rule_id: Some("VG-DCK-012".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Dangerous Docker Capability Granted".to_string(),
                description: "Dangerous capability (such as SYS_ADMIN or ALL) granted via cap_add."
                    .to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some(
                    "Drop unnecessary capabilities and avoid granting SYS_ADMIN or ALL."
                        .to_string(),
                ),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-012").map(String::from),
                ..Default::default()
            });
        }

        // 8. Weak Hardcoded Container Password (VG-DCK-010)
        if let Some(caps) = weak_env_pass_re.captures(line) {
            let pass_val = caps.get(2).map_or("", |m| m.as_str());
            let dummy = pass_val == "password"
                || pass_val == "secret"
                || pass_val == "admin"
                || pass_val.contains("redispassword");
            if dummy || pass_val.len() < 8 {
                *finding_counter += 1;
                findings.push(Finding {
                    id: "VG-DCK-010".to_string(),
                    rule_id: Some("VG-DCK-010".to_string()),
                    category: Category::Docker,
                    severity: Severity::HIGH,
                    title: "Weak Hardcoded Container Password".to_string(),
                    description: "Weak or default database password configured in container environment variables.".to_string(),
                    file: file_path.to_string(),
                    line: line_num,
                    column: Some(1),
                    evidence: Some(format!("{}=********", caps.get(1).map_or("", |m| m.as_str()))),
                    recommendation: Some("Use strong generated passwords or secret files instead of hardcoding in compose environment.".to_string()),
                    confidence: "HIGH".to_string(),
                    source: None,
                    sink: None,
                    data_flow: None,
                    cwe: rule_cwe("VG-DCK-010").map(String::from),
                    ..Default::default()
                });
            }
        }

        // 9. Host Network Mode (VG-DCK-015)
        if host_network_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-015".to_string(),
                rule_id: Some("VG-DCK-015".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Container Using Host Network Mode".to_string(),
                description: "Service specifies 'network_mode: host', bypassing container network namespace isolation.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Use bridge or custom user-defined overlay networks instead of host networking.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-015").map(String::from),
                ..Default::default()
            });
        }

        // 10. Shared Host PID / IPC Namespace (VG-DCK-016)
        if host_pid_ipc_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-016".to_string(),
                rule_id: Some("VG-DCK-016".to_string()),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Container Sharing Host Process Namespace".to_string(),
                description: "Service specifies host PID or IPC namespace, allowing container processes to view or signal host processes.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                column: Some(1),
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove 'pid: host' and 'ipc: host' to isolate container processes from the host.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-016").map(String::from),
                ..Default::default()
            });
        }
    }

    findings
}
