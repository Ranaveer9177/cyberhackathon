use crate::rules::rule_cwe;
use crate::types::{Category, Finding, Severity};
use regex::Regex;
use std::fs;
use std::path::Path;

pub fn scan_dockerfile(
    file_path: &str,
    content: &str,
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut has_user = false;
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
                id: "VG-DCK-002".to_string(),
                category: Category::Docker,
                severity: Severity::CRITICAL,
                title: "Secret in Container Environment".to_string(),
                description: "Sensitive credential discovered in Dockerfile ENV instruction.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some(
                    "Avoid setting sensitive data in ENV instructions. Use Docker secrets or runtime environment injection.".to_string(),
                ),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-002").map(|s| s.to_string()),
            });
        }

        if copy_all_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-003".to_string(),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Unbounded Directory Copy (COPY . .)".to_string(),
                description: "Using COPY . . copies the entire build context and can unintentionally bundle local secrets, .env files, or git metadata into the image.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some(
                    "Use a .dockerignore file and specify explicit directory/file paths.".to_string(),
                ),
                confidence: "MEDIUM".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-003").map(|s| s.to_string()),
            });
        }

        if expose_re.is_match(line) {
            let line_lower = line.to_lowercase();
            // Service-aware port exposure
            if line_lower.contains("5432") {
                *finding_counter += 1;
                findings.push(Finding {
                    id: "VG-DCK-006".to_string(),
                    category: Category::Docker,
                    severity: Severity::HIGH,
                    title: "Exposed Database Port in Dockerfile".to_string(),
                    description: "PostgreSQL port 5432 is explicitly exposed. Databases should reside in isolated container networks without host port exposure.".to_string(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some("Remove EXPOSE 5432 and connect containers via internal Docker bridge networks.".to_string()),
                    confidence: "HIGH".to_string(),
                    source: None,
                    sink: None,
                    data_flow: None,
                    cwe: rule_cwe("VG-DCK-006").map(|s| s.to_string()),
                });
            } else if line_lower.contains("6379") {
                *finding_counter += 1;
                findings.push(Finding {
                    id: "VG-DCK-007".to_string(),
                    category: Category::Docker,
                    severity: Severity::HIGH,
                    title: "Exposed Redis Port in Dockerfile".to_string(),
                    description: "Redis port 6379 is explicitly exposed. Insecure Redis instances can be accessed without authentication if exposed.".to_string(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(line.trim().to_string()),
                    recommendation: Some("Remove EXPOSE 6379 and keep cache servers inside private container networks.".to_string()),
                    confidence: "HIGH".to_string(),
                    source: None,
                    sink: None,
                    data_flow: None,
                    cwe: rule_cwe("VG-DCK-007").map(|s| s.to_string()),
                });
            } else {
                let ports = line.split_whitespace().count() - 1;
                if ports > 3 {
                    *finding_counter += 1;
                    findings.push(Finding {
                        id: "VG-DCK-005".to_string(),
                        category: Category::Docker,
                        severity: Severity::LOW,
                        title: "Privileged/Many port exposure".to_string(),
                        description: "Exposing many ports could increase the attack surface."
                            .to_string(),
                        file: file_path.to_string(),
                        line: line_num,
                        evidence: Some(line.trim().to_string()),
                        recommendation: Some("Only EXPOSE necessary ports.".to_string()),
                        confidence: "LOW".to_string(),
                        source: None,
                        sink: None,
                        data_flow: None,
                        cwe: rule_cwe("VG-DCK-005").map(|s| s.to_string()),
                    });
                }
            }
        }

        if from_latest_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-005".to_string(),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Floating Container Tag (:latest)".to_string(),
                description: "Base image uses the ':latest' tag, resulting in unpredictable and non-deterministic builds.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(line.trim().to_string()),
                recommendation: Some("Pin base images to specific immutable version tags or SHA-256 digests.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-005").map(|s| s.to_string()),
            });
        }
    }

    if !has_user {
        *finding_counter += 1;
        findings.push(Finding {
            id: "VG-DCK-001".to_string(),
            category: Category::Docker,
            severity: Severity::HIGH,
            title: "Container Running as Root".to_string(),
            description: "No non-root USER instruction specified in the Dockerfile. Container processes will run with root privileges.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some("Add a non-root USER instruction (e.g., 'USER appuser' or 'USER 10001').".to_string()),
            confidence: "HIGH".to_string(),
            source: None,
            sink: None,
            data_flow: None,
            cwe: rule_cwe("VG-DCK-001").map(|s| s.to_string()),
        });
    }

    if !has_healthcheck {
        *finding_counter += 1;
        findings.push(Finding {
            id: "VG-DCK-004".to_string(),
            category: Category::Docker,
            severity: Severity::LOW,
            title: "Missing HEALTHCHECK".to_string(),
            description: "No HEALTHCHECK instruction defined.".to_string(),
            file: file_path.to_string(),
            line: 1,
            evidence: None,
            recommendation: Some(
                "Add a HEALTHCHECK to ensure container liveness can be monitored.".to_string(),
            ),
            confidence: "MEDIUM".to_string(),
            source: None,
            sink: None,
            data_flow: None,
            cwe: rule_cwe("VG-DCK-004").map(|s| s.to_string()),
        });
    }

    findings
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
        r#"(?i)(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|REDIS_PASSWORD|PASSWORD)\s*[:=]\s*["']?([^"'\s]+)["']?"#,
    ).unwrap();

    let host_network_re = Regex::new(r#"(?i)^\s*network_mode:\s*["']?host["']?\s*$"#).unwrap();
    let host_pid_ipc_re = Regex::new(r#"(?i)^\s*(pid|ipc):\s*["']?host["']?\s*$"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // 1. Database Port Exposure (VG-DCK-006)
        if db_port_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-006".to_string(),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Exposed Database Port in Docker Compose".to_string(),
                description: "Database port (5432 / 3306 / 27017) is bound directly to the host network interface.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove host port bindings for databases. Let application services communicate via internal compose networks.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-006").map(|s| s.to_string()),
            });
        }

        // 2. Redis Port Exposure (VG-DCK-007)
        if redis_port_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-007".to_string(),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Exposed Redis Port in Docker Compose".to_string(),
                description: "Redis port 6379 is exposed to the host. Unauthenticated Redis instances allow remote code execution or data dumping.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove the Redis host port binding or bind strictly to localhost (127.0.0.1:6379:6379).".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-007").map(|s| s.to_string()),
            });
        }

        // 3. Container Running as Root (VG-DCK-008)
        if root_user_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-008".to_string(),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Container Running as Root in Docker Compose".to_string(),
                description: "Service explicitly specifies 'user: root', allowing processes full privileges inside the container.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Configure services to run as a non-privileged user (e.g. user: '1000:1000').".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-008").map(|s| s.to_string()),
            });
        }

        // 4. Sensitive Host Mount (VG-DCK-013)
        if sensitive_mount_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-013".to_string(),
                category: Category::Docker,
                severity: Severity::CRITICAL,
                title: "Sensitive Host Path Mounted in Container".to_string(),
                description: "Mounting sensitive host paths (e.g. /var/run/docker.sock, /etc, /root) grants host root access or docker daemon control.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove Docker socket or root path mounts from containers.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-013").map(|s| s.to_string()),
            });
        } else if host_mount_re.is_match(line) {
            // 5. General Host Filesystem Mount (VG-DCK-009)
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-009".to_string(),
                category: Category::Docker,
                severity: Severity::MEDIUM,
                title: "Host Filesystem Mount in Docker Compose".to_string(),
                description: "Service mounts local host directory into container (e.g. '.:/app'). Host file changes or container compromises can cross boundary.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Use named volumes or copy files into production images instead of binding host working directories.".to_string()),
                confidence: "MEDIUM".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-009").map(|s| s.to_string()),
            });
        }

        // 6. Privileged Container (VG-DCK-011)
        if privileged_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-011".to_string(),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Privileged Container Execution".to_string(),
                description: "Container runs with 'privileged: true', disabling all Linux security capabilities and seccomp profiles.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove privileged: true and grant only explicit, minimal capabilities needed.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-011").map(|s| s.to_string()),
            });
        }

        // 7. Dangerous Capabilities (VG-DCK-012)
        if dangerous_cap_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-012".to_string(),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Dangerous Docker Capability Granted".to_string(),
                description: "Dangerous capability (such as SYS_ADMIN or ALL) granted via cap_add."
                    .to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some(
                    "Drop unnecessary capabilities and avoid granting SYS_ADMIN or ALL."
                        .to_string(),
                ),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-012").map(|s| s.to_string()),
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
                    category: Category::Docker,
                    severity: Severity::HIGH,
                    title: "Weak Hardcoded Container Password".to_string(),
                    description: "Weak or default database password configured in container environment variables.".to_string(),
                    file: file_path.to_string(),
                    line: line_num,
                    evidence: Some(format!("{}=********", caps.get(1).map_or("", |m| m.as_str()))),
                    recommendation: Some("Use strong generated passwords or secret files instead of hardcoding in compose environment.".to_string()),
                    confidence: "HIGH".to_string(),
                    source: None,
                    sink: None,
                    data_flow: None,
                    cwe: rule_cwe("VG-DCK-010").map(|s| s.to_string()),
                });
            }
        }

        // 9. Host Network Mode (VG-DCK-015)
        if host_network_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-015".to_string(),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Container Using Host Network Mode".to_string(),
                description: "Service specifies 'network_mode: host', bypassing container network namespace isolation.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Use bridge or custom user-defined overlay networks instead of host networking.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-015").map(|s| s.to_string()),
            });
        }

        // 10. Shared Host PID / IPC Namespace (VG-DCK-016)
        if host_pid_ipc_re.is_match(line) {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-DCK-016".to_string(),
                category: Category::Docker,
                severity: Severity::HIGH,
                title: "Container Sharing Host Process Namespace".to_string(),
                description: "Service specifies host PID or IPC namespace, allowing container processes to view or signal host processes.".to_string(),
                file: file_path.to_string(),
                line: line_num,
                evidence: Some(trimmed.to_string()),
                recommendation: Some("Remove 'pid: host' and 'ipc: host' to isolate container processes from the host.".to_string()),
                confidence: "HIGH".to_string(),
                source: None,
                sink: None,
                data_flow: None,
                cwe: rule_cwe("VG-DCK-016").map(|s| s.to_string()),
            });
        }
    }

    findings
}

pub fn scan_cross_file_docker(
    files: &[String],
    project_path: &str,
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let has_env_file = files.iter().any(|f| {
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
    });

    if !has_env_file {
        return findings;
    }

    // Check if .dockerignore excludes sensitive files
    let dockerignore_path = Path::new(project_path).join(".dockerignore");
    let mut ignores_env = false;
    if let Ok(content) = fs::read_to_string(&dockerignore_path) {
        for line in content.lines() {
            let t = line.trim();
            if t == ".env"
                || t == ".env*"
                || t == "*.env"
                || t == "*.key"
                || t == "*.pem"
                || t == "secrets*"
            {
                ignores_env = true;
                break;
            }
        }
    }

    if ignores_env {
        return findings;
    }

    // Look for Dockerfile with COPY . .
    for file in files {
        let name = Path::new(file)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if name == "Dockerfile" || name.ends_with(".dockerfile") {
            if let Ok(content) = fs::read_to_string(file) {
                for (line_idx, line) in content.lines().enumerate() {
                    if line.contains("COPY . .")
                        || line.contains("COPY . /")
                        || line.contains("COPY .env")
                        || line.contains("COPY secrets")
                    {
                        *finding_counter += 1;
                        findings.push(Finding {
                            id: "VG-DCK-014".to_string(),
                            category: Category::Docker,
                            severity: Severity::HIGH,
                            title: "Potential Secret Included In Docker Image".to_string(),
                            description: "A sensitive configuration or credential file (.env/keys) exists in the build context and 'COPY . .' is used without .dockerignore protection. Secrets may be baked into image layers.".to_string(),
                            file: file.clone(),
                            line: line_idx + 1,
                            evidence: Some(line.trim().to_string()),
                            recommendation: Some("Add sensitive files to .dockerignore to prevent secrets from being copied into container images.".to_string()),
                            confidence: "HIGH".to_string(),
                            source: None,
                            sink: None,
                            data_flow: None,
                            cwe: rule_cwe("VG-DCK-014").map(|s| s.to_string()),
                        });
                        break;
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_compose_db_port() {
        let mut counter = 0;
        let content = r#"version: '3.8'
services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
    user: root
"#;
        let findings = scan_docker_compose("docker-compose.yml", content, &mut counter);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "VG-DCK-006"));
        assert!(findings.iter().any(|f| f.id == "VG-DCK-008"));
    }
}
