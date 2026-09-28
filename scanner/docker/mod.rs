#![allow(dead_code)]

pub mod compose;
pub mod dockerfile;
pub mod relationships;
pub mod types;

pub use compose::{parse_docker_compose, scan_docker_compose};
pub use dockerfile::{parse_dockerfile, scan_dockerfile};
pub use relationships::scan_docker_relationships;
pub use types::*;

use crate::types::Finding;
use std::fs;
use std::path::Path;

pub fn scan_cross_file_docker(
    files: &[String],
    project_path: &str,
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut parsed_dockerfiles = Vec::new();
    let mut parsed_composes = Vec::new();

    for f in files {
        let name = Path::new(f)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let lower = name.to_lowercase();

        if name == "Dockerfile" || name.ends_with(".dockerfile") {
            if let Ok(content) = fs::read_to_string(f) {
                parsed_dockerfiles.push(dockerfile::parse_dockerfile(f, &content));
            }
        } else if lower == "docker-compose.yml"
            || lower == "docker-compose.yaml"
            || lower == "compose.yml"
            || lower == "compose.yaml"
        {
            if let Ok(content) = fs::read_to_string(f) {
                parsed_composes.push(compose::parse_docker_compose(f, &content));
            }
        }
    }

    relationships::scan_docker_relationships(
        files,
        project_path,
        &parsed_dockerfiles,
        &parsed_composes,
        finding_counter,
    )
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

    #[test]
    fn test_dockerfile_user_root_and_nonroot() {
        let mut counter = 0;
        let root_df = "FROM alpine:3.18\nRUN echo hi\n";
        let root_findings = scan_dockerfile("Dockerfile", root_df, &mut counter);
        assert!(root_findings.iter().any(|f| f.id == "VG-DCK-001"));

        let nonroot_df = "FROM alpine:3.18\nUSER appuser\n";
        let nonroot_findings = scan_dockerfile("Dockerfile", nonroot_df, &mut counter);
        assert!(!nonroot_findings.iter().any(|f| f.id == "VG-DCK-001"));
    }

    #[test]
    fn test_docker_compose_redis_and_host_mount() {
        let mut counter = 0;
        let compose_content = r#"version: '3.8'
services:
  cache:
    image: redis:alpine
    ports:
      - "6379:6379"
  web:
    image: myapp:1.0
    volumes:
      - .:/app
"#;
        let findings = scan_docker_compose("docker-compose.yml", compose_content, &mut counter);
        assert!(findings.iter().any(|f| f.id == "VG-DCK-007"));
        assert!(findings.iter().any(|f| f.id == "VG-DCK-009"));
    }

    #[test]
    fn test_docker_compose_host_namespaces() {
        let mut counter = 0;
        let pos_content = r#"version: '3.8'
services:
  agent:
    image: monitor:latest
    network_mode: host
    pid: host
"#;
        let findings = scan_docker_compose("docker-compose.yml", pos_content, &mut counter);
        assert!(findings.iter().any(|f| f.id == "VG-DCK-015"));
        assert!(findings.iter().any(|f| f.id == "VG-DCK-016"));

        let neg_content = r#"version: '3.8'
services:
  agent:
    image: monitor:latest
    network_mode: bridge
"#;
        let neg_findings = scan_docker_compose("docker-compose.yml", neg_content, &mut counter);
        assert!(!neg_findings.iter().any(|f| f.id == "VG-DCK-015"));
        assert!(!neg_findings.iter().any(|f| f.id == "VG-DCK-016"));
    }

    #[test]
    fn test_dockerfile_sensitive_arg_detection() {
        let mut counter = 0;
        let content = "FROM alpine:3.18\nARG API_SECRET_KEY\nARG GITHUB_TOKEN=demo\n";
        let findings = scan_dockerfile("Dockerfile", content, &mut counter);
        assert!(findings.iter().any(|f| f.id == "VG-DCK-017"));
    }

    #[test]
    fn test_compose_service_relationships() {
        let mut counter = 0;
        let compose_content = r#"version: '3.8'
services:
  web:
    image: node:18
    ports:
      - "8080:8080"
  db:
    image: postgres:15
    ports:
      - "5432:5432"
    volumes:
      - .:/var/lib/postgresql/data
"#;
        let compose_model = compose::parse_docker_compose("docker-compose.yml", compose_content);
        let findings = relationships::scan_docker_relationships(
            &["docker-compose.yml".to_string()],
            ".",
            &[],
            &[compose_model],
            &mut counter,
        );
        assert!(findings.iter().any(|f| f.id == "VG-DCK-018"));
        assert!(findings.iter().any(|f| f.id == "VG-DCK-019"));
    }
}
