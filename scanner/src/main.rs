mod config;
mod docker;
mod git;
mod rules;
mod sast;
mod scanner;
mod secrets;
mod types;

use std::env;
use std::fs;
use std::path::Path;
use std::time::Instant;

use serde_json::json;
use types::ScanResult;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "{}",
            json!({ "error": "Usage: vibeguard-scanner <project_path> [--no-secrets] [--no-sast]" })
        );
        std::process::exit(2);
    }

    let project_path = &args[1];
    let start_time = Instant::now();

    // Check CLI flags
    let cli_no_secrets = args.iter().any(|a| a == "--no-secrets");
    let cli_no_sast = args.iter().any(|a| a == "--no-sast");

    // Check .vibeguard/config.json if present
    let mut enable_secrets = !cli_no_secrets;
    let mut enable_sast = !cli_no_sast;

    let cfg_file = Path::new(project_path).join(".vibeguard").join("config.json");
    if let Ok(cfg_data) = fs::read_to_string(&cfg_file) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cfg_data) {
            if let Some(sec) = parsed.get("secret_scan").and_then(|v| v.as_bool()) {
                if !sec {
                    enable_secrets = false;
                }
            }
            if let Some(src) = parsed.get("source_scan").and_then(|v| v.as_bool()) {
                if !src {
                    enable_sast = false;
                }
            }
        }
    }

    let files = scanner::scan_directory(project_path);
    let mut all_findings = Vec::new();
    let mut finding_counter = 0;

    for file_path in &files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip files that can't be read as string (e.g. binary)
        };

        if enable_secrets {
            let mut findings = secrets::scan_secrets(file_path, &content, &mut finding_counter);
            all_findings.append(&mut findings);
        }

        if enable_sast {
            let mut findings = sast::scan_source_code(file_path, &content, &mut finding_counter);
            all_findings.append(&mut findings);
        }

        let filename = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        let ext = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        if filename == "Dockerfile" || filename.ends_with(".dockerfile") {
            let mut docker_findings = docker::scan_dockerfile(file_path, &content, &mut finding_counter);
            all_findings.append(&mut docker_findings);
        }

        let config_exts = ["yaml", "yml", "toml", "ini", "conf", "cfg", "json"];
        if config_exts.contains(&ext) || filename.starts_with("config.") {
            let mut config_findings = config::scan_config(file_path, &content, &mut finding_counter);
            all_findings.append(&mut config_findings);
        }
    }

    if enable_secrets {
        let mut git_findings = git::scan_git_security(&files, &mut finding_counter);
        all_findings.append(&mut git_findings);
    }

    let project_name = Path::new(project_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let duration = start_time.elapsed().as_millis() as u64;

    let result = ScanResult {
        project: project_name,
        files_scanned: files.len(),
        findings: all_findings,
        scan_time_ms: duration,
    };

    match serde_json::to_string(&result) {
        Ok(json_out) => println!("{}", json_out),
        Err(e) => {
            eprintln!("{}", json!({ "error": format!("Serialization failed: {}", e) }));
            std::process::exit(2);
        }
    }
}
