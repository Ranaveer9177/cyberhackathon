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

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: vibeguard-scanner <project_path> [options]");
        println!();
        println!("Options:");
        println!("  --help");
        println!("  --version");
        println!("  --progress");
        println!("  --no-secrets");
        println!("  --no-sast");
        println!("  --include-tests");
        println!("  --include-docs");
        println!("  --show-excluded");
        std::process::exit(0);
    }

    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("vibeguard-scanner v4.6.0");
        std::process::exit(0);
    }

    // Validate all flags
    let valid_flags = [
        "--help",
        "-h",
        "--version",
        "-v",
        "--progress",
        "--no-secrets",
        "--no-sast",
        "--include-tests",
        "--include-docs",
        "--show-excluded",
    ];
    for arg in args.iter().skip(1) {
        if arg.starts_with('-') && !valid_flags.contains(&arg.as_str()) {
            eprintln!("Error: unknown option '{}'", arg);
            eprintln!("{}", json!({ "error": format!("Unknown option: {}", arg) }));
            std::process::exit(2);
        }
    }

    let mut project_path = "";
    for arg in args.iter().skip(1) {
        if !arg.starts_with('-') {
            project_path = arg;
            break;
        }
    }

    if project_path.is_empty() {
        eprintln!(
            "{}",
            json!({ "error": "Usage: vibeguard-scanner <project_path> [--no-secrets] [--no-sast]" })
        );
        std::process::exit(2);
    }

    let p = Path::new(project_path);
    if !p.exists() {
        eprintln!(
            "{}",
            json!({ "error": format!("Project path does not exist: {}", project_path) })
        );
        std::process::exit(2);
    }

    let start_time = Instant::now();

    // Check CLI flags
    let cli_no_secrets = args.iter().any(|a| a == "--no-secrets");
    let cli_no_sast = args.iter().any(|a| a == "--no-sast");
    let emit_progress = args.iter().any(|a| a == "--progress");

    // Check .vibeguard/config.json if present
    let mut enable_secrets = !cli_no_secrets;
    let mut enable_sast = !cli_no_sast;

    let cfg_file = Path::new(project_path)
        .join(".vibeguard")
        .join("config.json");
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

    let include_tests = args.iter().any(|a| a == "--include-tests");
    let include_docs = args.iter().any(|a| a == "--include-docs");

    let (files, excluded_count, binary_skipped) =
        scanner::scan_directory_ext(project_path, include_tests, include_docs);
    let total_files = files.len();
    let mut all_findings = Vec::new();
    let mut finding_counter = 0;
    let mut files_skipped_count = binary_skipped;
    let mut scan_warnings = Vec::new();

    for (idx, file_path) in files.iter().enumerate() {
        if emit_progress {
            eprintln!("PROGRESS:{}:{}:{}", idx + 1, total_files, file_path);
        }

        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                files_skipped_count += 1;
                scan_warnings.push(types::ScanWarning {
                    file: file_path.clone(),
                    reason: format!("Unable to read file as text: {}", e),
                });
                continue;
            }
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
            let mut docker_findings =
                docker::scan_dockerfile(file_path, &content, &mut finding_counter);
            all_findings.append(&mut docker_findings);
        }

        let source_exts = [
            "go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs",
        ];
        let config_exts = ["yaml", "yml", "toml", "ini", "conf", "cfg", "json"];
        if config_exts.contains(&ext)
            || (filename.starts_with("config.") && !source_exts.contains(&ext))
        {
            let mut config_findings =
                config::scan_config(file_path, &content, &mut finding_counter);
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
        files_skipped: if files_skipped_count > 0 {
            Some(files_skipped_count)
        } else {
            None
        },
        excluded_files: if excluded_count > 0 {
            Some(excluded_count)
        } else {
            None
        },
        findings: all_findings,
        scan_time_ms: duration,
        scan_warnings: if scan_warnings.is_empty() {
            None
        } else {
            Some(scan_warnings)
        },
    };

    match serde_json::to_string(&result) {
        Ok(json_out) => println!("{}", json_out),
        Err(e) => {
            eprintln!(
                "{}",
                json!({ "error": format!("Serialization failed: {}", e) })
            );
            std::process::exit(2);
        }
    }
}
