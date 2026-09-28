#[path = "../ast/mod.rs"]
pub mod ast;

#[path = "../analysis/mod.rs"]
pub mod analysis;

#[path = "../config/mod.rs"]
pub mod config;
#[path = "../docker/mod.rs"]
pub mod docker;
#[path = "../frameworks/mod.rs"]
pub mod frameworks;
mod git;
#[path = "../pipeline/mod.rs"]
pub mod pipeline;
mod rules;
mod sast;
mod scanner;
mod secrets;
#[path = "../semantic/mod.rs"]
pub mod semantic;
#[path = "../rules/mod.rs"]
pub mod semantic_rules;
#[path = "../taint/mod.rs"]
pub mod taint;
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
        println!("  --path <dir>     Path to scan (or pass as positional argument)");
        println!("  --json           Output results as JSON");
        println!("  --progress");
        println!("  --no-secrets");
        println!("  --no-sast");
        println!("  --include-tests");
        println!("  --include-docs");
        println!("  --show-excluded");
        println!("  --verbose");
        println!("  --all");
        std::process::exit(0);
    }

    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("vibeguard-scanner v7.0.0");
        std::process::exit(0);
    }

    // Validate all flags and extract project_path
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
        "--verbose",
        "--all",
        "--json",
        "--path",
        "-p",
    ];

    let mut project_path = String::new();
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--path" || arg == "-p" {
            if i + 1 < args.len() {
                project_path = args[i + 1].clone();
                i += 2;
                continue;
            } else {
                eprintln!("Error: --path requires a directory argument");
                std::process::exit(2);
            }
        } else if let Some(stripped) = arg.strip_prefix("--path=") {
            project_path = stripped.to_string();
            i += 1;
            continue;
        } else if arg.starts_with('-') {
            if !valid_flags.contains(&arg.as_str()) {
                eprintln!("Error: unknown option '{}'", arg);
                eprintln!("{}", json!({ "error": format!("Unknown option: {}", arg) }));
                std::process::exit(2);
            }
        } else if project_path.is_empty() {
            project_path = arg.clone();
        }
        i += 1;
    }

    if project_path.is_empty() {
        eprintln!(
            "{}",
            json!({ "error": "Usage: vibeguard-scanner <project_path> [--path <path>] [--no-secrets] [--no-sast]" })
        );
        std::process::exit(2);
    }

    let p = Path::new(&project_path);
    if !p.exists() {
        eprintln!(
            "{}",
            json!({ "error": format!("Project path does not exist: {}", project_path) })
        );
        std::process::exit(2);
    }

    let project_path = project_path.as_str();
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
    let mut parsed_ast_files: Vec<(String, ast::types::FileNode)> = Vec::new();

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

            if let Some(file_node) = ast::parse_file(file_path, &content) {
                let mut ast_findings =
                    ast::security::analyze_ast_security(&file_node, &mut finding_counter);
                all_findings.append(&mut ast_findings);
                parsed_ast_files.push((file_path.clone(), file_node));
            }
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

        let lower_filename = filename.to_lowercase();
        if lower_filename == "docker-compose.yml"
            || lower_filename == "docker-compose.yaml"
            || lower_filename == "compose.yml"
            || lower_filename == "compose.yaml"
            || lower_filename.ends_with(".compose.yml")
            || lower_filename.ends_with(".compose.yaml")
        {
            let mut compose_findings =
                docker::scan_docker_compose(file_path, &content, &mut finding_counter);
            all_findings.append(&mut compose_findings);
        }

        let source_exts = [
            "go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs",
        ];
        let config_exts = ["yaml", "yml", "toml", "ini", "conf", "cfg", "json", "env"];
        if config_exts.contains(&ext)
            || filename == ".env"
            || filename.starts_with(".env.")
            || filename.ends_with(".env")
            || (filename.starts_with("config.") && !source_exts.contains(&ext))
        {
            let mut config_findings =
                config::scan_config(file_path, &content, &mut finding_counter);
            all_findings.append(&mut config_findings);
        }
    }

    // Cross-file Docker analysis (e.g. .env + COPY . .)
    let mut cross_docker_findings =
        docker::scan_cross_file_docker(&files, project_path, &mut finding_counter);
    all_findings.append(&mut cross_docker_findings);

    // Cross-file Semantic Project Model & Deep Taint Engine
    let mut taint_flows: Vec<taint::TaintFlow> = Vec::new();
    if enable_sast && !parsed_ast_files.is_empty() {
        let file_refs: Vec<(&str, &ast::types::FileNode)> = parsed_ast_files
            .iter()
            .map(|(p, f)| (p.as_str(), f))
            .collect();

        let model = semantic::build_model(project_path, &file_refs);
        let mut semantic_findings =
            semantic::security::analyze_project_semantic(&model, &mut finding_counter);
        all_findings.append(&mut semantic_findings);

        taint_flows = taint::analyze_deep_taint(&model, &file_refs);
        let mut deep_taint_findings =
            analysis::generate_taint_findings(&taint_flows, &mut finding_counter);
        all_findings.append(&mut deep_taint_findings);

        let mut deep_rule_findings =
            semantic_rules::run_semantic_rules(&file_refs, &mut finding_counter);
        all_findings.append(&mut deep_rule_findings);
    }

    if enable_secrets {
        let mut git_findings = git::scan_git_security(&files, project_path, &mut finding_counter);
        all_findings.append(&mut git_findings);
    }

    let raw_count = all_findings.len();
    let all_findings = deduplicate_findings(all_findings);
    let dedup_count = all_findings.len();
    let suppressed = raw_count.saturating_sub(dedup_count);

    // ── v7.0: Pipeline post-processor (confidence, correlation, scope stats) ──
    let (all_findings, pipeline_meta) =
        pipeline::run_pipeline_postprocessor(all_findings, raw_count, suppressed, &taint_flows);

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
        pipeline_meta: Some(pipeline_meta),
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

fn deduplicate_findings(findings: Vec<types::Finding>) -> Vec<types::Finding> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::with_capacity(findings.len());

    for mut f in findings {
        if f.column.is_none() {
            f.column = Some(1);
        }
        if f.rule_id.is_none() {
            f.rule_id = Some(f.id.clone());
        }
        let fp = f.compute_fingerprint();
        f.fingerprint = Some(fp.clone());

        if seen.insert(fp) {
            deduped.push(f);
        }
    }

    deduped
}
