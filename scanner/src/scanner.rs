use std::path::Path;
use walkdir::WalkDir;

pub fn scan_directory(path: &str) -> Vec<String> {
    let mut files = Vec::new();

    let skipped_dirs = [
        "node_modules", "vendor", ".git", "target", "__pycache__", ".venv", "venv", "env",
        "dist", "build", "htmlcov", ".coverage", "coverage", ".pytest_cache", ".mypy_cache",
        ".tox", ".nyc_output", ".idea", ".vscode",
    ];

    let skipped_exts = [
        "exe", "dll", "so", "dylib", "bin", "dat", "zip", "tar", "gz", "png", "jpg", "gif", "mp4",
        "pdf",
    ];

    let mut config_excludes: Vec<String> = Vec::new();
    let config_path = Path::new(path).join(".vibeguard").join("config.json");
    if config_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&config_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(arr) = val.get("exclude").and_then(|e| e.as_array()) {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            config_excludes.push(s.replace('\\', "/"));
                        }
                    }
                }
            }
        }
    }

    let gitignore_path = Path::new(path).join(".gitignore");
    if gitignore_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&gitignore_path) {
            for line in data.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let pat = trimmed.trim_start_matches('/').trim_end_matches('/').replace('\\', "/");
                if !pat.is_empty() {
                    config_excludes.push(pat);
                }
            }
        }
    }

    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();
        
        let mut skip = false;
        for component in file_path.components() {
            if let Some(comp_str) = component.as_os_str().to_str() {
                if skipped_dirs.contains(&comp_str) {
                    skip = true;
                    break;
                }
            }
        }

        let rel_path = file_path.strip_prefix(path).unwrap_or(file_path);
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let rel_clean = rel_str.trim_start_matches('/');

        for exc in &config_excludes {
            let exc_clean = exc.trim_start_matches('/');
            if exc_clean.is_empty() {
                continue;
            }
            if exc_clean.starts_with("*.") {
                let ext_pattern = &exc_clean[1..]; // e.g. ".key"
                if rel_clean.ends_with(ext_pattern) {
                    skip = true;
                    break;
                }
            }
            if rel_clean == exc_clean || rel_clean.starts_with(&format!("{}/", exc_clean)) {
                skip = true;
                break;
            }
            if let Some(file_name) = file_path.file_name().and_then(|f| f.to_str()) {
                if file_name == exc_clean {
                    skip = true;
                    break;
                }
            }
        }
        
        if let Some(ext) = file_path.extension().and_then(|s| s.to_str()) {
            if skipped_exts.contains(&ext) {
                skip = true;
            }
        }

        
        if !skip {
            if let Some(path_str) = file_path.to_str() {
                files.push(path_str.to_string());
            }
        }
    }
    
    files
}
