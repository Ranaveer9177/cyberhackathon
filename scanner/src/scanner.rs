use std::path::Path;
use walkdir::WalkDir;

#[allow(dead_code)]
pub fn scan_directory(path: &str) -> Vec<String> {
    scan_directory_ext(path, false, false).0
}

pub fn scan_directory_ext(
    path: &str,
    include_tests: bool,
    include_docs: bool,
) -> (Vec<String>, usize, usize) {
    let mut files = Vec::new();
    let mut excluded_count = 0;
    let mut binary_skipped = 0;

    let skipped_dirs = [
        "node_modules",
        "vendor",
        ".git",
        ".vibeguard",
        "target",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        "htmlcov",
        ".coverage",
        "coverage",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".nyc_output",
        ".idea",
        ".vscode",
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
                            let s_norm = s.replace('\\', "/");
                            if include_tests && s_norm.to_lowercase().contains("test") {
                                continue;
                            }
                            if include_docs
                                && (s_norm.to_lowercase().contains("doc")
                                    || s_norm.to_lowercase().contains("report")
                                    || s_norm.to_lowercase().ends_with(".md"))
                            {
                                continue;
                            }
                            config_excludes.push(s_norm);
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
                let pat = trimmed
                    .trim_start_matches('/')
                    .trim_end_matches('/')
                    .replace('\\', "/");
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
                    excluded_count += 1;
                    break;
                }
            }
            if rel_clean == exc_clean || rel_clean.starts_with(&format!("{}/", exc_clean)) {
                skip = true;
                excluded_count += 1;
                break;
            }
            if let Some(file_name) = file_path.file_name().and_then(|f| f.to_str()) {
                if file_name == exc_clean {
                    skip = true;
                    excluded_count += 1;
                    break;
                }
            }
        }

        if !skip {
            if let Some(ext) = file_path.extension().and_then(|s| s.to_str()) {
                if skipped_exts.contains(&ext) {
                    skip = true;
                    binary_skipped += 1;
                }
            }
        }

        if !skip {
            if let Some(path_str) = file_path.to_str() {
                files.push(path_str.to_string());
            }
        }
    }

    (files, excluded_count, binary_skipped)
}

#[cfg(test)]
mod tests {
    use super::scan_directory_ext;
    use std::fs;

    #[test]
    fn excludes_vibeguard_internal_files_without_config_pattern() {
        let root =
            std::env::temp_dir().join(format!("vibeguard-scanner-test-{}", std::process::id()));
        let cache_dir = root.join(".vibeguard").join("cache").join("osv");
        fs::create_dir_all(&cache_dir).expect("create test directories");
        fs::write(
            cache_dir.join("cached.json"),
            r#"{"url":"http://example.com"}"#,
        )
        .expect("write cache fixture");
        fs::write(root.join("main.rs"), "fn main() {}").expect("write source fixture");

        let (files, _, _) = scan_directory_ext(
            root.to_str().expect("temporary path is valid UTF-8"),
            false,
            false,
        );

        assert!(
            files.iter().all(|file| !file
                .replace('\\', "/")
                .ends_with(".vibeguard/cache/osv/cached.json")),
            "internal cache file was included in scan: {files:?}"
        );
        assert_eq!(files.len(), 1);

        fs::remove_dir_all(root).expect("remove test directory");
    }
}
