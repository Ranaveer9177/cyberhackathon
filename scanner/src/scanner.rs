use std::path::Path;
use walkdir::WalkDir;

pub fn scan_directory(path: &str) -> Vec<String> {
    let mut files = Vec::new();

    let skipped_dirs = [
        "node_modules", "vendor", ".git", "target", "__pycache__", ".venv", "dist", "build",
    ];

    let skipped_exts = [
        "exe", "dll", "so", "dylib", "bin", "dat", "zip", "tar", "gz", "png", "jpg", "gif", "mp4",
        "pdf",
    ];

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
