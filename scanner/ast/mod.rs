pub mod go;
pub mod java;
pub mod javascript;
pub mod python;
pub mod security;
pub mod types;
pub mod typescript;

#[cfg(test)]
mod tests;

use crate::types::Finding;
use std::path::Path;

/// Parses source code into a unified AST FileNode according to file extension.
pub fn parse_file(file_path: &str, content: &str) -> Option<types::FileNode> {
    let p = Path::new(file_path);
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext.to_lowercase().as_str() {
        "py" => Some(python::parse_python(file_path, content)),
        "js" | "jsx" | "mjs" | "cjs" => Some(javascript::parse_javascript(file_path, content)),
        "ts" | "tsx" => Some(typescript::parse_typescript(file_path, content)),
        "go" => Some(go::parse_go(file_path, content)),
        "java" => Some(java::parse_java(file_path, content)),
        _ => None,
    }
}

/// Runs Tier-2 AST structural and security analysis over source code.
pub fn scan_ast(file_path: &str, content: &str, finding_counter: &mut usize) -> Vec<Finding> {
    if let Some(file_node) = parse_file(file_path, content) {
        security::analyze_ast_security(&file_node, finding_counter)
    } else {
        Vec::new()
    }
}
