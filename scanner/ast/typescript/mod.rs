#![allow(dead_code)]

use crate::ast::javascript::{parse_javascript, parse_js_expr};
use crate::ast::types::{ExprNode, FileNode};
use regex::Regex;

pub fn parse_typescript(file_path: &str, content: &str) -> FileNode {
    // Strip type definitions/interfaces so the standard structural JS parser can process syntax cleanly
    let interface_re =
        Regex::new(r#"(?ms)^\s*interface\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\{[^}]*\}"#).unwrap();
    let type_alias_re = Regex::new(r#"^\s*type\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=[^;]+;"#).unwrap();

    let clean1 = interface_re.replace_all(content, "");
    let mut clean_lines = Vec::new();
    for line in clean1.lines() {
        if type_alias_re.is_match(line) {
            clean_lines.push("");
        } else {
            clean_lines.push(line);
        }
    }
    let preprocessed = clean_lines.join("\n");

    let mut file_node = parse_javascript(file_path, &preprocessed);
    file_node.language = "typescript".to_string();
    file_node
}

pub fn parse_ts_expr(raw: &str, line: usize) -> ExprNode {
    // Strip "as Type" casting if present e.g. `param as string`
    let trimmed = raw.trim();
    let clean = if let Some(as_idx) = trimmed.rfind(" as ") {
        &trimmed[..as_idx]
    } else {
        trimmed
    };
    parse_js_expr(clean, line)
}
