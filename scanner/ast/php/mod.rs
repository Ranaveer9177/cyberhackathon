#![allow(dead_code)]

use crate::ast::types::{
    AssignmentNode, ClassNode, ConstantKind, ExprNode, FileNode, FunctionNode, ImportNode,
    ReturnNode, StmtNode,
};
use regex::Regex;

pub fn parse_php(file_path: &str, content: &str) -> FileNode {
    let mut file_node = FileNode {
        file_path: file_path.to_string(),
        language: "php".to_string(),
        ..Default::default()
    };

    let lines: Vec<&str> = content.lines().collect();
    let num_lines = lines.len();

    let func_re = Regex::new(
        r#"(?:public|protected|private|static|\s)*function\s+(?P<name>[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\((?P<params>[^)]*)\)"#,
    ).unwrap();
    let class_re = Regex::new(
        r#"(?:final\s+|abstract\s+)?class\s+(?P<name>[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)(?:\s+extends\s+(?P<base>[a-zA-Z_\x7f-\xff0-9\\]+))?"#,
    ).unwrap();
    let use_re =
        Regex::new(r#"^\s*use\s+(?P<ns>[a-zA-Z0-9_\\]+)(?:\s+as\s+(?P<alias>[a-zA-Z0-9_]+))?;"#)
            .unwrap();
    let require_re = Regex::new(
        r#"^\s*(?:require|require_once|include|include_once)\s*\(?['"](?P<file>[^'"]+)['"]\)?;"#,
    )
    .unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?P<target>\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*(?:->[a-zA-Z0-9_]+|\[[^\]]+\])?)\s*=\s*(?P<val>[^;]+);$"#,
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return(?:\s+(?P<val>[^;]+))?;$"#).unwrap();

    let mut current_class: Option<(ClassNode, i32)> = None;
    let mut brace_depth: i32 = 0;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with("<?php")
            || trimmed.starts_with("?>")
        {
            continue;
        }

        // Use / Namespace imports
        if let Some(caps) = use_re.captures(trimmed) {
            let ns = caps.name("ns").map_or("", |s| s.as_str()).to_string();
            let alias = caps.name("alias").map(|s| s.as_str().to_string());
            file_node.imports.push(ImportNode {
                module: ns.clone(),
                symbols: vec![ns],
                alias,
                line: line_num,
            });
            continue;
        }

        // Require / Include
        if let Some(caps) = require_re.captures(trimmed) {
            let f = caps.name("file").map_or("", |s| s.as_str()).to_string();
            file_node.imports.push(ImportNode {
                module: f.clone(),
                symbols: vec![f],
                alias: None,
                line: line_num,
            });
            continue;
        }

        // Classes
        if let Some(caps) = class_re.captures(trimmed) {
            let name = caps.name("name").map_or("", |s| s.as_str()).to_string();
            let base = caps
                .name("base")
                .map(|b| vec![b.as_str().to_string()])
                .unwrap_or_default();
            current_class = Some((
                ClassNode {
                    name,
                    base_classes: base,
                    methods: Vec::new(),
                    fields: Vec::new(),
                    line: line_num,
                    end_line: line_num,
                },
                brace_depth,
            ));
        }

        // Functions / Methods
        if let Some(caps) = func_re.captures(trimmed) {
            let name = caps.name("name").map_or("", |s| s.as_str()).to_string();
            let mut params = Vec::new();
            if let Some(p) = caps.name("params") {
                for param in p.as_str().split(',') {
                    let cleaned = param.trim();
                    if !cleaned.is_empty() {
                        let param_name = cleaned
                            .split_whitespace()
                            .last()
                            .unwrap_or(cleaned)
                            .trim_start_matches('&')
                            .to_string();
                        params.push(param_name);
                    }
                }
            }

            let func = FunctionNode {
                name,
                params,
                body: Vec::new(),
                is_method: current_class.is_some(),
                line: line_num,
                end_line: line_num,
            };
            if let Some((ref mut cls, _)) = current_class {
                cls.methods.push(func.clone());
            }
            file_node.functions.push(func);
        }

        // Assignments
        if let Some(caps) = assign_re.captures(trimmed) {
            let target = caps.name("target").map_or("", |s| s.as_str()).trim();
            let val = caps.name("val").map_or("", |s| s.as_str()).trim();

            file_node
                .statements
                .push(StmtNode::Assignment(AssignmentNode {
                    target: ExprNode::Identifier {
                        name: target.to_string(),
                        line: line_num,
                    },
                    value: ExprNode::Constant {
                        kind: ConstantKind::String(val.to_string()),
                        raw: val.to_string(),
                        line: line_num,
                    },
                    line: line_num,
                }));
        }

        // Returns
        if let Some(caps) = return_re.captures(trimmed) {
            let val = caps.name("val").map(|s| s.as_str().trim().to_string());
            file_node.statements.push(StmtNode::Return(ReturnNode {
                value: val.map(|v| ExprNode::Constant {
                    kind: ConstantKind::String(v.clone()),
                    raw: v,
                    line: line_num,
                }),
                line: line_num,
            }));
        }

        // Track braces
        for c in line.chars() {
            if c == '{' {
                brace_depth += 1;
            } else if c == '}' {
                brace_depth -= 1;
                if let Some((mut cls, start_depth)) = current_class.take() {
                    if brace_depth <= start_depth {
                        cls.end_line = line_num;
                        file_node.classes.push(cls);
                    } else {
                        current_class = Some((cls, start_depth));
                    }
                }
            }
        }
    }

    if let Some((mut cls, _)) = current_class {
        cls.end_line = num_lines;
        file_node.classes.push(cls);
    }

    file_node
}
