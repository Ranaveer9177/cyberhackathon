#![allow(dead_code)]

use crate::ast::types::{
    AssignmentNode, ClassNode, ConstantKind, ExprNode, FileNode, FunctionNode, ImportNode,
    ReturnNode, StmtNode,
};
use regex::Regex;

pub fn parse_ruby(file_path: &str, content: &str) -> FileNode {
    let mut file_node = FileNode {
        file_path: file_path.to_string(),
        language: "ruby".to_string(),
        ..Default::default()
    };

    let lines: Vec<&str> = content.lines().collect();
    let num_lines = lines.len();

    let def_re = Regex::new(
        r#"^\s*def\s+(?P<name>[a-zA-Z_0-9.!?]+)(?:\s*\((?P<params>[^)]*)\)|\s+(?P<bare_params>[a-zA-Z0-9_, ]+))?"#,
    ).unwrap();
    let class_re =
        Regex::new(r#"^\s*class\s+(?P<name>[a-zA-Z0-9_:]+)(?:\s*<\s*(?P<base>[a-zA-Z0-9_:]+))?"#)
            .unwrap();
    let require_re =
        Regex::new(r#"^\s*(?:require|require_relative|load)\s+['"](?P<mod>[^'"]+)['"]"#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?P<target>[$@a-zA-Z_][a-zA-Z0-9_]*(?:\[[^\]]+\])?)\s*=\s*(?P<val>[^#]+)"#,
    )
    .unwrap();
    let return_re = Regex::new(r#"^\s*return(?:\s+(?P<val>.*))?$"#).unwrap();

    let mut current_class: Option<(ClassNode, usize)> = None;
    let mut block_depth = 0;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Imports / Requires
        if let Some(caps) = require_re.captures(trimmed) {
            let m = caps.name("mod").map_or("", |s| s.as_str()).to_string();
            file_node.imports.push(ImportNode {
                module: m.clone(),
                symbols: vec![m],
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
            block_depth += 1;
            current_class = Some((
                ClassNode {
                    name,
                    base_classes: base,
                    methods: Vec::new(),
                    fields: Vec::new(),
                    line: line_num,
                    end_line: line_num,
                },
                block_depth,
            ));
            continue;
        }

        // Functions
        if let Some(caps) = def_re.captures(trimmed) {
            let name = caps.name("name").map_or("", |s| s.as_str()).to_string();
            let mut params = Vec::new();
            if let Some(p) = caps.name("params").or_else(|| caps.name("bare_params")) {
                for param in p.as_str().split(',') {
                    let cleaned = param.trim();
                    if !cleaned.is_empty() {
                        params.push(cleaned.to_string());
                    }
                }
            }
            block_depth += 1;
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
            continue;
        }

        // Other block openers
        if trimmed.starts_with("module ")
            || trimmed.starts_with("if ")
            || trimmed.starts_with("unless ")
            || trimmed.starts_with("case ")
            || trimmed.starts_with("while ")
            || trimmed.starts_with("until ")
            || trimmed.starts_with("for ")
            || trimmed.ends_with(" do")
            || trimmed == "do"
            || trimmed.starts_with("begin")
        {
            block_depth += 1;
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

        // Block closers
        if trimmed == "end" || trimmed.starts_with("end ") {
            if let Some((mut cls, start_depth)) = current_class.take() {
                if block_depth == start_depth {
                    cls.end_line = line_num;
                    file_node.classes.push(cls);
                } else {
                    current_class = Some((cls, start_depth));
                }
            }
            block_depth = block_depth.saturating_sub(1);
        }
    }

    if let Some((mut cls, _)) = current_class {
        cls.end_line = num_lines;
        file_node.classes.push(cls);
    }

    file_node
}
