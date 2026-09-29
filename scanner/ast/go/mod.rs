#![allow(dead_code)]

use crate::ast::types::{
    AssignmentNode, ClassNode, ConstantKind, ExprNode, FileNode, FunctionNode, ImportNode,
    ReturnNode, StmtNode,
};
use regex::Regex;

pub fn parse_go(file_path: &str, content: &str) -> FileNode {
    let mut file_node = FileNode {
        file_path: file_path.to_string(),
        language: "go".to_string(),
        ..Default::default()
    };

    let lines: Vec<&str> = content.lines().collect();
    let num_lines = lines.len();

    let func_re = Regex::new(
        r#"^func\s+(?:\((?P<recv>[^)]+)\)\s+)?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)"#,
    )
    .unwrap();
    let type_struct_re =
        Regex::new(r#"^type\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s+struct\s*\{"#).unwrap();
    let single_import_re = Regex::new(r#"^import\s+['"](?P<pkg>[^'"]+)['"]"#).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:var\s+)?(?P<target>[a-zA-Z0-9_.*]+(?:\s*,\s*[a-zA-Z0-9_.*]+)?)\s*(?::=|=)\s*(?P<val>.+)$"#,
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return(?:\s+(?P<val>.+))?$"#).unwrap();

    let mut in_import_block = false;
    let mut idx = 0;

    while idx < num_lines {
        let line = lines[idx];
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.is_empty() || trimmed.starts_with("//") {
            idx += 1;
            continue;
        }

        // Import block
        if trimmed == "import (" {
            in_import_block = true;
            idx += 1;
            continue;
        }

        if in_import_block {
            if trimmed == ")" {
                in_import_block = false;
            } else if trimmed.starts_with('"') && trimmed.ends_with('"') {
                let pkg = trimmed.trim_matches('"').to_string();
                file_node.imports.push(ImportNode {
                    module: pkg.clone(),
                    symbols: vec![pkg],
                    alias: None,
                    line: line_num,
                });
            }
            idx += 1;
            continue;
        }

        // Single line import
        if let Some(caps) = single_import_re.captures(line) {
            let pkg = caps.name("pkg").map_or("", |m| m.as_str()).to_string();
            file_node.imports.push(ImportNode {
                module: pkg.clone(),
                symbols: vec![pkg],
                alias: None,
                line: line_num,
            });
            idx += 1;
            continue;
        }

        // Struct (treated as class)
        if let Some(caps) = type_struct_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let (end_line, _) = parse_go_block(&lines, idx, line_num);
            file_node.classes.push(ClassNode {
                name,
                base_classes: Vec::new(),
                methods: Vec::new(),
                fields: Vec::new(),
                line: line_num,
                end_line,
            });
            idx = end_line + 1;
            continue;
        }

        // Function / Method
        if let Some(caps) = func_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let is_method = caps.name("recv").is_some();
            let params = parse_go_params(caps.name("params").map_or("", |m| m.as_str()));
            let (end_line, body) = parse_go_block(&lines, idx, line_num);

            file_node.functions.push(FunctionNode {
                name,
                params,
                body,
                is_method,
                line: line_num,
                end_line,
            });
            idx = end_line + 1;
            continue;
        }

        // Top level statements
        if let Some(caps) = assign_re.captures(line) {
            let target_str = caps.name("target").map_or("", |m| m.as_str());
            let val_str = caps.name("val").map_or("", |m| m.as_str());
            file_node
                .statements
                .push(StmtNode::Assignment(AssignmentNode {
                    target: parse_go_expr(target_str, line_num),
                    value: parse_go_expr(val_str, line_num),
                    line: line_num,
                }));
        } else if let Some(caps) = return_re.captures(line) {
            let val_opt = caps
                .name("val")
                .map(|m| parse_go_expr(m.as_str(), line_num));
            file_node.statements.push(StmtNode::Return(ReturnNode {
                value: val_opt,
                line: line_num,
            }));
        } else if trimmed.contains('(') && trimmed.ends_with(')') {
            file_node
                .statements
                .push(StmtNode::Call(parse_go_expr(trimmed, line_num)));
        }

        idx += 1;
    }

    file_node
}

fn parse_go_params(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|p| {
            let trimmed = p.trim();
            let name = trimmed.split_whitespace().next().unwrap_or(trimmed);
            name.trim().to_string()
        })
        .filter(|p| !p.is_empty())
        .collect()
}

fn parse_go_block(lines: &[&str], start_idx: usize, start_line: usize) -> (usize, Vec<StmtNode>) {
    let mut body = Vec::new();
    let mut depth = 0;
    let mut seen_open = false;
    let mut idx = start_idx;
    let mut end_line = start_line;

    let assign_re = Regex::new(
        r#"^\s*(?:var\s+)?(?P<target>[a-zA-Z0-9_.*]+(?:\s*,\s*[a-zA-Z0-9_.*]+)?)\s*(?::=|=)\s*(?P<val>.+)$"#,
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return(?:\s+(?P<val>.+))?$"#).unwrap();

    while idx < lines.len() {
        let line = lines[idx];
        let trimmed = line.trim();
        let line_num = idx + 1;

        for c in line.chars() {
            if c == '{' {
                depth += 1;
                seen_open = true;
            } else if c == '}' {
                depth -= 1;
            }
        }

        if seen_open && depth <= 0 {
            end_line = line_num;
            break;
        }

        if !trimmed.is_empty() && !trimmed.starts_with("//") {
            if let Some(caps) = assign_re.captures(line) {
                let target_str = caps.name("target").map_or("", |m| m.as_str());
                let val_str = caps.name("val").map_or("", |m| m.as_str());
                body.push(StmtNode::Assignment(AssignmentNode {
                    target: parse_go_expr(target_str, line_num),
                    value: parse_go_expr(val_str, line_num),
                    line: line_num,
                }));
            } else if let Some(caps) = return_re.captures(line) {
                let val_opt = caps
                    .name("val")
                    .map(|m| parse_go_expr(m.as_str(), line_num));
                body.push(StmtNode::Return(ReturnNode {
                    value: val_opt,
                    line: line_num,
                }));
            } else if trimmed.contains('(') && trimmed.ends_with(')') {
                body.push(StmtNode::Call(parse_go_expr(trimmed, line_num)));
            }
        }

        end_line = line_num;
        idx += 1;
    }

    (end_line, body)
}

pub fn parse_go_expr(raw: &str, line: usize) -> ExprNode {
    let trimmed = raw.trim();

    // 1. String literal
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
    {
        let content = if trimmed.len() >= 2 {
            &trimmed[1..trimmed.len() - 1]
        } else {
            ""
        };
        return ExprNode::Constant {
            kind: ConstantKind::String(content.to_string()),
            raw: trimmed.to_string(),
            line,
        };
    }

    // 2. Integer
    if let Ok(val) = trimmed.parse::<i64>() {
        return ExprNode::Constant {
            kind: ConstantKind::Integer(val),
            raw: trimmed.to_string(),
            line,
        };
    }

    // 3. Boolean
    if trimmed == "true" || trimmed == "false" {
        return ExprNode::Constant {
            kind: ConstantKind::Boolean(trimmed == "true"),
            raw: trimmed.to_string(),
            line,
        };
    }

    // 4. nil
    if trimmed == "nil" {
        return ExprNode::Constant {
            kind: ConstantKind::Null,
            raw: trimmed.to_string(),
            line,
        };
    }

    // 5. Binary op (+)
    if trimmed.contains('+') {
        let parts: Vec<&str> = trimmed.splitn(2, '+').collect();
        if parts.len() == 2 {
            return ExprNode::BinaryOp {
                op: "+".to_string(),
                left: Box::new(parse_go_expr(parts[0], line)),
                right: Box::new(parse_go_expr(parts[1], line)),
                line,
            };
        }
    }

    // 6. Call
    if let Some(open_paren) = trimmed.find('(') {
        if trimmed.ends_with(')') {
            let callee_str = &trimmed[..open_paren].trim();
            let args_str = &trimmed[open_paren + 1..trimmed.len() - 1].trim();
            let callee = Box::new(parse_go_expr(callee_str, line));
            let mut args = Vec::new();
            if !args_str.is_empty() {
                for a in args_str.split(',') {
                    args.push(parse_go_expr(a.trim(), line));
                }
            }
            return ExprNode::Call { callee, args, line };
        }
    }

    // 7. Attribute / Selector
    if let Some(dot_idx) = trimmed.rfind('.') {
        let obj_str = &trimmed[..dot_idx].trim();
        let attr_str = &trimmed[dot_idx + 1..].trim();
        if !obj_str.is_empty() && !attr_str.is_empty() {
            return ExprNode::Attribute {
                value: Box::new(parse_go_expr(obj_str, line)),
                attr: attr_str.to_string(),
                line,
            };
        }
    }

    ExprNode::Identifier {
        name: trimmed.to_string(),
        line,
    }
}
