#![allow(dead_code)]

use crate::ast::types::{
    AssignmentNode, ClassNode, ConstantKind, ExprNode, FileNode, FunctionNode, ImportNode,
    ReturnNode, StmtNode,
};
use regex::Regex;

pub fn parse_javascript(file_path: &str, content: &str) -> FileNode {
    let mut file_node = FileNode {
        file_path: file_path.to_string(),
        language: "javascript".to_string(),
        ..Default::default()
    };

    let lines: Vec<&str> = content.lines().collect();
    let num_lines = lines.len();

    let func_re = Regex::new(
        r#"(?:async\s+)?function\s+(?P<name>[a-zA-Z_$][a-zA-Z0-9_$]*)\s*\((?P<params>[^)]*)\)"#,
    )
    .unwrap();
    let arrow_func_re = Regex::new(
        r#"(?:const|let|var)\s+(?P<name>[a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s*)?\((?P<params>[^)]*)\)\s*=>"#,
    ).unwrap();
    let class_re = Regex::new(
        r#"class\s+(?P<name>[a-zA-Z_$][a-zA-Z0-9_$]*)(?:\s+extends\s+(?P<base>[a-zA-Z_$][a-zA-Z0-9_$]*))?"#,
    ).unwrap();
    let import_re = Regex::new(
        r#"import\s+(?:(?P<default>[a-zA-Z_$][a-zA-Z0-9_$]*)|(?:\{\s*(?P<named>[^}]+)\s*\}))\s+from\s+['"](?P<module>[^'"]+)['"]"#,
    ).unwrap();
    let require_re = Regex::new(
        r#"(?:const|let|var)\s+(?:(?P<name>[a-zA-Z_$][a-zA-Z0-9_$]*)|(?:\{\s*(?P<destruct>[^}]+)\s*\}))\s*=\s*require\(['"](?P<module>[^'"]+)['"]\)"#,
    ).unwrap();
    let assign_re = Regex::new(
        r#"^\s*(?:(?:const|let|var)\s+)?(?P<target>[a-zA-Z_$][a-zA-Z0-9_$.]*(?:\[[^\]]+\])?)\s*=\s*(?P<val>[^;]+);?$"#,
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return(?:\s+(?P<val>[^;]+))?;?$"#).unwrap();

    let mut idx = 0;
    while idx < num_lines {
        let line = lines[idx];
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
            idx += 1;
            continue;
        }

        // ES6 imports
        if let Some(caps) = import_re.captures(line) {
            let module = caps.name("module").map_or("", |m| m.as_str()).to_string();
            let mut symbols = Vec::new();
            if let Some(def) = caps.name("default") {
                symbols.push(def.as_str().to_string());
            }
            if let Some(named) = caps.name("named") {
                for s in named.as_str().split(',') {
                    let clean = s.trim().to_string();
                    if !clean.is_empty() {
                        symbols.push(clean);
                    }
                }
            }
            file_node.imports.push(ImportNode {
                module,
                symbols,
                alias: None,
                line: line_num,
            });
            idx += 1;
            continue;
        }

        // CommonJS require
        if let Some(caps) = require_re.captures(line) {
            let module = caps.name("module").map_or("", |m| m.as_str()).to_string();
            let mut symbols = Vec::new();
            if let Some(name) = caps.name("name") {
                symbols.push(name.as_str().to_string());
            }
            if let Some(destruct) = caps.name("destruct") {
                for s in destruct.as_str().split(',') {
                    let clean = s.trim().to_string();
                    if !clean.is_empty() {
                        symbols.push(clean);
                    }
                }
            }
            file_node.imports.push(ImportNode {
                module,
                symbols,
                alias: None,
                line: line_num,
            });
            idx += 1;
            continue;
        }

        // Class
        if let Some(caps) = class_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let base = caps
                .name("base")
                .map(|b| vec![b.as_str().to_string()])
                .unwrap_or_default();
            let (end_line, methods, fields) = parse_js_class_block(&lines, idx, line_num);
            file_node.classes.push(ClassNode {
                name,
                base_classes: base,
                methods,
                fields,
                line: line_num,
                end_line,
            });
            idx = end_line + 1;
            continue;
        }

        // Standard function
        if let Some(caps) = func_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let params = parse_js_params(caps.name("params").map_or("", |m| m.as_str()));
            let (end_line, body) = parse_js_block(&lines, idx, line_num);
            file_node.functions.push(FunctionNode {
                name,
                params,
                body,
                is_method: false,
                line: line_num,
                end_line,
            });
            idx = end_line + 1;
            continue;
        }

        // Arrow function assignment
        if let Some(caps) = arrow_func_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let params = parse_js_params(caps.name("params").map_or("", |m| m.as_str()));
            let (end_line, body) = parse_js_block(&lines, idx, line_num);
            file_node.functions.push(FunctionNode {
                name,
                params,
                body,
                is_method: false,
                line: line_num,
                end_line,
            });
            idx = end_line + 1;
            continue;
        }

        // Statements
        if let Some(caps) = assign_re.captures(line) {
            let target_str = caps.name("target").map_or("", |m| m.as_str());
            let val_str = caps.name("val").map_or("", |m| m.as_str());
            file_node
                .statements
                .push(StmtNode::Assignment(AssignmentNode {
                    target: parse_js_expr(target_str, line_num),
                    value: parse_js_expr(val_str, line_num),
                    line: line_num,
                }));
        } else if let Some(caps) = return_re.captures(line) {
            let val_opt = caps
                .name("val")
                .map(|m| parse_js_expr(m.as_str(), line_num));
            file_node.statements.push(StmtNode::Return(ReturnNode {
                value: val_opt,
                line: line_num,
            }));
        } else if trimmed.contains('(') && (trimmed.ends_with(')') || trimmed.ends_with(");")) {
            let clean = trimmed.trim_end_matches(';');
            file_node
                .statements
                .push(StmtNode::Call(parse_js_expr(clean, line_num)));
        }

        idx += 1;
    }

    file_node
}

fn parse_js_params(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|p| {
            let trimmed = p.trim();
            let without_type = trimmed.split(':').next().unwrap_or(trimmed);
            let name = without_type.split('=').next().unwrap_or(without_type);
            name.trim().to_string()
        })
        .filter(|p| !p.is_empty())
        .collect()
}

fn parse_js_block(lines: &[&str], start_idx: usize, start_line: usize) -> (usize, Vec<StmtNode>) {
    let mut body = Vec::new();
    let mut depth = 0;
    let mut seen_open = false;
    let mut idx = start_idx;
    let mut end_line = start_line;

    let assign_re = Regex::new(
        r#"^(?:\s*(?:const|let|var)\s+)?(?P<target>[a-zA-Z_$][a-zA-Z0-9_$.]*(?:\[[^\]]+\])?)\s*=\s*(?P<val>[^;]+);?$"#,
    ).unwrap();
    let return_re = Regex::new(r#"^\s*return(?:\s+(?P<val>[^;]+))?;?$"#).unwrap();

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
                    target: parse_js_expr(target_str, line_num),
                    value: parse_js_expr(val_str, line_num),
                    line: line_num,
                }));
            } else if let Some(caps) = return_re.captures(line) {
                let val_opt = caps
                    .name("val")
                    .map(|m| parse_js_expr(m.as_str(), line_num));
                body.push(StmtNode::Return(ReturnNode {
                    value: val_opt,
                    line: line_num,
                }));
            } else if trimmed.contains('(') && (trimmed.ends_with(')') || trimmed.ends_with(");")) {
                let clean = trimmed.trim_end_matches(';');
                body.push(StmtNode::Call(parse_js_expr(clean, line_num)));
            }
        }

        end_line = line_num;
        idx += 1;
    }

    (end_line, body)
}

fn parse_js_class_block(
    lines: &[&str],
    start_idx: usize,
    class_line: usize,
) -> (usize, Vec<FunctionNode>, Vec<AssignmentNode>) {
    let mut methods = Vec::new();
    let fields = Vec::new();
    let mut depth = 0;
    let mut seen_open = false;
    let mut idx = start_idx;
    let mut end_line = class_line;

    let method_re = Regex::new(
        r#"^\s*(?:async\s+)?(?P<name>[a-zA-Z_$][a-zA-Z0-9_$]*)\s*\((?P<params>[^)]*)\)\s*\{"#,
    )
    .unwrap();

    while idx < lines.len() {
        let line = lines[idx];
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

        if let Some(caps) = method_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let params = parse_js_params(caps.name("params").map_or("", |m| m.as_str()));
            let (m_end, body) = parse_js_block(lines, idx, line_num);
            methods.push(FunctionNode {
                name,
                params,
                body,
                is_method: true,
                line: line_num,
                end_line: m_end,
            });
            idx = m_end;
        }

        end_line = line_num;
        idx += 1;
    }

    (end_line, methods, fields)
}

pub fn parse_js_expr(raw: &str, line: usize) -> ExprNode {
    let trimmed = raw.trim().trim_end_matches(';');

    // 1. Template literal (`` `SELECT ... ${user}` ``)
    if trimmed.starts_with('`') && trimmed.ends_with('`') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut parts = Vec::new();
        let re = Regex::new(r#"\$\{([^}]+)\}"#).unwrap();
        for cap in re.captures_iter(inner) {
            if let Some(m) = cap.get(1) {
                parts.push(parse_js_expr(m.as_str(), line));
            }
        }
        return ExprNode::FormattedString {
            parts,
            raw: trimmed.to_string(),
            line,
        };
    }

    // 2. String literal
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
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

    // 3. Integer / Float
    if let Ok(val) = trimmed.parse::<i64>() {
        return ExprNode::Constant {
            kind: ConstantKind::Integer(val),
            raw: trimmed.to_string(),
            line,
        };
    }

    // 4. Boolean
    if trimmed == "true" || trimmed == "false" {
        return ExprNode::Constant {
            kind: ConstantKind::Boolean(trimmed == "true"),
            raw: trimmed.to_string(),
            line,
        };
    }

    // 5. Null / Undefined
    if trimmed == "null" || trimmed == "undefined" {
        return ExprNode::Constant {
            kind: ConstantKind::Null,
            raw: trimmed.to_string(),
            line,
        };
    }

    pub fn split_arg_list(s: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut paren_depth = 0;
        let mut bracket_depth = 0;
        let mut brace_depth = 0;
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut escape = false;

        for c in s.chars() {
            if escape {
                current.push(c);
                escape = false;
                continue;
            }
            if c == '\\' {
                current.push(c);
                escape = true;
                continue;
            }

            if in_single_quote {
                current.push(c);
                if c == '\'' {
                    in_single_quote = false;
                }
                continue;
            }
            if in_double_quote {
                current.push(c);
                if c == '"' {
                    in_double_quote = false;
                }
                continue;
            }

            match c {
                '\'' => {
                    in_single_quote = true;
                    current.push(c);
                }
                '"' => {
                    in_double_quote = true;
                    current.push(c);
                }
                '(' => {
                    paren_depth += 1;
                    current.push(c);
                }
                ')' => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    current.push(c);
                }
                '[' => {
                    bracket_depth += 1;
                    current.push(c);
                }
                ']' => {
                    if bracket_depth > 0 {
                        bracket_depth -= 1;
                    }
                    current.push(c);
                }
                '{' => {
                    brace_depth += 1;
                    current.push(c);
                }
                '}' => {
                    if brace_depth > 0 {
                        brace_depth -= 1;
                    }
                    current.push(c);
                }
                ',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        args.push(trimmed.to_string());
                    }
                    current.clear();
                }
                _ => {
                    current.push(c);
                }
            }
        }

        let trimmed = current.trim();
        if !trimmed.is_empty() {
            args.push(trimmed.to_string());
        }

        args
    }

    // 6. List literal: [elem1, elem2, ...]
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1].trim();
        let mut elements = Vec::new();
        if !inner.is_empty() {
            for item in split_arg_list(inner) {
                elements.push(parse_js_expr(&item, line));
            }
        }
        return ExprNode::List { elements, line };
    }

    // 7. Binary op (+)
    if trimmed.contains('+') {
        let parts: Vec<&str> = trimmed.splitn(2, '+').collect();
        if parts.len() == 2 {
            return ExprNode::BinaryOp {
                op: "+".to_string(),
                left: Box::new(parse_js_expr(parts[0], line)),
                right: Box::new(parse_js_expr(parts[1], line)),
                line,
            };
        }
    }

    // 8. Call
    if let Some(open_paren) = trimmed.find('(') {
        if trimmed.ends_with(')') {
            let callee_str = &trimmed[..open_paren].trim();
            let args_str = &trimmed[open_paren + 1..trimmed.len() - 1].trim();
            let callee = Box::new(parse_js_expr(callee_str, line));
            let mut args = Vec::new();
            if !args_str.is_empty() {
                for a in split_arg_list(args_str) {
                    args.push(parse_js_expr(a.trim(), line));
                }
            }
            return ExprNode::Call { callee, args, line };
        }
    }

    // 9. Subscript
    if let Some(open_bracket) = trimmed.find('[') {
        if open_bracket > 0 && trimmed.ends_with(']') {
            let val_str = &trimmed[..open_bracket].trim();
            let slice_str = &trimmed[open_bracket + 1..trimmed.len() - 1].trim();
            return ExprNode::Subscript {
                value: Box::new(parse_js_expr(val_str, line)),
                slice: Box::new(parse_js_expr(slice_str, line)),
                line,
            };
        }
    }

    // 10. Attribute
    if let Some(dot_idx) = trimmed.rfind('.') {
        let obj_str = &trimmed[..dot_idx].trim();
        let attr_str = &trimmed[dot_idx + 1..].trim();
        if !obj_str.is_empty() && !attr_str.is_empty() {
            return ExprNode::Attribute {
                value: Box::new(parse_js_expr(obj_str, line)),
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
