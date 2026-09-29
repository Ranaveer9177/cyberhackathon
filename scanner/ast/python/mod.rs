#![allow(dead_code)]

use crate::ast::types::{
    AssignmentNode, ClassNode, ConditionNode, ConstantKind, ExprNode, FileNode, FunctionNode,
    ImportNode, LoopNode, ReturnNode, StmtNode, TryCatchNode,
};
use regex::Regex;

pub fn parse_python(file_path: &str, content: &str) -> FileNode {
    let mut file_node = FileNode {
        file_path: file_path.to_string(),
        language: "python".to_string(),
        ..Default::default()
    };

    let lines: Vec<&str> = content.lines().collect();
    let num_lines = lines.len();

    let def_re = Regex::new(
        r#"^(?P<indent>\s*)def\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)"#,
    )
    .unwrap();
    let class_re = Regex::new(
        r#"^(?P<indent>\s*)class\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)(?:\((?P<bases>[^)]*)\))?\s*:"#,
    )
    .unwrap();
    let import_re = Regex::new(r#"^(?P<indent>\s*)import\s+(?P<module>[^\n#;]+)"#).unwrap();
    let from_import_re = Regex::new(
        r#"^(?P<indent>\s*)from\s+(?P<module>[a-zA-Z0-9_.]+)\s+import\s+(?P<symbols>[^\n#;]+)"#,
    )
    .unwrap();
    let assign_re = Regex::new(
        r#"^(?P<indent>\s*)(?P<target>[a-zA-Z0-9_.]+(?:\[[^\]]+\])?)\s*=\s*(?P<val>.+)$"#,
    )
    .unwrap();
    let return_re = Regex::new(r#"^(?P<indent>\s*)return(?:\s+(?P<val>.+))?$"#).unwrap();
    let call_stmt_re =
        Regex::new(r#"^(?P<indent>\s*)(?P<callee>[a-zA-Z0-9_.]+)\s*\((?P<args>.*)\)\s*$"#).unwrap();

    let mut idx = 0;
    while idx < num_lines {
        let line = lines[idx];
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('@') {
            idx += 1;
            continue;
        }

        // Imports
        if let Some(caps) = from_import_re.captures(line) {
            let module = caps.name("module").map_or("", |m| m.as_str()).to_string();
            let raw_syms = caps.name("symbols").map_or("", |m| m.as_str());
            let symbols = raw_syms
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            file_node.imports.push(ImportNode {
                module,
                symbols,
                alias: None,
                line: line_num,
            });
            idx += 1;
            continue;
        }

        if let Some(caps) = import_re.captures(line) {
            let module = caps.name("module").map_or("", |m| m.as_str()).to_string();
            file_node.imports.push(ImportNode {
                module: module.clone(),
                symbols: vec![module],
                alias: None,
                line: line_num,
            });
            idx += 1;
            continue;
        }

        // Class
        if let Some(caps) = class_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let bases_raw = caps.name("bases").map_or("", |m| m.as_str());
            let base_classes = bases_raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let indent_len = caps.name("indent").map_or(0, |m| m.as_str().len());
            let (next_idx, methods, fields) =
                parse_class_body(&lines, idx + 1, indent_len, line_num);

            file_node.classes.push(ClassNode {
                name,
                base_classes,
                methods,
                fields,
                line: line_num,
                end_line: next_idx,
            });
            idx = next_idx;
            continue;
        }

        // Function
        if let Some(caps) = def_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let raw_params = caps.name("params").map_or("", |m| m.as_str());
            let params = parse_params(raw_params);
            let indent_len = caps.name("indent").map_or(0, |m| m.as_str().len());

            let (next_idx, body) = parse_body(&lines, idx + 1, indent_len, line_num);

            file_node.functions.push(FunctionNode {
                name,
                params,
                body,
                is_method: false,
                line: line_num,
                end_line: next_idx,
            });
            idx = next_idx;
            continue;
        }

        // Top-level statements
        if let Some(caps) = assign_re.captures(line) {
            let target_str = caps.name("target").map_or("", |m| m.as_str());
            let val_str = caps.name("val").map_or("", |m| m.as_str());
            let target = parse_expr(target_str, line_num);
            let value = parse_expr(val_str, line_num);
            file_node
                .statements
                .push(StmtNode::Assignment(AssignmentNode {
                    target,
                    value,
                    line: line_num,
                }));
        } else if let Some(caps) = return_re.captures(line) {
            let val_opt = caps.name("val").map(|m| parse_expr(m.as_str(), line_num));
            file_node.statements.push(StmtNode::Return(ReturnNode {
                value: val_opt,
                line: line_num,
            }));
        } else if call_stmt_re.is_match(line) {
            let expr = parse_expr(trimmed, line_num);
            file_node.statements.push(StmtNode::Call(expr));
        }

        idx += 1;
    }

    file_node
}

fn parse_params(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|p| {
            let trimmed = p.trim();
            // remove type annotations and defaults: `user_id: int = 1` -> `user_id`
            let without_type = trimmed.split(':').next().unwrap_or(trimmed);
            let name = without_type.split('=').next().unwrap_or(without_type);
            name.trim().to_string()
        })
        .filter(|p| !p.is_empty() && p != "self" && p != "cls")
        .collect()
}

fn parse_body(
    lines: &[&str],
    start_idx: usize,
    parent_indent: usize,
    _func_line: usize,
) -> (usize, Vec<StmtNode>) {
    let mut body = Vec::new();
    let mut idx = start_idx;

    let assign_re = Regex::new(
        r#"^(?P<indent>\s*)(?P<target>[a-zA-Z0-9_.]+(?:\[[^\]]+\])?)\s*=\s*(?P<val>.+)$"#,
    )
    .unwrap();
    let return_re = Regex::new(r#"^(?P<indent>\s*)return(?:\s+(?P<val>.+))?$"#).unwrap();

    while idx < lines.len() {
        let line = lines[idx];
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.is_empty() || trimmed.starts_with('#') {
            idx += 1;
            continue;
        }

        let current_indent = line.len() - line.trim_start().len();
        if current_indent <= parent_indent {
            break;
        }

        // Control flow: if / elif / else
        if trimmed.starts_with("if ") && trimmed.ends_with(':') {
            let test_str = trimmed[3..trimmed.len() - 1].trim();
            let test = parse_expr(test_str, line_num);
            let (next_idx, then_body) = parse_body(lines, idx + 1, current_indent, line_num);
            let mut else_body = Vec::new();
            idx = next_idx;

            if idx < lines.len() {
                let next_line = lines[idx];
                let next_trimmed = next_line.trim();
                let next_indent = next_line.len() - next_line.trim_start().len();
                if next_indent == current_indent
                    && (next_trimmed == "else:" || next_trimmed.starts_with("else :"))
                {
                    let (else_end, parsed_else) =
                        parse_body(lines, idx + 1, current_indent, idx + 1);
                    else_body = parsed_else;
                    idx = else_end;
                }
            }

            body.push(StmtNode::Condition(ConditionNode {
                test,
                then_body,
                else_body,
                line: line_num,
            }));
            continue;
        }

        // Control flow: for / while loops
        if (trimmed.starts_with("for ") || trimmed.starts_with("while ")) && trimmed.ends_with(':')
        {
            let cond = if trimmed.starts_with("while ") {
                Some(parse_expr(trimmed[6..trimmed.len() - 1].trim(), line_num))
            } else {
                Some(parse_expr(trimmed[4..trimmed.len() - 1].trim(), line_num))
            };
            let (next_idx, loop_body) = parse_body(lines, idx + 1, current_indent, line_num);
            body.push(StmtNode::Loop(LoopNode {
                condition: cond,
                body: loop_body,
                line: line_num,
            }));
            idx = next_idx;
            continue;
        }

        // Control flow: try / except / finally
        if trimmed == "try:" || trimmed.starts_with("try :") {
            let (try_end, try_body) = parse_body(lines, idx + 1, current_indent, line_num);
            idx = try_end;
            let mut catch_body = Vec::new();
            let mut finally_body = Vec::new();

            while idx < lines.len() {
                let next_line = lines[idx];
                let next_trimmed = next_line.trim();
                let next_indent = next_line.len() - next_line.trim_start().len();
                if next_indent != current_indent {
                    break;
                }
                if next_trimmed.starts_with("except") && next_trimmed.ends_with(':') {
                    let (catch_end, parsed_catch) =
                        parse_body(lines, idx + 1, current_indent, idx + 1);
                    catch_body.extend(parsed_catch);
                    idx = catch_end;
                } else if next_trimmed == "finally:" || next_trimmed.starts_with("finally :") {
                    let (finally_end, parsed_finally) =
                        parse_body(lines, idx + 1, current_indent, idx + 1);
                    finally_body = parsed_finally;
                    idx = finally_end;
                } else {
                    break;
                }
            }

            body.push(StmtNode::TryCatch(TryCatchNode {
                try_body,
                catch_body,
                finally_body,
                line: line_num,
            }));
            continue;
        }

        if let Some(caps) = assign_re.captures(line) {
            let target_str = caps.name("target").map_or("", |m| m.as_str());
            let val_str = caps.name("val").map_or("", |m| m.as_str());
            body.push(StmtNode::Assignment(AssignmentNode {
                target: parse_expr(target_str, line_num),
                value: parse_expr(val_str, line_num),
                line: line_num,
            }));
        } else if let Some(caps) = return_re.captures(line) {
            let val_opt = caps.name("val").map(|m| parse_expr(m.as_str(), line_num));
            body.push(StmtNode::Return(ReturnNode {
                value: val_opt,
                line: line_num,
            }));
        } else if trimmed.contains('(') && trimmed.ends_with(')') {
            body.push(StmtNode::Call(parse_expr(trimmed, line_num)));
        } else {
            body.push(StmtNode::Expression(parse_expr(trimmed, line_num)));
        }

        idx += 1;
    }

    (idx, body)
}

fn parse_class_body(
    lines: &[&str],
    start_idx: usize,
    class_indent: usize,
    _class_line: usize,
) -> (usize, Vec<FunctionNode>, Vec<AssignmentNode>) {
    let mut methods = Vec::new();
    let mut fields = Vec::new();
    let mut idx = start_idx;

    let def_re = Regex::new(
        r#"^(?P<indent>\s*)def\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)"#,
    )
    .unwrap();
    let assign_re =
        Regex::new(r#"^(?P<indent>\s*)(?P<target>[a-zA-Z0-9_.]+)\s*=\s*(?P<val>.+)$"#).unwrap();

    while idx < lines.len() {
        let line = lines[idx];
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('@') {
            idx += 1;
            continue;
        }

        let current_indent = line.len() - line.trim_start().len();
        if current_indent <= class_indent {
            break;
        }

        if let Some(caps) = def_re.captures(line) {
            let name = caps.name("name").map_or("", |m| m.as_str()).to_string();
            let raw_params = caps.name("params").map_or("", |m| m.as_str());
            let params = parse_params(raw_params);
            let indent_len = caps.name("indent").map_or(0, |m| m.as_str().len());

            let (next_idx, body) = parse_body(lines, idx + 1, indent_len, line_num);

            methods.push(FunctionNode {
                name,
                params,
                body,
                is_method: true,
                line: line_num,
                end_line: next_idx,
            });
            idx = next_idx;
            continue;
        } else if let Some(caps) = assign_re.captures(line) {
            let target_str = caps.name("target").map_or("", |m| m.as_str());
            let val_str = caps.name("val").map_or("", |m| m.as_str());
            fields.push(AssignmentNode {
                target: parse_expr(target_str, line_num),
                value: parse_expr(val_str, line_num),
                line: line_num,
            });
        }

        idx += 1;
    }

    (idx, methods, fields)
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

pub fn parse_expr(raw: &str, line: usize) -> ExprNode {
    let trimmed = raw.trim();

    // 1. Python f-string
    if (trimmed.starts_with("f\"") && trimmed.ends_with('"'))
        || (trimmed.starts_with("f'") && trimmed.ends_with('\''))
    {
        let inner = &trimmed[2..trimmed.len() - 1];
        let mut parts = Vec::new();
        let re = Regex::new(r#"\{([^}]+)\}"#).unwrap();
        for cap in re.captures_iter(inner) {
            if let Some(m) = cap.get(1) {
                parts.push(parse_expr(m.as_str(), line));
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

    // 3. Integer literal
    if let Ok(val) = trimmed.parse::<i64>() {
        return ExprNode::Constant {
            kind: ConstantKind::Integer(val),
            raw: trimmed.to_string(),
            line,
        };
    }

    // 4. Boolean literal
    if trimmed == "True" || trimmed == "False" {
        return ExprNode::Constant {
            kind: ConstantKind::Boolean(trimmed == "True"),
            raw: trimmed.to_string(),
            line,
        };
    }

    // 5. None literal
    if trimmed == "None" {
        return ExprNode::Constant {
            kind: ConstantKind::Null,
            raw: trimmed.to_string(),
            line,
        };
    }

    // 6. List literal: [elem1, elem2, ...]
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1].trim();
        let mut elements = Vec::new();
        if !inner.is_empty() {
            for item in split_arg_list(inner) {
                elements.push(parse_expr(&item, line));
            }
        }
        return ExprNode::List { elements, line };
    }

    // 7. Binary operation (+)
    if trimmed.contains('+') {
        let parts: Vec<&str> = trimmed.splitn(2, '+').collect();
        if parts.len() == 2 {
            return ExprNode::BinaryOp {
                op: "+".to_string(),
                left: Box::new(parse_expr(parts[0], line)),
                right: Box::new(parse_expr(parts[1], line)),
                line,
            };
        }
    }

    // 8. Call: callee(args)
    if trimmed.ends_with(')') {
        let mut depth = 0;
        let mut matching_open = None;
        for (i, c) in trimmed.char_indices().rev() {
            if c == ')' {
                depth += 1;
            } else if c == '(' {
                depth -= 1;
                if depth == 0 {
                    matching_open = Some(i);
                    break;
                }
            }
        }
        if let Some(open_paren) = matching_open {
            let callee_str = trimmed[..open_paren].trim();
            if !callee_str.is_empty() {
                let args_str = trimmed[open_paren + 1..trimmed.len() - 1].trim();
                let callee = Box::new(parse_expr(callee_str, line));
                let mut args = Vec::new();
                if !args_str.is_empty() {
                    for a in split_arg_list(args_str) {
                        args.push(parse_expr(&a, line));
                    }
                }
                return ExprNode::Call { callee, args, line };
            }
        }
    }

    // 9. Subscript: value[slice]
    if let Some(open_bracket) = trimmed.find('[') {
        if open_bracket > 0 && trimmed.ends_with(']') {
            let val_str = &trimmed[..open_bracket].trim();
            let slice_str = &trimmed[open_bracket + 1..trimmed.len() - 1].trim();
            return ExprNode::Subscript {
                value: Box::new(parse_expr(val_str, line)),
                slice: Box::new(parse_expr(slice_str, line)),
                line,
            };
        }
    }

    // 10. Attribute: obj.attr
    if let Some(dot_idx) = trimmed.rfind('.') {
        let obj_str = &trimmed[..dot_idx].trim();
        let attr_str = &trimmed[dot_idx + 1..].trim();
        if !obj_str.is_empty() && !attr_str.is_empty() {
            return ExprNode::Attribute {
                value: Box::new(parse_expr(obj_str, line)),
                attr: attr_str.to_string(),
                line,
            };
        }
    }

    // 11. Identifier fallback
    ExprNode::Identifier {
        name: trimmed.to_string(),
        line,
    }
}
