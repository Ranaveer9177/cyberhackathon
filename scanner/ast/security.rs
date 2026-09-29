#![allow(dead_code)]

use crate::ast::types::{ConstantKind, ExprNode, FileNode, FunctionNode, StmtNode};
use crate::types::{Category, Finding, Severity};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct VarInfo {
    name: String,
    assigned_line: usize,
    raw_expr: String,
    is_sql_fragment: bool,
    is_cmd_fragment: bool,
    is_constant: bool,
    untrusted_source: Option<String>,
}

pub fn analyze_ast_security(file_node: &FileNode, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Analyze top-level statements
    analyze_block_security(
        &file_node.statements,
        &[],
        &file_node.file_path,
        finding_counter,
        &mut findings,
    );

    // 2. Analyze functions
    for func in &file_node.functions {
        analyze_function_security(func, &file_node.file_path, finding_counter, &mut findings);
    }

    // 3. Analyze classes and their methods
    for cls in &file_node.classes {
        for method in &cls.methods {
            analyze_function_security(method, &file_node.file_path, finding_counter, &mut findings);
        }
    }

    findings
}

fn analyze_function_security(
    func: &FunctionNode,
    file_path: &str,
    finding_counter: &mut usize,
    findings: &mut Vec<Finding>,
) {
    analyze_block_security(
        &func.body,
        &func.params,
        file_path,
        finding_counter,
        findings,
    );
}

fn analyze_block_security(
    stmts: &[StmtNode],
    params: &[String],
    file_path: &str,
    finding_counter: &mut usize,
    findings: &mut Vec<Finding>,
) {
    let mut var_table: HashMap<String, VarInfo> = HashMap::new();

    // Register parameters as potential untrusted sources
    for p in params {
        var_table.insert(
            p.clone(),
            VarInfo {
                name: p.clone(),
                assigned_line: 0,
                raw_expr: p.clone(),
                is_sql_fragment: false,
                is_cmd_fragment: false,
                is_constant: false,
                untrusted_source: Some(format!("Function parameter '{}'", p)),
            },
        );
    }

    for stmt in stmts {
        match stmt {
            StmtNode::Assignment(assign) => {
                let target_name = assign.target.to_source_string();
                let line = assign.line;
                let val_str = assign.value.to_source_string();

                let is_sql = is_sql_expression(&assign.value, &var_table);
                let is_cmd = is_cmd_expression(&assign.value, &var_table);
                let is_const = is_constant_expression(&assign.value);

                let source = detect_untrusted_source(&assign.value, &var_table);

                var_table.insert(
                    target_name.clone(),
                    VarInfo {
                        name: target_name,
                        assigned_line: line,
                        raw_expr: val_str,
                        is_sql_fragment: is_sql,
                        is_cmd_fragment: is_cmd,
                        is_constant: is_const,
                        untrusted_source: source,
                    },
                );

                // If the assignment itself contains a call, inspect it as well
                inspect_call_in_expr(
                    &assign.value,
                    &var_table,
                    file_path,
                    finding_counter,
                    findings,
                );
            }
            StmtNode::Call(expr) => {
                inspect_call_in_expr(expr, &var_table, file_path, finding_counter, findings);
            }
            StmtNode::Return(ret) => {
                if let Some(val) = &ret.value {
                    inspect_call_in_expr(val, &var_table, file_path, finding_counter, findings);
                }
            }
            StmtNode::Condition(cond) => {
                inspect_call_in_expr(&cond.test, &var_table, file_path, finding_counter, findings);
                analyze_block_security(
                    &cond.then_body,
                    params,
                    file_path,
                    finding_counter,
                    findings,
                );
                analyze_block_security(
                    &cond.else_body,
                    params,
                    file_path,
                    finding_counter,
                    findings,
                );
            }
            StmtNode::Loop(loop_node) => {
                if let Some(c) = &loop_node.condition {
                    inspect_call_in_expr(c, &var_table, file_path, finding_counter, findings);
                }
                analyze_block_security(
                    &loop_node.body,
                    params,
                    file_path,
                    finding_counter,
                    findings,
                );
            }
            StmtNode::TryCatch(try_catch) => {
                analyze_block_security(
                    &try_catch.try_body,
                    params,
                    file_path,
                    finding_counter,
                    findings,
                );
                analyze_block_security(
                    &try_catch.catch_body,
                    params,
                    file_path,
                    finding_counter,
                    findings,
                );
                analyze_block_security(
                    &try_catch.finally_body,
                    params,
                    file_path,
                    finding_counter,
                    findings,
                );
            }
            StmtNode::Expression(e) => {
                inspect_call_in_expr(e, &var_table, file_path, finding_counter, findings);
            }
        }
    }
}

fn inspect_call_in_expr(
    expr: &ExprNode,
    var_table: &HashMap<String, VarInfo>,
    file_path: &str,
    finding_counter: &mut usize,
    findings: &mut Vec<Finding>,
) {
    if let ExprNode::Call { callee, args, line } = expr {
        let callee_name = callee.to_source_string();

        // 1. SQL Injection Sinks
        if is_sql_sink(&callee_name) {
            if let Some(first_arg) = args.first() {
                check_sql_arg(
                    first_arg,
                    &callee_name,
                    *line,
                    var_table,
                    file_path,
                    finding_counter,
                    findings,
                );
            }
        }

        // 2. Command Injection Sinks
        if is_command_sink(&callee_name) {
            if let Some(first_arg) = args.first() {
                check_command_arg(
                    first_arg,
                    &callee_name,
                    *line,
                    var_table,
                    file_path,
                    finding_counter,
                    findings,
                );
            }
        }

        // Recursively inspect arguments for nested calls
        for a in args {
            inspect_call_in_expr(a, var_table, file_path, finding_counter, findings);
        }
    }
}

fn check_sql_arg(
    arg: &ExprNode,
    callee: &str,
    call_line: usize,
    var_table: &HashMap<String, VarInfo>,
    file_path: &str,
    finding_counter: &mut usize,
    findings: &mut Vec<Finding>,
) {
    match arg {
        // Case 1: Variable identifier passed to execute(query)
        ExprNode::Identifier { name, .. } => {
            if let Some(var_info) = var_table.get(name) {
                if var_info.is_sql_fragment && !var_info.is_constant {
                    *finding_counter += 1;
                    let source_desc = var_info
                        .untrusted_source
                        .clone()
                        .unwrap_or_else(|| format!("Variable '{}'", name));
                    let data_flow = vec![
                        format!(
                            "Line {}: {} = {}",
                            var_info.assigned_line, name, var_info.raw_expr
                        ),
                        format!(
                            "Line {}: {}({}) [SINK: SQL query execution]",
                            call_line, callee, name
                        ),
                    ];

                    findings.push(Finding {
                        id: "VG-SAST-001".to_string(),
                        rule_id: Some("VG-SAST-001".to_string()),
                        category: Category::SourceCode,
                        severity: Severity::HIGH,
                        title: "Potential SQL Injection (AST Correlated)".to_string(),
                        description: format!(
                            "AST analysis detected variable '{}' containing dynamically formatted SQL query (defined on line {}) passed to database sink '{}(...)'.",
                            name, var_info.assigned_line, callee
                        ),
                        file: file_path.to_string(),
                        line: call_line,
                        column: Some(1),
                        evidence: Some(format!("{}({})", callee, name)),
                        recommendation: Some("Use parameterized queries, prepared statements, or ORM parameter binding.".to_string()),
                        confidence: "HIGH".to_string(),
                        source: Some(source_desc),
                        sink: Some(format!("{}({})", callee, name)),
                        data_flow: Some(data_flow),
                        cwe: Some("CWE-89".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
        // Case 2: Inline formatted string or concatenation: db.execute(f"SELECT ... {user}")
        ExprNode::FormattedString { raw, line, .. } => {
            if is_sql_keyword(raw) {
                *finding_counter += 1;
                findings.push(Finding {
                    id: "VG-SAST-001".to_string(),
                    rule_id: Some("VG-SAST-001".to_string()),
                    category: Category::SourceCode,
                    severity: Severity::HIGH,
                    title: "Potential SQL Injection (AST Correlated)".to_string(),
                    description: format!(
                        "AST analysis detected inline dynamic string formatting in database sink call '{}(...)'.",
                        callee
                    ),
                    file: file_path.to_string(),
                    line: *line,
                    column: Some(1),
                    evidence: Some(format!("{}({})", callee, raw)),
                    recommendation: Some("Use parameterized queries or prepared statements.".to_string()),
                    confidence: "HIGH".to_string(),
                    source: Some("Inline string interpolation".to_string()),
                    sink: Some(format!("{}(...)", callee)),
                    data_flow: Some(vec![format!("Line {}: {}({})", line, callee, raw)]),
                    cwe: Some("CWE-89".to_string()),
                    ..Default::default()
                });
            }
        }
        // Case 3: Binary op concatenation: db.execute("SELECT ... " + user)
        ExprNode::BinaryOp {
            op,
            left,
            right,
            line,
        } if op == "+" => {
            let left_str = left.to_source_string();
            let right_str = right.to_source_string();
            if is_sql_keyword(&left_str) || is_sql_keyword(&right_str) {
                *finding_counter += 1;
                findings.push(Finding {
                    id: "VG-SAST-001".to_string(),
                    rule_id: Some("VG-SAST-001".to_string()),
                    category: Category::SourceCode,
                    severity: Severity::HIGH,
                    title: "Potential SQL Injection (AST Correlated)".to_string(),
                    description: format!(
                        "AST analysis detected dynamic string concatenation in database sink call '{}(...)'.",
                        callee
                    ),
                    file: file_path.to_string(),
                    line: *line,
                    column: Some(1),
                    evidence: Some(format!("{}({} + {})", callee, left_str, right_str)),
                    recommendation: Some("Use parameterized queries or prepared statements.".to_string()),
                    confidence: "HIGH".to_string(),
                    source: Some("Dynamic string concatenation".to_string()),
                    sink: Some(format!("{}(...)", callee)),
                    data_flow: Some(vec![format!("Line {}: {}({} + {})", line, callee, left_str, right_str)]),
                    cwe: Some("CWE-89".to_string()),
                    ..Default::default()
                });
            }
        }
        _ => {}
    }
}

fn check_command_arg(
    arg: &ExprNode,
    callee: &str,
    call_line: usize,
    var_table: &HashMap<String, VarInfo>,
    file_path: &str,
    finding_counter: &mut usize,
    findings: &mut Vec<Finding>,
) {
    match arg {
        ExprNode::List { elements, line } => {
            for elem in elements {
                check_command_arg(
                    elem,
                    callee,
                    *line,
                    var_table,
                    file_path,
                    finding_counter,
                    findings,
                );
            }
        }
        ExprNode::Identifier { name, .. } => {
            if let Some(var_info) = var_table.get(name) {
                if !var_info.is_constant {
                    *finding_counter += 1;
                    let source_desc = var_info
                        .untrusted_source
                        .clone()
                        .unwrap_or_else(|| format!("Variable '{}'", name));
                    let data_flow = vec![
                        format!(
                            "Line {}: {} = {}",
                            var_info.assigned_line, name, var_info.raw_expr
                        ),
                        format!(
                            "Line {}: {}({}) [SINK: OS command execution]",
                            call_line, callee, name
                        ),
                    ];

                    findings.push(Finding {
                        id: "VG-SAST-002".to_string(),
                        rule_id: Some("VG-SAST-002".to_string()),
                        category: Category::SourceCode,
                        severity: Severity::CRITICAL,
                        title: "Potential OS Command Injection (AST Correlated)".to_string(),
                        description: format!(
                            "AST analysis detected variable '{}' (defined on line {}) passed to command execution sink '{}(...)'.",
                            name, var_info.assigned_line, callee
                        ),
                        file: file_path.to_string(),
                        line: call_line,
                        column: Some(1),
                        evidence: Some(format!("{}({})", callee, name)),
                        recommendation: Some("Avoid executing OS commands with untrusted input. Use safe parameter lists without a shell.".to_string()),
                        confidence: "HIGH".to_string(),
                        source: Some(source_desc),
                        sink: Some(format!("{}({})", callee, name)),
                        data_flow: Some(data_flow),
                        cwe: Some("CWE-78".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
        ExprNode::FormattedString { raw, line, .. } => {
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-SAST-002".to_string(),
                rule_id: Some("VG-SAST-002".to_string()),
                category: Category::SourceCode,
                severity: Severity::CRITICAL,
                title: "Potential OS Command Injection (AST Correlated)".to_string(),
                description: format!(
                    "AST analysis detected inline dynamic string formatting in command execution sink '{}(...)'.",
                    callee
                ),
                file: file_path.to_string(),
                line: *line,
                column: Some(1),
                evidence: Some(format!("{}({})", callee, raw)),
                recommendation: Some("Avoid executing OS commands with untrusted input. Use safe parameter lists without a shell.".to_string()),
                confidence: "HIGH".to_string(),
                source: Some("Inline string interpolation".to_string()),
                sink: Some(format!("{}(...)", callee)),
                data_flow: Some(vec![format!("Line {}: {}({})", line, callee, raw)]),
                cwe: Some("CWE-78".to_string()),
                ..Default::default()
            });
        }
        ExprNode::BinaryOp {
            op,
            left,
            right,
            line,
        } if op == "+" => {
            let left_str = left.to_source_string();
            let right_str = right.to_source_string();
            *finding_counter += 1;
            findings.push(Finding {
                id: "VG-SAST-002".to_string(),
                rule_id: Some("VG-SAST-002".to_string()),
                category: Category::SourceCode,
                severity: Severity::CRITICAL,
                title: "Potential OS Command Injection (AST Correlated)".to_string(),
                description: format!(
                    "AST analysis detected dynamic string concatenation in command execution sink '{}(...)'.",
                    callee
                ),
                file: file_path.to_string(),
                line: *line,
                column: Some(1),
                evidence: Some(format!("{}({} + {})", callee, left_str, right_str)),
                recommendation: Some("Avoid executing OS commands with untrusted input. Use safe parameter lists without a shell.".to_string()),
                confidence: "HIGH".to_string(),
                source: Some("Dynamic string concatenation".to_string()),
                sink: Some(format!("{}(...)", callee)),
                data_flow: Some(vec![format!("Line {}: {}({} + {})", line, callee, left_str, right_str)]),
                cwe: Some("CWE-78".to_string()),
                ..Default::default()
            });
        }
        _ => {}
    }
}

fn is_sql_sink(callee: &str) -> bool {
    let lower = callee.to_lowercase();
    if let Some(dot_idx) = lower.rfind('.') {
        let receiver = &lower[..dot_idx];
        let method = &lower[dot_idx + 1..];

        let is_non_sql = receiver == "tmpl"
            || receiver == "template"
            || receiver == "htmltemplate"
            || receiver == "texttemplate"
            || receiver == "t"
            || receiver == "w"
            || receiver == "writer"
            || receiver == "cmd"
            || receiver == "rootcmd"
            || receiver == "command"
            || receiver == "cobracommand"
            || receiver == "c"
            || receiver == "app"
            || receiver == "task"
            || receiver == "runner"
            || receiver == "workflow"
            || receiver == "future"
            || receiver == "promise"
            || receiver == "executor"
            || receiver == "batch";

        if is_non_sql {
            false
        } else if method == "execute" || method == "exec" {
            receiver == "db"
                || receiver == "cursor"
                || receiver == "cur"
                || receiver == "conn"
                || receiver == "connection"
                || receiver == "session"
                || receiver == "orm"
                || receiver == "tx"
                || receiver == "sql"
                || receiver == "repo"
                || receiver == "repository"
                || receiver == "client"
                || receiver == "engine"
                || receiver == "stmt"
                || receiver.ends_with("db")
                || receiver.ends_with("conn")
                || receiver.ends_with("cursor")
                || receiver.ends_with("session")
                || receiver.ends_with("repo")
        } else {
            method == "executemany"
                || method == "query"
                || method == "queryrow"
                || method == "query_row"
                || method == "raw"
                || method == "executequery"
                || method == "executeupdate"
        }
    } else {
        lower == "db.execute"
            || lower == "conn.execute"
            || lower == "cursor.execute"
            || lower == "session.execute"
    }
}

fn is_command_sink(callee: &str) -> bool {
    let lower = callee.to_lowercase();
    lower.ends_with("os.system")
        || lower.ends_with("subprocess.check_output")
        || lower.ends_with("subprocess.run")
        || lower.ends_with("subprocess.call")
        || lower.ends_with("subprocess.popen")
        || lower.ends_with("child_process.exec")
        || lower.ends_with("child_process.spawn")
        || lower.ends_with("runtime.getruntime().exec")
        || lower.ends_with("exec.command")
}

fn is_sql_keyword(s: &str) -> bool {
    let upper = s.to_uppercase();
    upper.contains("SELECT ")
        || upper.contains("INSERT INTO ")
        || upper.contains("UPDATE ")
        || upper.contains("DELETE FROM ")
        || upper.contains("DROP TABLE")
}

fn is_sql_expression(expr: &ExprNode, var_table: &HashMap<String, VarInfo>) -> bool {
    match expr {
        ExprNode::FormattedString { raw, .. } => is_sql_keyword(raw),
        ExprNode::BinaryOp {
            op, left, right, ..
        } if op == "+" => is_sql_expression(left, var_table) || is_sql_expression(right, var_table),
        ExprNode::Constant {
            kind: ConstantKind::String(s),
            ..
        } => is_sql_keyword(s),
        ExprNode::Call { callee, args, .. } => {
            let callee_name = callee.to_source_string();
            if callee_name.contains("Sprintf") {
                if let Some(first) = args.first() {
                    return is_sql_expression(first, var_table);
                }
            }
            false
        }
        ExprNode::Identifier { name, .. } => {
            if let Some(v) = var_table.get(name) {
                return v.is_sql_fragment;
            }
            false
        }
        _ => false,
    }
}

fn is_cmd_expression(expr: &ExprNode, var_table: &HashMap<String, VarInfo>) -> bool {
    match expr {
        ExprNode::FormattedString { .. } => true,
        ExprNode::BinaryOp {
            op, left, right, ..
        } if op == "+" => is_cmd_expression(left, var_table) || is_cmd_expression(right, var_table),
        ExprNode::Identifier { name, .. } => {
            if let Some(v) = var_table.get(name) {
                return v.is_cmd_fragment || v.untrusted_source.is_some();
            }
            false
        }
        _ => false,
    }
}

fn is_constant_expression(expr: &ExprNode) -> bool {
    match expr {
        ExprNode::Constant { .. } => true,
        ExprNode::BinaryOp {
            op, left, right, ..
        } if op == "+" => is_constant_expression(left) && is_constant_expression(right),
        _ => false,
    }
}

fn detect_untrusted_source(
    expr: &ExprNode,
    var_table: &HashMap<String, VarInfo>,
) -> Option<String> {
    let source_str = expr.to_source_string();
    if source_str.contains("request.args")
        || source_str.contains("request.form")
        || source_str.contains("request.get_json")
        || source_str.contains("req.query")
        || source_str.contains("req.body")
        || source_str.contains("r.URL.Query")
        || source_str.contains("user_input")
        || source_str.contains("userInput")
    {
        return Some(format!("Untrusted input: {}", source_str));
    }

    match expr {
        ExprNode::Identifier { name, .. } => {
            if let Some(v) = var_table.get(name) {
                return v.untrusted_source.clone();
            }
        }
        ExprNode::FormattedString { parts, .. } => {
            for p in parts {
                if let Some(src) = detect_untrusted_source(p, var_table) {
                    return Some(src);
                }
            }
        }
        ExprNode::BinaryOp { left, right, .. } => {
            if let Some(src) = detect_untrusted_source(left, var_table) {
                return Some(src);
            }
            if let Some(src) = detect_untrusted_source(right, var_table) {
                return Some(src);
            }
        }
        _ => {}
    }

    None
}
