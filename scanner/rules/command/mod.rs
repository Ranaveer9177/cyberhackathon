#![allow(dead_code)]

use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::types::{InferredType, TypeEnvironment};
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::taint::sanitizers::SanitizerModel;
use crate::types::{Category, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandControl {
    Constant,
    PartiallyControlled,
    FullyControlled,
    Sanitized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellMode {
    ShellTrue,
    ShellFalse,
    DirectShell,
}

pub struct CommandRuleEngine<'a> {
    pub file_node: &'a FileNode,
    pub var_types: &'a TypeEnvironment,
    pub constants: &'a ConstantEnvironment,
}

impl<'a> CommandRuleEngine<'a> {
    pub fn new(
        file_node: &'a FileNode,
        var_types: &'a TypeEnvironment,
        constants: &'a ConstantEnvironment,
    ) -> Self {
        Self {
            file_node,
            var_types,
            constants,
        }
    }

    pub fn analyze(&self, finding_counter: &mut usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &self.file_node.functions {
            self.analyze_stmts(&func.body, finding_counter, &mut findings);
        }

        self.analyze_stmts(&self.file_node.statements, finding_counter, &mut findings);

        findings
    }

    fn analyze_stmts(
        &self,
        stmts: &[StmtNode],
        finding_counter: &mut usize,
        findings: &mut Vec<Finding>,
    ) {
        let mut returned = false;
        for stmt in stmts {
            if returned {
                break;
            }
            match stmt {
                StmtNode::Assignment(assign) => {
                    self.inspect_expr(&assign.value, assign.line, finding_counter, findings);
                }
                StmtNode::Call(expr) => {
                    self.inspect_expr(expr, expr.line(), finding_counter, findings);
                }
                StmtNode::Return(ret) => {
                    if let Some(val) = &ret.value {
                        self.inspect_expr(val, ret.line, finding_counter, findings);
                    }
                    returned = true;
                }
                StmtNode::Condition(c) => {
                    self.inspect_expr(&c.test, c.line, finding_counter, findings);
                    self.analyze_stmts(&c.then_body, finding_counter, findings);
                    self.analyze_stmts(&c.else_body, finding_counter, findings);
                }
                StmtNode::Loop(l) => {
                    if let Some(cond) = &l.condition {
                        self.inspect_expr(cond, l.line, finding_counter, findings);
                    }
                    self.analyze_stmts(&l.body, finding_counter, findings);
                }
                StmtNode::TryCatch(t) => {
                    self.analyze_stmts(&t.try_body, finding_counter, findings);
                    self.analyze_stmts(&t.catch_body, finding_counter, findings);
                    self.analyze_stmts(&t.finally_body, finding_counter, findings);
                }
                StmtNode::Expression(e) => {
                    self.inspect_expr(e, e.line(), finding_counter, findings);
                }
            }
        }
    }

    fn inspect_expr(
        &self,
        expr: &ExprNode,
        line: usize,
        finding_counter: &mut usize,
        findings: &mut Vec<Finding>,
    ) {
        if let ExprNode::Call { callee, args, .. } = expr {
            let callee_str = callee.to_source_string();

            // Detect command execution sinks
            let is_cmd_sink = callee_str == "os.system"
                || callee_str == "os.popen"
                || callee_str.starts_with("subprocess.")
                || callee_str == "exec"
                || callee_str.ends_with(".exec")
                || callee_str.ends_with(".execFile")
                || callee_str.ends_with(".spawn")
                || callee_str.ends_with(".execSync")
                || callee_str == "exec.Command"
                || callee_str == "exec.CommandContext"
                || callee_str.contains("Runtime.getRuntime().exec")
                || callee_str.contains("ProcessBuilder");

            if is_cmd_sink {
                let (control, shell_mode) = self.classify_command_invocation(&callee_str, args);

                // Constant commands and sanitized commands are safe!
                if control == CommandControl::Constant || control == CommandControl::Sanitized {
                    return;
                }

                *finding_counter += 1;
                let fid = format!("VG-{:03}", *finding_counter);
                let snippet = expr.to_source_string();

                let (sev, title_suffix) = match control {
                    CommandControl::FullyControlled => (
                        Severity::CRITICAL,
                        "Arbitrary Command Injection (Fully Controlled)",
                    ),
                    CommandControl::PartiallyControlled => match shell_mode {
                        ShellMode::ShellTrue | ShellMode::DirectShell => (
                            Severity::CRITICAL,
                            "Command Injection (Shell Metacharacters Enabled)",
                        ),
                        ShellMode::ShellFalse => (
                            Severity::HIGH,
                            "Argument Injection (Shell Disabled, Subprocess Argument)",
                        ),
                    },
                    _ => (Severity::HIGH, "Command Injection"),
                };

                findings.push(Finding {
                    id: fid,
                    rule_id: Some("VG-CMD-001".to_string()),
                    category: Category::SourceCode,
                    severity: sev,
                    title: format!("OS Command Injection: {}", title_suffix),
                    description: format!(
                        "Invocation of '{}' with unquoted, non-constant input. Control level: {:?}, Shell mode: {:?}.",
                        callee_str, control, shell_mode
                    ),
                    file: self.file_node.file_path.clone(),
                    line,
                    column: Some(1),
                    evidence: Some(snippet),
                    recommendation: Some(
                        "Pass arguments as a fixed array with shell=False, or sanitize parameters using shlex.quote() / escapeshellarg(). Avoid dynamic shell string concatenation.".to_string(),
                    ),
                    confidence: "HIGH".to_string(),
                    source: Some(callee_str.clone()),
                    sink: Some(format!("{}:{}", self.file_node.file_path, line)),
                    data_flow: Some(vec![format!("{}: {}", line, expr.to_source_string())]),
                    cwe: Some("CWE-78".to_string()),
                    fingerprint: Some(format!("VG-CMD-001:{}:{}:{}", self.file_node.file_path, line, callee_str)),
                    ..Default::default()
                });
            }

            // Recurse into arguments
            for a in args {
                self.inspect_expr(a, line, finding_counter, findings);
            }
        }
    }

    fn classify_command_invocation(
        &self,
        callee: &str,
        args: &[ExprNode],
    ) -> (CommandControl, ShellMode) {
        // Detect shell mode
        let mut shell_mode = if callee == "os.system"
            || callee == "os.popen"
            || callee.ends_with(".exec")
            || callee.ends_with(".execSync")
        {
            ShellMode::DirectShell
        } else {
            ShellMode::ShellFalse
        };

        // Check for shell=True in kwargs or arguments
        for arg in args {
            let s = arg.to_source_string();
            if s.contains("shell=True") || s.contains("shell=1") {
                shell_mode = ShellMode::ShellTrue;
            } else if s.contains("shell=False") {
                shell_mode = ShellMode::ShellFalse;
            }
        }

        // Determine command control level from primary argument
        if let Some(cmd_arg) = args.first() {
            let cmd_str = cmd_arg.to_source_string();

            // 1. Sanitized Check: shlex.quote() or regex validation
            let (sanitized_kinds, is_sanitizer) = SanitizerModel::sanitized_kinds(&cmd_str);
            if is_sanitizer.is_some()
                || sanitized_kinds.contains(&crate::taint::types::TaintKind::Command)
            {
                return (CommandControl::Sanitized, shell_mode);
            }

            // 2. Constant Check: Compile-time constant string literal or all-constant arguments
            if self.constants.eval_expr(cmd_arg).is_constant() {
                return (CommandControl::Constant, shell_mode);
            }

            // For non-shell calls (e.g. exec.Command), if all arguments are constants, command is constant
            if shell_mode == ShellMode::ShellFalse
                && !args.is_empty()
                && args
                    .iter()
                    .all(|a| self.constants.eval_expr(a).is_constant())
            {
                return (CommandControl::Constant, shell_mode);
            }

            // 3. Integer/Boolean Check: Safe scalar types cannot inject command delimiters
            let ty = self.var_types.infer_expr(cmd_arg);
            if ty == InferredType::Integer || ty == InferredType::Boolean {
                return (CommandControl::Constant, shell_mode);
            }

            // 4. Formatted string or concatenation with constant binary: Partially Controlled
            if let ExprNode::FormattedString { raw, .. } = cmd_arg {
                if raw.starts_with("f\"") || raw.starts_with("f'") {
                    // If first part is a known binary (e.g. "ping "), it is partially controlled
                    return (CommandControl::PartiallyControlled, shell_mode);
                }
            }

            if let ExprNode::BinaryOp { op, left, .. } = cmd_arg {
                if op == "+" && self.constants.eval_expr(left).is_constant() {
                    return (CommandControl::PartiallyControlled, shell_mode);
                }
            }

            // 5. Bare identifier or dynamic request parameter: Fully Controlled
            if let ExprNode::Identifier { .. } = cmd_arg {
                return (CommandControl::FullyControlled, shell_mode);
            }

            if cmd_str.contains("request.")
                || cmd_str.contains("req.")
                || cmd_str.contains("params[")
                || cmd_str.contains("args[")
            {
                return (CommandControl::FullyControlled, shell_mode);
            }

            (CommandControl::PartiallyControlled, shell_mode)
        } else {
            (CommandControl::Constant, shell_mode)
        }
    }
}
