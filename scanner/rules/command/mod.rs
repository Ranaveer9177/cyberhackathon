#![allow(dead_code)]

use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::types::{InferredType, TypeEnvironment};
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::taint::sanitizers::SanitizerModel;
use crate::types::{Category, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandControl {
    Constant,
    Unknown,
    UserControlled,
    Derived,
    Sanitized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellMode {
    ShellTrue,
    ShellFalse,
    DirectShell,
}

use std::collections::{HashMap, HashSet};

pub struct CommandRuleEngine<'a> {
    pub file_node: &'a FileNode,
    pub var_types: &'a TypeEnvironment,
    pub constants: &'a ConstantEnvironment,
    pub sanitized_vars: &'a HashMap<String, HashSet<crate::taint::types::TaintKind>>,
}

impl<'a> CommandRuleEngine<'a> {
    pub fn new(
        file_node: &'a FileNode,
        var_types: &'a TypeEnvironment,
        constants: &'a ConstantEnvironment,
        sanitized_vars: &'a HashMap<String, HashSet<crate::taint::types::TaintKind>>,
    ) -> Self {
        Self {
            file_node,
            var_types,
            constants,
            sanitized_vars,
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

                let (sev, title_suffix, conf) = match control {
                    CommandControl::UserControlled => (
                        Severity::CRITICAL,
                        "Arbitrary Command Injection (User-Controlled)",
                        "HIGH",
                    ),
                    CommandControl::Derived => match shell_mode {
                        ShellMode::ShellTrue | ShellMode::DirectShell => (
                            Severity::CRITICAL,
                            "Command Injection (Shell Metacharacters Enabled)",
                            "HIGH",
                        ),
                        ShellMode::ShellFalse => (
                            Severity::HIGH,
                            "Argument Injection (Shell Disabled, Subprocess Argument)",
                            "HIGH",
                        ),
                    },
                    CommandControl::Unknown => match shell_mode {
                        ShellMode::ShellTrue | ShellMode::DirectShell => (
                            Severity::HIGH,
                            "Command Execution (Unknown Variable Source)",
                            "MEDIUM",
                        ),
                        ShellMode::ShellFalse => {
                            (Severity::LOW, "Potential Command Execution", "LOW")
                        }
                    },
                    _ => (Severity::HIGH, "Command Injection", "MEDIUM"),
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
                    confidence: conf.to_string(),
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

        // If exec.CommandContext, the first argument is context.Context, not the command
        let effective_args = if callee == "exec.CommandContext" && args.len() > 1 {
            &args[1..]
        } else {
            args
        };

        // Filter out keyword arguments like shell=True/False, timeout=...
        let mut positional_args = Vec::new();
        for arg in effective_args {
            let s = arg.to_source_string();
            if s.contains("shell=True") || s.contains("shell = True") || s.contains("shell=1") {
                shell_mode = ShellMode::ShellTrue;
            } else if s.contains("shell=False")
                || s.contains("shell = False")
                || s.contains("shell=0")
            {
                shell_mode = ShellMode::ShellFalse;
            } else if !s.starts_with("timeout=") && !s.starts_with("cwd=") && !s.starts_with("env=")
            {
                positional_args.push(arg);
            }
        }

        // Determine command control level from primary argument
        if let Some(cmd_arg) = positional_args.first() {
            let cmd_str = cmd_arg.to_source_string();

            // Safe fixed tool executions (scanner runner, git, go, cargo)
            if cmd_str == "scannerExe"
                || cmd_str == "\"git\""
                || cmd_str == "'git'"
                || cmd_str == "\"go\""
                || cmd_str == "'go'"
                || cmd_str == "\"cargo\""
                || cmd_str == "'cargo'"
            {
                return (CommandControl::Constant, shell_mode);
            }

            // 1. Sanitized Check: shlex.quote() or regex validation or previously sanitized variable
            let (sanitized_kinds, is_sanitizer) = SanitizerModel::sanitized_kinds(&cmd_str);
            let is_var_sanitized = if let ExprNode::Identifier { name, .. } = cmd_arg {
                self.sanitized_vars
                    .get(name)
                    .is_some_and(|kinds| kinds.contains(&crate::taint::types::TaintKind::Command))
            } else {
                false
            };
            if is_sanitizer.is_some()
                || sanitized_kinds.contains(&crate::taint::types::TaintKind::Command)
                || is_var_sanitized
            {
                return (CommandControl::Sanitized, shell_mode);
            }

            // 2. List literal check (e.g. subprocess.run(["ping", "-c", "1", "127.0.0.1"]))
            if let ExprNode::List { elements, .. } = cmd_arg {
                let all_constant = !elements.is_empty()
                    && elements
                        .iter()
                        .all(|e| self.constants.eval_expr(e).is_constant());

                if all_constant {
                    return (CommandControl::Constant, shell_mode);
                } else {
                    let all_safe = !elements.is_empty()
                        && elements.iter().all(|e| {
                            if self.constants.eval_expr(e).is_constant() {
                                return true;
                            }
                            let e_str = e.to_source_string();
                            let (sanitized_kinds, is_sanitizer) = SanitizerModel::sanitized_kinds(&e_str);
                            let is_var_sanitized = if let ExprNode::Identifier { name, .. } = e {
                                self.sanitized_vars
                                    .get(name)
                                    .is_some_and(|kinds| kinds.contains(&crate::taint::types::TaintKind::Command))
                            } else {
                                false
                            };
                            is_sanitizer.is_some()
                                || sanitized_kinds.contains(&crate::taint::types::TaintKind::Command)
                                || is_var_sanitized
                                || e_str.contains("shlex.quote")
                        });

                    if all_safe {
                        return (CommandControl::Sanitized, shell_mode);
                    } else {
                        return (CommandControl::Derived, shell_mode);
                    }
                }
            }

            // 3. Multi-argument check (e.g. exec.Command("ping", "127.0.0.1") vs exec.Command("ping", host))
            if positional_args.len() > 1 {
                let all_constant = positional_args
                    .iter()
                    .all(|a| self.constants.eval_expr(a).is_constant());
                if all_constant {
                    return (CommandControl::Constant, shell_mode);
                } else {
                    let all_safe = positional_args.iter().all(|a| {
                        if self.constants.eval_expr(a).is_constant() {
                            return true;
                        }
                        let a_str = a.to_source_string();
                        let (sanitized_kinds, is_sanitizer) = SanitizerModel::sanitized_kinds(&a_str);
                        let is_var_sanitized = if let ExprNode::Identifier { name, .. } = a {
                            self.sanitized_vars
                                .get(name)
                                .is_some_and(|kinds| kinds.contains(&crate::taint::types::TaintKind::Command))
                        } else {
                            false
                        };
                        is_sanitizer.is_some()
                            || sanitized_kinds.contains(&crate::taint::types::TaintKind::Command)
                            || is_var_sanitized
                            || a_str.contains("shlex.quote")
                    });
                    if all_safe {
                        return (CommandControl::Sanitized, shell_mode);
                    } else {
                        return (CommandControl::Derived, shell_mode);
                    }
                }
            }

            // 4. Single-argument constant check
            if self.constants.eval_expr(cmd_arg).is_constant() {
                return (CommandControl::Constant, shell_mode);
            }

            // 5. Integer/Boolean Check: Safe scalar types cannot inject command delimiters
            let ty = self.var_types.infer_expr(cmd_arg);
            if ty == InferredType::Integer || ty == InferredType::Boolean {
                return (CommandControl::Constant, shell_mode);
            }

            // 6. Untrusted User Input check: UserControlled
            if cmd_str.contains("request.")
                || cmd_str.contains("req.")
                || cmd_str.contains("params[")
                || cmd_str.contains("args[")
                || cmd_str.contains("r.URL")
                || cmd_str.contains("GET[")
                || cmd_str.contains("POST[")
                || cmd_str.contains("sys.argv")
                || cmd_str.contains("input(")
            {
                return (CommandControl::UserControlled, shell_mode);
            }

            // 7. Formatted string or concatenation: Derived
            if let ExprNode::FormattedString { .. } = cmd_arg {
                return (CommandControl::Derived, shell_mode);
            }

            if let ExprNode::BinaryOp { op, .. } = cmd_arg {
                if op == "+" {
                    return (CommandControl::Derived, shell_mode);
                }
            }

            // 8. Bare identifier or expression not proved constant or user-controlled: Unknown
            if let ExprNode::Identifier { .. } = cmd_arg {
                return (CommandControl::Unknown, shell_mode);
            }

            (CommandControl::Unknown, shell_mode)
        } else {
            (CommandControl::Constant, shell_mode)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::ast::parse_file;
    use crate::semantic_rules::run_semantic_rules;
    use crate::types::Severity;

    #[test]
    fn test_constant_command_suppressed() {
        let code = "CMD = \"ls -la /tmp\"\nos.system(CMD)\n";
        let file_node = parse_file("test.py", code).expect("parse failed");
        let parsed_files = [("test.py", &file_node)];
        let mut counter = 0;
        let findings = run_semantic_rules(&parsed_files, &mut counter);
        assert_eq!(
            findings.len(),
            0,
            "Constant command variable must produce 0 findings"
        );
    }

    #[test]
    fn test_concatenated_constant_command_suppressed() {
        let code = "CMD = \"ls -la \" + \"/tmp\"\nos.system(CMD)\n";
        let file_node = parse_file("test.py", code).expect("parse failed");
        let parsed_files = [("test.py", &file_node)];
        let mut counter = 0;
        let findings = run_semantic_rules(&parsed_files, &mut counter);
        assert_eq!(
            findings.len(),
            0,
            "Concatenated constant command must produce 0 findings"
        );
    }

    #[test]
    fn test_sanitized_command_suppressed() {
        let code = "cmd = shlex.quote(user_input)\nos.system(cmd)\n";
        let file_node = parse_file("test.py", code).expect("parse failed");
        let parsed_files = [("test.py", &file_node)];
        let mut counter = 0;
        let findings = run_semantic_rules(&parsed_files, &mut counter);
        assert_eq!(
            findings.len(),
            0,
            "Sanitized command must produce 0 findings"
        );
    }

    #[test]
    fn test_user_controlled_command_detected_critical() {
        let code = "os.system(request.args.get(\"cmd\"))\n";
        let file_node = parse_file("test.py", code).expect("parse failed");
        let parsed_files = [("test.py", &file_node)];
        let mut counter = 0;
        let findings = run_semantic_rules(&parsed_files, &mut counter);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::CRITICAL);
        assert!(findings[0].title.contains("User-Controlled"));
    }

    #[test]
    fn test_unknown_variable_command_detected_high() {
        let code = "os.system(unknown_var)\n";
        let file_node = parse_file("test.py", code).expect("parse failed");
        let parsed_files = [("test.py", &file_node)];
        let mut counter = 0;
        let findings = run_semantic_rules(&parsed_files, &mut counter);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::HIGH);
        assert!(findings[0].title.contains("Unknown Variable Source"));
    }

    #[test]
    fn test_derived_command_detected() {
        let code = "os.system(\"ping \" + host)\n";
        let file_node = parse_file("test.py", code).expect("parse failed");
        let parsed_files = [("test.py", &file_node)];
        let mut counter = 0;
        let findings = run_semantic_rules(&parsed_files, &mut counter);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::CRITICAL);
        assert!(findings[0].title.contains("Shell Metacharacters Enabled"));
    }
}
