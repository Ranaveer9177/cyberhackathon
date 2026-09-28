#![allow(dead_code)]

use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::types::TypeEnvironment;
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::types::{Category, Finding, Severity};

pub struct PathRuleEngine<'a> {
    pub file_node: &'a FileNode,
    pub var_types: &'a TypeEnvironment,
    pub constants: &'a ConstantEnvironment,
}

impl<'a> PathRuleEngine<'a> {
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

            // Detect file operation sinks
            let is_file_sink = callee_str == "open"
                || callee_str == "os.remove"
                || callee_str == "os.unlink"
                || callee_str == "shutil.copy"
                || callee_str == "shutil.rmtree"
                || callee_str.starts_with("fs.readFile")
                || callee_str.starts_with("fs.writeFile")
                || callee_str.starts_with("fs.createReadStream")
                || callee_str == "os.Open"
                || callee_str == "os.ReadFile"
                || callee_str == "os.WriteFile"
                || callee_str.contains("FileInputStream")
                || callee_str.contains("FileOutputStream")
                || callee_str.contains("Files.readAllBytes");

            if is_file_sink {
                if let Some(path_arg) = args.first() {
                    // 1. Constant check: hardcoded paths (e.g. "config.json" or "/var/log/app.log") are safe!
                    if self.constants.eval_expr(path_arg).is_constant() {
                        return;
                    }

                    let raw_expr = expr.to_source_string();
                    let path_str = path_arg.to_source_string();

                    // 2. Directory Boundary / Containment check:
                    // e.g. path.startswith(base_dir) or filepath.HasPrefix(clean, baseDir)
                    let has_boundary_check = raw_expr.contains(".startswith(")
                        || raw_expr.contains("startswith(safe_")
                        || raw_expr.contains("commonpath(")
                        || raw_expr.contains("is_relative_to(")
                        || raw_expr.contains("secure_filename(")
                        || raw_expr.contains("filepath.HasPrefix");

                    if has_boundary_check {
                        return;
                    }

                    // 3. Check for dynamic construction without boundary validation
                    let severity = if path_str.contains("..") {
                        Severity::CRITICAL
                    } else {
                        Severity::HIGH
                    };

                    *finding_counter += 1;
                    let fid = format!("VG-{:03}", *finding_counter);

                    findings.push(Finding {
                        id: fid,
                        rule_id: Some("VG-PATH-001".to_string()),
                        category: Category::SourceCode,
                        severity,
                        title: "Path Traversal via Unvalidated File Path Construction".to_string(),
                        description: format!(
                            "Dynamic path argument passed to file sink '{}' without canonical directory boundary containment validation.",
                            callee_str
                        ),
                        file: self.file_node.file_path.clone(),
                        line,
                        column: Some(1),
                        evidence: Some(raw_expr),
                        recommendation: Some(
                            "Resolve path using os.path.realpath / path.resolve and verify that the canonical path starts with the intended base directory (e.g. resolved.startswith(BASE_DIR)). Use werkzeug.utils.secure_filename for uploaded file names.".to_string(),
                        ),
                        confidence: "HIGH".to_string(),
                        source: Some(path_str),
                        sink: Some(format!("{}:{}", self.file_node.file_path, line)),
                        data_flow: Some(vec![format!("{}: {}", line, expr.to_source_string())]),
                        cwe: Some("CWE-22".to_string()),
                        fingerprint: Some(format!("VG-PATH-001:{}:{}:{}", self.file_node.file_path, line, callee_str)),
                    });
                }
            }

            for a in args {
                self.inspect_expr(a, line, finding_counter, findings);
            }
        }
    }
}
