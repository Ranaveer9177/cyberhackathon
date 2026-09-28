#![allow(dead_code)]

use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::types::{InferredType, TypeEnvironment};
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::taint::sanitizers::SanitizerModel;
use crate::types::{Category, Finding, Severity};

pub struct XssRuleEngine<'a> {
    pub file_node: &'a FileNode,
    pub var_types: &'a TypeEnvironment,
    pub constants: &'a ConstantEnvironment,
}

impl<'a> XssRuleEngine<'a> {
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
                    let target_name = assign.target.to_source_string();

                    // 1. DOM innerHTML assignment: el.innerHTML = dynamic_val
                    if target_name.ends_with(".innerHTML")
                        || target_name.ends_with(".outerHTML")
                        || target_name.ends_with("dangerouslySetInnerHTML")
                    {
                        self.check_xss_sink(
                            &assign.value,
                            &target_name,
                            assign.line,
                            finding_counter,
                            findings,
                        );
                    }

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

            // 2. Raw HTML / Markup constructors
            let is_raw_html_sink = callee_str == "Markup"
                || callee_str == "mark_safe"
                || callee_str == "SafeString"
                || callee_str == "render_template_string"
                || callee_str == "document.write"
                || callee_str == "document.writeln"
                || callee_str.ends_with(".html")
                || callee_str.ends_with("dangerouslySetInnerHTML");

            if is_raw_html_sink {
                if let Some(first_arg) = args.first() {
                    self.check_xss_sink(first_arg, &callee_str, line, finding_counter, findings);
                }
            }

            for a in args {
                self.inspect_expr(a, line, finding_counter, findings);
            }
        }
    }

    fn check_xss_sink(
        &self,
        val_expr: &ExprNode,
        sink_name: &str,
        line: usize,
        finding_counter: &mut usize,
        findings: &mut Vec<Finding>,
    ) {
        // 1. Constant check: hardcoded HTML (e.g. Markup("<b>ok</b>") or innerHTML = "") is safe!
        if self.constants.eval_expr(val_expr).is_constant() {
            return;
        }

        // 2. Integer/Boolean check: safe scalar types cannot execute script payloads
        let ty = self.var_types.infer_expr(val_expr);
        if ty == InferredType::Integer || ty == InferredType::Boolean {
            return;
        }

        // 3. Sanitizer check: html.escape(), DOMPurify.sanitize(), validator.escape()
        let val_str = val_expr.to_source_string();
        let (sanitized_kinds, is_sanitizer) = SanitizerModel::sanitized_kinds(&val_str);
        if is_sanitizer.is_some() || sanitized_kinds.contains(&crate::taint::types::TaintKind::Xss)
        {
            return;
        }

        *finding_counter += 1;
        let fid = format!("VG-{:03}", *finding_counter);

        findings.push(Finding {
            id: fid,
            rule_id: Some("VG-XSS-001".to_string()),
            category: Category::SourceCode,
            severity: Severity::HIGH,
            title: "Cross-Site Scripting (XSS) via Unescaped HTML Rendering".to_string(),
            description: format!(
                "Unescaped dynamic content passed to raw HTML sink '{}'. Auto-escaping is bypassed without HTML entity sanitization.",
                sink_name
            ),
            file: self.file_node.file_path.clone(),
            line,
            column: Some(1),
            evidence: Some(val_str.clone()),
            recommendation: Some(
                "Rely on framework auto-escaping in templates. Do not wrap untrusted input in Markup() / mark_safe(). For DOM operations, use textContent instead of innerHTML or sanitize with DOMPurify.".to_string(),
            ),
            confidence: "HIGH".to_string(),
            source: Some(val_str),
            sink: Some(format!("{}:{}", self.file_node.file_path, line)),
            data_flow: Some(vec![format!("{}: {}", line, val_expr.to_source_string())]),
            cwe: Some("CWE-79".to_string()),
            fingerprint: Some(format!("VG-XSS-001:{}:{}:{}", self.file_node.file_path, line, sink_name)),
        });
    }
}
