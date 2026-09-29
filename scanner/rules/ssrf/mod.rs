#![allow(dead_code)]

use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::types::TypeEnvironment;
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::types::{Category, Finding, Severity};

pub struct SsrfRuleEngine<'a> {
    pub file_node: &'a FileNode,
    pub var_types: &'a TypeEnvironment,
    pub constants: &'a ConstantEnvironment,
}

impl<'a> SsrfRuleEngine<'a> {
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

            // Detect HTTP client sinks
            let is_http_client = callee_str.starts_with("requests.")
                || callee_str.starts_with("urllib.request.")
                || callee_str.starts_with("httpx.")
                || callee_str == "fetch"
                || callee_str.starts_with("axios.")
                || callee_str == "http.Get"
                || callee_str == "http.Post"
                || callee_str == "http.NewRequest"
                || callee_str.contains("HttpClient.send")
                || callee_str.contains("RestTemplate.")
                || callee_str.contains("WebClient.");

            if is_http_client {
                if let Some(url_arg) = args.first() {
                    // 1. Constant check: hardcoded URLs (e.g. "https://api.github.com") are safe!
                    if self.constants.eval_expr(url_arg).is_constant() {
                        return;
                    }

                    // 2. Allowlist or hostname check: if the expression validates hostname against allowlist
                    let url_str = url_arg.to_source_string();
                    let is_allowlisted = url_str.contains("ALLOWED_")
                        || url_str.contains("whitelist")
                        || url_str.contains("allowlist")
                        || url_str.contains(".is_safe_host")
                        || url_str.contains("validate_url(");

                    if is_allowlisted {
                        return;
                    }

                    // 3. Private IP & metadata check:
                    let raw_expr = expr.to_source_string();
                    let has_metadata_protection = raw_expr.contains("169.254.169.254")
                        || raw_expr.contains("is_private")
                        || raw_expr.contains("is_loopback");

                    if has_metadata_protection {
                        return;
                    }

                    // Check for dangerous redirect follow-through
                    let follows_redirects = raw_expr.contains("allow_redirects=True")
                        || !raw_expr.contains("allow_redirects=False");

                    *finding_counter += 1;
                    let fid = format!("VG-{:03}", *finding_counter);

                    let desc = if follows_redirects {
                        format!(
                            "Untrusted URL passed to HTTP client '{}' without domain allowlisting or private IP blocking. Automatically follows redirects, risking metadata / internal network SSRF.",
                            callee_str
                        )
                    } else {
                        format!(
                            "Untrusted URL passed to HTTP client '{}' without domain allowlisting or private IP blocking.",
                            callee_str
                        )
                    };

                    findings.push(Finding {
                        id: fid,
                        rule_id: Some("VG-SSRF-001".to_string()),
                        category: Category::SourceCode,
                        severity: Severity::HIGH,
                        title: "Server-Side Request Forgery (SSRF) via Dynamic URL".to_string(),
                        description: desc,
                        file: self.file_node.file_path.clone(),
                        line,
                        column: Some(1),
                        evidence: Some(raw_expr),
                        recommendation: Some(
                            "Validate requested URLs against a strict allowlist of authorized domains. Block private and link-local IP addresses (e.g. 127.0.0.1, 169.254.169.254, 10.0.0.0/8), and disable automatic redirect following.".to_string(),
                        ),
                        confidence: "HIGH".to_string(),
                        source: Some(url_str),
                        sink: Some(format!("{}:{}", self.file_node.file_path, line)),
                        data_flow: Some(vec![format!("{}: {}", line, expr.to_source_string())]),
                        cwe: Some("CWE-918".to_string()),
                        fingerprint: Some(format!("VG-SSRF-001:{}:{}:{}", self.file_node.file_path, line, callee_str)),
                        ..Default::default()
                    });
                }
            }

            for a in args {
                self.inspect_expr(a, line, finding_counter, findings);
            }
        }
    }
}
