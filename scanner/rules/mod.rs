#![allow(dead_code)]

pub mod command;
pub mod path;
pub mod sql;
pub mod ssrf;
pub mod xss;

use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::types::TypeEnvironment;
use crate::ast::types::{FileNode, StmtNode};
use crate::types::Finding;

pub use command::CommandRuleEngine;
pub use path::PathRuleEngine;
pub use sql::SqlRuleEngine;
pub use ssrf::SsrfRuleEngine;
pub use xss::XssRuleEngine;

use std::collections::{HashMap, HashSet};

fn collect_stmts_env(
    stmts: &[StmtNode],
    const_env: &mut ConstantEnvironment,
    type_env: &mut TypeEnvironment,
    sanitizer_env: &mut HashMap<String, HashSet<crate::taint::types::TaintKind>>,
) {
    for stmt in stmts {
        match stmt {
            StmtNode::Assignment(assign) => {
                let target = assign.target.to_source_string();
                const_env.set_constant(&target, const_env.eval_expr(&assign.value));
                type_env.set_type(&target, type_env.infer_expr(&assign.value));
                let (kinds, _) = crate::taint::sanitizers::SanitizerModel::sanitized_kinds(
                    &assign.value.to_source_string(),
                );
                if !kinds.is_empty() {
                    sanitizer_env.entry(target).or_default().extend(kinds);
                }
            }
            StmtNode::Condition(c) => {
                collect_stmts_env(&c.then_body, const_env, type_env, sanitizer_env);
                collect_stmts_env(&c.else_body, const_env, type_env, sanitizer_env);
            }
            StmtNode::Loop(l) => {
                collect_stmts_env(&l.body, const_env, type_env, sanitizer_env);
            }
            StmtNode::TryCatch(t) => {
                collect_stmts_env(&t.try_body, const_env, type_env, sanitizer_env);
                collect_stmts_env(&t.catch_body, const_env, type_env, sanitizer_env);
                collect_stmts_env(&t.finally_body, const_env, type_env, sanitizer_env);
            }
            _ => {}
        }
    }
}

/// Runs all semantic security rules (SQL, Command Injection, SSRF, Path Traversal, XSS)
/// across the project's parsed AST files.
pub fn run_semantic_rules(
    parsed_files: &[(&str, &FileNode)],
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (_file_path, file_node) in parsed_files {
        let mut type_env = TypeEnvironment::new();
        let mut const_env = ConstantEnvironment::new();
        let mut sanitizer_env: HashMap<String, HashSet<crate::taint::types::TaintKind>> =
            HashMap::new();

        collect_stmts_env(
            &file_node.statements,
            &mut const_env,
            &mut type_env,
            &mut sanitizer_env,
        );
        for func in &file_node.functions {
            collect_stmts_env(
                &func.body,
                &mut const_env,
                &mut type_env,
                &mut sanitizer_env,
            );
        }
        for cls in &file_node.classes {
            for field in &cls.fields {
                let target = field.target.to_source_string();
                const_env.set_constant(&target, const_env.eval_expr(&field.value));
                type_env.set_type(&target, type_env.infer_expr(&field.value));
                let (kinds, _) = crate::taint::sanitizers::SanitizerModel::sanitized_kinds(
                    &field.value.to_source_string(),
                );
                if !kinds.is_empty() {
                    sanitizer_env.entry(target).or_default().extend(kinds);
                }
            }
            for method in &cls.methods {
                collect_stmts_env(
                    &method.body,
                    &mut const_env,
                    &mut type_env,
                    &mut sanitizer_env,
                );
            }
        }

        // 1. Semantic SQL Injection rules
        let sql_engine = SqlRuleEngine::new(file_node, &type_env, &const_env);
        findings.append(&mut sql_engine.analyze(finding_counter));

        // 2. Semantic Command Injection rules
        let cmd_engine = CommandRuleEngine::new(file_node, &type_env, &const_env, &sanitizer_env);
        findings.append(&mut cmd_engine.analyze(finding_counter));

        // 3. Semantic SSRF rules
        let ssrf_engine = SsrfRuleEngine::new(file_node, &type_env, &const_env);
        findings.append(&mut ssrf_engine.analyze(finding_counter));

        // 4. Semantic Path Traversal rules
        let path_engine = PathRuleEngine::new(file_node, &type_env, &const_env);
        findings.append(&mut path_engine.analyze(finding_counter));

        // 5. Semantic XSS rules
        let xss_engine = XssRuleEngine::new(file_node, &type_env, &const_env);
        findings.append(&mut xss_engine.analyze(finding_counter));
    }

    findings
}
