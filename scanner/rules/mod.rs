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

        for stmt in &file_node.statements {
            if let StmtNode::Assignment(assign) = stmt {
                let target = assign.target.to_source_string();
                const_env.set_constant(&target, const_env.eval_expr(&assign.value));
                type_env.set_type(&target, type_env.infer_expr(&assign.value));
            }
        }
        for func in &file_node.functions {
            for stmt in &func.body {
                if let StmtNode::Assignment(assign) = stmt {
                    let target = assign.target.to_source_string();
                    const_env.set_constant(&target, const_env.eval_expr(&assign.value));
                    type_env.set_type(&target, type_env.infer_expr(&assign.value));
                }
            }
        }

        // 1. Semantic SQL Injection rules
        let sql_engine = SqlRuleEngine::new(file_node, &type_env, &const_env);
        findings.append(&mut sql_engine.analyze(finding_counter));

        // 2. Semantic Command Injection rules
        let cmd_engine = CommandRuleEngine::new(file_node, &type_env, &const_env);
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
