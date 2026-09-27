#![allow(dead_code)]

use crate::semantic::project_model::ProjectModel;
use crate::types::{Category, Finding, Severity};
use std::collections::HashSet;

pub fn analyze_project_semantic(model: &ProjectModel, finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut chains = model.find_sink_chains(8);
    chains.sort_by_key(|a| std::cmp::Reverse(a.edges.len()));

    let mut seen_sinks = HashSet::new();
    let mut seen_fingerprints = HashSet::new();

    for chain in &chains {
        // We are particularly interested in interprocedural chains (>= 2 edges or crossing file boundaries)
        if chain.edges.is_empty() {
            continue;
        }

        if !seen_sinks.insert(chain.sink_id.clone()) {
            continue;
        }

        let first_edge = &chain.edges[0];
        let last_edge = chain.edges.last().unwrap();

        let crosses_files = chain
            .edges
            .iter()
            .any(|e| e.caller_file != first_edge.caller_file);

        let (rule_id, cwe, title, default_sev, default_desc, recommendation) = match chain.sink_kind.as_str() {
            "SQL_INJECTION" => (
                "VG-SAST-001",
                "CWE-89",
                "Interprocedural SQL Injection",
                Severity::CRITICAL,
                "Untrusted user input flows through project call chain into database query execution without parameterization.",
                "Use parameterized queries, prepared statements, or ORM parameter binding across all service and query layers.",
            ),
            "COMMAND_INJECTION" => (
                "VG-SAST-002",
                "CWE-78",
                "Interprocedural Command Injection",
                Severity::CRITICAL,
                "Untrusted input propagates through inter-module call graph directly into an OS system command execution sink.",
                "Avoid shell execution or pass arguments as a pre-tokenized array without shell invocation.",
            ),
            "CODE_INJECTION" => (
                "VG-SAST-003",
                "CWE-94",
                "Interprocedural Dynamic Code Execution",
                Severity::HIGH,
                "Data flows through call chain into dynamic code evaluation function.",
                "Refactor code to avoid dynamic code evaluation or eval functions.",
            ),
            _ => (
                "VG-SAST-000",
                "CWE-20",
                "Interprocedural Taint Flow to Sink",
                Severity::HIGH,
                "External input propagates across function calls into a sensitive operation sink.",
                "Validate and sanitize input before passing it to sinks.",
            ),
        };

        let formatted_chain = chain.format_chain(&model.call_graph.nodes);
        let data_flow = chain.to_data_flow_list(&model.call_graph.nodes);

        let fingerprint = format!(
            "{}:{}:{}:{}",
            rule_id, first_edge.caller_file, last_edge.callee_file, last_edge.call_line
        );

        if !seen_fingerprints.insert(fingerprint.clone()) {
            continue;
        }

        *finding_counter += 1;
        let finding_id = format!("VG-{:03}", *finding_counter);

        let start_node = model.call_graph.nodes.get(&chain.start_id);
        let entry_line = start_node.map(|n| n.line).unwrap_or(first_edge.call_line);

        let severity = if crosses_files {
            Severity::CRITICAL
        } else {
            default_sev
        };

        findings.push(Finding {
            id: finding_id,
            rule_id: Some(rule_id.to_string()),
            category: Category::SourceCode,
            severity,
            title: title.to_string(),
            description: format!(
                "{} (Call depth: {}, Crosses files: {})",
                default_desc,
                chain.edges.len(),
                crosses_files
            ),
            file: first_edge.caller_file.clone(),
            line: entry_line,
            column: Some(1),
            evidence: Some(formatted_chain),
            recommendation: Some(recommendation.to_string()),
            confidence: "HIGH".to_string(),
            source: Some(chain.start_id.clone()),
            sink: Some(chain.sink_id.clone()),
            data_flow: Some(data_flow),
            cwe: Some(cwe.to_string()),
            fingerprint: Some(fingerprint),
        });
    }

    findings
}
