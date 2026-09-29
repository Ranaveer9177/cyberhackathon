pub mod cfg;
pub mod constants;
pub mod rules;
pub mod string_propagation;
pub mod types;
pub mod verification;

use crate::taint::types::TaintFlow;
use crate::types::{Category, Finding, Severity};
use std::collections::HashSet;

pub use cfg::{CfgEdgeKind, CfgNodeKind, ControlFlowGraph};
pub use constants::{ConstantEnvironment, ConstantValue};
pub use rules::get_rule_meta;
pub use string_propagation::{StringFragment, StringPropagator, StringTransformation};
pub use types::{InferredType, TypeEnvironment};
pub use verification::{EvidenceTier, FindingVerificationEngine, VerificationResult};

/// Converts deep TaintFlow paths into normalized, deduplicated security findings.
pub fn generate_taint_findings(flows: &[TaintFlow], finding_counter: &mut usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_fingerprints = HashSet::new();

    for flow in flows {
        if flow.is_sanitized {
            continue;
        }

        let meta = get_rule_meta(flow.kind);
        let fingerprint = format!(
            "{}:{}:{}:{}",
            meta.rule_id, flow.source_file, flow.sink_file, flow.sink_line
        );

        if !seen_fingerprints.insert(fingerprint.clone()) {
            continue;
        }

        *finding_counter += 1;
        let finding_id = format!("VG-{:03}", *finding_counter);

        let severity = if flow.crosses_files {
            Severity::CRITICAL
        } else {
            Severity::HIGH
        };

        let evidence_diagram = flow.format_evidence_diagram();
        let data_flow = flow.to_data_flow_list();

        let desc = format!(
            "{} (Trace steps: {}, Crosses files: {})",
            meta.description,
            flow.steps.len(),
            flow.crosses_files
        );

        findings.push(Finding {
            id: finding_id,
            rule_id: Some(meta.rule_id.to_string()),
            category: Category::SourceCode,
            severity,
            title: meta.title.to_string(),
            description: desc,
            file: flow.source_file.clone(),
            line: flow.source_line,
            column: Some(1),
            evidence: Some(evidence_diagram),
            recommendation: Some(meta.recommendation.to_string()),
            confidence: "HIGH".to_string(),
            source: Some(format!("{}: {}", flow.source_file, flow.source_symbol)),
            sink: Some(format!("{}: {}", flow.sink_file, flow.sink_symbol)),
            data_flow: Some(data_flow),
            cwe: Some(meta.cwe.to_string()),
            fingerprint: Some(fingerprint),
            ..Default::default()
        });
    }

    findings
}
