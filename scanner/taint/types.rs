#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintKind {
    Sql,
    Command,
    Ssrf,
    Path,
    Xss,
    Template,
    Deserialization,
}

impl TaintKind {
    pub fn all() -> Vec<TaintKind> {
        vec![
            TaintKind::Sql,
            TaintKind::Command,
            TaintKind::Ssrf,
            TaintKind::Path,
            TaintKind::Xss,
            TaintKind::Template,
            TaintKind::Deserialization,
        ]
    }

    pub fn cwe(&self) -> &'static str {
        match self {
            TaintKind::Sql => "CWE-89",
            TaintKind::Command => "CWE-78",
            TaintKind::Ssrf => "CWE-918",
            TaintKind::Path => "CWE-22",
            TaintKind::Xss => "CWE-79",
            TaintKind::Template => "CWE-1336",
            TaintKind::Deserialization => "CWE-502",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            TaintKind::Sql => "SQL Injection",
            TaintKind::Command => "Command Injection",
            TaintKind::Ssrf => "Server-Side Request Forgery (SSRF)",
            TaintKind::Path => "Path Traversal",
            TaintKind::Xss => "Cross-Site Scripting (XSS)",
            TaintKind::Template => "Server-Side Template Injection (SSTI)",
            TaintKind::Deserialization => "Insecure Deserialization",
        }
    }

    pub fn rule_id(&self) -> &'static str {
        match self {
            TaintKind::Sql => "VG-TAINT-SQL",
            TaintKind::Command => "VG-TAINT-CMD",
            TaintKind::Ssrf => "VG-TAINT-SSRF",
            TaintKind::Path => "VG-TAINT-PATH",
            TaintKind::Xss => "VG-TAINT-XSS",
            TaintKind::Template => "VG-TAINT-SSTI",
            TaintKind::Deserialization => "VG-TAINT-DESER",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintStepType {
    Source,
    Assignment,
    Transformation,
    FunctionParameter,
    FunctionCall,
    Return,
    AnotherFile,
    Sink,
}

impl TaintStepType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaintStepType::Source => "SOURCE",
            TaintStepType::Assignment => "assignment",
            TaintStepType::Transformation => "transformation",
            TaintStepType::FunctionParameter => "function parameter",
            TaintStepType::FunctionCall => "function call",
            TaintStepType::Return => "return",
            TaintStepType::AnotherFile => "another file",
            TaintStepType::Sink => "SINK",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStep {
    pub file: String,
    pub line: usize,
    pub symbol: String,
    pub step_type: TaintStepType,
    pub snippet: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub kind: TaintKind,
    pub source_file: String,
    pub source_line: usize,
    pub source_symbol: String,
    pub sink_file: String,
    pub sink_line: usize,
    pub sink_symbol: String,
    pub steps: Vec<TaintStep>,
    pub is_sanitized: bool,
    pub sanitizer_name: Option<String>,
    pub crosses_files: bool,
    pub call_depth: usize,
}

impl TaintFlow {
    pub fn format_evidence_diagram(&self) -> String {
        let mut lines = Vec::new();

        for (i, step) in self.steps.iter().enumerate() {
            if i > 0 {
                lines.push(format!(" ↓ {}", step.step_type.as_str()));
            }

            let basename = std::path::Path::new(&step.file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&step.file);

            match step.step_type {
                TaintStepType::Source => {
                    lines.push(format!(
                        "SOURCE [{}:{}] ({})",
                        basename, step.line, step.snippet
                    ));
                }
                TaintStepType::Sink => {
                    lines.push(format!(
                        "SINK [{}:{}] ({} - {})",
                        basename,
                        step.line,
                        step.snippet,
                        self.kind.name()
                    ));
                }
                _ => {
                    lines.push(format!("{} [{}:{}]", step.snippet, basename, step.line));
                }
            }
        }

        lines.join("\n")
    }

    pub fn to_data_flow_list(&self) -> Vec<String> {
        self.steps
            .iter()
            .map(|s| {
                let basename = std::path::Path::new(&s.file)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&s.file);
                format!(
                    "{}:{}: {} [{}]",
                    basename,
                    s.line,
                    s.snippet,
                    s.step_type.as_str()
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct TaintedVariable {
    pub name: String,
    pub scope: String,
    pub file: String,
    pub line: usize,
    pub taints: HashSet<TaintKind>,
    pub sanitized_for: HashSet<TaintKind>,
    pub steps: Vec<TaintStep>,
}
