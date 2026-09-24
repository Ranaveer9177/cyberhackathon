#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Specific class of vulnerability for data-flow taint propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintKind {
    Sql,
    Command,
    Path,
    Ssrf,
    Xss,
    Template,
    Deserialization,
    Ldap,
}

impl TaintKind {
    pub fn cwe(&self) -> &'static str {
        match self {
            TaintKind::Sql => "CWE-89",
            TaintKind::Command => "CWE-78",
            TaintKind::Path => "CWE-22",
            TaintKind::Ssrf => "CWE-918",
            TaintKind::Xss => "CWE-79",
            TaintKind::Template => "CWE-1336",
            TaintKind::Deserialization => "CWE-502",
            TaintKind::Ldap => "CWE-90",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            TaintKind::Sql => "SQL Injection",
            TaintKind::Command => "Command Injection",
            TaintKind::Path => "Path Traversal",
            TaintKind::Ssrf => "Server-Side Request Forgery",
            TaintKind::Xss => "Cross-Site Scripting",
            TaintKind::Template => "Server-Side Template Injection",
            TaintKind::Deserialization => "Insecure Deserialization",
            TaintKind::Ldap => "LDAP Injection",
        }
    }
}

/// Individual step in a multi-hop taint trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStep {
    pub file: String,
    pub line: usize,
    pub symbol: String,
    pub step_type: String, // "source", "assignment", "arg_to_param", "return", "sink"
    pub snippet: String,
}

/// Complete end-to-end data flow path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub kind: TaintKind,
    pub source_expr: String,
    pub sink_expr: String,
    pub steps: Vec<TaintStep>,
    pub is_sanitized: bool,
    pub sanitizer_used: Option<String>,
}

impl TaintFlow {
    pub fn new(kind: TaintKind, source_expr: &str, sink_expr: &str) -> Self {
        Self {
            kind,
            source_expr: source_expr.to_string(),
            sink_expr: sink_expr.to_string(),
            steps: Vec::new(),
            is_sanitized: false,
            sanitizer_used: None,
        }
    }

    pub fn add_step(
        &mut self,
        file: &str,
        line: usize,
        symbol: &str,
        step_type: &str,
        snippet: &str,
    ) {
        self.steps.push(TaintStep {
            file: file.to_string(),
            line,
            symbol: symbol.to_string(),
            step_type: step_type.to_string(),
            snippet: snippet.to_string(),
        });
    }

    pub fn to_provenance_strings(&self) -> Vec<String> {
        self.steps
            .iter()
            .map(|s| {
                format!(
                    "{} (line {}): {} [{}]",
                    std::path::Path::new(&s.file)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&s.file),
                    s.line,
                    s.snippet,
                    s.step_type
                )
            })
            .collect()
    }
}

/// Vulnerability-specific sanitizer model.
pub struct SanitizerModel;

impl SanitizerModel {
    /// Checks whether an expression effectively sanitizes a specific taint kind.
    pub fn is_effective(kind: TaintKind, expr: &str) -> bool {
        match kind {
            TaintKind::Sql => {
                // Numeric typecasts eliminate SQL injection
                expr.contains("int(")
                    || expr.contains("float(")
                    || expr.contains("parseInt(")
                    || expr.contains("strconv.Atoi(")
            }
            TaintKind::Command => {
                // Shell argument escaping or explicit quote helpers
                expr.contains("shlex.quote(")
                    || expr.contains("escapeshellcmd(")
                    || expr.contains("escapeshellarg(")
            }
            TaintKind::Path => {
                // Path normalization / filename extraction
                expr.contains("os.path.basename(")
                    || expr.contains("filepath.Base(")
                    || expr.contains("path.basename(")
            }
            TaintKind::Ssrf => {
                // URL allowlist checks
                expr.contains("is_safe_url(")
                    || expr.contains("validate_url(")
                    || expr.contains("urlparse(")
            }
            TaintKind::Xss => {
                // HTML entity encoders
                expr.contains("html.escape(")
                    || expr.contains("DOMPurify.sanitize(")
                    || expr.contains("escapeHtml(")
            }
            _ => false,
        }
    }
}
