use serde::Serialize;

#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Debug, Serialize, Clone, PartialEq, Eq, Default)]
pub enum Severity {
    CRITICAL,
    HIGH,
    #[default]
    MEDIUM,
    LOW,
    INFO,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secret,
    #[default]
    SourceCode,
    Dependency,
    Configuration,
    Docker,
    Git,
    File,
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    pub evidence: Option<String>,
    pub recommendation: Option<String>,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_flow: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            id: String::new(),
            rule_id: None,
            category: Category::SourceCode,
            severity: Severity::MEDIUM,
            title: String::new(),
            description: String::new(),
            file: String::new(),
            line: 0,
            column: Some(1),
            evidence: None,
            recommendation: None,
            confidence: "HIGH".to_string(),
            source: None,
            sink: None,
            data_flow: None,
            cwe: None,
            fingerprint: None,
        }
    }
}

impl Finding {
    pub fn compute_fingerprint(&self) -> String {
        let norm_file = self.file.replace('\\', "/");
        let rule = self.rule_id.as_deref().unwrap_or(&self.id);
        let rule_clean = if rule.starts_with("VG-0") {
            self.title.trim().to_lowercase()
        } else {
            rule.to_string()
        };
        let src = self.source.as_deref().unwrap_or("").trim();
        let snk = self.sink.as_deref().unwrap_or("").trim();
        let col = self.column.unwrap_or(1);
        let evidence = self.evidence.as_deref().unwrap_or("").trim();
        let evidence_prefix = if evidence.len() > 60 {
            &evidence[..60]
        } else {
            evidence
        };
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            rule_clean, norm_file, self.line, col, src, snk, evidence_prefix
        )
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct ScanWarning {
    pub file: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub project: String,
    pub files_scanned: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_skipped: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_files: Option<usize>,
    pub findings: Vec<Finding>,
    pub scan_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_warnings: Option<Vec<ScanWarning>>,
}
