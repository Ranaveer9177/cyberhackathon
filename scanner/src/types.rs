use serde::Serialize;

#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secret,
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
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
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
