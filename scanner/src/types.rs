use serde::Serialize;

#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Debug, Serialize, Clone)]
pub enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone)]
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
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub project: String,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
    pub scan_time_ms: u64,
}
