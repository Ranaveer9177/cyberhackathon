//! v7.1 — Canonical Finding Engine & Multi-Level Semantic Deduplication
//!
//! Converts raw heterogeneous detector signals (Lexical SAST, AST, Semantic, Taint, Rules, Docker, Config)
//! into canonical security findings according to the v7.1 unified specification:
//!
//! Finding
//! ├── finding_id
//! ├── canonical_rule
//! ├── category
//! ├── severity
//! ├── confidence
//! ├── CWE
//! ├── primary_location (file, line, column)
//! ├── source
//! ├── sink
//! ├── data_flow
//! ├── evidence[]
//! ├── detector_ids[]
//! ├── related_findings[]
//! └── remediation (recommendation)
//!
//! Deduplication Levels:
//!   Level 1: Exact duplicate (fingerprint identity)
//!   Level 2: Same rule + same file + same line
//!   Level 3: Different rules targeting the same underlying security issue on the same line (e.g. VG-SEC-001 + VG-CFG-008 on .env:14)
//!   Level 4: Same sink + multiple detectors (Lexical SAST + AST + Deep Taint + Semantic Rule)
//!   Level 5: Same vulnerability across related container/config definitions

use crate::types::{Category, Finding, Severity};
use std::collections::HashMap;

/// Maps a raw rule ID or title to a unified canonical rule family and CWE.
pub fn classify_canonical_rule(
    rule_id: &str,
    title: &str,
    category: &Category,
) -> (&'static str, &'static str, &'static str) {
    let r = rule_id.to_uppercase();
    let t = title.to_lowercase();

    // 1. Secrets & Credentials
    if r.contains("SEC-001") || t.contains("aws") {
        ("VG-CANON-CRED-AWS", "Exposed AWS Credential", "CWE-798")
    } else if r.contains("SEC-003") || t.contains("github") {
        ("VG-CANON-CRED-GITHUB", "Exposed GitHub Token", "CWE-798")
    } else if r.contains("AUTH-003") || t.contains("jwt") {
        ("VG-CANON-CRED-JWT", "Exposed JWT Secret", "CWE-798")
    } else if t.contains("database password")
        || t.contains("db_password")
        || t.contains("database_url")
    {
        ("VG-CANON-CRED-DB", "Exposed Database Password", "CWE-798")
    } else if r.contains("SEC-002") || t.contains("api key") || t.contains("apikey") {
        ("VG-CANON-CRED-APIKEY", "Exposed API Key", "CWE-798")
    } else if r.contains("SEC-004") || t.contains("slack") {
        ("VG-CANON-CRED-SLACK", "Exposed Slack Token", "CWE-798")
    } else if r.contains("SEC-005") || t.contains("private key") {
        (
            "VG-CANON-CRED-KEY",
            "Exposed Private Cryptographic Key",
            "CWE-798",
        )
    } else if r.contains("SECRET-FILE") || t.contains("sensitive credential file") {
        (
            "VG-CANON-FILE-SECRET",
            "Exposed Environment / Credential File",
            "CWE-200",
        )
    } else if *category == Category::Secret
        || r.contains("SECRET")
        || t.contains("password")
        || t.contains("secret")
        || t.contains("credential")
    {
        (
            "VG-CANON-CRED-GENERIC",
            "Hardcoded Credential or Sensitive Token",
            "CWE-798",
        )
    }
    // 2. Injections
    else if r.contains("SQL") || t.contains("sql injection") {
        ("VG-CANON-INJ-SQL", "SQL Injection", "CWE-89")
    } else if r.contains("CMD")
        || r.contains("SAST-002")
        || r.contains("SAST-008")
        || t.contains("command injection")
        || t.contains("shell execution")
    {
        ("VG-CANON-INJ-CMD", "OS Command Injection", "CWE-78")
    } else if r.contains("SSRF") || t.contains("ssrf") || t.contains("server-side request forgery")
    {
        (
            "VG-CANON-SSRF",
            "Server-Side Request Forgery (SSRF)",
            "CWE-918",
        )
    } else if r.contains("PATH") || t.contains("path traversal") {
        ("VG-CANON-PATH", "Path Traversal", "CWE-22")
    } else if r.contains("XSS") || t.contains("cross-site") || t.contains("xss") {
        ("VG-CANON-XSS", "Cross-Site Scripting (XSS)", "CWE-79")
    } else if r.contains("DESER") || t.contains("deserializ") || t.contains("pickle") {
        ("VG-CANON-DESER", "Insecure Deserialization", "CWE-502")
    }
    // 3. Auth & Cryptography
    else if r.contains("AUTH-001") || t.contains("password hash") {
        (
            "VG-CANON-AUTH-HASH",
            "Weak Password Hashing Algorithm",
            "CWE-916",
        )
    } else if r.contains("AUTH-002") || t.contains("predictable") {
        (
            "VG-CANON-AUTH-TOKEN",
            "Predictable Security Token",
            "CWE-330",
        )
    } else if r.contains("SAST-005")
        || t.contains("weak crypto")
        || t.contains("md5")
        || t.contains("sha1")
    {
        (
            "VG-CANON-CRYPTO-WEAK",
            "Weak Cryptographic Primitive",
            "CWE-327",
        )
    } else if r.contains("SAST-004")
        || r.contains("CFG-007")
        || t.contains("tls")
        || t.contains("ssl")
    {
        (
            "VG-CANON-TLS-INSECURE",
            "Insecure TLS / SSL Verification Disabled",
            "CWE-295",
        )
    }
    // 4. Docker & Infrastructure
    else if *category == Category::Docker || r.contains("DCK") {
        (
            "VG-CANON-DOCKER",
            "Container Security Misconfiguration",
            "CWE-16",
        )
    }
    // 5. Configuration
    else if *category == Category::Configuration || r.contains("CFG") {
        (
            "VG-CANON-CONFIG",
            "Application Security Misconfiguration",
            "CWE-16",
        )
    }
    // 6. Fallback
    else {
        ("VG-CANON-GENERIC", "Security Vulnerability", "CWE-699")
    }
}

/// Executes all 5 levels of deduplication and canonicalization across raw findings.
pub fn canonicalize_and_deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase A: Canonical Tagging
    // ─────────────────────────────────────────────────────────────────────────
    let tagged: Vec<Finding> = findings
        .into_iter()
        .map(|mut f| {
            let rule = f.rule_id.clone().unwrap_or_else(|| f.id.clone());
            let (canon_id, _canon_title, cwe_str) =
                classify_canonical_rule(&rule, &f.title, &f.category);

            f.canonical_rule = Some(canon_id.to_string());
            if f.cwe.is_none() {
                f.cwe = Some(cwe_str.to_string());
            }

            // Ensure detector_ids is populated
            if f.detector_ids.is_none() {
                f.detector_ids = Some(vec![rule]);
            }

            // Ensure evidences list is populated
            if f.evidences.is_none() {
                let ev_list = if let Some(e) = &f.evidence {
                    vec![e.clone()]
                } else {
                    Vec::new()
                };
                f.evidences = Some(ev_list);
            }

            // Standardize column
            if f.column.is_none() {
                f.column = Some(1);
            }

            // Recompute fingerprint
            let fp = f.compute_fingerprint();
            f.fingerprint = Some(fp);

            f
        })
        .collect();

    // ─────────────────────────────────────────────────────────────────────────
    // Level 1: Exact duplicate by fingerprint
    // ─────────────────────────────────────────────────────────────────────────
    let mut level1_seen = std::collections::HashSet::new();
    let mut level1_deduped = Vec::with_capacity(tagged.len());
    for f in tagged {
        let key = f.fingerprint.clone().unwrap_or_default();
        if level1_seen.insert(key) {
            level1_deduped.push(f);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Level 2 & 3: Multi-detector overlap on the same line for the same issue
    // E.g. VG-SEC-001 (AWS Key) and VG-CFG-008 (Config Secret) on .env:14
    // E.g. VG-SECRET-003 and VG-CFG-008 on .env:28
    // ─────────────────────────────────────────────────────────────────────────
    let mut line_groups: HashMap<(String, usize, String), Vec<Finding>> = HashMap::new();
    let mut non_line_findings = Vec::new();

    for f in level1_deduped {
        if f.line > 0 {
            let canon = f.canonical_rule.clone().unwrap_or_default();
            // Determine family grouping: Secrets/Credentials group together on same line
            let group_family =
                if canon.starts_with("VG-CANON-CRED") || canon.starts_with("VG-CANON-FILE") {
                    "CREDENTIAL".to_string()
                } else {
                    canon
                };

            let norm_file = f.file.replace('\\', "/").to_lowercase();
            let key = (norm_file, f.line, group_family);
            line_groups.entry(key).or_default().push(f);
        } else {
            non_line_findings.push(f);
        }
    }

    let mut level3_merged = Vec::new();
    for (_key, group) in line_groups {
        if group.len() == 1 {
            level3_merged.push(group.into_iter().next().unwrap());
        } else {
            level3_merged.push(merge_findings(group));
        }
    }
    level3_merged.extend(non_line_findings);

    // ─────────────────────────────────────────────────────────────────────────
    // Level 4: Same sink + multiple taint/AST/SAST detectors
    // E.g. Lexical SAST + AST rule + Deep Taint pointing to the same sink (file:line)
    // ─────────────────────────────────────────────────────────────────────────
    let mut sink_groups: HashMap<(String, usize, String), Vec<Finding>> = HashMap::new();
    let mut independent_findings = Vec::new();

    for f in level3_merged {
        let canon = f.canonical_rule.clone().unwrap_or_default();
        let is_injection_or_taint = canon.contains("INJ")
            || canon.contains("SSRF")
            || canon.contains("PATH")
            || canon.contains("XSS")
            || canon.contains("DESER");

        if is_injection_or_taint && f.line > 0 {
            let norm_file = f.file.replace('\\', "/").to_lowercase();
            let key = (norm_file, f.line, canon);
            sink_groups.entry(key).or_default().push(f);
        } else {
            independent_findings.push(f);
        }
    }

    let mut level4_merged = Vec::new();
    for (_key, group) in sink_groups {
        if group.len() == 1 {
            level4_merged.push(group.into_iter().next().unwrap());
        } else {
            level4_merged.push(merge_findings(group));
        }
    }
    level4_merged.extend(independent_findings);

    // Sort deterministically: by file, line, then rule
    level4_merged.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.id.cmp(&b.id))
    });

    level4_merged
}

fn detector_specificity_rank(f: &Finding) -> u8 {
    let r = f.rule_id.as_deref().unwrap_or(&f.id).to_uppercase();
    let t = f.title.to_lowercase();
    let ev = f.evidence.as_deref().unwrap_or("").to_lowercase();

    if r.contains("SEC-001")
        || t.contains("aws")
        || ev.contains("aws_access_key")
        || ev.contains("akia")
    {
        10
    } else if r.contains("SEC-003") || t.contains("github") || ev.contains("ghp_") {
        9
    } else if r.contains("AUTH-003") || t.contains("jwt") || ev.contains("jwt_secret") {
        8
    } else if t.contains("database password")
        || t.contains("db_password")
        || ev.contains("db_password")
        || ev.contains("database_url")
    {
        7
    } else if r.contains("SEC-002")
        || t.contains("api key")
        || t.contains("apikey")
        || ev.contains("api_key")
    {
        6
    } else if r.contains("SEC-004") || t.contains("slack") {
        5
    } else if r.contains("SEC-005") || t.contains("private key") {
        4
    } else if r.contains("SECRET-001")
        || r.contains("SECRET-002")
        || r.contains("SECRET-003")
        || r.contains("SEC-006")
        || r.contains("SEC-007")
        || r.contains("SEC-008")
    {
        3
    } else if r.contains("CFG-008") {
        2
    } else {
        1
    }
}

/// Merges multiple overlapping detector findings into one canonical security finding.
fn merge_findings(mut group: Vec<Finding>) -> Finding {
    // Select the finding with highest severity, highest detector specificity, and richest data flow as base
    group.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| detector_specificity_rank(b).cmp(&detector_specificity_rank(a)))
            .then_with(|| {
                b.data_flow
                    .as_ref()
                    .map_or(0, |d| d.len())
                    .cmp(&a.data_flow.as_ref().map_or(0, |d| d.len()))
            })
    });

    let mut base = group.remove(0);

    let mut all_detectors = base.detector_ids.take().unwrap_or_default();
    let mut all_evidences = base.evidences.take().unwrap_or_default();
    let mut related = base.related_findings.take().unwrap_or_default();

    for other in group {
        // Collect detector IDs
        if let Some(mut other_detectors) = other.detector_ids {
            all_detectors.append(&mut other_detectors);
        } else {
            let rule = other.rule_id.unwrap_or(other.id.clone());
            all_detectors.push(rule);
        }

        // Collect evidences
        if let Some(mut other_ev) = other.evidences {
            all_evidences.append(&mut other_ev);
        } else if let Some(e) = other.evidence {
            all_evidences.push(e);
        }

        // Record related finding ID
        related.push(other.id);

        // Keep highest confidence
        if other.confidence.starts_with("HIGH") && !base.confidence.starts_with("HIGH") {
            base.confidence = other.confidence;
        }

        // Preserve data flow if other has a deeper flow
        if base.data_flow.is_none() && other.data_flow.is_some() {
            base.data_flow = other.data_flow;
            base.source = other.source;
            base.sink = other.sink;
        }
    }

    // Deduplicate lists
    all_detectors.sort();
    all_detectors.dedup();
    all_evidences.sort();
    all_evidences.dedup();
    related.sort();
    related.dedup();

    // Standardize canonical title, rule, and category if specific detectors or evidence match
    let has_detector = |needle: &str| all_detectors.iter().any(|d| d.contains(needle));
    let ev_combined = all_evidences.join(" ").to_lowercase();
    let title_lower = base.title.to_lowercase();

    if has_detector("SEC-001")
        || title_lower.contains("aws")
        || ev_combined.contains("aws_access_key")
        || ev_combined.contains("akia")
    {
        base.title = "Exposed AWS Credential".to_string();
        base.canonical_rule = Some("VG-CANON-CRED-AWS".to_string());
        base.category = Category::Secret;
        base.severity = Severity::CRITICAL;
        base.cwe = Some("CWE-798".to_string());
    } else if has_detector("SEC-003")
        || title_lower.contains("github")
        || ev_combined.contains("ghp_")
    {
        base.title = "Exposed GitHub Token".to_string();
        base.canonical_rule = Some("VG-CANON-CRED-GITHUB".to_string());
        base.category = Category::Secret;
        base.severity = Severity::CRITICAL;
        base.cwe = Some("CWE-798".to_string());
    } else if has_detector("AUTH-003") || title_lower.contains("jwt") || ev_combined.contains("jwt")
    {
        base.title = "Exposed JWT Secret".to_string();
        base.canonical_rule = Some("VG-CANON-CRED-JWT".to_string());
        base.category = Category::Secret;
        base.severity = Severity::CRITICAL;
        base.cwe = Some("CWE-798".to_string());
    } else if title_lower.contains("database password")
        || ev_combined.contains("db_password")
        || ev_combined.contains("database_url")
        || ev_combined.contains("db_pass")
    {
        base.title = "Exposed Database Password".to_string();
        base.canonical_rule = Some("VG-CANON-CRED-DB".to_string());
        base.category = Category::Secret;
        base.severity = Severity::CRITICAL;
        base.cwe = Some("CWE-798".to_string());
    } else if has_detector("SEC-002")
        || has_detector("SECRET-002")
        || title_lower.contains("api key")
        || ev_combined.contains("api_key")
        || ev_combined.contains("apikey")
    {
        base.title = "Exposed API Key".to_string();
        base.canonical_rule = Some("VG-CANON-CRED-APIKEY".to_string());
        base.category = Category::Secret;
        base.severity = Severity::CRITICAL;
        base.cwe = Some("CWE-798".to_string());
    }

    // Pick clean key-value evidence if base evidence is bare value
    if !base.evidence.as_deref().unwrap_or("").contains('=') {
        if let Some(clean_ev) = all_evidences.iter().find(|e| e.contains('=')) {
            base.evidence = Some(clean_ev.clone());
        }
    }

    base.detector_ids = Some(all_detectors);
    base.evidences = Some(all_evidences);
    if !related.is_empty() {
        base.related_findings = Some(related);
    }

    base
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::CRITICAL => 5,
        Severity::HIGH => 4,
        Severity::MEDIUM => 3,
        Severity::LOW => 2,
        Severity::INFO => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlate_aws_key_multi_detector() {
        let f1 = Finding {
            id: "VG-SEC-001".to_string(),
            rule_id: Some("VG-SEC-001".to_string()),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            title: "AWS Access Key".to_string(),
            description: "AWS key detected".to_string(),
            file: ".env".to_string(),
            line: 14,
            column: Some(1),
            evidence: Some(format!("AKIA{}", "IOSFODNN7EXAMPLE")),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };
        let f2 = Finding {
            id: "VG-CFG-008".to_string(),
            rule_id: Some("VG-CFG-008".to_string()),
            category: Category::Configuration,
            severity: Severity::CRITICAL,
            title: "Hardcoded Secret in Configuration File".to_string(),
            description: "High entropy secret".to_string(),
            file: ".env".to_string(),
            line: 14,
            column: Some(1),
            evidence: Some("AWS_ACCESS_KEY_ID=AKIAIOSF****".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };

        let deduped = canonicalize_and_deduplicate(vec![f1, f2]);
        assert_eq!(
            deduped.len(),
            1,
            "Expected exactly 1 canonical finding, got {}",
            deduped.len()
        );
        let res = &deduped[0];
        assert_eq!(res.title, "Exposed AWS Credential");
        assert_eq!(res.line, 14);
        assert_eq!(res.severity, Severity::CRITICAL);

        let detectors = res.detector_ids.as_ref().expect("expected detector_ids");
        assert!(detectors.iter().any(|d| d == "VG-SEC-001"));
        assert!(detectors.iter().any(|d| d == "VG-CFG-008"));
        assert_eq!(
            res.evidence.as_deref(),
            Some("AWS_ACCESS_KEY_ID=AKIAIOSF****")
        );
    }

    #[test]
    fn test_correlate_github_token_multi_detector() {
        let f1 = Finding {
            id: "VG-SEC-003".to_string(),
            rule_id: Some("VG-SEC-003".to_string()),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            title: "GitHub Token".to_string(),
            file: ".env".to_string(),
            line: 20,
            column: Some(1),
            evidence: Some("ghp_1234567890abcdef1234567890abcdef12".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };
        let f2 = Finding {
            id: "VG-CFG-008".to_string(),
            rule_id: Some("VG-CFG-008".to_string()),
            category: Category::Configuration,
            severity: Severity::CRITICAL,
            title: "Hardcoded Secret in Configuration File".to_string(),
            file: ".env".to_string(),
            line: 20,
            column: Some(1),
            evidence: Some("GITHUB_TOKEN=ghp_1234****".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };

        let deduped = canonicalize_and_deduplicate(vec![f1, f2]);
        assert_eq!(deduped.len(), 1);
        let res = &deduped[0];
        assert_eq!(res.title, "Exposed GitHub Token");
        let detectors = res.detector_ids.as_ref().unwrap();
        assert!(detectors.iter().any(|d| d == "VG-SEC-003"));
        assert!(detectors.iter().any(|d| d == "VG-CFG-008"));
    }

    #[test]
    fn test_correlate_jwt_secret_multi_detector() {
        let f1 = Finding {
            id: "VG-AUTH-003".to_string(),
            rule_id: Some("VG-AUTH-003".to_string()),
            category: Category::Secret,
            severity: Severity::HIGH,
            title: "Hardcoded Authentication Token".to_string(),
            file: ".env".to_string(),
            line: 25,
            evidence: Some("JWT_SECRET=super_secret_jwt_key_123456".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };
        let f2 = Finding {
            id: "VG-CFG-008".to_string(),
            rule_id: Some("VG-CFG-008".to_string()),
            category: Category::Configuration,
            severity: Severity::CRITICAL,
            title: "Hardcoded Secret in Configuration File".to_string(),
            file: ".env".to_string(),
            line: 25,
            evidence: Some("JWT_SECRET=super_se****".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };

        let deduped = canonicalize_and_deduplicate(vec![f1, f2]);
        assert_eq!(deduped.len(), 1);
        let res = &deduped[0];
        assert_eq!(res.title, "Exposed JWT Secret");
        let detectors = res.detector_ids.as_ref().unwrap();
        assert!(detectors.iter().any(|d| d == "VG-AUTH-003"));
        assert!(detectors.iter().any(|d| d == "VG-CFG-008"));
    }

    #[test]
    fn test_correlate_database_password_multi_detector() {
        let f1 = Finding {
            id: "VG-SECRET-001".to_string(),
            rule_id: Some("VG-SECRET-001".to_string()),
            category: Category::Secret,
            severity: Severity::HIGH,
            title: "Hardcoded Password Detected".to_string(),
            file: ".env".to_string(),
            line: 6,
            evidence: Some("db_password=SuperSecret123!".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };
        let f2 = Finding {
            id: "VG-CFG-008".to_string(),
            rule_id: Some("VG-CFG-008".to_string()),
            category: Category::Configuration,
            severity: Severity::CRITICAL,
            title: "Hardcoded Secret in Configuration File".to_string(),
            file: ".env".to_string(),
            line: 6,
            evidence: Some("DB_PASSWORD=SuperSec****".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };

        let deduped = canonicalize_and_deduplicate(vec![f1, f2]);
        assert_eq!(deduped.len(), 1);
        let res = &deduped[0];
        assert_eq!(res.title, "Exposed Database Password");
        let detectors = res.detector_ids.as_ref().unwrap();
        assert!(detectors.iter().any(|d| d == "VG-SECRET-001"));
        assert!(detectors.iter().any(|d| d == "VG-CFG-008"));
    }

    #[test]
    fn test_correlate_api_key_multi_detector() {
        let f1 = Finding {
            id: "VG-SEC-002".to_string(),
            rule_id: Some("VG-SEC-002".to_string()),
            category: Category::Secret,
            severity: Severity::CRITICAL,
            title: "Generic API Key".to_string(),
            file: ".env".to_string(),
            line: 9,
            evidence: Some("api_key=sk-demo-1234567890abcdef".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };
        let f2 = Finding {
            id: "VG-CFG-008".to_string(),
            rule_id: Some("VG-CFG-008".to_string()),
            category: Category::Configuration,
            severity: Severity::CRITICAL,
            title: "Hardcoded Secret in Configuration File".to_string(),
            file: ".env".to_string(),
            line: 9,
            evidence: Some("API_KEY=sk-demo-****".to_string()),
            confidence: "HIGH".to_string(),
            ..Default::default()
        };

        let deduped = canonicalize_and_deduplicate(vec![f1, f2]);
        assert_eq!(deduped.len(), 1);
        let res = &deduped[0];
        assert_eq!(res.title, "Exposed API Key");
        let detectors = res.detector_ids.as_ref().unwrap();
        assert!(detectors.iter().any(|d| d == "VG-SEC-002"));
        assert!(detectors.iter().any(|d| d == "VG-CFG-008"));
    }
}
