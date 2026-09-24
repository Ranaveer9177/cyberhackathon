use crate::rules::get_sast_rules;
use crate::types::{Category, Finding, Severity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub fn scan_source_code(
    file_path: &str,
    content: &str,
    finding_counter: &mut usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let allowed_exts = [
        "go", "js", "ts", "py", "java", "rs", "rb", "php", "c", "cpp", "cs",
    ];
    if !allowed_exts.contains(&ext) {
        return findings;
    }

    let rules = get_sast_rules();
    let lines: Vec<&str> = content.lines().collect();

    // -------------------------------------------------------------
    // 1. Data-Flow & Taint Tracking Analysis
    // -------------------------------------------------------------
    // Detect sources of user-controlled input:
    // e.g. host = request.args.get("host")
    let source_assign_re = Regex::new(
        r#"(?i)(?:^|[\s;])(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(?:request\.(?:args|form|values|json|get_json|data|files)|req\.(?:query|body|params)|r\.(?:URL\.Query|FormValue))"#,
    ).unwrap();
    let assign_re = Regex::new(r#"(?i)(?:^|[\s;])(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]"#).unwrap();

    let mut tainted_vars: HashMap<String, usize> = HashMap::new(); // var_name -> line_num
    let mut intermediate_vars: HashMap<String, (String, usize)> = HashMap::new(); // derived_var -> (source_var, line_num)

    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }

        if let Some(caps) = source_assign_re.captures(line) {
            if let Some(var_match) = caps.name("var") {
                let var_name = var_match.as_str().to_string();
                tainted_vars.insert(var_name, line_num);
            }
        }

        // Track intermediate derivations: e.g. cmd = f"ping -n 1 {host}"
        // or query = f"SELECT ... {user_id}"
        for t_var in tainted_vars.keys() {
            if line.contains(t_var) {
                if let Some(caps) = assign_re.captures(line) {
                    if let Some(derived_var) = caps.name("var") {
                        let d_name = derived_var.as_str().to_string();
                        if d_name != *t_var {
                            intermediate_vars.insert(d_name, (t_var.clone(), line_num));
                        }
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------
    // 2. Line-by-Line SAST Rule Evaluation
    // -------------------------------------------------------------
    let mut reported_lines: HashSet<(String, usize)> = HashSet::new();

    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // Stop scanning Rust files when entering test module
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }

        // Skip rule definition files (rules.rs)
        if file_path.ends_with("rules.rs") {
            continue;
        }

        // Skip rule definition metadata lines and scanner self-inspection
        if trimmed.starts_with("description:")
            || trimmed.starts_with("recommendation:")
            || trimmed.starts_with("name:")
            || trimmed.starts_with("id:")
            || trimmed.starts_with("category:")
            || trimmed.starts_with("severity:")
            || trimmed.starts_with("pattern:")
            || trimmed.starts_with("Rule {")
            || trimmed.starts_with("Regex::new")
            || trimmed.starts_with("regexp.MustCompile")
            || trimmed.starts_with("r#\"")
            || trimmed.starts_with("`(?i)")
        {
            continue;
        }

        // Skip comment lines
        if trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("--")
        {
            continue;
        }

        for rule in &rules {
            if rule.pattern.is_match(line) {
                // Skip scanner tool self-inspection patterns
                if line.contains("Regex::new")
                    || line.contains("regexp.MustCompile")
                    || line.contains("pattern:")
                    || line.contains(r#"contains("http"#)
                    || line.contains(r#"contains(lineLower, "http"#)
                    || line.contains("Rule {")
                {
                    continue;
                }

                // Skip safe fixed tool executions for command injection
                if rule.id == "VG-SAST-002"
                    && (line.contains(r#"exec.Command("git""#)
                        || line.contains("exec.CommandContext")
                        || line.contains("cargo")
                        || line.contains("go"))
                {
                    continue;
                }

                // Insecure HTTP URL refinement
                if rule.id == "VG-SAST-006" {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("http://localhost")
                        || line_lower.contains("http://127.0.0.1")
                        || line_lower.contains("http://0.0.0.0")
                        || line_lower.contains("http://::1")
                        || line_lower.contains("http://[::1]")
                        || line_lower.contains("w3.org")
                        || line_lower.contains("schemas.")
                        || line_lower.contains("json-schema.org")
                        || line_lower.contains("apache.org")
                        || line_lower.contains("example.com")
                        || line_lower.contains("example.org")
                        || line_lower.contains("http://{")
                        || line_lower.contains("http://${")
                        || line_lower.contains("http://%")
                    {
                        continue;
                    }
                }

                // Data flow escalation for SQL Injection
                let mut confidence = "MEDIUM".to_string();
                let mut severity = rule.severity.clone();
                let mut description = rule.description.clone();

                if rule.id == "VG-SAST-001" {
                    for (t_var, src_line) in &tainted_vars {
                        if line.contains(t_var) {
                            confidence = "HIGH".to_string();
                            description = format!(
                                "SQL injection detected: untrusted input from variable '{}' (line {}) flows into query.",
                                t_var, src_line
                            );
                            break;
                        }
                    }
                    for (d_var, (src_var, _)) in &intermediate_vars {
                        if line.contains(d_var) {
                            confidence = "HIGH".to_string();
                            description = format!(
                                "SQL injection detected: tainted query variable '{}' (derived from '{}') flows into execute.",
                                d_var, src_var
                            );
                            break;
                        }
                    }
                }

                // Data flow escalation for Command Injection & shell=True
                if rule.id == "VG-SAST-002" || rule.id == "VG-SAST-008" {
                    let mut reaches_command = false;
                    for (t_var, src_line) in &tainted_vars {
                        if line.contains(t_var) {
                            reaches_command = true;
                            confidence = "HIGH".to_string();
                            severity = Severity::CRITICAL;
                            description = format!(
                                "Untrusted input from variable '{}' (line {}) directly reaches command execution.",
                                t_var, src_line
                            );
                            break;
                        }
                    }
                    if !reaches_command {
                        for (d_var, (src_var, _)) in &intermediate_vars {
                            if line.contains(d_var) {
                                confidence = "HIGH".to_string();
                                severity = Severity::CRITICAL;
                                description = format!(
                                    "Untrusted command variable '{}' (derived from input '{}') reaches execution.",
                                    d_var, src_var
                                );
                                break;
                            }
                        }
                    }
                }

                if !reported_lines.contains(&(rule.id.clone(), line_num)) {
                    reported_lines.insert((rule.id.clone(), line_num));
                    *finding_counter += 1;
                    findings.push(Finding {
                        id: rule.id.clone(),
                        category: rule.category.clone(),
                        severity,
                        title: rule.name.clone(),
                        description,
                        file: file_path.to_string(),
                        line: line_num,
                        evidence: Some(line.trim().to_string()),
                        recommendation: Some(rule.recommendation.clone()),
                        confidence,
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------
    // 3. Webhook Signature Verification Analysis (VG-WEBHOOK-001)
    // -------------------------------------------------------------
    // Identifies webhook route endpoints (e.g. @app.route("/webhook"))
    // and checks if signature verification is performed.
    let webhook_route_re = Regex::new(r#"(?i)@app\.route\(.*webhook.*|def\s+[a-zA-Z0-9_]*webhook[a-zA-Z0-9_]*\s*\(|func\s+[a-zA-Z0-9_]*Webhook"#).unwrap();
    let body_consumption_re = Regex::new(r#"(?i)(request\.get_json|request\.json|request\.data|request\.body|json\.loads\(request\.data\))"#).unwrap();
    let signature_check_re = Regex::new(r#"(?i)(X-Hub-Signature|X-Signature|Stripe-Signature|hmac\.(compare_digest|new)|verify_signature|signature_valid|verify_webhook)"#).unwrap();

    let has_signature_check = signature_check_re.is_match(content);

    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        if webhook_route_re.is_match(line) {
            // Check following lines for payload consumption without signature verification
            let end_idx = std::cmp::min(line_idx + 35, lines.len());
            let mut consumes_payload = false;
            let mut consumes_line = line_num;

            for (sub_idx, sub_line) in lines[line_idx..end_idx].iter().enumerate() {
                if body_consumption_re.is_match(sub_line) {
                    consumes_payload = true;
                    consumes_line = line_idx + sub_idx + 1;
                    break;
                }
            }

            if consumes_payload && !has_signature_check {
                *finding_counter += 1;
                findings.push(Finding {
                    id: "VG-WEBHOOK-001".to_string(),
                    category: Category::SourceCode,
                    severity: Severity::HIGH,
                    title: "Missing Webhook Signature Verification".to_string(),
                    description: "Webhook handler processes incoming request payload without cryptographic signature verification (e.g., HMAC, X-Hub-Signature, Stripe-Signature). An attacker can forge arbitrary webhook events.".to_string(),
                    file: file_path.to_string(),
                    line: consumes_line,
                    evidence: Some(lines[consumes_line - 1].trim().to_string()),
                    recommendation: Some("Verify incoming webhook signatures using HMAC-SHA256 and timing-safe comparison before processing events.".to_string()),
                    confidence: "HIGH".to_string(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sql_injection_fstring() {
        let mut counter = 0;
        let content = r#"query = f"SELECT * FROM notes WHERE user_id = {user_id}""#;
        let findings = scan_source_code("app.py", content, &mut counter);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].id, "VG-SAST-001");
    }

    #[test]
    fn test_detect_command_injection_subprocess() {
        let mut counter = 0;
        let content = r#"res = subprocess.check_output(f"ping -n 1 {host}", shell=True)"#;
        let findings = scan_source_code("ping.py", content, &mut counter);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.id == "VG-SAST-002" || f.id == "VG-SAST-008"));
    }

    #[test]
    fn test_detect_weak_password_hashing() {
        let mut counter = 0;
        let content = "hashed = hashlib.md5(password.encode()).hexdigest()\n";
        let findings = scan_source_code("auth.py", content, &mut counter);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "VG-AUTH-001"));
    }

    #[test]
    fn test_detect_predictable_token() {
        let mut counter = 0;
        let content = "token = base64.b64encode(email.encode()).decode()\n";
        let findings = scan_source_code("auth.py", content, &mut counter);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "VG-AUTH-002"));
    }

    #[test]
    fn test_detect_missing_webhook_signature() {
        let mut counter = 0;
        let content = r#"@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json()
    process_event(data)
"#;
        let findings = scan_source_code("api.py", content, &mut counter);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "VG-WEBHOOK-001"));
    }
}
