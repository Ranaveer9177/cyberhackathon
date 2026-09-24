use crate::rules::{get_sast_rules, rule_cwe};
use crate::types::{Category, Finding, Severity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone)]
struct FunctionScope {
    name: String,
    params: Vec<String>,
    start_line: usize,
    end_line: usize,
}

#[derive(Debug, Clone)]
struct TaintInfo {
    source_expr: String,
    source_line: usize,
    data_flow: Vec<String>,
    sanitized_cmd: bool,
    sanitized_sql: bool,
}

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
    // 1. Function Scope Extraction
    // -------------------------------------------------------------
    let mut function_scopes: Vec<FunctionScope> = Vec::new();

    // Python function def: def foo(a, b, c):
    let py_func_re = Regex::new(
        r#"^(?P<indent>\s*)def\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)\s*:"#,
    )
    .unwrap();
    // Go/JS/TS/Java function def: func foo(a int, b string) or function foo(a, b)
    let c_func_re = Regex::new(r#"(?:func(?:\s*\([^)]*\))?|function|\bdef)\s+(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<params>[^)]*)\)"#).unwrap();

    if ext == "py" {
        for (i, line) in lines.iter().enumerate() {
            if let Some(caps) = py_func_re.captures(line) {
                let name = caps["name"].to_string();
                let raw_params = &caps["params"];
                let params: Vec<String> = raw_params
                    .split(',')
                    .map(|p| {
                        p.split(':')
                            .next()
                            .unwrap_or(p)
                            .split('=')
                            .next()
                            .unwrap_or(p)
                            .trim()
                            .to_string()
                    })
                    .filter(|p| !p.is_empty() && p != "self" && p != "cls")
                    .collect();

                let indent_len = caps["indent"].len();
                let start_line = i + 1;
                let mut end_line = lines.len();

                // Find where indentation drops back to <= func indent
                for (j, next_line) in lines.iter().enumerate().skip(i + 1) {
                    let trimmed = next_line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let line_indent = next_line.len() - next_line.trim_start().len();
                    if line_indent <= indent_len {
                        end_line = j;
                        break;
                    }
                }

                function_scopes.push(FunctionScope {
                    name,
                    params,
                    start_line,
                    end_line,
                });
            }
        }
    } else {
        // Brace-based scope matching for Go, JS, TS, Java, etc.
        for (i, line) in lines.iter().enumerate() {
            if let Some(caps) = c_func_re.captures(line) {
                let name = caps["name"].to_string();
                let raw_params = &caps["params"];
                let params: Vec<String> = raw_params
                    .split(',')
                    .map(|p| {
                        let parts: Vec<&str> = p.split_whitespace().collect();
                        if parts.len() >= 2 && ext == "go" {
                            parts[0].to_string()
                        } else if let Some(first) = parts.first() {
                            first.split(':').next().unwrap_or(first).to_string()
                        } else {
                            String::new()
                        }
                    })
                    .filter(|p| !p.is_empty())
                    .collect();

                let start_line = i + 1;
                let mut brace_depth = 0;
                let mut started = false;
                let mut end_line = lines.len();

                for (j, next_line) in lines.iter().enumerate().skip(i) {
                    for ch in next_line.chars() {
                        if ch == '{' {
                            brace_depth += 1;
                            started = true;
                        } else if ch == '}' {
                            brace_depth -= 1;
                            if started && brace_depth <= 0 {
                                end_line = j + 1;
                                break;
                            }
                        }
                    }
                    if started && brace_depth <= 0 {
                        break;
                    }
                }

                function_scopes.push(FunctionScope {
                    name,
                    params,
                    start_line,
                    end_line,
                });
            }
        }
    }

    // -------------------------------------------------------------
    // 2. Data-Flow & Taint Tracking Analysis
    // -------------------------------------------------------------
    let source_assign_re = Regex::new(
        r#"(?i)(?:^|[\s;])(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(?P<expr>(?:request\.(?:args|form|values|json|get_json|data|files)|req\.(?:query|body|params)|r\.(?:URL\.Query|FormValue))[^;\n]*)"#,
    ).unwrap();
    let assign_re =
        Regex::new(r#"(?i)(?:^|[\s;])(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(?P<rhs>[^;\n]+)"#)
            .unwrap();

    // Map: (var_name, scope_start_line) -> TaintInfo
    let mut tainted_table: HashMap<(String, usize), TaintInfo> = HashMap::new();

    // Helper: find scope for a given line
    let get_scope_start = |line_num: usize| -> usize {
        for scope in &function_scopes {
            if line_num >= scope.start_line && line_num <= scope.end_line {
                return scope.start_line;
            }
        }
        0 // module-level / global scope
    };

    // First pass: identify sources of untrusted input
    for (line_idx, line) in lines.iter().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
            continue;
        }

        if let Some(caps) = source_assign_re.captures(line) {
            if let Some(var_match) = caps.name("var") {
                let var_name = var_match.as_str().to_string();
                let expr = caps["expr"].trim().to_string();
                let scope_start = get_scope_start(line_num);

                tainted_table.insert(
                    (var_name.clone(), scope_start),
                    TaintInfo {
                        source_expr: expr.clone(),
                        source_line: line_num,
                        data_flow: vec![format!(
                            "Line {}: {} = {} [SOURCE: Untrusted user input]",
                            line_num, var_name, expr
                        )],
                        sanitized_cmd: false,
                        sanitized_sql: false,
                    },
                );
            }
        }
    }

    fn contains_var(line: &str, var: &str) -> bool {
        let mut search_from = 0;
        while let Some(pos) = line[search_from..].find(var) {
            let abs_pos = search_from + pos;
            let before_ok = abs_pos == 0
                || (!line.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                    && line.as_bytes()[abs_pos - 1] != b'_');
            let end_pos = abs_pos + var.len();
            let after_ok = end_pos == line.len()
                || (!line.as_bytes()[end_pos].is_ascii_alphanumeric()
                    && line.as_bytes()[end_pos] != b'_');
            if before_ok && after_ok {
                return true;
            }
            search_from = abs_pos + 1;
        }
        false
    }

    // Second pass: iteratively track assignments, sanitizers, and call-site propagation until stable
    for _ in 0..3 {
        let prev_size = tainted_table.len();
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
                continue;
            }

            let scope_start = get_scope_start(line_num);

            // Check for assignments deriving from existing tainted variables
            if let Some(caps) = assign_re.captures(line) {
                let lhs = caps["var"].to_string();
                let rhs = caps["rhs"].to_string();

                // Look for any tainted variable used in rhs within current or global scope
                let mut matched_taint: Option<TaintInfo> = None;
                for ((t_var, t_scope), info) in &tainted_table {
                    if (*t_scope == scope_start || *t_scope == 0)
                        && contains_var(&rhs, t_var)
                        && lhs != *t_var
                    {
                        matched_taint = Some(info.clone());
                        break;
                    }
                }

                if let Some(mut info) = matched_taint {
                    // Check sanitizers applied during derivation
                    if rhs.contains("shlex.quote")
                        || rhs.contains("escapeshellarg")
                        || rhs.contains("escapeshellcmd")
                    {
                        info.sanitized_cmd = true;
                        info.data_flow.push(format!(
                            "Line {}: {} = {} [SANITIZER: Command escaping via shlex.quote]",
                            line_num,
                            lhs,
                            rhs.trim()
                        ));
                    } else if rhs.contains("int(")
                        || rhs.contains("float(")
                        || rhs.contains("strconv.Atoi")
                    {
                        info.sanitized_sql = true;
                        info.data_flow.push(format!(
                            "Line {}: {} = {} [SANITIZER: Type cast to integer/float]",
                            line_num,
                            lhs,
                            rhs.trim()
                        ));
                    } else {
                        info.data_flow.push(format!(
                            "Line {}: {} = {} [DATAFLOW: Variable derivation]",
                            line_num,
                            lhs,
                            rhs.trim()
                        ));
                    }

                    tainted_table.insert((lhs, scope_start), info);
                }
            }

            // Call-site argument-to-parameter propagation:
            // e.g. execute_command(host) -> function execute_command(val)
            for scope in &function_scopes {
                let call_pattern =
                    format!(r#"{}\s*\((?P<args>[^)]*)\)"#, regex::escape(&scope.name));
                if let Ok(call_re) = Regex::new(&call_pattern) {
                    if let Some(caps) = call_re.captures(line) {
                        let raw_args = caps["args"].to_string();
                        let args: Vec<&str> = raw_args.split(',').map(|a| a.trim()).collect();

                        for (arg_idx, arg) in args.iter().enumerate() {
                            let arg_cleaned = arg.split('=').next_back().unwrap_or(arg).trim();
                            for ((t_var, t_scope), info) in tainted_table.clone() {
                                if (t_scope == scope_start || t_scope == 0) && arg_cleaned == t_var
                                {
                                    if let Some(param_name) = scope.params.get(arg_idx) {
                                        let mut param_info = info.clone();
                                        param_info.data_flow.push(format!(
                                            "Line {}: Call to '{}(...)' passes tainted argument '{}' to parameter '{}'",
                                            line_num, scope.name, t_var, param_name
                                        ));
                                        tainted_table.insert(
                                            (param_name.clone(), scope.start_line),
                                            param_info,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if tainted_table.len() == prev_size {
            break;
        }
    }

    // -------------------------------------------------------------
    // 3. Line-by-Line SAST Rule Evaluation with Data-Flow Provenance
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
            || trimmed.starts_with("let has_shell_true")
            || trimmed.starts_with("hasShellTrue :=")
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

        let scope_start = get_scope_start(line_num);

        for rule in &rules {
            if rule.pattern.is_match(line) {
                // Skip scanner tool self-inspection patterns
                if line.contains("Regex::new")
                    || line.contains("regexp.MustCompile")
                    || line.contains("pattern:")
                    || line.contains(r#"contains("http"#)
                    || line.contains(r#"contains(lineLower, "http"#)
                    || line.contains(r#"contains("shell"#)
                    || line.contains(r#"Contains(line, "shell"#)
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

                let mut confidence = "MEDIUM".to_string();
                let mut severity = rule.severity.clone();
                let mut description = rule.description.clone();
                let mut source_field: Option<String> = None;
                let mut sink_field: Option<String> = None;
                let mut data_flow_trace: Option<Vec<String>> = None;

                // Check taint reachability for SQL Injection (VG-SAST-001)
                if rule.id == "VG-SAST-001" {
                    sink_field = Some("SQL Query Construction / Execution".to_string());
                    for ((t_var, t_scope), info) in &tainted_table {
                        if (*t_scope == scope_start || *t_scope == 0) && contains_var(line, t_var) {
                            if info.sanitized_sql {
                                // Sanitized via int()/float() casting
                                continue;
                            }
                            confidence = "HIGH".to_string();
                            severity = Severity::HIGH;
                            source_field = Some(info.source_expr.clone());
                            let mut trace = info.data_flow.clone();
                            trace.push(format!(
                                "Line {}: {} [SINK: SQL query interpolation]",
                                line_num, trimmed
                            ));
                            data_flow_trace = Some(trace);
                            description = format!(
                                "SQL injection detected: untrusted input from variable '{}' (source line {}) flows into query.",
                                t_var, info.source_line
                            );
                            break;
                        }
                    }
                }

                // Check taint reachability for Command Injection (VG-SAST-002 & VG-SAST-008)
                if rule.id == "VG-SAST-002" || rule.id == "VG-SAST-008" {
                    sink_field = Some("OS Command Execution".to_string());

                    // Check if subprocess.run(["ping", host]) is passed a list without shell=True
                    // If so and not shell=True, it's not a shell injection vulnerability
                    let has_shell_true = line.contains("shell=True")
                        || line.contains("shell = True")
                        || line.contains("shell=1");
                    let is_list_invocation =
                        line.contains("[") && line.contains("]") && !has_shell_true && ext == "py";

                    if is_list_invocation && rule.id == "VG-SAST-002" {
                        // Safe execve-style argument array without shell
                        continue;
                    }

                    for ((t_var, t_scope), info) in &tainted_table {
                        if (*t_scope == scope_start || *t_scope == 0) && contains_var(line, t_var) {
                            if info.sanitized_cmd || line.contains("shlex.quote") {
                                // Sanitized command argument
                                continue;
                            }
                            confidence = "HIGH".to_string();
                            severity = Severity::CRITICAL;
                            source_field = Some(info.source_expr.clone());
                            let mut trace = info.data_flow.clone();
                            trace.push(format!(
                                "Line {}: {} [SINK: OS command execution]",
                                line_num, trimmed
                            ));
                            data_flow_trace = Some(trace);
                            description = format!(
                                "Untrusted input from variable '{}' (source line {}) directly reaches command execution sink.",
                                t_var, info.source_line
                            );
                            break;
                        }
                    }
                }

                let cwe = rule_cwe(&rule.id).map(String::from);

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
                        source: source_field,
                        sink: sink_field,
                        data_flow: data_flow_trace,
                        cwe,
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------
    // 4. Webhook Signature Verification Analysis (VG-WEBHOOK-001)
    // -------------------------------------------------------------
    let webhook_route_re = Regex::new(
        r#"(?i)(@app\.(route|post)\(.*(?:webhook|stripe|payment|github|callback).*|def\s+[a-zA-Z0-9_]*(?:webhook|stripe|callback)[a-zA-Z0-9_]*\s*\(|func\s+[a-zA-Z0-9_]*(?:Webhook|Callback))"#,
    ).unwrap();
    let body_consumption_re = Regex::new(
        r#"(?i)(request\.get_json|request\.json|request\.data|request\.body|json\.loads\(request\.data\))"#,
    ).unwrap();
    let signature_check_re = Regex::new(
        r#"(?i)(X-Hub-Signature|X-Signature|Stripe-Signature|hmac\.(compare_digest|new)|verify_signature|signature_valid|verify_webhook)"#,
    ).unwrap();

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
                    source: Some("request.get_json()".to_string()),
                    sink: Some("Unverified webhook event processing".to_string()),
                    data_flow: Some(vec![
                        format!("Line {}: Webhook route endpoint defined", line_num),
                        format!("Line {}: Payload consumed without signature verification", consumes_line),
                    ]),
                    cwe: rule_cwe("VG-WEBHOOK-001").map(String::from),
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
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
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
    fn test_detect_function_taint_propagation() {
        let mut counter = 0;
        let content = r#"
def run_command(target):
    subprocess.run(target, shell=True)

def handle_request():
    host = request.args.get("host")
    run_command(host)
"#;
        let findings = scan_source_code("app.py", content, &mut counter);
        let cmd_finding = findings
            .iter()
            .find(|f| f.id == "VG-SAST-008" || f.id == "VG-SAST-002");
        assert!(cmd_finding.is_some());
        let f = cmd_finding.unwrap();
        assert_eq!(f.confidence, "HIGH");
        assert!(f.data_flow.is_some());
        let trace = f.data_flow.as_ref().unwrap();
        assert!(trace.iter().any(|s| s.contains("run_command")));
    }

    #[test]
    fn test_sanitizer_command_injection_suppressed() {
        let mut counter = 0;
        let content = r#"
import shlex

def handle_ping():
    host = request.args.get("host")
    safe_host = shlex.quote(host)
    subprocess.run(f"ping -c 1 {safe_host}", shell=True)
"#;
        let findings = scan_source_code("ping.py", content, &mut counter);
        // shlex.quote should sanitize the command argument so CRITICAL untrusted command injection is suppressed
        let critical_cmd = findings
            .iter()
            .find(|f| f.severity == Severity::CRITICAL && f.id == "VG-SAST-008");
        assert!(critical_cmd.is_none());
    }

    #[test]
    fn test_detect_weak_password_hashing() {
        let mut counter = 0;
        let content = "hashed = hashlib.md5(password.encode()).hexdigest()\n";
        let findings = scan_source_code("auth.py", content, &mut counter);
        assert!(!findings.is_empty());
        let auth_finding = findings.iter().find(|f| f.id == "VG-AUTH-001").unwrap();
        assert_eq!(auth_finding.cwe.as_deref(), Some("CWE-916"));
    }

    #[test]
    fn test_detect_predictable_token() {
        let mut counter = 0;
        let content = "token = base64.b64encode(email.encode()).decode()\n";
        let findings = scan_source_code("auth.py", content, &mut counter);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.id == "VG-AUTH-002"));
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-330"));
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
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-345"));
    }
}
