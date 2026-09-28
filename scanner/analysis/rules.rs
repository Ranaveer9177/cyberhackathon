#![allow(dead_code)]

use crate::taint::types::TaintKind;

pub struct TaintRuleMeta {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub cwe: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
}

pub fn get_rule_meta(kind: TaintKind) -> TaintRuleMeta {
    match kind {
        TaintKind::Sql => TaintRuleMeta {
            rule_id: "VG-TAINT-SQL",
            title: "Deep Taint: Cross-Scope SQL Injection",
            cwe: "CWE-89",
            description: "Untrusted external input propagates across assignment, function calls, and module boundaries into database query execution without valid parameterization.",
            recommendation: "Use parameterized queries, prepared statements, or ORM parameter binding. Numeric casting (int/float) also neutralizes SQL injection.",
        },
        TaintKind::Command => TaintRuleMeta {
            rule_id: "VG-TAINT-CMD",
            title: "Deep Taint: Cross-Scope Command Injection",
            cwe: "CWE-78",
            description: "Untrusted input propagates through inter-module call graph directly into an operating system command execution sink.",
            recommendation: "Avoid invoking system shells (e.g. avoid shell=True) or escape shell metacharacters using shlex.quote / escapeshellarg.",
        },
        TaintKind::Ssrf => TaintRuleMeta {
            rule_id: "VG-TAINT-SSRF",
            title: "Deep Taint: Server-Side Request Forgery (SSRF)",
            cwe: "CWE-918",
            description: "User-controlled input flows into an outbound HTTP client request without strict hostname allowlisting.",
            recommendation: "Validate requested URLs against a strict whitelist of allowed domains and block access to private/internal IP address ranges (RFC 1918 / 169.254.169.254).",
        },
        TaintKind::Path => TaintRuleMeta {
            rule_id: "VG-TAINT-PATH",
            title: "Deep Taint: Path Traversal",
            cwe: "CWE-22",
            description: "Untrusted input propagates into filesystem access functions without path normalization or filename isolation.",
            recommendation: "Isolate filenames using os.path.basename / filepath.Base and verify resolved paths remain within the intended base directory.",
        },
        TaintKind::Xss => TaintRuleMeta {
            rule_id: "VG-TAINT-XSS",
            title: "Deep Taint: Cross-Site Scripting (XSS)",
            cwe: "CWE-79",
            description: "Unsanitized user input is reflected into dynamic HTML templates or HTTP responses.",
            recommendation: "Contextually encode all user-controlled data using HTML entity escaping (html.escape / DOMPurify) before rendering.",
        },
        TaintKind::Template => TaintRuleMeta {
            rule_id: "VG-TAINT-SSTI",
            title: "Deep Taint: Server-Side Template Injection",
            cwe: "CWE-1336",
            description: "Untrusted input is compiled directly into a template string, enabling remote code execution.",
            recommendation: "Do not pass user input to render_template_string or Template constructors; use static template files with variable context binding.",
        },
        TaintKind::Deserialization => TaintRuleMeta {
            rule_id: "VG-TAINT-DESER",
            title: "Deep Taint: Insecure Deserialization",
            cwe: "CWE-502",
            description: "Untrusted input is processed by an unsafe deserializer (e.g. pickle, yaml.load) which can execute arbitrary code during object hydration.",
            recommendation: "Use safe serialization formats such as JSON or safe YAML loaders (yaml.safe_load). Avoid pickle / marshal on untrusted data.",
        },
    }
}
