#![allow(dead_code)]

use crate::taint::types::TaintKind;

pub struct SinkModel;

impl SinkModel {
    /// Categorizes a callee expression or statement into its corresponding vulnerability TaintKind.
    pub fn classify_sink(callee: &str) -> Option<(TaintKind, &'static str)> {
        let clean = callee.trim();
        let lower = clean.to_lowercase();

        // 1. SQL Injection Sinks
        if lower.ends_with(".execute")
            || lower.ends_with(".executemany")
            || lower.ends_with(".query")
            || lower.ends_with(".queryrow")
            || lower.ends_with(".query_row")
            || lower.ends_with(".exec")
            || lower.ends_with(".raw")
            || lower.ends_with(".executequery")
            || lower.ends_with(".executeupdate")
            || lower == "execute"
            || lower == "db.execute"
            || lower == "conn.execute"
            || lower == "cursor.execute"
            || lower == "session.execute"
        {
            return Some((TaintKind::Sql, "database_query_execution"));
        }

        // 2. Command Injection Sinks
        if lower == "os.system"
            || lower == "os.popen"
            || lower.starts_with("subprocess.")
            || lower == "exec.command"
            || lower.starts_with("child_process.")
            || lower == "runtime.getruntime().exec"
            || lower == "processbuilder"
            || lower == "eval"
            || lower == "system"
        {
            return Some((TaintKind::Command, "os_command_execution"));
        }

        // 3. SSRF Sinks
        if lower.starts_with("requests.get")
            || lower.starts_with("requests.post")
            || lower.starts_with("requests.request")
            || lower.starts_with("urllib.request.urlopen")
            || lower.starts_with("httpx.get")
            || lower.starts_with("httpx.post")
            || lower.starts_with("http.get")
            || lower.starts_with("http.post")
            || lower.starts_with("http.newrequest")
            || lower.starts_with("axios.get")
            || lower.starts_with("axios.post")
            || (lower.starts_with("fetch(") && !lower.contains("localhost"))
        {
            return Some((TaintKind::Ssrf, "http_client_request"));
        }

        // 4. Path Traversal Sinks
        if (lower.starts_with("open(") && !lower.contains(".log"))
            || lower.starts_with("os.remove(")
            || lower.starts_with("os.unlink(")
            || lower.starts_with("shutil.rmtree(")
            || lower.starts_with("fs.readfile")
            || lower.starts_with("fs.writefile")
            || lower.starts_with("os.open(")
            || lower.starts_with("os.readfile(")
            || lower.starts_with("new fileinputstream(")
            || lower.starts_with("files.readallbytes(")
        {
            return Some((TaintKind::Path, "filesystem_access"));
        }

        // 5. Template Injection (SSTI)
        if lower.contains("render_template_string")
            || lower.contains("jinja2.template(")
            || lower.contains("from_string(")
        {
            return Some((TaintKind::Template, "template_compilation"));
        }

        // 6. Cross-Site Scripting (XSS)
        if lower.contains("render_template_string(")
            || lower.contains("markupsafe.markup(")
            || lower.contains("response.write(")
            || lower.contains("res.send(")
        {
            return Some((TaintKind::Xss, "html_response_reflection"));
        }

        // 7. Insecure Deserialization
        if lower.contains("pickle.loads(")
            || lower.contains("pickle.load(")
            || (lower.contains("yaml.load(")
                && !lower.contains("safeloader")
                && !lower.contains("safe_load"))
            || lower.contains("marshal.loads(")
            || lower.contains("unserialize(")
            || lower.contains("readobject(")
        {
            return Some((TaintKind::Deserialization, "object_deserialization"));
        }

        None
    }
}
