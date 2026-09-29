use crate::frameworks::FrameworkRegistry;
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct SanitizerModel;

impl SanitizerModel {
    /// Returns which taint kinds are legitimately sanitized by the given expression.
    /// Crucial: HTML escaping does NOT sanitize SQL; numeric casting does NOT sanitize Path Traversal.
    pub fn sanitized_kinds(expr: &str) -> (HashSet<TaintKind>, Option<String>) {
        let (mut kinds, mut used_name) = FrameworkRegistry::new().sanitize_kinds(expr);
        let lower = expr.to_lowercase();

        // 1. SQL & Command Sanitizers (numeric casting, parameterized wrappers)
        if lower.contains("int(")
            || lower.contains("float(")
            || lower.contains("parseint(")
            || lower.contains("parsefloat(")
            || lower.contains("number(")
            || lower.contains("strconv.atoi(")
            || lower.contains("strconv.parseint(")
            || lower.contains("integer.parseint(")
            || lower.contains("long.parselong(")
            || lower.contains("double.parsedouble(")
            || lower.contains("to_i")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Command); // Numeric scalars cannot inject shell command operators
            kinds.insert(TaintKind::Xss); // Numbers are also safe against HTML injection
            if used_name.is_none() {
                used_name = Some("numeric_typecast".to_string());
            }
        }

        // 2. Command Injection Sanitizers
        if lower.contains("shlex.quote(")
            || lower.contains("escapeshellarg(")
            || lower.contains("escapeshellcmd(")
            || lower.contains("shell_escape(")
        {
            kinds.insert(TaintKind::Command);
            if used_name.is_none() {
                used_name = Some("shell_escape_function".to_string());
            }
        }

        // 3. Path Traversal Sanitizers
        if lower.contains("os.path.basename(")
            || lower.contains("path.basename(")
            || lower.contains("filepath.base(")
            || lower.contains("secure_filename(")
            || lower.contains("path.clean(")
            || lower.contains("filepath.clean(")
        {
            kinds.insert(TaintKind::Path);
            if used_name.is_none() {
                used_name = Some("basename_path_isolation".to_string());
            }
        }

        // 4. SSRF Sanitizers (URL validation, allowlisting)
        if lower.contains("is_safe_url(")
            || lower.contains("validate_ip(")
            || lower.contains("check_url_allowlist(")
            || lower.contains("is_allowed_host(")
        {
            kinds.insert(TaintKind::Ssrf);
            if used_name.is_none() {
                used_name = Some("url_allowlist_validator".to_string());
            }
        }

        // 5. XSS Sanitizers (HTML entity encoders)
        // NOTICE: Does NOT sanitize SQL or Command!
        if lower.contains("html.escape(")
            || lower.contains("cgi.escape(")
            || lower.contains("dompurify.sanitize(")
            || lower.contains("escapehtml(")
            || lower.contains("encodeuricomponent(")
            || lower.contains("validator.escape(")
        {
            kinds.insert(TaintKind::Xss);
            if used_name.is_none() {
                used_name = Some("html_entity_encoder".to_string());
            }
        }

        // 6. Template Injection Sanitizers
        if lower.contains("render_template(") && !lower.contains("render_template_string(") {
            kinds.insert(TaintKind::Template);
            if used_name.is_none() {
                used_name = Some("static_template_file".to_string());
            }
        }

        // 7. Deserialization Sanitizers (safe parsers)
        if lower.contains("yaml.safe_load(")
            || lower.contains("json.loads(")
            || lower.contains("json.parse(")
            || lower.contains("json.unmarshal(")
        {
            kinds.insert(TaintKind::Deserialization);
            if used_name.is_none() {
                used_name = Some("safe_deserializer".to_string());
            }
        }

        // 8. UUID & GUID Sanitizers (fixed hex/hyphen format prevents injection)
        if lower.contains("uuid.parse(")
            || lower.contains("uuid.uuid(")
            || lower.contains("uuid.uuid4(")
            || lower.contains("uuid.uuid1(")
            || lower.contains("uuid.fromstring(")
            || lower.contains("uuid.mustparse(")
            || lower.contains("uuid.new(")
            || lower.contains("is_uuid(")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Command);
            kinds.insert(TaintKind::Path);
            if used_name.is_none() {
                used_name = Some("uuid_validator".to_string());
            }
        }

        // 9. Boolean Sanitizers (true/false scalars cannot carry injection payloads)
        if lower.contains("bool(")
            || lower.contains("boolean(")
            || lower.contains("strconv.parsebool(")
            || lower.contains("parse_bool(")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Command);
            kinds.insert(TaintKind::Path);
            kinds.insert(TaintKind::Xss);
            kinds.insert(TaintKind::Ssrf);
            if used_name.is_none() {
                used_name = Some("boolean_typecast".to_string());
            }
        }

        // 10. URL Encoding Sanitizers
        if lower.contains("urllib.parse.quote(")
            || lower.contains("url.queryescape(")
            || lower.contains("url.pathescape(")
        {
            kinds.insert(TaintKind::Path);
            kinds.insert(TaintKind::Command);
            if used_name.is_none() {
                used_name = Some("url_encoder".to_string());
            }
        }

        // 11. Hex / Base64 Safe String Encoding
        if lower.contains("hex.encodetostring(")
            || lower.contains("base64.b64encode(")
            || lower.contains("base64.stdencoding.encodetostring(")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Command);
            if used_name.is_none() {
                used_name = Some("alphanumeric_encoder".to_string());
            }
        }

        (kinds, used_name)
    }

    /// Evaluates if an expression effectively sanitizes a specific vulnerability taint kind.
    pub fn is_effective_for(kind: TaintKind, expr: &str) -> bool {
        let (sanitized_kinds, _) = Self::sanitized_kinds(expr);
        sanitized_kinds.contains(&kind)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_shlex_quote_sanitizer_precision() {
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Command,
            "shlex.quote(user_input)"
        ));
        assert!(!SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "shlex.quote(user_input)"
        ));
        assert!(!SanitizerModel::is_effective_for(
            TaintKind::Path,
            "shlex.quote(user_input)"
        ));
    }

    #[test]
    fn test_basename_sanitizer_precision() {
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Path,
            "os.path.basename(path)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Path,
            "filepath.Base(path)"
        ));
        assert!(!SanitizerModel::is_effective_for(
            TaintKind::Command,
            "os.path.basename(path)"
        ));
        assert!(!SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "os.path.basename(path)"
        ));
    }

    #[test]
    fn test_numeric_cast_sanitizer_precision() {
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "int(user_id)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "float(price)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Command,
            "int(port)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Command,
            "float(timeout)"
        ));
        assert!(!SanitizerModel::is_effective_for(
            TaintKind::Ssrf,
            "int(id)"
        ));
    }

    #[test]
    fn test_html_escape_does_not_sanitize_sql() {
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Xss,
            "html.escape(raw)"
        ));
        assert!(!SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "html.escape(raw)"
        ));
        assert!(!SanitizerModel::is_effective_for(
            TaintKind::Command,
            "html.escape(raw)"
        ));
    }

    #[test]
    fn test_uuid_sanitizer_precision() {
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "uuid.UUID(param)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Command,
            "uuid.parse(param)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Path,
            "uuid.fromString(param)"
        ));
    }

    #[test]
    fn test_boolean_sanitizer_precision() {
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "bool(flag)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Command,
            "strconv.ParseBool(flag)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Xss,
            "Boolean(flag)"
        ));
    }

    #[test]
    fn test_encoding_sanitizers_precision() {
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Command,
            "url.QueryEscape(input)"
        ));
        assert!(SanitizerModel::is_effective_for(
            TaintKind::Sql,
            "hex.EncodeToString(bytes)"
        ));
    }
}
