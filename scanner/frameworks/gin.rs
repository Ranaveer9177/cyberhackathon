#![allow(dead_code)]

use crate::frameworks::types::{FrameworkKind, FrameworkModel, RouteEndpoint};
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct GinModel;

impl FrameworkModel for GinModel {
    fn framework(&self) -> FrameworkKind {
        FrameworkKind::Gin
    }

    fn detect(&self, file_path: &str, content: &str) -> bool {
        if !file_path.ends_with(".go") {
            return false;
        }

        content.contains("github.com/gin-gonic/gin")
            || content.contains("gin.Default()")
            || content.contains("gin.New()")
            || content.contains("*gin.Context")
            || content.contains("gin.Context")
    }

    fn is_source(&self, expr_str: &str) -> bool {
        let lower = expr_str.to_lowercase();
        lower.contains("c.query(")
            || lower.contains("c.defaultquery(")
            || lower.contains("c.param(")
            || lower.contains("c.postform(")
            || lower.contains("c.defaultpostform(")
            || lower.contains("c.getheader(")
            || lower.contains("c.cookie(")
            || lower.contains("c.bindjson(")
            || lower.contains("c.shouldbind(")
            || lower.contains("c.shouldbindjson(")
            || lower.contains("c.shouldbindquery(")
            || lower.contains("c.shouldbinduri(")
            || lower.contains("c.bind(")
            || lower.contains("c.bindquery(")
            || lower.contains("c.request.body")
            || lower.contains("c.request.url.query")
            || lower.contains("c.getrawdata(")
    }

    fn is_request_param(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        lower == "c" || lower == "ctx" || lower == "*gin.context" || lower == "context"
    }

    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        let lower = callee_str.to_lowercase();

        // XSS reflection
        if lower.contains("c.string(") || lower.contains("c.data(") {
            return Some((TaintKind::Xss, "gin_c_string_reflection"));
        }

        // Open redirect
        if lower.contains("c.redirect(") {
            return Some((TaintKind::Ssrf, "gin_c_redirect"));
        }

        // Template SSTI / injection
        if lower.contains("c.html(") {
            return Some((TaintKind::Template, "gin_c_html_render"));
        }

        None
    }

    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>) {
        let mut kinds = HashSet::new();
        let lower = expr_str.to_lowercase();

        if lower.contains("html.escapestring(") {
            kinds.insert(TaintKind::Xss);
            return (kinds, Some("html_escape_string"));
        }

        if lower.contains("filepath.clean(") || lower.contains("path.clean(") {
            kinds.insert(TaintKind::Path);
            return (kinds, Some("filepath_clean"));
        }

        if lower.contains("strconv.atoi(") || lower.contains("strconv.parseint(") {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Command);
            kinds.insert(TaintKind::Xss);
            return (kinds, Some("strconv_atoi"));
        }

        (kinds, None)
    }

    fn is_route_endpoint(
        &self,
        func_name: &str,
        file_path: &str,
        func_code: &str,
    ) -> Option<RouteEndpoint> {
        let lower = func_code.to_lowercase();
        let methods = vec!["GET".to_string()];

        let is_handler = lower.contains("*gin.context")
            || lower.contains("c.json(")
            || lower.contains("c.string(")
            || lower.contains("c.html(")
            || lower.contains("c.status(");

        if is_handler {
            let (is_auth, auth_mech) = self.check_auth(func_code);
            Some(RouteEndpoint {
                framework: FrameworkKind::Gin,
                file_path: file_path.to_string(),
                function_name: func_name.to_string(),
                route_path: format!("/{}", func_name.to_lowercase()),
                http_methods: methods,
                parameters: vec!["c".to_string()],
                is_authenticated: is_auth,
                auth_mechanism: auth_mech,
            })
        } else {
            None
        }
    }

    fn is_request_object(&self, ident: &str) -> bool {
        let lower = ident.to_lowercase();
        lower == "c" || lower == "ctx" || lower == "gin.context"
    }

    fn is_db_interface(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("db.")
            || lower.contains("tx.")
            || lower.contains("gorm.")
            || lower.contains("sqlx.")
    }

    fn is_raw_db_query(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("db.raw(")
            || lower.contains("db.exec(")
            || lower.contains("tx.exec(")
            || lower.contains("gorm.raw(")
    }

    fn is_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("c.html(") || lower.contains("tmpl.execute(")
    }

    fn is_unsafe_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("template.html(")
    }

    fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        let lower = func_code.to_lowercase();
        if lower.contains("auth")
            || lower.contains("jwt")
            || lower.contains("token")
            || lower.contains("requireauth")
            || lower.contains("session")
        {
            (true, Some("middleware_auth_check".to_string()))
        } else {
            (false, None)
        }
    }
}
