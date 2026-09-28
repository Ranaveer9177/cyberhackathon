#![allow(dead_code)]

use crate::frameworks::types::{FrameworkKind, FrameworkModel, RouteEndpoint};
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct FlaskModel;

impl FrameworkModel for FlaskModel {
    fn framework(&self) -> FrameworkKind {
        FrameworkKind::Flask
    }

    fn detect(&self, file_path: &str, content: &str) -> bool {
        let is_py = file_path.ends_with(".py");
        if !is_py {
            return false;
        }

        content.contains("from flask import")
            || content.contains("import flask")
            || content.contains("Flask(__name__)")
            || content.contains("Blueprint(")
    }

    fn is_source(&self, expr_str: &str) -> bool {
        let lower = expr_str.to_lowercase();
        lower.contains("request.args")
            || lower.contains("request.form")
            || lower.contains("request.values")
            || lower.contains("request.json")
            || lower.contains("request.get_json")
            || lower.contains("request.data")
            || lower.contains("request.headers")
            || lower.contains("request.cookies")
            || lower.contains("request.files")
            || lower.contains("request.view_args")
            || lower.contains("request.query_string")
            || lower.contains("request.stream")
    }

    fn is_request_param(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        lower == "request"
            || lower == "req"
            || lower.contains("user_id")
            || lower.contains("username")
            || lower.contains("item_id")
            || lower.contains("token")
            || lower.contains("query")
            || lower.contains("slug")
    }

    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        let lower = callee_str.to_lowercase();

        // Template Injection (SSTI)
        if lower.contains("render_template_string") {
            return Some((TaintKind::Template, "flask_render_template_string_ssti"));
        }

        // Raw SQL via SQLAlchemy session / cursor
        if lower.ends_with("db.session.execute")
            || lower.ends_with("session.execute")
            || lower.ends_with("cursor.execute")
        {
            return Some((TaintKind::Sql, "flask_sqlalchemy_raw_execute"));
        }

        // Path Traversal via send_file
        if lower.starts_with("send_file(") || lower.starts_with("send_from_directory(") {
            return Some((TaintKind::Path, "flask_send_file_traversal"));
        }

        // Open Redirect / SSRF via redirect()
        if lower.starts_with("redirect(") {
            return Some((TaintKind::Ssrf, "flask_redirect_open_url"));
        }

        None
    }

    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>) {
        let mut kinds = HashSet::new();
        let mut name = None;
        let lower = expr_str.to_lowercase();

        if lower.contains("secure_filename(") {
            kinds.insert(TaintKind::Path);
            name = Some("werkzeug_secure_filename");
        }

        if lower.contains("escape(") || lower.contains("markup.escape(") {
            kinds.insert(TaintKind::Xss);
            kinds.insert(TaintKind::Template);
            if name.is_none() {
                name = Some("flask_markup_escape");
            }
        }

        if lower.contains("render_template(") && !lower.contains("render_template_string(") {
            kinds.insert(TaintKind::Template);
            if name.is_none() {
                name = Some("flask_safe_template_render");
            }
        }

        (kinds, name)
    }

    fn is_route_endpoint(
        &self,
        func_name: &str,
        file_path: &str,
        func_code: &str,
    ) -> Option<RouteEndpoint> {
        let lower_code = func_code.to_lowercase();
        let has_route_decorator = lower_code.contains("@app.route")
            || lower_code.contains("@bp.route")
            || lower_code.contains("@blueprint.route")
            || lower_code.contains("@api.route")
            || lower_code.contains(".route(");

        if !has_route_decorator {
            return None;
        }

        let (is_auth, auth_mech) = self.check_auth(func_code);

        // Extract route path if possible
        let mut route_path = "/".to_string();
        if let Some(pos) = func_code.find(".route(") {
            let after = &func_code[pos + 7..];
            if let Some(quote_start) = after.find(['\'', '"']) {
                let quote_char = after.chars().nth(quote_start).unwrap();
                let remaining = &after[quote_start + 1..];
                if let Some(quote_end) = remaining.find(quote_char) {
                    route_path = remaining[..quote_end].to_string();
                }
            }
        }

        let mut methods = vec!["GET".to_string()];
        if lower_code.contains("methods=['post'")
            || lower_code.contains("methods=[\"post\"")
            || lower_code.contains("'post'")
            || lower_code.contains("\"post\"")
        {
            methods.push("POST".to_string());
        }

        Some(RouteEndpoint {
            framework: FrameworkKind::Flask,
            file_path: file_path.to_string(),
            function_name: func_name.to_string(),
            route_path,
            http_methods: methods,
            parameters: Vec::new(),
            is_authenticated: is_auth,
            auth_mechanism: auth_mech,
        })
    }

    fn is_request_object(&self, ident: &str) -> bool {
        let lower = ident.to_lowercase();
        lower == "request" || lower == "flask.request" || lower == "g"
    }

    fn is_db_interface(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("db.session") || lower.contains(".query(") || lower.contains("sqlalchemy")
    }

    fn is_raw_db_query(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.ends_with(".execute") || lower.ends_with(".raw") || lower.ends_with(".executemany")
    }

    fn is_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("render_template")
    }

    fn is_unsafe_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("render_template_string")
    }

    fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        let lower = func_code.to_lowercase();
        if lower.contains("@login_required") {
            return (true, Some("flask_login_required".to_string()));
        }
        if lower.contains("@jwt_required") {
            return (true, Some("flask_jwt_required".to_string()));
        }
        if lower.contains("current_user.is_authenticated") {
            return (true, Some("flask_current_user_check".to_string()));
        }
        (false, None)
    }
}
