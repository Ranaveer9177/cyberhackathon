#![allow(dead_code)]

use crate::frameworks::types::{FrameworkKind, FrameworkModel, RouteEndpoint};
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct DjangoModel;

impl FrameworkModel for DjangoModel {
    fn framework(&self) -> FrameworkKind {
        FrameworkKind::Django
    }

    fn detect(&self, file_path: &str, content: &str) -> bool {
        let is_py = file_path.ends_with(".py");
        if !is_py {
            return false;
        }

        content.contains("from django")
            || content.contains("import django")
            || content.contains("django.http")
            || content.contains("django.db")
            || content.contains("django.shortcuts")
            || content.contains("urlpatterns =")
            || file_path.ends_with("views.py")
            || file_path.ends_with("models.py")
    }

    fn is_source(&self, expr_str: &str) -> bool {
        let clean = expr_str.trim();
        clean.contains("request.GET")
            || clean.contains("request.POST")
            || clean.contains("request.COOKIES")
            || clean.contains("request.headers")
            || clean.contains("request.body")
            || clean.contains("request.FILES")
            || clean.contains("request.META")
    }

    fn is_request_param(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        lower == "request"
            || lower == "req"
            || lower == "pk"
            || lower == "id"
            || lower == "slug"
            || lower.contains("user_id")
            || lower.contains("username")
    }

    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        let clean = callee_str.trim();
        let lower = clean.to_lowercase();

        // Django Raw SQL Sinks
        if clean.ends_with(".raw")
            || clean.contains("objects.raw")
            || clean.contains(".extra(")
            || clean.ends_with("cursor.execute")
        {
            return Some((TaintKind::Sql, "django_orm_raw_sql"));
        }

        // XSS bypass via mark_safe
        if lower.contains("mark_safe") || lower.contains("safestring") {
            return Some((TaintKind::Xss, "django_mark_safe_xss"));
        }

        // Open Redirect via redirect
        if lower.starts_with("redirect(") || lower.starts_with("httpresponseredirect(") {
            return Some((TaintKind::Ssrf, "django_redirect_open_url"));
        }

        None
    }

    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>) {
        let mut kinds = HashSet::new();
        let mut name = None;
        let lower = expr_str.to_lowercase();

        if lower.contains("escape(") || lower.contains("conditional_escape(") {
            kinds.insert(TaintKind::Xss);
            kinds.insert(TaintKind::Template);
            name = Some("django_html_escape");
        }

        if lower.contains("slugify(") {
            kinds.insert(TaintKind::Path);
            kinds.insert(TaintKind::Command);
            if name.is_none() {
                name = Some("django_slugify");
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
        let lower_path = file_path.to_lowercase();
        let is_view_file = lower_path.contains("views") || lower_path.ends_with("view.py");

        let first_param_is_request = func_code.contains(&format!("def {}(request", func_name))
            || func_code.contains(&format!("def {}(req", func_name));

        if !is_view_file && !first_param_is_request {
            return None;
        }

        let (is_auth, auth_mech) = self.check_auth(func_code);

        Some(RouteEndpoint {
            framework: FrameworkKind::Django,
            file_path: file_path.to_string(),
            function_name: func_name.to_string(),
            route_path: format!("/django/{}", func_name),
            http_methods: vec!["GET".to_string(), "POST".to_string()],
            parameters: vec!["request".to_string()],
            is_authenticated: is_auth,
            auth_mechanism: auth_mech,
        })
    }

    fn is_request_object(&self, ident: &str) -> bool {
        let lower = ident.to_lowercase();
        lower == "request" || lower == "httprequest" || lower == "wsgi_request"
    }

    fn is_db_interface(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains(".objects.")
            || lower.contains("models.model")
            || lower.contains("connection.cursor")
    }

    fn is_raw_db_query(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains(".raw(") || lower.contains(".extra(") || lower.contains("cursor.execute")
    }

    fn is_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.starts_with("render(") || lower.contains("render_to_string(")
    }

    fn is_unsafe_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("template(") && lower.contains(".render(")
    }

    fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        let lower = func_code.to_lowercase();
        if lower.contains("@login_required") {
            return (true, Some("django_login_required".to_string()));
        }
        if lower.contains("@permission_required") {
            return (true, Some("django_permission_required".to_string()));
        }
        if lower.contains("request.user.is_authenticated") {
            return (true, Some("django_user_is_authenticated".to_string()));
        }
        if lower.contains("loginrequiredmixin") {
            return (true, Some("django_login_required_mixin".to_string()));
        }
        (false, None)
    }
}
