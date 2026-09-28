#![allow(dead_code)]

use crate::frameworks::types::{FrameworkKind, FrameworkModel, RouteEndpoint};
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct FastApiModel;

impl FrameworkModel for FastApiModel {
    fn framework(&self) -> FrameworkKind {
        FrameworkKind::FastApi
    }

    fn detect(&self, file_path: &str, content: &str) -> bool {
        let is_py = file_path.ends_with(".py");
        if !is_py {
            return false;
        }

        content.contains("from fastapi import")
            || content.contains("import fastapi")
            || content.contains("FastAPI(")
            || content.contains("APIRouter(")
            || content.contains("pydantic")
    }

    fn is_source(&self, expr_str: &str) -> bool {
        let clean = expr_str.trim();
        clean.contains("Query(")
            || clean.contains("Path(")
            || clean.contains("Body(")
            || clean.contains("Header(")
            || clean.contains("Cookie(")
            || clean.contains("Form(")
            || clean.contains("File(")
            || clean.contains("request.body")
            || clean.contains("request.json")
    }

    fn is_request_param(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        // Skip common internal dependencies
        if lower == "db" || lower == "session" || lower == "background_tasks" {
            return false;
        }
        true
    }

    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        let lower = callee_str.to_lowercase();

        // SQL injection in SQLAlchemy / databases / asyncpg
        if lower.ends_with("session.execute")
            || lower.ends_with("db.execute")
            || lower.ends_with("session.exec")
            || lower.contains("raw_sql")
        {
            return Some((TaintKind::Sql, "fastapi_sqlalchemy_execute"));
        }

        // Direct HTML response without escaping
        if lower.starts_with("htmlresponse(") {
            return Some((TaintKind::Xss, "fastapi_raw_html_response"));
        }

        // Open redirect
        if lower.starts_with("redirectresponse(") {
            return Some((TaintKind::Ssrf, "fastapi_redirect_response"));
        }

        None
    }

    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>) {
        let mut kinds = HashSet::new();
        let mut name = None;
        let lower = expr_str.to_lowercase();

        // Pydantic scalar types sanitize SQL and Command injections
        if lower.contains(": int")
            || lower.contains(": float")
            || lower.contains(": bool")
            || lower.contains(": uuid")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Command);
            kinds.insert(TaintKind::Xss);
            name = Some("fastapi_pydantic_type_validation");
        }

        if lower.contains("html.escape(") {
            kinds.insert(TaintKind::Xss);
            if name.is_none() {
                name = Some("python_html_escape");
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
        let lower = func_code.to_lowercase();
        let methods_found = [
            ("@app.get", "GET"),
            ("@app.post", "POST"),
            ("@app.put", "PUT"),
            ("@app.delete", "DELETE"),
            ("@app.patch", "PATCH"),
            ("@router.get", "GET"),
            ("@router.post", "POST"),
            ("@router.put", "PUT"),
            ("@router.delete", "DELETE"),
            ("@router.patch", "PATCH"),
            ("@api_router.get", "GET"),
            ("@api_router.post", "POST"),
        ];

        let mut matched_method = None;
        let mut decorator_slice = None;

        for (dec, method) in methods_found {
            if let Some(pos) = lower.find(dec) {
                matched_method = Some(method.to_string());
                decorator_slice = Some(&func_code[pos..]);
                break;
            }
        }

        let matched_method = matched_method?;

        let mut route_path = "/".to_string();
        if let Some(slice) = decorator_slice {
            if let Some(paren_open) = slice.find('(') {
                let inner = &slice[paren_open + 1..];
                if let Some(quote_start) = inner.find(['\'', '"']) {
                    let quote_char = inner.chars().nth(quote_start).unwrap();
                    let rest = &inner[quote_start + 1..];
                    if let Some(quote_end) = rest.find(quote_char) {
                        route_path = rest[..quote_end].to_string();
                    }
                }
            }
        }

        let (is_auth, auth_mech) = self.check_auth(func_code);

        Some(RouteEndpoint {
            framework: FrameworkKind::FastApi,
            file_path: file_path.to_string(),
            function_name: func_name.to_string(),
            route_path,
            http_methods: vec![matched_method],
            parameters: Vec::new(),
            is_authenticated: is_auth,
            auth_mechanism: auth_mech,
        })
    }

    fn is_request_object(&self, ident: &str) -> bool {
        let lower = ident.to_lowercase();
        lower == "request" || lower == "fastapi.request" || lower == "basemodel"
    }

    fn is_db_interface(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("session.") || lower.contains("db.") || lower.contains("engine.")
    }

    fn is_raw_db_query(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.ends_with(".execute") || lower.ends_with(".exec") || lower.contains("text(")
    }

    fn is_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("templateresponse")
    }

    fn is_unsafe_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("htmlresponse(")
    }

    fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        let lower = func_code.to_lowercase();
        if lower.contains("depends(get_current_user")
            || lower.contains("depends(get_user")
            || lower.contains("depends(verify_token")
            || lower.contains("depends(auth")
        {
            return (true, Some("fastapi_auth_dependency".to_string()));
        }
        if lower.contains("security(") || lower.contains("oauth2passwordbearer") {
            return (true, Some("fastapi_oauth2_security".to_string()));
        }
        (false, None)
    }
}
