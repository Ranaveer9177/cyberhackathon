#![allow(dead_code)]

use crate::frameworks::types::{FrameworkKind, FrameworkModel, RouteEndpoint};
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct ExpressModel;

impl FrameworkModel for ExpressModel {
    fn framework(&self) -> FrameworkKind {
        FrameworkKind::Express
    }

    fn detect(&self, file_path: &str, content: &str) -> bool {
        let is_js = file_path.ends_with(".js")
            || file_path.ends_with(".ts")
            || file_path.ends_with(".mjs")
            || file_path.ends_with(".cjs");
        if !is_js {
            return false;
        }

        content.contains("require('express')")
            || content.contains("require(\"express\")")
            || content.contains("from 'express'")
            || content.contains("from \"express\"")
            || content.contains("express()")
            || content.contains("express.Router()")
    }

    fn is_source(&self, expr_str: &str) -> bool {
        let lower = expr_str.to_lowercase();
        lower.contains("req.params")
            || lower.contains("req.query")
            || lower.contains("req.body")
            || lower.contains("req.headers")
            || lower.contains("req.cookies")
            || lower.contains("req.signedcookies")
            || lower.contains("req.param(")
            || lower.contains("request.query")
            || lower.contains("request.body")
            || lower.contains("request.params")
    }

    fn is_request_param(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        lower == "req" || lower == "request"
    }

    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        let lower = callee_str.to_lowercase();

        // XSS reflection via response
        if lower == "res.send" || lower == "res.write" || lower == "response.send" {
            return Some((TaintKind::Xss, "express_res_send_reflection"));
        }

        // Open redirect
        if lower == "res.redirect" || lower == "response.redirect" {
            return Some((TaintKind::Ssrf, "express_res_redirect"));
        }

        // Database raw query sinks
        if lower.ends_with("db.query")
            || lower.ends_with("pool.query")
            || lower.ends_with("sequelize.query")
            || lower.ends_with("knex.raw")
        {
            return Some((TaintKind::Sql, "express_raw_sql_query"));
        }

        // Command execution
        if lower == "child_process.exec" || lower == "exec" || lower == "child_process.spawnsync" {
            return Some((TaintKind::Command, "node_child_process_exec"));
        }

        None
    }

    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>) {
        let mut kinds = HashSet::new();
        let mut name = None;
        let lower = expr_str.to_lowercase();

        if lower.contains("validator.escape(") || lower.contains("dompurify.sanitize(") {
            kinds.insert(TaintKind::Xss);
            name = Some("express_xss_sanitizer");
        }

        if lower.contains("parseint(") || lower.contains("number(") || lower.contains("parsefloat(")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Xss);
            kinds.insert(TaintKind::Command);
            if name.is_none() {
                name = Some("javascript_numeric_cast");
            }
        }

        if lower.contains("path.basename(") {
            kinds.insert(TaintKind::Path);
            if name.is_none() {
                name = Some("node_path_basename");
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
        let routes = [
            ("app.get(", "GET"),
            ("app.post(", "POST"),
            ("app.put(", "PUT"),
            ("app.delete(", "DELETE"),
            ("router.get(", "GET"),
            ("router.post(", "POST"),
            ("router.put(", "PUT"),
            ("router.delete(", "DELETE"),
        ];

        let mut matched = None;
        let mut path_str = "/".to_string();

        for (pattern, method) in routes {
            if let Some(pos) = lower.find(pattern) {
                matched = Some(method.to_string());
                let after = &func_code[pos + pattern.len()..];
                if let Some(quote_start) = after.find(['\'', '"']) {
                    let quote_char = after.chars().nth(quote_start).unwrap();
                    let rem = &after[quote_start + 1..];
                    if let Some(quote_end) = rem.find(quote_char) {
                        path_str = rem[..quote_end].to_string();
                    }
                }
                break;
            }
        }

        let matched = matched?;

        let (is_auth, auth_mech) = self.check_auth(func_code);

        Some(RouteEndpoint {
            framework: FrameworkKind::Express,
            file_path: file_path.to_string(),
            function_name: func_name.to_string(),
            route_path: path_str,
            http_methods: vec![matched],
            parameters: vec!["req".to_string(), "res".to_string()],
            is_authenticated: is_auth,
            auth_mechanism: auth_mech,
        })
    }

    fn is_request_object(&self, ident: &str) -> bool {
        let lower = ident.to_lowercase();
        lower == "req" || lower == "request"
    }

    fn is_db_interface(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("db.")
            || lower.contains("pool.")
            || lower.contains("sequelize")
            || lower.contains("prisma")
            || lower.contains("mongoose")
    }

    fn is_raw_db_query(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.ends_with(".query") || lower.ends_with(".raw") || lower.contains("$queryraw")
    }

    fn is_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower == "res.render" || lower == "response.render"
    }

    fn is_unsafe_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("ejs.render(") || lower.contains("pug.render(")
    }

    fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        let lower = func_code.to_lowercase();
        if lower.contains("passport.authenticate") {
            return (true, Some("express_passport_auth".to_string()));
        }
        if lower.contains("isauthenticated")
            || lower.contains("verifytoken")
            || lower.contains("checkauth")
        {
            return (true, Some("express_auth_middleware".to_string()));
        }
        if lower.contains("jwt.verify") {
            return (true, Some("express_jwt_verify".to_string()));
        }
        (false, None)
    }
}
