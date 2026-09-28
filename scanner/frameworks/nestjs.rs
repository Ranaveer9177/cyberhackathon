#![allow(dead_code)]

use crate::frameworks::types::{FrameworkKind, FrameworkModel, RouteEndpoint};
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct NestJsModel;

impl FrameworkModel for NestJsModel {
    fn framework(&self) -> FrameworkKind {
        FrameworkKind::NestJs
    }

    fn detect(&self, file_path: &str, content: &str) -> bool {
        let is_ts = file_path.ends_with(".ts") || file_path.ends_with(".js");
        if !is_ts {
            return false;
        }

        content.contains("@nestjs/")
            || content.contains("@Controller(")
            || content.contains("@Injectable()")
            || content.contains("NestFactory.create")
    }

    fn is_source(&self, expr_str: &str) -> bool {
        let clean = expr_str.trim();
        clean.contains("@Body(")
            || clean.contains("@Query(")
            || clean.contains("@Param(")
            || clean.contains("@Headers(")
            || clean.contains("@Req()")
            || clean.contains("@Request()")
    }

    fn is_request_param(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        lower.contains("dto")
            || lower.contains("body")
            || lower.contains("query")
            || lower.contains("param")
            || lower.contains("req")
            || lower.contains("payload")
    }

    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        let lower = callee_str.to_lowercase();

        // TypeORM or Prisma raw query
        if lower.ends_with("repo.query")
            || lower.ends_with("repository.query")
            || lower.ends_with("manager.query")
            || lower.contains("$queryraw")
        {
            return Some((TaintKind::Sql, "nestjs_raw_sql_query"));
        }

        // Response reflection
        if lower == "res.send" || lower == "res.write" {
            return Some((TaintKind::Xss, "nestjs_res_send_reflection"));
        }

        None
    }

    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>) {
        let mut kinds = HashSet::new();
        let mut name = None;
        let lower = expr_str.to_lowercase();

        // NestJS ValidationPipe / class-validator numeric validation
        if lower.contains("@isint()")
            || lower.contains("@isnumber()")
            || lower.contains("@isuuid()")
            || lower.contains("parseintpipe")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Xss);
            kinds.insert(TaintKind::Command);
            name = Some("nestjs_type_validation_pipe");
        }

        if lower.contains("validationpipe") {
            kinds.insert(TaintKind::Xss);
            if name.is_none() {
                name = Some("nestjs_validation_pipe");
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
        let decorators = [
            ("@get(", "GET"),
            ("@post(", "POST"),
            ("@put(", "PUT"),
            ("@delete(", "DELETE"),
            ("@patch(", "PATCH"),
            ("@get()", "GET"),
            ("@post()", "POST"),
            ("@put()", "PUT"),
            ("@delete()", "DELETE"),
            ("@patch()", "PATCH"),
        ];

        let mut matched = None;
        let mut path_str = "/".to_string();

        for (dec, method) in decorators {
            if let Some(pos) = lower.find(dec) {
                matched = Some(method.to_string());
                if dec.ends_with("(") {
                    let after = &func_code[pos + dec.len()..];
                    if let Some(quote_start) = after.find(['\'', '"']) {
                        let quote_char = after.chars().nth(quote_start).unwrap();
                        let rem = &after[quote_start + 1..];
                        if let Some(quote_end) = rem.find(quote_char) {
                            path_str = rem[..quote_end].to_string();
                        }
                    }
                }
                break;
            }
        }

        let matched = matched?;

        let (is_auth, auth_mech) = self.check_auth(func_code);

        Some(RouteEndpoint {
            framework: FrameworkKind::NestJs,
            file_path: file_path.to_string(),
            function_name: func_name.to_string(),
            route_path: path_str,
            http_methods: vec![matched],
            parameters: Vec::new(),
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
        lower.contains("repository.")
            || lower.contains("repo.")
            || lower.contains("prisma.")
            || lower.contains("entitymanager")
    }

    fn is_raw_db_query(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.ends_with(".query") || lower.contains("$queryraw")
    }

    fn is_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("@render(") || lower == "res.render"
    }

    fn is_unsafe_template_render(&self, _callee: &str) -> bool {
        false
    }

    fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        let lower = func_code.to_lowercase();
        if lower.contains("@useguards(") {
            return (true, Some("nestjs_use_guards".to_string()));
        }
        if lower.contains("@roles(") {
            return (true, Some("nestjs_roles_guard".to_string()));
        }
        (false, None)
    }
}
