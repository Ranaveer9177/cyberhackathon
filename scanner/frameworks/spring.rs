#![allow(dead_code)]

use crate::frameworks::types::{FrameworkKind, FrameworkModel, RouteEndpoint};
use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct SpringModel;

impl FrameworkModel for SpringModel {
    fn framework(&self) -> FrameworkKind {
        FrameworkKind::Spring
    }

    fn detect(&self, file_path: &str, content: &str) -> bool {
        let is_jvm = file_path.ends_with(".java") || file_path.ends_with(".kt");
        if !is_jvm {
            return false;
        }

        content.contains("org.springframework.")
            || content.contains("@RestController")
            || content.contains("@Controller")
            || content.contains("@SpringBootApplication")
            || content.contains("@RequestMapping")
    }

    fn is_source(&self, expr_str: &str) -> bool {
        let clean = expr_str.trim();
        clean.contains("@RequestParam")
            || clean.contains("@PathVariable")
            || clean.contains("@RequestBody")
            || clean.contains("@RequestHeader")
            || clean.contains("@CookieValue")
            || clean.contains("@ModelAttribute")
            || clean.contains("request.getParameter(")
            || clean.contains("request.getReader(")
    }

    fn is_request_param(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        lower == "request"
            || lower.contains("dto")
            || lower.contains("payload")
            || lower.contains("body")
            || lower.contains("query")
            || lower.contains("id")
            || lower.contains("username")
    }

    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        let lower = callee_str.to_lowercase();

        // JDBC / JPA Native query execution
        if lower.contains("jdbctemplate.query")
            || lower.contains("jdbctemplate.execute")
            || lower.contains("createnativequery")
            || lower.contains("namedparameterjdbctemplate")
        {
            return Some((TaintKind::Sql, "spring_jdbc_native_query"));
        }

        // Servlet response write (XSS)
        if lower.contains("response.getwriter().write")
            || lower.contains("response.getwriter().print")
        {
            return Some((TaintKind::Xss, "spring_servlet_response_write"));
        }

        // SSRF via RestTemplate
        if lower.contains("resttemplate.getforobject")
            || lower.contains("resttemplate.postforobject")
            || lower.contains("resttemplate.exchange")
            || lower.contains("webclient.create")
        {
            return Some((TaintKind::Ssrf, "spring_rest_client_ssrf"));
        }

        // Command execution
        if lower.contains("runtime.getruntime().exec") || lower.contains("processbuilder") {
            return Some((TaintKind::Command, "java_runtime_exec"));
        }

        None
    }

    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>) {
        let mut kinds = HashSet::new();
        let mut name = None;
        let lower = expr_str.to_lowercase();

        if lower.contains("htmlutils.htmlescape(") {
            kinds.insert(TaintKind::Xss);
            name = Some("spring_html_escape");
        }

        if lower.contains("integer.parseint(")
            || lower.contains("long.parselong(")
            || lower.contains("double.parsedouble(")
        {
            kinds.insert(TaintKind::Sql);
            kinds.insert(TaintKind::Xss);
            kinds.insert(TaintKind::Command);
            if name.is_none() {
                name = Some("java_numeric_parse");
            }
        }

        if lower.contains("@valid") || lower.contains("@validated") {
            kinds.insert(TaintKind::Xss);
            if name.is_none() {
                name = Some("spring_bean_validation");
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
        let annotations = [
            ("@getmapping", "GET"),
            ("@postmapping", "POST"),
            ("@putmapping", "PUT"),
            ("@deletemapping", "DELETE"),
            ("@patchmapping", "PATCH"),
            ("@requestmapping", "GET"),
        ];

        let mut matched = None;
        let mut path_str = "/".to_string();

        for (ann, method) in annotations {
            if let Some(pos) = lower.find(ann) {
                matched = Some(method.to_string());
                let after = &func_code[pos + ann.len()..];
                if let Some(paren_open) = after.find('(') {
                    let inner = &after[paren_open + 1..];
                    if let Some(quote_start) = inner.find('"') {
                        let rem = &inner[quote_start + 1..];
                        if let Some(quote_end) = rem.find('"') {
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
            framework: FrameworkKind::Spring,
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
        lower.contains("httpservletrequest")
            || lower.contains("serverhttprequest")
            || lower.contains("webrequest")
    }

    fn is_db_interface(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("jdbctemplate")
            || lower.contains("entitymanager")
            || lower.contains("repository")
    }

    fn is_raw_db_query(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("createnativequery") || lower.contains("jdbctemplate.query")
    }

    fn is_template_render(&self, callee: &str) -> bool {
        let lower = callee.to_lowercase();
        lower.contains("modelandview") || lower.contains("model.addattribute")
    }

    fn is_unsafe_template_render(&self, _callee: &str) -> bool {
        false
    }

    fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        let lower = func_code.to_lowercase();
        if lower.contains("@preauthorize(") {
            return (true, Some("spring_pre_authorize".to_string()));
        }
        if lower.contains("@secured(") {
            return (true, Some("spring_secured".to_string()));
        }
        if lower.contains("@rolesallowed(") {
            return (true, Some("spring_roles_allowed".to_string()));
        }
        (false, None)
    }
}
