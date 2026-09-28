#![allow(dead_code)]

pub mod django;
pub mod express;
pub mod fastapi;
pub mod flask;
pub mod nestjs;
pub mod spring;
pub mod types;

pub use django::DjangoModel;
pub use express::ExpressModel;
pub use fastapi::FastApiModel;
pub use flask::FlaskModel;
pub use nestjs::NestJsModel;
pub use spring::SpringModel;
pub use types::{FrameworkKind, FrameworkModel, RouteEndpoint};

use crate::taint::types::TaintKind;
use std::collections::HashSet;

pub struct FrameworkRegistry {
    models: Vec<Box<dyn FrameworkModel>>,
}

impl Default for FrameworkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkRegistry {
    pub fn new() -> Self {
        Self {
            models: vec![
                Box::new(FlaskModel),
                Box::new(DjangoModel),
                Box::new(FastApiModel),
                Box::new(ExpressModel),
                Box::new(NestJsModel),
                Box::new(SpringModel),
            ],
        }
    }

    /// Detects all frameworks active in the project based on file contents
    pub fn detect_active_frameworks(&self, files: &[(&str, &str)]) -> Vec<FrameworkKind> {
        let mut active = HashSet::new();
        for (path, content) in files {
            for model in &self.models {
                if model.detect(path, content) {
                    active.insert(model.framework());
                }
            }
        }
        active.into_iter().collect()
    }

    /// Queries all framework models to determine if an expression accesses an untrusted HTTP source
    pub fn is_request_source(&self, expr_str: &str) -> bool {
        self.models.iter().any(|m| m.is_source(expr_str))
    }

    /// Queries all framework models to check if a parameter name represents HTTP request input
    pub fn is_request_param(&self, param_name: &str) -> bool {
        self.models.iter().any(|m| m.is_request_param(param_name))
    }

    /// Classifies an invocation across all framework sink definitions
    pub fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)> {
        for model in &self.models {
            if let Some(res) = model.classify_sink(callee_str) {
                return Some(res);
            }
        }
        None
    }

    /// Checks if an expression matches any framework sanitizer
    pub fn sanitize_kinds(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<String>) {
        let mut all_kinds = HashSet::new();
        let mut first_name = None;

        for model in &self.models {
            let (kinds, name) = model.is_sanitizer(expr_str);
            if !kinds.is_empty() {
                all_kinds.extend(kinds);
                if first_name.is_none() && name.is_some() {
                    first_name = name.map(|s| s.to_string());
                }
            }
        }

        (all_kinds, first_name)
    }

    /// Analyzes if a function definition is an HTTP route endpoint in any framework
    pub fn is_route_endpoint(
        &self,
        func_name: &str,
        file_path: &str,
        func_code: &str,
    ) -> Option<RouteEndpoint> {
        for model in &self.models {
            if let Some(route) = model.is_route_endpoint(func_name, file_path, func_code) {
                return Some(route);
            }
        }
        None
    }

    /// Checks if a variable or type name is a framework Request object
    pub fn is_request_object(&self, ident: &str) -> bool {
        self.models.iter().any(|m| m.is_request_object(ident))
    }

    /// Checks if a call interacts with a database/ORM interface
    pub fn is_database_call(&self, callee: &str) -> bool {
        self.models.iter().any(|m| m.is_db_interface(callee))
    }

    /// Checks if an ORM/database call executes raw SQL
    pub fn is_raw_database_query(&self, callee: &str) -> bool {
        self.models.iter().any(|m| m.is_raw_db_query(callee))
    }

    /// Checks if a call renders a template
    pub fn is_template_render(&self, callee: &str) -> bool {
        self.models.iter().any(|m| m.is_template_render(callee))
    }

    /// Checks if a template render call is dangerous
    pub fn is_unsafe_template_render(&self, callee: &str) -> bool {
        self.models
            .iter()
            .any(|m| m.is_unsafe_template_render(callee))
    }

    /// Checks if authentication checks protect the function
    pub fn check_auth(&self, func_code: &str) -> (bool, Option<String>) {
        for model in &self.models {
            let (is_auth, mech) = model.check_auth(func_code);
            if is_auth {
                return (true, mech);
            }
        }
        (false, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flask_model() {
        let registry = FrameworkRegistry::new();
        // Sources
        assert!(registry.is_request_source("request.args.get('search')"));
        assert!(registry.is_request_source("request.get_json()"));

        // Sinks
        let ssti = registry.classify_sink("render_template_string");
        assert!(ssti.is_some());
        assert_eq!(ssti.unwrap().0, TaintKind::Template);

        let sql = registry.classify_sink("db.session.execute");
        assert!(sql.is_some());
        assert_eq!(sql.unwrap().0, TaintKind::Sql);

        // Sanitizers
        let (sanitized, _) = registry.sanitize_kinds("secure_filename(path)");
        assert!(sanitized.contains(&TaintKind::Path));

        // Routing & Auth
        let code = "@app.route('/profile')\n@login_required\ndef profile(): pass";
        let route = registry.is_route_endpoint("profile", "app.py", code);
        assert!(route.is_some());
        let r = route.unwrap();
        assert_eq!(r.framework, FrameworkKind::Flask);
        assert!(r.is_authenticated);
    }

    #[test]
    fn test_django_model() {
        let registry = FrameworkRegistry::new();
        // Sources
        assert!(registry.is_request_source("request.GET['query']"));
        assert!(registry.is_request_source("request.POST.get('data')"));

        // Sinks
        let sql = registry.classify_sink("Model.objects.raw");
        assert!(sql.is_some());
        assert_eq!(sql.unwrap().0, TaintKind::Sql);

        let xss = registry.classify_sink("mark_safe");
        assert!(xss.is_some());
        assert_eq!(xss.unwrap().0, TaintKind::Xss);

        // Sanitizers
        let (sanitized, _) = registry.sanitize_kinds("slugify(title)");
        assert!(sanitized.contains(&TaintKind::Path));

        // Routing & Auth
        let code = "@login_required\ndef user_view(request, id):\n    pass";
        let route = registry.is_route_endpoint("user_view", "views.py", code);
        assert!(route.is_some());
        assert!(route.unwrap().is_authenticated);
    }

    #[test]
    fn test_fastapi_model() {
        let registry = FrameworkRegistry::new();
        // Sources
        assert!(registry.is_request_source("Query(..., description='search')"));
        assert!(registry.is_request_source("Body(...)"));

        // Sinks
        let sql = registry.classify_sink("session.execute");
        assert!(sql.is_some());
        assert_eq!(sql.unwrap().0, TaintKind::Sql);

        let xss = registry.classify_sink("HTMLResponse(html_str)");
        assert!(xss.is_some());
        assert_eq!(xss.unwrap().0, TaintKind::Xss);

        // Routing & Auth
        let code = "@app.get('/users/{user_id}')\ndef get_user(user_id: int, current_user = Depends(get_current_user)): pass";
        let route = registry.is_route_endpoint("get_user", "api.py", code);
        assert!(route.is_some());
        let r = route.unwrap();
        assert_eq!(r.framework, FrameworkKind::FastApi);
        assert!(r.is_authenticated);
    }

    #[test]
    fn test_express_model() {
        let registry = FrameworkRegistry::new();
        // Sources
        assert!(registry.is_request_source("req.query.id"));
        assert!(registry.is_request_source("req.body.name"));

        // Sinks
        let xss = registry.classify_sink("res.send");
        assert!(xss.is_some());
        assert_eq!(xss.unwrap().0, TaintKind::Xss);

        let sql = registry.classify_sink("db.query");
        assert!(sql.is_some());
        assert_eq!(sql.unwrap().0, TaintKind::Sql);

        // Sanitizers
        let (sanitized, _) = registry.sanitize_kinds("parseInt(req.query.id)");
        assert!(sanitized.contains(&TaintKind::Sql));

        // Routing & Auth
        let code = "app.get('/dashboard', passport.authenticate('jwt'), (req, res) => {});";
        let route = registry.is_route_endpoint("dashboardHandler", "server.js", code);
        assert!(route.is_some());
        assert!(route.unwrap().is_authenticated);
    }

    #[test]
    fn test_nestjs_model() {
        let registry = FrameworkRegistry::new();
        // Sources
        assert!(registry.is_request_source("@Body() dto: UserDto"));
        assert!(registry.is_request_source("@Query('page') page: string"));

        // Sinks
        let sql = registry.classify_sink("repo.query");
        assert!(sql.is_some());
        assert_eq!(sql.unwrap().0, TaintKind::Sql);

        // Sanitizers
        let (sanitized, _) = registry.sanitize_kinds("@IsInt() id: number");
        assert!(sanitized.contains(&TaintKind::Sql));

        // Routing & Auth
        let code = "@UseGuards(AuthGuard)\n@Get('/items')\ngetItems() {}";
        let route = registry.is_route_endpoint("getItems", "items.controller.ts", code);
        assert!(route.is_some());
        assert!(route.unwrap().is_authenticated);
    }

    #[test]
    fn test_spring_model() {
        let registry = FrameworkRegistry::new();
        // Sources
        assert!(registry.is_request_source("@RequestParam(\"name\") String name"));
        assert!(registry.is_request_source("@RequestBody UserDto user"));

        // Sinks
        let sql = registry.classify_sink("jdbcTemplate.query");
        assert!(sql.is_some());
        assert_eq!(sql.unwrap().0, TaintKind::Sql);

        let ssrf = registry.classify_sink("restTemplate.getForObject");
        assert!(ssrf.is_some());
        assert_eq!(ssrf.unwrap().0, TaintKind::Ssrf);

        // Sanitizers
        let (sanitized, _) = registry.sanitize_kinds("HtmlUtils.htmlEscape(input)");
        assert!(sanitized.contains(&TaintKind::Xss));

        // Routing & Auth
        let code = "@PreAuthorize(\"hasRole('ADMIN')\")\n@GetMapping(\"/admin/users\")\npublic List<User> getUsers() {}";
        let route = registry.is_route_endpoint("getUsers", "UserController.java", code);
        assert!(route.is_some());
        assert!(route.unwrap().is_authenticated);
    }
}
