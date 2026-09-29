#![allow(dead_code)]

use crate::taint::types::TaintKind;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrameworkKind {
    Flask,
    Django,
    FastApi,
    Express,
    NestJs,
    Spring,
    Gin,
}

impl FrameworkKind {
    pub fn display_name(&self) -> &'static str {
        match self {
            FrameworkKind::Flask => "Flask",
            FrameworkKind::Django => "Django",
            FrameworkKind::FastApi => "FastAPI",
            FrameworkKind::Express => "Express",
            FrameworkKind::NestJs => "NestJS",
            FrameworkKind::Spring => "Spring",
            FrameworkKind::Gin => "Gin",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEndpoint {
    pub framework: FrameworkKind,
    pub file_path: String,
    pub function_name: String,
    pub route_path: String,
    pub http_methods: Vec<String>,
    pub parameters: Vec<String>,
    pub is_authenticated: bool,
    pub auth_mechanism: Option<String>,
}

pub trait FrameworkModel: Send + Sync {
    fn framework(&self) -> FrameworkKind;

    /// Checks if this framework is detected in the file content or imports
    fn detect(&self, file_path: &str, content: &str) -> bool;

    /// Checks if an expression or variable access is an untrusted HTTP source
    fn is_source(&self, expr_str: &str) -> bool;

    /// Checks if a parameter name or parameter type represents incoming HTTP input
    fn is_request_param(&self, param_name: &str) -> bool;

    /// Classifies an invocation as a framework-specific vulnerability sink
    fn classify_sink(&self, callee_str: &str) -> Option<(TaintKind, &'static str)>;

    /// Identifies sanitizers/validators and the taint kinds they neutralize
    fn is_sanitizer(&self, expr_str: &str) -> (HashSet<TaintKind>, Option<&'static str>);

    /// Analyzes a function definition and surrounding decorators to detect if it is an HTTP route
    fn is_route_endpoint(
        &self,
        func_name: &str,
        file_path: &str,
        func_code: &str,
    ) -> Option<RouteEndpoint>;

    /// Checks if a variable or type represents the framework's Request object
    fn is_request_object(&self, ident: &str) -> bool;

    /// Checks if a call interacts with a database or ORM
    fn is_db_interface(&self, callee: &str) -> bool;

    /// Checks if an ORM or database call executes a raw / unescaped SQL query
    fn is_raw_db_query(&self, callee: &str) -> bool;

    /// Checks if a call renders a template
    fn is_template_render(&self, callee: &str) -> bool;

    /// Checks if a template render call is dangerous (e.g., SSTI via string rendering)
    fn is_unsafe_template_render(&self, callee: &str) -> bool;

    /// Checks whether authentication checks or decorators are attached to the function
    fn check_auth(&self, func_code: &str) -> (bool, Option<String>);
}
