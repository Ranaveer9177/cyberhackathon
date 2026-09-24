#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebFramework {
    Flask,
    Django,
    FastApi,
    Express,
    NestJs,
    SpringBoot,
    Unknown,
}

pub struct FrameworkModel;

impl FrameworkModel {
    /// Detects potential web framework based on file contents or imports
    pub fn detect_framework(content: &str) -> WebFramework {
        if content.contains("from flask import") || content.contains("import flask") {
            WebFramework::Flask
        } else if content.contains("from django") || content.contains("import django") {
            WebFramework::Django
        } else if content.contains("from fastapi import") || content.contains("import fastapi") {
            WebFramework::FastApi
        } else if content.contains("express()")
            || content.contains("require('express')")
            || content.contains("from 'express'")
        {
            WebFramework::Express
        } else if content.contains("@nestjs/") {
            WebFramework::NestJs
        } else if content.contains("org.springframework.") || content.contains("@RestController") {
            WebFramework::SpringBoot
        } else {
            WebFramework::Unknown
        }
    }

    /// Checks if a code snippet accesses an untrusted HTTP source in the given framework
    pub fn is_http_source(framework: WebFramework, expr: &str) -> bool {
        match framework {
            WebFramework::Flask => {
                expr.contains("request.args")
                    || expr.contains("request.form")
                    || expr.contains("request.values")
                    || expr.contains("request.json")
                    || expr.contains("request.get_json()")
                    || expr.contains("request.headers")
                    || expr.contains("request.cookies")
            }
            WebFramework::Django => {
                expr.contains("request.GET")
                    || expr.contains("request.POST")
                    || expr.contains("request.COOKIES")
                    || expr.contains("request.body")
            }
            WebFramework::FastApi => {
                // FastAPI parameter sources
                expr.contains("Query(")
                    || expr.contains("Body(")
                    || expr.contains("Header(")
                    || expr.contains("Path(")
            }
            WebFramework::Express | WebFramework::NestJs => {
                expr.contains("req.query")
                    || expr.contains("req.body")
                    || expr.contains("req.params")
                    || expr.contains("req.headers")
            }
            WebFramework::SpringBoot => {
                expr.contains("@RequestParam")
                    || expr.contains("@PathVariable")
                    || expr.contains("@RequestBody")
                    || expr.contains("@RequestHeader")
            }
            WebFramework::Unknown => {
                // Generic heuristic sources
                expr.contains("request.args")
                    || expr.contains("req.query")
                    || expr.contains("req.body")
                    || expr.contains("r.URL.Query()")
            }
        }
    }
}
