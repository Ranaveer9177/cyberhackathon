#![allow(dead_code)]

pub struct SourceModel;

impl SourceModel {
    /// Detects if an expression or variable initialization originates from an external untrusted source.
    pub fn is_untrusted_source(expr: &str) -> bool {
        let lower = expr.to_lowercase();

        // Python (Flask, Django, FastAPI)
        if lower.contains("request.args")
            || lower.contains("request.form")
            || lower.contains("request.values")
            || lower.contains("request.get_json")
            || lower.contains("request.json")
            || lower.contains("request.data")
            || lower.contains("request.cookies")
            || lower.contains("request.headers")
            || lower.contains("request.get")
            || lower.contains("request.post")
            || lower.contains("request.body")
            || lower.contains("input(")
            || lower.contains("sys.argv")
        {
            return true;
        }

        // JavaScript / TypeScript (Express, Koa, Fastify, Next.js)
        if lower.contains("req.query")
            || lower.contains("req.body")
            || lower.contains("req.params")
            || lower.contains("req.headers")
            || lower.contains("req.cookies")
            || lower.contains("request.query")
            || lower.contains("request.body")
            || lower.contains("process.argv")
            || lower.contains("window.location")
            || lower.contains("document.location")
        {
            return true;
        }

        // Go (net/http, Gin, Fiber, Echo)
        if lower.contains("r.url.query()")
            || lower.contains("r.formvalue(")
            || lower.contains("r.postformvalue(")
            || lower.contains("c.query(")
            || lower.contains("c.param(")
            || lower.contains("c.body(")
            || lower.contains("os.args")
        {
            return true;
        }

        // Java (Servlets, Spring)
        if lower.contains("request.getparameter(")
            || lower.contains("request.getheaders(")
            || lower.contains("@requestparam")
            || lower.contains("@pathvariable")
            || lower.contains("@requestbody")
        {
            return true;
        }

        false
    }

    /// Checks if a parameter name indicates incoming request / user input.
    pub fn is_untrusted_parameter_name(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("user_id")
            || lower.contains("uid")
            || lower.contains("username")
            || lower.contains("param")
            || lower.contains("query")
            || lower.contains("host")
            || lower.contains("url")
            || lower.contains("cmd")
            || lower.contains("command")
            || lower.contains("filename")
            || lower.contains("path")
            || lower.contains("payload")
            || lower.contains("data")
            || lower.contains("input")
            || lower.contains("req")
            || lower.contains("request")
    }
}
