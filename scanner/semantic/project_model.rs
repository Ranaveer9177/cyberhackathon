#![allow(dead_code)]

use crate::ast::types::FileNode;
use crate::semantic::call_graph::{CallChain, CallGraph, CallGraphEdge, CallGraphNode};
use crate::semantic::function_resolver::FunctionResolver;
use crate::semantic::module_resolver::ModuleResolver;
use crate::semantic::symbols::{self, SymbolTable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub entry_file: String,
    pub entry_line: usize,
    pub sink_file: String,
    pub sink_line: usize,
    pub call_chain_formatted: String,
    pub data_flow: Vec<String>,
    pub recommendation: String,
}

pub struct ProjectModel {
    pub project_root: String,
    pub symbol_table: SymbolTable,
    pub module_resolver: ModuleResolver,
    pub call_graph: CallGraph,
}

impl ProjectModel {
    pub fn build(project_root: &str, parsed_files: &[(&str, &FileNode)]) -> Self {
        let known_files: Vec<String> = parsed_files
            .iter()
            .map(|(path, _)| path.to_string())
            .collect();

        let mut module_resolver = ModuleResolver::new(project_root, &known_files);
        let mut symbol_table = SymbolTable::new();

        // 1. Extract symbols for each file into symbol table
        for (_, file_node) in parsed_files {
            let mut module_symbol = symbols::extract_module_symbols(file_node, project_root);

            // Register imports with module resolver
            for imp in &mut module_symbol.imports {
                if let Some(target) =
                    module_resolver.register_import(&module_symbol.file_path, &imp.module_specifier)
                {
                    imp.resolved_file = Some(target);
                }
            }

            symbol_table.add_module(module_symbol);
        }

        // 2. Build Call Graph
        let mut call_graph = CallGraph::new();

        // Register all functions as nodes
        for func in symbol_table.functions_by_qualified_name.values() {
            let is_source = is_likely_source(func);
            let source_kind = if is_source {
                Some("API_ENTRYPOINT_OR_INPUT".to_string())
            } else {
                None
            };

            call_graph.add_node(CallGraphNode {
                id: func.qualified_name.clone(),
                display_name: format!("{}()", func.name),
                file_path: func.file_path.clone(),
                line: func.line,
                is_sink: false,
                sink_kind: None,
                is_source,
                source_kind,
            });
        }

        // Register top-level module scripts as nodes if they have calls
        for module in symbol_table.modules.values() {
            if !module.top_level_calls.is_empty() {
                let top_node_id = format!("{}::<top_level>", module.file_path);
                call_graph.add_node(CallGraphNode {
                    id: top_node_id,
                    display_name: format!("<top_level:{}>", module.name),
                    file_path: module.file_path.clone(),
                    line: 1,
                    is_sink: false,
                    sink_kind: None,
                    is_source: true,
                    source_kind: Some("SCRIPT_ENTRYPOINT".to_string()),
                });
            }
        }

        // 3. Resolve calls and add call graph edges
        let function_resolver = FunctionResolver::new(&symbol_table, &module_resolver);

        for func in symbol_table.functions_by_qualified_name.values() {
            for call in &func.calls {
                if let Some((sink_kind, sink_cat)) = classify_sink(&call.callee_expr) {
                    let sink_node_id =
                        format!("sink::{}:{}:{}", func.file_path, call.line, sink_cat);
                    call_graph.add_node(CallGraphNode {
                        id: sink_node_id.clone(),
                        display_name: format!("{}()", call.callee_expr),
                        file_path: func.file_path.clone(),
                        line: call.line,
                        is_sink: true,
                        sink_kind: Some(sink_kind),
                        is_source: false,
                        source_kind: None,
                    });

                    call_graph.add_edge(CallGraphEdge {
                        caller_id: func.qualified_name.clone(),
                        callee_id: sink_node_id,
                        caller_file: func.file_path.clone(),
                        call_line: call.line,
                        callee_file: func.file_path.clone(),
                        arguments: call.arguments.clone(),
                    });
                } else if let Some(resolved) = function_resolver.resolve(
                    &func.file_path,
                    Some(&func.qualified_name),
                    &call.callee_expr,
                ) {
                    call_graph.add_edge(CallGraphEdge {
                        caller_id: func.qualified_name.clone(),
                        callee_id: resolved.qualified_name.clone(),
                        caller_file: func.file_path.clone(),
                        call_line: call.line,
                        callee_file: resolved.file_path.clone(),
                        arguments: call.arguments.clone(),
                    });
                }
            }
        }

        // Top level calls
        for module in symbol_table.modules.values() {
            let top_node_id = format!("{}::<top_level>", module.file_path);
            for call in &module.top_level_calls {
                if let Some((sink_kind, sink_cat)) = classify_sink(&call.callee_expr) {
                    let sink_node_id =
                        format!("sink::{}:{}:{}", module.file_path, call.line, sink_cat);
                    call_graph.add_node(CallGraphNode {
                        id: sink_node_id.clone(),
                        display_name: format!("{}()", call.callee_expr),
                        file_path: module.file_path.clone(),
                        line: call.line,
                        is_sink: true,
                        sink_kind: Some(sink_kind),
                        is_source: false,
                        source_kind: None,
                    });

                    call_graph.add_edge(CallGraphEdge {
                        caller_id: top_node_id.clone(),
                        callee_id: sink_node_id,
                        caller_file: module.file_path.clone(),
                        call_line: call.line,
                        callee_file: module.file_path.clone(),
                        arguments: call.arguments.clone(),
                    });
                } else if let Some(resolved) =
                    function_resolver.resolve(&module.file_path, None, &call.callee_expr)
                {
                    call_graph.add_edge(CallGraphEdge {
                        caller_id: top_node_id.clone(),
                        callee_id: resolved.qualified_name.clone(),
                        caller_file: module.file_path.clone(),
                        call_line: call.line,
                        callee_file: resolved.file_path.clone(),
                        arguments: call.arguments.clone(),
                    });
                }
            }
        }

        Self {
            project_root: project_root.to_string(),
            symbol_table,
            module_resolver,
            call_graph,
        }
    }

    pub fn find_sink_chains(&self, max_depth: usize) -> Vec<CallChain> {
        self.call_graph.find_paths_to_sinks(max_depth)
    }
}

fn is_likely_source(func: &symbols::FunctionSymbol) -> bool {
    let lower_name = func.name.to_lowercase();
    let lower_path = func.file_path.to_lowercase();

    // Check function name patterns common for web handlers / API endpoints
    if lower_name.starts_with("handle_")
        || lower_name.starts_with("get_")
        || lower_name.starts_with("post_")
        || lower_name.starts_with("put_")
        || lower_name.starts_with("delete_")
        || lower_name.starts_with("api_")
        || lower_name.starts_with("route_")
        || lower_name == "main"
        || lower_name == "handler"
    {
        return true;
    }

    // Check file paths common for controllers / routes / endpoints
    if lower_path.contains("routes")
        || lower_path.contains("controllers")
        || lower_path.contains("views")
        || lower_path.contains("api")
        || lower_path.contains("endpoints")
    {
        return true;
    }

    // Check if parameters indicate external input
    let fw = crate::frameworks::FrameworkRegistry::new();
    for p in &func.parameters {
        if fw.is_request_param(&p.name) {
            return true;
        }
        let p_lower = p.name.to_lowercase();
        if p_lower.contains("req")
            || p_lower.contains("request")
            || p_lower.contains("input")
            || p_lower.contains("query")
            || p_lower.contains("param")
            || p_lower.contains("payload")
            || p_lower.contains("user")
            || p_lower.contains("args")
        {
            return true;
        }
    }

    // Check local variables for request / input access
    for var in func.local_variables.values() {
        if let Some(val) = &var.initial_value {
            if fw.is_request_source(val) {
                return true;
            }
            let v_lower = val.to_lowercase();
            if v_lower.contains("request.args")
                || v_lower.contains("request.form")
                || v_lower.contains("request.json")
                || v_lower.contains("req.query")
                || v_lower.contains("req.body")
                || v_lower.contains("req.params")
                || v_lower.contains("input(")
                || v_lower.contains("readline")
                || v_lower.contains("r.url.query")
            {
                return true;
            }
        }
    }

    false
}

fn classify_sink(callee: &str) -> Option<(String, String)> {
    if let Some((kind, name)) = crate::frameworks::FrameworkRegistry::new().classify_sink(callee) {
        return Some((format!("{:?}", kind).to_uppercase(), name.to_string()));
    }

    let clean = callee.trim();
    let lower = clean.to_lowercase();

    // SQL Injection Sinks (v7.2 Context & Receiver Analysis)
    let is_sql_sink = if let Some(dot_idx) = lower.rfind('.') {
        let receiver = &lower[..dot_idx];
        let method = &lower[dot_idx + 1..];

        let is_non_sql = receiver == "tmpl"
            || receiver == "template"
            || receiver == "htmltemplate"
            || receiver == "texttemplate"
            || receiver == "t"
            || receiver == "w"
            || receiver == "writer"
            || receiver == "cmd"
            || receiver == "rootcmd"
            || receiver == "command"
            || receiver == "cobracommand"
            || receiver == "c"
            || receiver == "app"
            || receiver == "task"
            || receiver == "runner"
            || receiver == "workflow"
            || receiver == "future"
            || receiver == "promise"
            || receiver == "executor"
            || receiver == "batch";

        if is_non_sql {
            false
        } else if method == "execute" || method == "exec" {
            receiver == "db"
                || receiver == "cursor"
                || receiver == "cur"
                || receiver == "conn"
                || receiver == "connection"
                || receiver == "session"
                || receiver == "orm"
                || receiver == "tx"
                || receiver == "sql"
                || receiver == "repo"
                || receiver == "repository"
                || receiver == "client"
                || receiver == "engine"
                || receiver == "stmt"
                || receiver.ends_with("db")
                || receiver.ends_with("conn")
                || receiver.ends_with("cursor")
                || receiver.ends_with("session")
                || receiver.ends_with("repo")
        } else {
            method == "executemany"
                || method == "query"
                || method == "queryrow"
                || method == "query_row"
                || method == "raw"
                || method == "executequery"
                || method == "executeupdate"
        }
    } else {
        lower == "execute"
            || lower == "db.execute"
            || lower == "conn.execute"
            || lower == "cursor.execute"
            || lower == "session.execute"
    };

    if is_sql_sink {
        return Some(("SQL_INJECTION".to_string(), "sql_execute".to_string()));
    }

    // Command Injection Sinks
    if clean == "os.system"
        || clean == "os.popen"
        || clean.starts_with("subprocess.")
        || clean == "exec.Command"
        || clean == "child_process.exec"
        || clean == "child_process.execSync"
        || clean == "child_process.spawn"
        || clean == "Runtime.getRuntime().exec"
        || clean == "exec"
    {
        return Some(("COMMAND_INJECTION".to_string(), "cmd_exec".to_string()));
    }

    // Dangerous Code Evaluation
    if clean == "eval" || clean == "Function" {
        return Some(("CODE_INJECTION".to_string(), "code_eval".to_string()));
    }

    None
}
