#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

/// Inferred or declared type category for variables and expressions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TypeKind {
    String,
    Integer,
    Float,
    Boolean,
    List,
    Map,
    Object,
    Bytes,
    Unknown,
}

impl TypeKind {
    /// Returns true if this type is a numeric primitive, naturally preventing SQL injection syntax
    pub fn is_numeric(&self) -> bool {
        matches!(self, TypeKind::Integer | TypeKind::Float)
    }
}

/// Represents a function or method definition in a source file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionModel {
    pub name: String,
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub parameters: Vec<String>,
    pub local_variables: HashSet<String>,
    pub outgoing_calls: Vec<String>,
    pub return_expressions: Vec<String>,
    pub inferred_param_types: HashMap<String, TypeKind>,
}

impl FunctionModel {
    pub fn new(name: &str, file_path: &str, line_start: usize, line_end: usize) -> Self {
        Self {
            name: name.to_string(),
            file_path: file_path.to_string(),
            line_start,
            line_end,
            parameters: Vec::new(),
            local_variables: HashSet::new(),
            outgoing_calls: Vec::new(),
            return_expressions: Vec::new(),
            inferred_param_types: HashMap::new(),
        }
    }
}

/// Project-wide symbol table resolving imports, modules, and cross-file functions.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SymbolTable {
    /// Maps module name / relative path -> map of exported symbol name to file path
    pub module_exports: HashMap<String, HashMap<String, String>>,
    /// Maps file path -> list of function names defined in that file
    pub file_functions: HashMap<String, Vec<String>>,
    /// Maps file path -> map of imported symbol name to source module
    pub file_imports: HashMap<String, HashMap<String, String>>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a function declared in a specific file
    pub fn register_function(&mut self, file_path: &str, func_name: &str) {
        self.file_functions
            .entry(file_path.to_string())
            .or_default()
            .push(func_name.to_string());

        // Derive module name from file path (e.g. "services/database.py" -> "database")
        let module_name = std::path::Path::new(file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(file_path);

        self.module_exports
            .entry(module_name.to_string())
            .or_default()
            .insert(func_name.to_string(), file_path.to_string());
    }

    /// Register an import statement in a file (e.g. from utils import execute_command)
    pub fn register_import(&mut self, file_path: &str, symbol: &str, module: &str) {
        self.file_imports
            .entry(file_path.to_string())
            .or_default()
            .insert(symbol.to_string(), module.to_string());
    }

    /// Resolve a call from a given file to its target definition file and function name
    pub fn resolve_call(&self, caller_file: &str, call_expr: &str) -> Option<(String, String)> {
        // Direct method call like `database.execute_query(x)`
        if let Some((mod_part, func_part)) = call_expr.split_once('.') {
            if let Some(exports) = self.module_exports.get(mod_part) {
                if let Some(target_file) = exports.get(func_part) {
                    return Some((target_file.clone(), func_part.to_string()));
                }
            }
        }

        // Direct imported call like `execute_command(x)` where `execute_command` was imported
        if let Some(imports) = self.file_imports.get(caller_file) {
            if let Some(mod_name) = imports.get(call_expr) {
                if let Some(exports) = self.module_exports.get(mod_name) {
                    if let Some(target_file) = exports.get(call_expr) {
                        return Some((target_file.clone(), call_expr.to_string()));
                    }
                }
            }
        }

        // Intra-file function call
        if let Some(funcs) = self.file_functions.get(caller_file) {
            if funcs.contains(&call_expr.to_string()) {
                return Some((caller_file.to_string(), call_expr.to_string()));
            }
        }

        None
    }
}

/// Project-wide call graph recording directed invocations across functions.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CallGraph {
    /// Maps "file::function" -> list of "target_file::target_function"
    pub edges: HashMap<String, Vec<String>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_edge(&mut self, caller: &str, callee: &str) {
        self.edges
            .entry(caller.to_string())
            .or_default()
            .push(callee.to_string());
    }

    pub fn get_callees(&self, caller: &str) -> &[String] {
        self.edges.get(caller).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Root semantic model representing the entire scanned project.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProjectModel {
    pub symbol_table: SymbolTable,
    pub call_graph: CallGraph,
    pub functions: HashMap<String, FunctionModel>,
}

impl ProjectModel {
    pub fn new() -> Self {
        Self::default()
    }
}
