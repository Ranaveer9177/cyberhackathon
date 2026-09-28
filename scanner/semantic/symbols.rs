#![allow(dead_code)]

use crate::ast::types::{AssignmentNode, ExprNode, FileNode, FunctionNode, StmtNode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSymbol {
    pub name: String,
    pub position: usize,
    pub default_value: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnSymbol {
    pub expression: String,
    pub line: usize,
    pub returned_identifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableSymbol {
    pub name: String,
    pub scope: String,
    pub file_path: String,
    pub line: usize,
    pub initial_value: Option<String>,
    pub is_parameter: bool,
    pub is_field: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub callee_expr: String,
    pub line: usize,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSymbol {
    pub name: String,
    pub qualified_name: String,
    pub module_name: String,
    pub file_path: String,
    pub is_method: bool,
    pub enclosing_class: Option<String>,
    pub parameters: Vec<ParameterSymbol>,
    pub returns: Vec<ReturnSymbol>,
    pub local_variables: HashMap<String, VariableSymbol>,
    pub calls: Vec<CallSite>,
    pub line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassSymbol {
    pub name: String,
    pub qualified_name: String,
    pub module_name: String,
    pub file_path: String,
    pub base_classes: Vec<String>,
    pub methods: HashMap<String, FunctionSymbol>,
    pub fields: HashMap<String, VariableSymbol>,
    pub line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSymbol {
    pub module_specifier: String,
    pub symbols: Vec<String>,
    pub alias: Option<String>,
    pub resolved_file: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSymbol {
    pub name: String,
    pub file_path: String,
    pub language: String,
    pub imports: Vec<ImportSymbol>,
    pub classes: HashMap<String, ClassSymbol>,
    pub functions: HashMap<String, FunctionSymbol>,
    pub variables: HashMap<String, VariableSymbol>,
    pub top_level_calls: Vec<CallSite>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolTable {
    pub modules: HashMap<String, ModuleSymbol>,
    pub module_name_to_file: HashMap<String, String>,
    pub functions_by_qualified_name: HashMap<String, FunctionSymbol>,
    pub functions_by_short_name: HashMap<String, Vec<String>>,
    pub classes_by_qualified_name: HashMap<String, ClassSymbol>,
    pub classes_by_short_name: HashMap<String, Vec<String>>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_module(&mut self, module: ModuleSymbol) {
        let file_path = module.file_path.clone();
        let module_name = module.name.clone();

        self.module_name_to_file
            .insert(module_name.clone(), file_path.clone());

        for (cls_name, cls) in &module.classes {
            self.classes_by_qualified_name
                .insert(cls.qualified_name.clone(), cls.clone());
            self.classes_by_short_name
                .entry(cls_name.clone())
                .or_default()
                .push(cls.qualified_name.clone());

            for (m_name, method) in &cls.methods {
                self.functions_by_qualified_name
                    .insert(method.qualified_name.clone(), method.clone());
                self.functions_by_short_name
                    .entry(m_name.clone())
                    .or_default()
                    .push(method.qualified_name.clone());
            }
        }

        for (func_name, func) in &module.functions {
            self.functions_by_qualified_name
                .insert(func.qualified_name.clone(), func.clone());
            self.functions_by_short_name
                .entry(func_name.clone())
                .or_default()
                .push(func.qualified_name.clone());
        }

        self.modules.insert(file_path, module);
    }

    pub fn lookup_module_by_path(&self, file_path: &str) -> Option<&ModuleSymbol> {
        let normalized = file_path.replace('\\', "/");
        if let Some(m) = self.modules.get(&normalized) {
            return Some(m);
        }
        for (path, module) in &self.modules {
            if path.ends_with(&normalized) || normalized.ends_with(path) {
                return Some(module);
            }
        }
        None
    }

    pub fn lookup_module_by_name(&self, mod_name: &str) -> Option<&ModuleSymbol> {
        if let Some(file_path) = self.module_name_to_file.get(mod_name) {
            return self.modules.get(file_path);
        }
        let dotted = mod_name.replace('/', ".");
        let slashed = mod_name.replace('.', "/");
        for (name, file_path) in &self.module_name_to_file {
            if name == &dotted || name == &slashed || name.ends_with(&dotted) {
                return self.modules.get(file_path);
            }
        }
        None
    }

    pub fn lookup_function(&self, qualified_or_short_name: &str) -> Option<&FunctionSymbol> {
        if let Some(f) = self
            .functions_by_qualified_name
            .get(qualified_or_short_name)
        {
            return Some(f);
        }
        if let Some(qnames) = self.functions_by_short_name.get(qualified_or_short_name) {
            if let Some(first) = qnames.first() {
                return self.functions_by_qualified_name.get(first);
            }
        }
        None
    }

    pub fn lookup_function_in_module(
        &self,
        file_path: &str,
        func_name: &str,
    ) -> Option<&FunctionSymbol> {
        if let Some(module) = self.lookup_module_by_path(file_path) {
            if let Some(func) = module.functions.get(func_name) {
                return Some(func);
            }
            for cls in module.classes.values() {
                if let Some(method) = cls.methods.get(func_name) {
                    return Some(method);
                }
            }
        }
        None
    }

    pub fn lookup_class(&self, qualified_or_short_name: &str) -> Option<&ClassSymbol> {
        if let Some(c) = self.classes_by_qualified_name.get(qualified_or_short_name) {
            return Some(c);
        }
        if let Some(qnames) = self.classes_by_short_name.get(qualified_or_short_name) {
            if let Some(first) = qnames.first() {
                return self.classes_by_qualified_name.get(first);
            }
        }
        None
    }

    pub fn lookup_method_in_class(
        &self,
        file_path: &str,
        class_name: &str,
        method_name: &str,
    ) -> Option<&FunctionSymbol> {
        if let Some(module) = self.lookup_module_by_path(file_path) {
            if let Some(cls) = module.classes.get(class_name) {
                if let Some(method) = cls.methods.get(method_name) {
                    return Some(method);
                }
            }
        }
        if let Some(cls) = self.lookup_class(class_name) {
            if let Some(method) = cls.methods.get(method_name) {
                return Some(method);
            }
        }
        None
    }

    pub fn lookup_variable(
        &self,
        file_path: &str,
        scope: &str,
        var_name: &str,
    ) -> Option<&VariableSymbol> {
        if let Some(module) = self.lookup_module_by_path(file_path) {
            for func in module.functions.values() {
                if func.qualified_name == scope || func.name == scope {
                    if let Some(var) = func.local_variables.get(var_name) {
                        return Some(var);
                    }
                }
            }
            for cls in module.classes.values() {
                if cls.qualified_name == scope || cls.name == scope {
                    if let Some(field) = cls.fields.get(var_name) {
                        return Some(field);
                    }
                }
                for method in cls.methods.values() {
                    if method.qualified_name == scope || method.name == scope {
                        if let Some(var) = method.local_variables.get(var_name) {
                            return Some(var);
                        }
                    }
                }
            }
            if let Some(var) = module.variables.get(var_name) {
                return Some(var);
            }
        }
        None
    }
}

pub fn normalize_module_path(file_path: &str, project_root: &str) -> (String, String) {
    let norm_path = file_path.replace('\\', "/");
    let norm_root = project_root.replace('\\', "/");

    let rel_path = if norm_path.starts_with(&norm_root) {
        let trimmed = &norm_path[norm_root.len()..];
        trimmed.trim_start_matches('/').to_string()
    } else {
        norm_path.clone()
    };

    let p = Path::new(&rel_path);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let parent = p.parent().and_then(|p| p.to_str()).unwrap_or("");

    let mod_name = if parent.is_empty() || parent == "." {
        stem.to_string()
    } else {
        let parent_mod = parent.replace('/', ".");
        if stem == "__init__" || stem == "index" || stem == "mod" {
            parent_mod
        } else {
            format!("{}.{}", parent_mod, stem)
        }
    };

    (rel_path, mod_name)
}

pub fn extract_module_symbols(file_node: &FileNode, project_root: &str) -> ModuleSymbol {
    let (rel_path, mod_name) = normalize_module_path(&file_node.file_path, project_root);

    let mut imports = Vec::new();
    for imp in &file_node.imports {
        imports.push(ImportSymbol {
            module_specifier: imp.module.clone(),
            symbols: imp.symbols.clone(),
            alias: imp.alias.clone(),
            resolved_file: None,
            line: imp.line,
        });
    }

    let mut top_level_vars = HashMap::new();
    let mut top_level_calls = Vec::new();
    let mut unused_returns = Vec::new();

    collect_statements(
        &file_node.statements,
        &mut top_level_vars,
        &mut top_level_calls,
        &mut unused_returns,
        "module",
        &rel_path,
    );

    let mut classes = HashMap::new();
    for cls in &file_node.classes {
        let qualified_cls_name = format!("{}::{}", mod_name, cls.name);
        let mut fields = HashMap::new();
        for field in &cls.fields {
            let field_name = field.target.to_source_string();
            fields.insert(
                field_name.clone(),
                VariableSymbol {
                    name: field_name,
                    scope: format!("class:{}", qualified_cls_name),
                    file_path: rel_path.clone(),
                    line: field.line,
                    initial_value: Some(field.value.to_source_string()),
                    is_parameter: false,
                    is_field: true,
                },
            );
        }

        let mut methods = HashMap::new();
        for method in &cls.methods {
            let func_sym = extract_function_symbol(
                method,
                &mod_name,
                &rel_path,
                Some(&cls.name),
                Some(&qualified_cls_name),
            );
            methods.insert(method.name.clone(), func_sym);
        }

        classes.insert(
            cls.name.clone(),
            ClassSymbol {
                name: cls.name.clone(),
                qualified_name: qualified_cls_name,
                module_name: mod_name.clone(),
                file_path: rel_path.clone(),
                base_classes: cls.base_classes.clone(),
                methods,
                fields,
                line: cls.line,
                end_line: cls.end_line,
            },
        );
    }

    let mut functions = HashMap::new();
    for func in &file_node.functions {
        let func_sym = extract_function_symbol(func, &mod_name, &rel_path, None, None);
        functions.insert(func.name.clone(), func_sym);
    }

    ModuleSymbol {
        name: mod_name,
        file_path: rel_path,
        language: file_node.language.clone(),
        imports,
        classes,
        functions,
        variables: top_level_vars,
        top_level_calls,
    }
}

fn extract_function_symbol(
    func: &FunctionNode,
    mod_name: &str,
    rel_path: &str,
    enclosing_class: Option<&str>,
    qualified_class: Option<&str>,
) -> FunctionSymbol {
    let qualified_name = match qualified_class {
        Some(qc) => format!("{}::{}", qc, func.name),
        None => format!("{}::{}", mod_name, func.name),
    };

    let mut parameters = Vec::new();
    let mut local_variables = HashMap::new();

    for (pos, param) in func.params.iter().enumerate() {
        parameters.push(ParameterSymbol {
            name: param.clone(),
            position: pos,
            default_value: None,
            line: func.line,
        });

        local_variables.insert(
            param.clone(),
            VariableSymbol {
                name: param.clone(),
                scope: qualified_name.clone(),
                file_path: rel_path.to_string(),
                line: func.line,
                initial_value: None,
                is_parameter: true,
                is_field: false,
            },
        );
    }

    let mut calls = Vec::new();
    let mut returns = Vec::new();

    collect_statements(
        &func.body,
        &mut local_variables,
        &mut calls,
        &mut returns,
        &qualified_name,
        rel_path,
    );

    FunctionSymbol {
        name: func.name.clone(),
        qualified_name,
        module_name: mod_name.to_string(),
        file_path: rel_path.to_string(),
        is_method: func.is_method,
        enclosing_class: enclosing_class.map(|s| s.to_string()),
        parameters,
        returns,
        local_variables,
        calls,
        line: func.line,
        end_line: func.end_line,
    }
}

fn collect_statements(
    stmts: &[StmtNode],
    vars: &mut HashMap<String, VariableSymbol>,
    calls: &mut Vec<CallSite>,
    returns: &mut Vec<ReturnSymbol>,
    scope: &str,
    file_path: &str,
) {
    for stmt in stmts {
        match stmt {
            StmtNode::Assignment(AssignmentNode {
                target,
                value,
                line,
            }) => {
                let var_name = target.to_source_string();
                let val_expr = value.to_source_string();

                vars.insert(
                    var_name.clone(),
                    VariableSymbol {
                        name: var_name,
                        scope: scope.to_string(),
                        file_path: file_path.to_string(),
                        line: *line,
                        initial_value: Some(val_expr),
                        is_parameter: false,
                        is_field: false,
                    },
                );

                extract_calls_from_expr(value, calls);
            }
            StmtNode::Call(call_expr) => {
                extract_calls_from_expr(call_expr, calls);
            }
            StmtNode::Return(ret) => {
                let expr_str = ret
                    .value
                    .as_ref()
                    .map(|v| v.to_source_string())
                    .unwrap_or_default();
                let idents = ret
                    .value
                    .as_ref()
                    .map(extract_identifiers)
                    .unwrap_or_default();

                returns.push(ReturnSymbol {
                    expression: expr_str,
                    line: ret.line,
                    returned_identifiers: idents,
                });

                if let Some(val) = &ret.value {
                    extract_calls_from_expr(val, calls);
                }
            }
            StmtNode::Condition(c) => {
                extract_calls_from_expr(&c.test, calls);
                collect_statements(&c.then_body, vars, calls, returns, scope, file_path);
                collect_statements(&c.else_body, vars, calls, returns, scope, file_path);
            }
            StmtNode::Loop(l) => {
                if let Some(cond) = &l.condition {
                    extract_calls_from_expr(cond, calls);
                }
                collect_statements(&l.body, vars, calls, returns, scope, file_path);
            }
            StmtNode::TryCatch(t) => {
                collect_statements(&t.try_body, vars, calls, returns, scope, file_path);
                collect_statements(&t.catch_body, vars, calls, returns, scope, file_path);
                collect_statements(&t.finally_body, vars, calls, returns, scope, file_path);
            }
            StmtNode::Expression(e) => {
                extract_calls_from_expr(e, calls);
            }
        }
    }
}

pub fn extract_identifiers(expr: &ExprNode) -> Vec<String> {
    let mut idents = Vec::new();
    match expr {
        ExprNode::Identifier { name, .. } => {
            idents.push(name.clone());
        }
        ExprNode::Attribute { value, .. } => {
            idents.extend(extract_identifiers(value));
        }
        ExprNode::Subscript { value, slice, .. } => {
            idents.extend(extract_identifiers(value));
            idents.extend(extract_identifiers(slice));
        }
        ExprNode::Call { callee, args, .. } => {
            idents.extend(extract_identifiers(callee));
            for arg in args {
                idents.extend(extract_identifiers(arg));
            }
        }
        ExprNode::BinaryOp { left, right, .. } => {
            idents.extend(extract_identifiers(left));
            idents.extend(extract_identifiers(right));
        }
        ExprNode::FormattedString { parts, .. } => {
            for part in parts {
                idents.extend(extract_identifiers(part));
            }
        }
        ExprNode::List { elements, .. } => {
            for el in elements {
                idents.extend(extract_identifiers(el));
            }
        }
        ExprNode::Constant { .. } | ExprNode::Unknown { .. } => {}
    }
    idents
}

pub fn extract_calls_from_expr(expr: &ExprNode, calls: &mut Vec<CallSite>) {
    match expr {
        ExprNode::Call { callee, args, line } => {
            let callee_name = callee.to_source_string();
            let arg_strings = args.iter().map(|a| a.to_source_string()).collect();

            calls.push(CallSite {
                callee_expr: callee_name,
                line: *line,
                arguments: arg_strings,
            });

            extract_calls_from_expr(callee, calls);
            for arg in args {
                extract_calls_from_expr(arg, calls);
            }
        }
        ExprNode::Attribute { value, .. } => {
            extract_calls_from_expr(value, calls);
        }
        ExprNode::Subscript { value, slice, .. } => {
            extract_calls_from_expr(value, calls);
            extract_calls_from_expr(slice, calls);
        }
        ExprNode::BinaryOp { left, right, .. } => {
            extract_calls_from_expr(left, calls);
            extract_calls_from_expr(right, calls);
        }
        ExprNode::FormattedString { parts, .. } => {
            for part in parts {
                extract_calls_from_expr(part, calls);
            }
        }
        ExprNode::List { elements, .. } => {
            for el in elements {
                extract_calls_from_expr(el, calls);
            }
        }
        ExprNode::Identifier { .. } | ExprNode::Constant { .. } | ExprNode::Unknown { .. } => {}
    }
}
