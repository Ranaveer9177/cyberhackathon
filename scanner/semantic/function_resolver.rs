#![allow(dead_code)]

use crate::semantic::module_resolver::ModuleResolver;
use crate::semantic::symbols::{FunctionSymbol, SymbolTable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionKind {
    Local,
    ImportedDirect,
    ImportedModule,
    ClassMethod,
    ProjectUnique,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedFunction {
    pub name: String,
    pub qualified_name: String,
    pub file_path: String,
    pub line: usize,
    pub end_line: usize,
    pub parameters: Vec<String>,
    pub kind: ResolutionKind,
}

pub struct FunctionResolver<'a> {
    pub symbol_table: &'a SymbolTable,
    pub module_resolver: &'a ModuleResolver,
}

impl<'a> FunctionResolver<'a> {
    pub fn new(symbol_table: &'a SymbolTable, module_resolver: &'a ModuleResolver) -> Self {
        Self {
            symbol_table,
            module_resolver,
        }
    }

    pub fn resolve(
        &self,
        caller_file: &str,
        caller_func: Option<&str>,
        callee_expr: &str,
    ) -> Option<ResolvedFunction> {
        let clean_expr = clean_callee_name(callee_expr);
        if clean_expr.is_empty() {
            return None;
        }

        let norm_file = self.module_resolver.normalize_file_path(caller_file);

        // 1. Check local function in caller file
        if let Some(func) = self
            .symbol_table
            .lookup_function_in_module(&norm_file, &clean_expr)
        {
            return Some(make_resolved(func, ResolutionKind::Local));
        }

        // 2. Check method on self/this or enclosing class
        if clean_expr.starts_with("self.")
            || clean_expr.starts_with("this.")
            || clean_expr.starts_with("super.")
        {
            let method_name = clean_expr.split('.').nth(1).unwrap_or("");
            if let Some(c_func) = caller_func {
                if let Some(parent_func) = self.symbol_table.lookup_function(c_func) {
                    if let Some(cls_name) = &parent_func.enclosing_class {
                        if let Some(method) = self.symbol_table.lookup_method_in_class(
                            &norm_file,
                            cls_name,
                            method_name,
                        ) {
                            return Some(make_resolved(method, ResolutionKind::ClassMethod));
                        }
                    }
                }
            }
        }

        // 3. Qualified call: obj.func() or module.func()
        if clean_expr.contains('.') {
            let parts: Vec<&str> = clean_expr.split('.').collect();
            if parts.len() == 2 {
                let obj_or_mod = parts[0];
                let func_name = parts[1];

                // Check imports in caller file for module / alias
                if let Some(module) = self.symbol_table.lookup_module_by_path(&norm_file) {
                    for imp in &module.imports {
                        // Matching alias: "import services.user as user_svc" -> obj_or_mod == "user_svc"
                        let matches_alias = imp.alias.as_deref() == Some(obj_or_mod);
                        // Matching module last component: "import services.user" -> obj_or_mod == "user"
                        let last_comp = imp.module_specifier.split('.').next_back().unwrap_or("");
                        let matches_comp = last_comp == obj_or_mod;

                        if matches_alias || matches_comp {
                            let target_file = imp.resolved_file.clone().or_else(|| {
                                self.module_resolver
                                    .resolve_import(&norm_file, &imp.module_specifier)
                            });

                            if let Some(tf) = &target_file {
                                if let Some(func) =
                                    self.symbol_table.lookup_function_in_module(tf, func_name)
                                {
                                    return Some(make_resolved(
                                        func,
                                        ResolutionKind::ImportedModule,
                                    ));
                                }
                            }
                        }
                    }
                }

                // Check if obj_or_mod is a known class name in caller module or project
                if let Some(cls) = self.symbol_table.lookup_class(obj_or_mod) {
                    if let Some(method) = cls.methods.get(func_name) {
                        return Some(make_resolved(method, ResolutionKind::ClassMethod));
                    }
                }

                // Check direct dotted module: e.g. "services.user.find_user"
                if let Some(target_file) =
                    self.module_resolver.resolve_import(&norm_file, obj_or_mod)
                {
                    if let Some(func) = self
                        .symbol_table
                        .lookup_function_in_module(&target_file, func_name)
                    {
                        return Some(make_resolved(func, ResolutionKind::ImportedModule));
                    }
                }
            }
        }

        // 4. Direct imported symbol in caller file
        if let Some(module) = self.symbol_table.lookup_module_by_path(&norm_file) {
            for imp in &module.imports {
                // from module import symbol
                if imp.symbols.iter().any(|s| s == &clean_expr) {
                    let target_file = imp.resolved_file.clone().or_else(|| {
                        self.module_resolver
                            .resolve_import(&norm_file, &imp.module_specifier)
                    });

                    if let Some(tf) = &target_file {
                        if let Some(func) =
                            self.symbol_table.lookup_function_in_module(tf, &clean_expr)
                        {
                            return Some(make_resolved(func, ResolutionKind::ImportedDirect));
                        }
                    }
                }

                // star import: from module import *
                if imp.symbols.iter().any(|s| s == "*") {
                    let target_file = imp.resolved_file.clone().or_else(|| {
                        self.module_resolver
                            .resolve_import(&norm_file, &imp.module_specifier)
                    });

                    if let Some(tf) = &target_file {
                        if let Some(func) =
                            self.symbol_table.lookup_function_in_module(tf, &clean_expr)
                        {
                            return Some(make_resolved(func, ResolutionKind::ImportedDirect));
                        }
                    }
                }
            }
        }

        // 5. Fallback: project-wide unique symbol
        if let Some(qnames) = self.symbol_table.functions_by_short_name.get(&clean_expr) {
            if qnames.len() == 1 {
                if let Some(func) = self.symbol_table.lookup_function(&qnames[0]) {
                    return Some(make_resolved(func, ResolutionKind::ProjectUnique));
                }
            }
        }

        None
    }
}

fn clean_callee_name(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(idx) = s.find('(') {
        s = &s[..idx];
    }
    s.trim().to_string()
}

fn make_resolved(func: &FunctionSymbol, kind: ResolutionKind) -> ResolvedFunction {
    ResolvedFunction {
        name: func.name.clone(),
        qualified_name: func.qualified_name.clone(),
        file_path: func.file_path.clone(),
        line: func.line,
        end_line: func.end_line,
        parameters: func.parameters.iter().map(|p| p.name.clone()).collect(),
        kind,
    }
}
