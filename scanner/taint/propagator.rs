#![allow(dead_code)]

use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::string_propagation::StringPropagator;
use crate::analysis::types::TypeEnvironment;
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::semantic::function_resolver::FunctionResolver;
use crate::semantic::project_model::ProjectModel;
use crate::taint::sanitizers::SanitizerModel;
use crate::taint::sinks::SinkModel;
use crate::taint::sources::SourceModel;
use crate::taint::types::{TaintFlow, TaintKind, TaintStep, TaintStepType, TaintedVariable};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
struct InterproceduralContext {
    pub target_func_qname: String,
    pub target_file: String,
    pub param_index: usize,
    pub taint_kind: TaintKind,
    pub steps: Vec<TaintStep>,
}

struct AnalysisContext<'b> {
    pub file_path: &'b str,
    pub scope: &'b str,
    pub function_resolver: &'b FunctionResolver<'b>,
    pub cfg: Option<&'b ControlFlowGraph>,
}

#[derive(Default, Clone)]
struct LocalEnv {
    pub taints: HashMap<String, TaintedVariable>,
    pub type_env: TypeEnvironment,
    pub const_env: ConstantEnvironment,
}

pub struct DeepTaintPropagator<'a> {
    pub project_model: &'a ProjectModel,
    pub parsed_files: &'a [(&'a str, &'a FileNode)],
}

impl<'a> DeepTaintPropagator<'a> {
    pub fn new(
        project_model: &'a ProjectModel,
        parsed_files: &'a [(&'a str, &'a FileNode)],
    ) -> Self {
        Self {
            project_model,
            parsed_files,
        }
    }

    pub fn execute(&self) -> Vec<TaintFlow> {
        let mut flows = Vec::new();
        let function_resolver = FunctionResolver::new(
            &self.project_model.symbol_table,
            &self.project_model.module_resolver,
        );

        let mut queue: VecDeque<InterproceduralContext> = VecDeque::new();
        let mut visited_contexts: HashSet<String> = HashSet::new();

        // 1. Initial Pass: Identify entrypoint functions and top-level scripts
        for (file_path, file_node) in self.parsed_files {
            let rel_file = self
                .project_model
                .module_resolver
                .normalize_file_path(file_path);

            // Analyze functions in file
            for func in &file_node.functions {
                let is_entrypoint = is_api_entrypoint(&func.name, &rel_file);
                let mut local_taints: HashMap<String, TaintedVariable> = HashMap::new();

                // If entrypoint or parameter indicates user input, seed parameters
                for param in &func.params {
                    if is_entrypoint || SourceModel::is_untrusted_parameter_name(param) {
                        let mut taints = HashSet::new();
                        for k in TaintKind::all() {
                            taints.insert(k);
                        }

                        let initial_step = TaintStep {
                            file: rel_file.clone(),
                            line: func.line,
                            symbol: param.clone(),
                            step_type: TaintStepType::FunctionParameter,
                            snippet: format!("{} in {}()", param, func.name),
                            description:
                                "Untrusted entrypoint parameter receives external request input"
                                    .to_string(),
                        };

                        local_taints.insert(
                            param.clone(),
                            TaintedVariable {
                                name: param.clone(),
                                scope: func.name.clone(),
                                file: rel_file.clone(),
                                line: func.line,
                                taints,
                                sanitized_for: HashSet::new(),
                                steps: vec![initial_step],
                            },
                        );
                    }
                }

                let cfg = ControlFlowGraph::build_from_statements(&func.body);
                let mut env = LocalEnv {
                    taints: local_taints,
                    type_env: TypeEnvironment::new(),
                    const_env: ConstantEnvironment::new(),
                };

                let ctx = AnalysisContext {
                    file_path: &rel_file,
                    scope: &func.name,
                    function_resolver: &function_resolver,
                    cfg: Some(&cfg),
                };

                // Analyze function body statements
                self.analyze_statement_block(&func.body, &ctx, &mut env, &mut queue, &mut flows);
            }

            // Analyze top-level statements
            let top_cfg = ControlFlowGraph::build_from_statements(&file_node.statements);
            let mut top_env = LocalEnv::default();
            let top_ctx = AnalysisContext {
                file_path: &rel_file,
                scope: "<top_level>",
                function_resolver: &function_resolver,
                cfg: Some(&top_cfg),
            };

            self.analyze_statement_block(
                &file_node.statements,
                &top_ctx,
                &mut top_env,
                &mut queue,
                &mut flows,
            );
        }

        // 2. Interprocedural Propagation Pass (traverse queued cross-function calls)
        let max_hops = 12;
        let mut hops = 0;

        while let Some(ctx) = queue.pop_front() {
            hops += 1;
            if hops > max_hops * 100 {
                break;
            }

            let origin = ctx
                .steps
                .first()
                .map(|s| format!("{}:{}", s.file, s.symbol))
                .unwrap_or_default();
            let ctx_key = format!(
                "{}:{}:{}:{:?}",
                origin, ctx.target_func_qname, ctx.param_index, ctx.taint_kind
            );
            if !visited_contexts.insert(ctx_key) {
                continue;
            }

            // Find the target function definition
            if let Some(func_sym) = self
                .project_model
                .symbol_table
                .lookup_function(&ctx.target_func_qname)
            {
                if let Some(target_file_node) = self.find_file_node(&func_sym.file_path) {
                    if let Some(target_func) = target_file_node
                        .functions
                        .iter()
                        .find(|f| f.name == func_sym.name)
                    {
                        if ctx.param_index < target_func.params.len() {
                            let param_name = &target_func.params[ctx.param_index];
                            let mut local_taints: HashMap<String, TaintedVariable> = HashMap::new();

                            let mut current_steps = ctx.steps.clone();
                            current_steps.push(TaintStep {
                                file: func_sym.file_path.clone(),
                                line: target_func.line,
                                symbol: param_name.clone(),
                                step_type: TaintStepType::FunctionParameter,
                                snippet: format!("{}: param {}", target_func.name, param_name),
                                description: format!(
                                    "Taint propagated across boundary into parameter '{}'",
                                    param_name
                                ),
                            });

                            let mut taints = HashSet::new();
                            taints.insert(ctx.taint_kind);

                            local_taints.insert(
                                param_name.clone(),
                                TaintedVariable {
                                    name: param_name.clone(),
                                    scope: target_func.name.clone(),
                                    file: func_sym.file_path.clone(),
                                    line: target_func.line,
                                    taints,
                                    sanitized_for: HashSet::new(),
                                    steps: current_steps,
                                },
                            );

                            let target_cfg =
                                ControlFlowGraph::build_from_statements(&target_func.body);
                            let mut target_env = LocalEnv {
                                taints: local_taints,
                                type_env: TypeEnvironment::new(),
                                const_env: ConstantEnvironment::new(),
                            };

                            let block_ctx = AnalysisContext {
                                file_path: &func_sym.file_path,
                                scope: &target_func.name,
                                function_resolver: &function_resolver,
                                cfg: Some(&target_cfg),
                            };

                            self.analyze_statement_block(
                                &target_func.body,
                                &block_ctx,
                                &mut target_env,
                                &mut queue,
                                &mut flows,
                            );
                        }
                    }
                }
            }
        }

        flows
    }

    fn analyze_statement_block(
        &self,
        stmts: &[StmtNode],
        ctx: &AnalysisContext,
        env: &mut LocalEnv,
        queue: &mut VecDeque<InterproceduralContext>,
        flows: &mut Vec<TaintFlow>,
    ) {
        for stmt in stmts {
            match stmt {
                StmtNode::Assignment(assign) => {
                    let target_name = assign.target.to_source_string();
                    let val_expr = assign.value.to_source_string();

                    // Update constant and type environments
                    let const_val = env.const_env.eval_expr(&assign.value);
                    env.const_env.set_constant(&target_name, const_val);

                    let inferred_ty = env.type_env.infer_expr(&assign.value);
                    env.type_env.set_type(&target_name, inferred_ty);

                    // Track string propagation
                    let string_trans = StringPropagator::analyze(&assign.value, &env.taints);

                    // Check if assigned from direct untrusted source
                    if SourceModel::is_untrusted_source(&val_expr) {
                        let mut initial_taints = HashSet::new();
                        let mut initial_sanitized = HashSet::new();

                        for k in TaintKind::all() {
                            if inferred_ty.is_safe_for_taint_kind(k) {
                                initial_sanitized.insert(k);
                            } else {
                                initial_taints.insert(k);
                            }
                        }

                        let step = TaintStep {
                            file: ctx.file_path.to_string(),
                            line: assign.line,
                            symbol: target_name.clone(),
                            step_type: TaintStepType::Source,
                            snippet: format!("{} = {}", target_name, val_expr),
                            description: "External request source assigned to variable".to_string(),
                        };

                        env.taints.insert(
                            target_name.clone(),
                            TaintedVariable {
                                name: target_name.clone(),
                                scope: ctx.scope.to_string(),
                                file: ctx.file_path.to_string(),
                                line: assign.line,
                                taints: initial_taints,
                                sanitized_for: initial_sanitized,
                                steps: vec![step],
                            },
                        );
                    } else {
                        // Check if assigned from an existing tainted variable or string transformation
                        let referenced_vars = extract_variable_names(&assign.value);
                        let mut matched_parent: Option<TaintedVariable> = None;

                        for ref_var in &referenced_vars {
                            if let Some(parent_tainted) = env.taints.get(ref_var) {
                                matched_parent = Some(parent_tainted.clone());
                                break;
                            }
                        }

                        if matched_parent.is_none() && string_trans.is_tainted() {
                            let kinds = string_trans.collect_taints();
                            if !kinds.is_empty() {
                                matched_parent = Some(TaintedVariable {
                                    name: target_name.clone(),
                                    scope: ctx.scope.to_string(),
                                    file: ctx.file_path.to_string(),
                                    line: assign.line,
                                    taints: kinds,
                                    sanitized_for: HashSet::new(),
                                    steps: Vec::new(),
                                });
                            }
                        }

                        if let Some(parent_tainted) = matched_parent {
                            let (sanitized, _used_sanitizer) =
                                SanitizerModel::sanitized_kinds(&val_expr);

                            let mut remaining_taints = parent_tainted.taints.clone();
                            let mut newly_sanitized = parent_tainted.sanitized_for.clone();

                            for s in &sanitized {
                                remaining_taints.remove(s);
                                newly_sanitized.insert(*s);
                            }

                            // Type-based sanitization
                            for k in TaintKind::all() {
                                if inferred_ty.is_safe_for_taint_kind(k) {
                                    remaining_taints.remove(&k);
                                    newly_sanitized.insert(k);
                                }
                            }

                            if !remaining_taints.is_empty() {
                                let mut new_steps = parent_tainted.steps.clone();
                                new_steps.push(TaintStep {
                                    file: ctx.file_path.to_string(),
                                    line: assign.line,
                                    symbol: target_name.clone(),
                                    step_type: TaintStepType::Transformation,
                                    snippet: format!("{} = {}", target_name, val_expr),
                                    description:
                                        "Variable transformed, concatenated or string-propagated"
                                            .to_string(),
                                });

                                env.taints.insert(
                                    target_name.clone(),
                                    TaintedVariable {
                                        name: target_name.clone(),
                                        scope: ctx.scope.to_string(),
                                        file: ctx.file_path.to_string(),
                                        line: assign.line,
                                        taints: remaining_taints,
                                        sanitized_for: newly_sanitized,
                                        steps: new_steps,
                                    },
                                );
                            }
                        }
                    }

                    // Check calls within assignment expression (e.g. `res = db.execute(q)`)
                    self.inspect_calls_in_expr(&assign.value, ctx, env, queue, flows);
                }
                StmtNode::Call(call_expr) => {
                    self.inspect_calls_in_expr(call_expr, ctx, env, queue, flows);
                }
                StmtNode::Return(ret) => {
                    if let Some(val) = &ret.value {
                        self.inspect_calls_in_expr(val, ctx, env, queue, flows);
                    }
                }
                StmtNode::Condition(c) => {
                    self.inspect_calls_in_expr(&c.test, ctx, env, queue, flows);
                    let test_str = c.test.to_source_string();
                    let is_allowlist_guard = test_str.contains("ALLOWED_")
                        || test_str.contains("allowlist")
                        || test_str.contains("whitelist")
                        || test_str.contains(".is_safe_host");

                    if is_allowlist_guard {
                        let mut guarded_env = env.clone();
                        for var in guarded_env.taints.values_mut() {
                            var.taints.remove(&TaintKind::Ssrf);
                            var.sanitized_for.insert(TaintKind::Ssrf);
                        }
                        self.analyze_statement_block(&c.then_body, ctx, &mut guarded_env, queue, flows);
                        self.analyze_statement_block(&c.else_body, ctx, env, queue, flows);
                    } else {
                        self.analyze_statement_block(&c.then_body, ctx, env, queue, flows);
                        self.analyze_statement_block(&c.else_body, ctx, env, queue, flows);
                    }
                }
                StmtNode::Loop(l) => {
                    if let Some(cond) = &l.condition {
                        self.inspect_calls_in_expr(cond, ctx, env, queue, flows);
                    }
                    self.analyze_statement_block(&l.body, ctx, env, queue, flows);
                }
                StmtNode::TryCatch(t) => {
                    self.analyze_statement_block(&t.try_body, ctx, env, queue, flows);
                    self.analyze_statement_block(&t.catch_body, ctx, env, queue, flows);
                    self.analyze_statement_block(&t.finally_body, ctx, env, queue, flows);
                }
                StmtNode::Expression(e) => {
                    self.inspect_calls_in_expr(e, ctx, env, queue, flows);
                }
            }
        }
    }

    fn inspect_calls_in_expr(
        &self,
        expr: &ExprNode,
        ctx: &AnalysisContext,
        env: &mut LocalEnv,
        queue: &mut VecDeque<InterproceduralContext>,
        flows: &mut Vec<TaintFlow>,
    ) {
        match expr {
            ExprNode::Call { callee, args, line } => {
                let callee_str = callee.to_source_string();

                // 1. Check if callee is a known vulnerability sink
                if let Some((sink_kind, _)) = SinkModel::classify_sink(&callee_str) {
                    if callee_str == "exec.Command" || callee_str == "exec.CommandContext" {
                        if let Some(first_arg) = args.first() {
                            let arg_s = first_arg.to_source_string();
                            let clean_arg = arg_s.trim_matches(|c| c == '"' || c == '\'');
                            if clean_arg == "git"
                                || clean_arg == "go"
                                || clean_arg == "cargo"
                                || clean_arg == "scannerExe"
                            {
                                return;
                            }
                        }
                    }

                    // For SQL sinks, only the primary query argument (args[0]) is the query sink.
                    // Subsequent arguments (args[1..]) are safe bind parameters.
                    let sink_args: Vec<&ExprNode> = if sink_kind == TaintKind::Sql {
                        if let Some(first) = args.first() {
                            vec![first]
                        } else {
                            Vec::new()
                        }
                    } else {
                        args.iter().collect()
                    };

                    for arg in sink_args {
                        // 1.1 Constant Analysis: If argument is compile-time constant, safe!
                        if env.const_env.is_constant_sink_argument(arg) {
                            continue;
                        }

                        // 1.2 Type Analysis: If argument type is safe against this sink kind, safe!
                        let arg_type = env.type_env.infer_expr(arg);
                        if arg_type.is_safe_for_taint_kind(sink_kind) {
                            continue;
                        }

                        let arg_vars = extract_variable_names(arg);
                        for var in &arg_vars {
                            if let Some(tainted_var) = env.taints.get(var) {
                                if tainted_var.taints.contains(&sink_kind) {
                                    // 1.3 CFG Reachability Check
                                    if let Some(cfg) = ctx.cfg {
                                        if !cfg.can_flow_to_sink(tainted_var.line, *line) {
                                            continue;
                                        }
                                    }

                                    // SINK REACHED with active, unsanitized vulnerability-specific taint!
                                    let mut final_steps = tainted_var.steps.clone();
                                    final_steps.push(TaintStep {
                                        file: ctx.file_path.to_string(),
                                        line: *line,
                                        symbol: callee_str.clone(),
                                        step_type: TaintStepType::Sink,
                                        snippet: format!("{}({})", callee_str, arg.to_source_string()),
                                        description: format!(
                                            "Tainted data consumed by {} sink without valid {} sanitization",
                                            sink_kind.name(),
                                            sink_kind.name()
                                        ),
                                    });

                                    let first_step = final_steps.first().unwrap();
                                    let crosses =
                                        final_steps.iter().any(|s| s.file != first_step.file);

                                    flows.push(TaintFlow {
                                        kind: sink_kind,
                                        source_file: first_step.file.clone(),
                                        source_line: first_step.line,
                                        source_symbol: first_step.symbol.clone(),
                                        sink_file: ctx.file_path.to_string(),
                                        sink_line: *line,
                                        sink_symbol: callee_str.clone(),
                                        steps: final_steps,
                                        is_sanitized: false,
                                        sanitizer_name: None,
                                        crosses_files: crosses,
                                        call_depth: env.taints.len(),
                                    });
                                }
                            }
                        }
                    }
                } else {
                    // 2. Check if callee is a project function call (interprocedural call hop)
                    if let Some(resolved) =
                        ctx.function_resolver
                            .resolve(ctx.file_path, Some(ctx.scope), &callee_str)
                    {
                        for (idx, arg) in args.iter().enumerate() {
                            let arg_vars = extract_variable_names(arg);
                            for var in &arg_vars {
                                if let Some(tainted_var) = env.taints.get(var) {
                                    for &k in &tainted_var.taints {
                                        let mut call_steps = tainted_var.steps.clone();
                                        call_steps.push(TaintStep {
                                            file: ctx.file_path.to_string(),
                                            line: *line,
                                            symbol: callee_str.clone(),
                                            step_type: TaintStepType::FunctionCall,
                                            snippet: format!(
                                                "{}({})",
                                                callee_str,
                                                arg.to_source_string()
                                            ),
                                            description: format!(
                                                "Passing tainted argument '{}' to function '{}'",
                                                var, resolved.name
                                            ),
                                        });

                                        if resolved.file_path != ctx.file_path {
                                            call_steps.push(TaintStep {
                                                file: resolved.file_path.clone(),
                                                line: resolved.line,
                                                symbol: resolved.file_path.clone(),
                                                step_type: TaintStepType::AnotherFile,
                                                snippet: format!("module {}", resolved.file_path),
                                                description: format!(
                                                    "Execution crosses into another file: {}",
                                                    resolved.file_path
                                                ),
                                            });
                                        }

                                        queue.push_back(InterproceduralContext {
                                            target_func_qname: resolved.qualified_name.clone(),
                                            target_file: resolved.file_path.clone(),
                                            param_index: idx,
                                            taint_kind: k,
                                            steps: call_steps,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // Recurse into nested calls
                self.inspect_calls_in_expr(callee, ctx, env, queue, flows);
                for a in args {
                    self.inspect_calls_in_expr(a, ctx, env, queue, flows);
                }
            }
            ExprNode::BinaryOp { left, right, .. } => {
                self.inspect_calls_in_expr(left, ctx, env, queue, flows);
                self.inspect_calls_in_expr(right, ctx, env, queue, flows);
            }
            ExprNode::Attribute { value, .. } => {
                self.inspect_calls_in_expr(value, ctx, env, queue, flows);
            }
            ExprNode::Subscript { value, slice, .. } => {
                self.inspect_calls_in_expr(value, ctx, env, queue, flows);
                self.inspect_calls_in_expr(slice, ctx, env, queue, flows);
            }
            ExprNode::FormattedString { parts, .. } => {
                for p in parts {
                    self.inspect_calls_in_expr(p, ctx, env, queue, flows);
                }
            }
            _ => {}
        }
    }

    fn find_file_node(&self, file_path: &str) -> Option<&FileNode> {
        let norm = self
            .project_model
            .module_resolver
            .normalize_file_path(file_path);
        for (path, node) in self.parsed_files {
            let n = self.project_model.module_resolver.normalize_file_path(path);
            if n == norm || path.ends_with(&norm) || norm.ends_with(path) {
                return Some(node);
            }
        }
        None
    }
}

fn extract_variable_names(expr: &ExprNode) -> Vec<String> {
    let mut vars = Vec::new();
    match expr {
        ExprNode::Identifier { name, .. } => {
            vars.push(name.clone());
        }
        ExprNode::Attribute { value, attr, .. } => {
            vars.push(format!("{}.{}", value.to_source_string(), attr));
            vars.extend(extract_variable_names(value));
        }
        ExprNode::Subscript { value, slice, .. } => {
            vars.extend(extract_variable_names(value));
            vars.extend(extract_variable_names(slice));
        }
        ExprNode::BinaryOp { left, right, .. } => {
            vars.extend(extract_variable_names(left));
            vars.extend(extract_variable_names(right));
        }
        ExprNode::FormattedString { parts, .. } => {
            for p in parts {
                vars.extend(extract_variable_names(p));
            }
        }
        ExprNode::Call { callee, args, .. } => {
            vars.extend(extract_variable_names(callee));
            for a in args {
                vars.extend(extract_variable_names(a));
            }
        }
        _ => {}
    }
    vars
}

fn is_api_entrypoint(name: &str, file: &str) -> bool {
    let lower_name = name.to_lowercase();
    let lower_file = file.to_lowercase();

    lower_file.contains("routes")
        || lower_file.contains("route")
        || lower_file.contains("views")
        || lower_file.contains("view")
        || lower_file.contains("controllers")
        || lower_file.contains("controller")
        || lower_file.contains("api")
        || lower_file.contains("endpoints")
        || lower_file.contains("endpoint")
        || lower_file.contains("handlers")
        || lower_file.contains("handler")
        || lower_file.contains("app.py")
        || lower_file.contains("main.py")
        || lower_file.contains("server.")
        || lower_file.contains("index.")
        || lower_name.starts_with("handle_")
        || lower_name.starts_with("get_")
        || lower_name.starts_with("post_")
        || lower_name.starts_with("put_")
        || lower_name.starts_with("delete_")
        || lower_name.starts_with("patch_")
        || lower_name == "main"
        || lower_name == "handler"
}
