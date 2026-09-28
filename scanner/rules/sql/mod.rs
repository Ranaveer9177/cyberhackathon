#![allow(dead_code)]

use crate::analysis::constants::ConstantEnvironment;
use crate::analysis::types::{InferredType, TypeEnvironment};
use crate::ast::types::{ExprNode, FileNode, StmtNode};
use crate::taint::sources::SourceModel;
use crate::types::{Category, Finding, Severity};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlConstructionKind {
    Concatenation,
    FString,
    FormatCall,
    RawSql,
    OrmRawQuery,
    DynamicIdentifier,
    UnsafeQueryBuilder,
}

impl SqlConstructionKind {
    pub fn description(&self) -> &'static str {
        match self {
            SqlConstructionKind::Concatenation => "Dynamic string concatenation in SQL query",
            SqlConstructionKind::FString => "Interpolated f-string in SQL query construction",
            SqlConstructionKind::FormatCall => "String format() call constructing SQL statement",
            SqlConstructionKind::RawSql => "Unparameterized raw SQL execution",
            SqlConstructionKind::OrmRawQuery => "Unparameterized ORM raw query escape hatch",
            SqlConstructionKind::DynamicIdentifier => {
                "Dynamic table/column identifier in SQL query (cannot be parameterized via bind variables)"
            }
            SqlConstructionKind::UnsafeQueryBuilder => {
                "Unsafe raw clause in query builder (whereRaw/havingRaw)"
            }
        }
    }
}

pub struct SqlRuleEngine<'a> {
    pub file_node: &'a FileNode,
    pub var_types: &'a TypeEnvironment,
    pub constants: &'a ConstantEnvironment,
}

impl<'a> SqlRuleEngine<'a> {
    pub fn new(
        file_node: &'a FileNode,
        var_types: &'a TypeEnvironment,
        constants: &'a ConstantEnvironment,
    ) -> Self {
        Self {
            file_node,
            var_types,
            constants,
        }
    }

    pub fn analyze(&self, finding_counter: &mut usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Analyze functions
        for func in &self.file_node.functions {
            let mut local_vars = HashMap::new();
            for param in &func.params {
                if SourceModel::is_untrusted_parameter_name(param) {
                    local_vars.insert(param.clone(), param.clone());
                }
            }
            self.analyze_block(&func.body, &mut local_vars, finding_counter, &mut findings);
        }

        // 2. Analyze top-level statements
        let mut top_vars = HashMap::new();
        self.analyze_block(
            &self.file_node.statements,
            &mut top_vars,
            finding_counter,
            &mut findings,
        );

        findings
    }

    fn analyze_block(
        &self,
        stmts: &[StmtNode],
        vars: &mut HashMap<String, String>,
        finding_counter: &mut usize,
        findings: &mut Vec<Finding>,
    ) {
        let mut returned = false;
        for stmt in stmts {
            if returned {
                break;
            }
            match stmt {
                StmtNode::Assignment(assign) => {
                    let target = assign.target.to_source_string();
                    let val_str = assign.value.to_source_string();

                    // Check if variable is built from untrusted source
                    if SourceModel::is_untrusted_source(&val_str) {
                        vars.insert(target.clone(), target.clone());
                    }

                    // Check if assignment builds dynamic SQL
                    if let Some(kind) = self.classify_sql_construction(&assign.value, vars) {
                        vars.insert(target.clone(), format!("sql:{}", target));

                        // Check if this assignment directly calls a sink
                        self.check_expr_sinks(
                            &assign.value,
                            Some(kind),
                            assign.line,
                            finding_counter,
                            findings,
                        );
                    } else if let Some(parent) = vars.get(&val_str).cloned() {
                        vars.insert(target.clone(), parent);
                    }

                    self.check_expr_sinks(
                        &assign.value,
                        None,
                        assign.line,
                        finding_counter,
                        findings,
                    );
                }
                StmtNode::Call(expr) => {
                    self.check_expr_sinks(expr, None, expr.line(), finding_counter, findings);
                }
                StmtNode::Return(ret) => {
                    if let Some(val) = &ret.value {
                        self.check_expr_sinks(val, None, ret.line, finding_counter, findings);
                    }
                    returned = true;
                }
                StmtNode::Condition(c) => {
                    self.check_expr_sinks(&c.test, None, c.line, finding_counter, findings);
                    self.analyze_block(&c.then_body, vars, finding_counter, findings);
                    self.analyze_block(&c.else_body, vars, finding_counter, findings);
                }
                StmtNode::Loop(l) => {
                    if let Some(cond) = &l.condition {
                        self.check_expr_sinks(cond, None, l.line, finding_counter, findings);
                    }
                    self.analyze_block(&l.body, vars, finding_counter, findings);
                }
                StmtNode::TryCatch(t) => {
                    self.analyze_block(&t.try_body, vars, finding_counter, findings);
                    self.analyze_block(&t.catch_body, vars, finding_counter, findings);
                    self.analyze_block(&t.finally_body, vars, finding_counter, findings);
                }
                StmtNode::Expression(e) => {
                    self.check_expr_sinks(e, None, e.line(), finding_counter, findings);
                }
            }
        }
    }

    fn classify_sql_construction(
        &self,
        expr: &ExprNode,
        _vars: &HashMap<String, String>,
    ) -> Option<SqlConstructionKind> {
        let text = expr.to_source_string();
        let upper = text.to_uppercase();

        let is_sql_keyword = upper.contains("SELECT ")
            || upper.contains("INSERT INTO ")
            || upper.contains("UPDATE ")
            || upper.contains("DELETE FROM ")
            || upper.contains("WHERE ")
            || upper.contains("ORDER BY ")
            || upper.contains("GROUP BY ");

        if !is_sql_keyword {
            return None;
        }

        // 1. Dynamic Table/Column Identifiers: e.g. ORDER BY {col} or FROM {table}
        if (upper.contains("ORDER BY") || upper.contains("GROUP BY") || upper.contains("FROM {"))
            && (text.contains('{') || text.contains('+') || text.contains("%s"))
        {
            return Some(SqlConstructionKind::DynamicIdentifier);
        }

        // 2. F-String interpolation: f"SELECT ... {user}"
        if let ExprNode::FormattedString { parts, .. } = expr {
            // Check if interpolated parts are constants or safe integers
            let has_dynamic_unsafe = parts.iter().any(|p| {
                let ty = self.var_types.infer_expr(p);
                let is_const = self.constants.eval_expr(p).is_constant();
                !is_const && ty != InferredType::Integer && ty != InferredType::Boolean
            });
            if has_dynamic_unsafe {
                return Some(SqlConstructionKind::FString);
            }
        }

        // 3. String concatenation: "SELECT ... " + id
        if let ExprNode::BinaryOp {
            op, left, right, ..
        } = expr
        {
            if op == "+" {
                let left_ty = self.var_types.infer_expr(left);
                let right_ty = self.var_types.infer_expr(right);
                let left_const = self.constants.eval_expr(left).is_constant();
                let right_const = self.constants.eval_expr(right).is_constant();

                let unsafe_dynamic = (!left_const
                    && left_ty != InferredType::Integer
                    && left_ty != InferredType::Boolean)
                    || (!right_const
                        && right_ty != InferredType::Integer
                        && right_ty != InferredType::Boolean);

                if unsafe_dynamic {
                    return Some(SqlConstructionKind::Concatenation);
                }
            }
        }

        // 4. String format() or %: "...".format(id)
        if let ExprNode::Call { callee, args, .. } = expr {
            let callee_str = callee.to_source_string();
            if callee_str.ends_with(".format") || callee_str == "fmt.Sprintf" {
                let has_dynamic = args.iter().any(|a| {
                    let ty = self.var_types.infer_expr(a);
                    let is_const = self.constants.eval_expr(a).is_constant();
                    !is_const && ty != InferredType::Integer && ty != InferredType::Boolean
                });
                if has_dynamic {
                    return Some(SqlConstructionKind::FormatCall);
                }
            }
        }

        // 5. Query builder raw clauses: knex.whereRaw(...), query.havingRaw(...)
        if text.contains("whereRaw(")
            || text.contains("havingRaw(")
            || text.contains(".Where(fmt.Sprintf(")
        {
            return Some(SqlConstructionKind::UnsafeQueryBuilder);
        }

        // 6. ORM Raw queries: Model.objects.raw(...), session.execute(text(...)), $queryRaw(...)
        if text.contains(".raw(")
            || text.contains(".extra(")
            || text.contains("text(")
            || text.contains("$queryRaw(")
            || text.contains("$executeRaw(")
            || text.contains("db.Raw(")
        {
            return Some(SqlConstructionKind::OrmRawQuery);
        }

        None
    }

    fn check_expr_sinks(
        &self,
        expr: &ExprNode,
        known_kind: Option<SqlConstructionKind>,
        line: usize,
        finding_counter: &mut usize,
        findings: &mut Vec<Finding>,
    ) {
        if let ExprNode::Call { callee, args, .. } = expr {
            let callee_str = callee.to_source_string();

            // Sinks: raw execute, query, etc.
            let is_sql_sink = callee_str.ends_with(".execute")
                || callee_str.ends_with(".exec")
                || callee_str.ends_with(".query")
                || callee_str.ends_with(".Query")
                || callee_str.ends_with(".QueryRow")
                || callee_str.ends_with(".executeQuery")
                || callee_str.ends_with(".executeUpdate")
                || callee_str.ends_with(".raw")
                || callee_str.ends_with(".Raw")
                || callee_str.ends_with("$queryRaw")
                || callee_str.ends_with("$executeRaw");

            if is_sql_sink {
                // Check if properly parameterized:
                // e.g. cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
                // In Python/Go/Java, args.len() >= 2 where arg[0] has placeholders and arg[1] is params tuple/array
                let is_parameterized = args.len() >= 2 && {
                    let first_arg_const = self.constants.eval_expr(&args[0]).is_constant();
                    let first_arg_src = args[0].to_source_string();
                    first_arg_const
                        && (first_arg_src.contains('?')
                            || first_arg_src.contains("%s")
                            || first_arg_src.contains("$1")
                            || first_arg_src.contains(':'))
                };

                if is_parameterized {
                    // Safe parameterized query!
                    return;
                }

                // Check query argument
                if let Some(first_arg) = args.first() {
                    // 1. If compile-time constant, safe!
                    if self.constants.eval_expr(first_arg).is_constant() {
                        return;
                    }

                    // 2. If integer or boolean type, safe!
                    let ty = self.var_types.infer_expr(first_arg);
                    if ty == InferredType::Integer || ty == InferredType::Boolean {
                        return;
                    }

                    // 3. If formatted string interpolating only constants, integers or booleans: safe!
                    if let ExprNode::FormattedString { parts, .. } = first_arg {
                        let all_safe = parts.iter().all(|p| {
                            let p_ty = self.var_types.infer_expr(p);
                            self.constants.eval_expr(p).is_constant()
                                || p_ty == InferredType::Integer
                                || p_ty == InferredType::Boolean
                        });
                        if all_safe {
                            return;
                        }
                    }

                    let kind = known_kind.unwrap_or(SqlConstructionKind::RawSql);
                    *finding_counter += 1;
                    let fid = format!("VG-{:03}", *finding_counter);
                    let snippet = expr.to_source_string();

                    findings.push(Finding {
                        id: fid,
                        rule_id: Some("VG-SQL-001".to_string()),
                        category: Category::SourceCode,
                        severity: Severity::CRITICAL,
                        title: format!("SQL Injection: {}", kind.description()),
                        description: format!(
                            "Semantic SQL injection detected in call to '{}'. Query is constructed dynamically without secure bind parameterization.",
                            callee_str
                        ),
                        file: self.file_node.file_path.clone(),
                        line,
                        column: Some(1),
                        evidence: Some(snippet),
                        recommendation: Some(
                            "Use parameterized queries with bind variables (e.g. '?', '%s', or ':param'), or typecast numeric inputs using int(). Avoid raw string interpolation in queries.".to_string(),
                        ),
                        confidence: "HIGH".to_string(),
                        source: Some(callee_str.clone()),
                        sink: Some(format!("{}:{}", self.file_node.file_path, line)),
                        data_flow: Some(vec![format!("{}: {}", line, expr.to_source_string())]),
                        cwe: Some("CWE-89".to_string()),
                        fingerprint: Some(format!("VG-SQL-001:{}:{}:{}", self.file_node.file_path, line, callee_str)),
                    });
                }
            }
        }
    }
}
