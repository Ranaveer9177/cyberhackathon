#![allow(dead_code)]

use crate::ast::types::{ConstantKind, ExprNode};
use crate::taint::types::TaintKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InferredType {
    String,
    Integer,
    Boolean,
    List,
    Map,
    Object,
    Bytes,
    Unknown,
}

impl InferredType {
    pub fn name(&self) -> &'static str {
        match self {
            InferredType::String => "string",
            InferredType::Integer => "integer",
            InferredType::Boolean => "boolean",
            InferredType::List => "list",
            InferredType::Map => "map",
            InferredType::Object => "object",
            InferredType::Bytes => "bytes",
            InferredType::Unknown => "unknown",
        }
    }

    /// Returns true if this type cannot carry arbitrary injection payloads
    /// (e.g. SQL Injection, Command Injection, Path Traversal, Template Injection)
    pub fn is_safe_for_taint_kind(&self, kind: TaintKind) -> bool {
        match kind {
            TaintKind::Sql
            | TaintKind::Command
            | TaintKind::Path
            | TaintKind::Template
            | TaintKind::Xss => matches!(self, InferredType::Integer | InferredType::Boolean),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeEnvironment {
    pub variables: HashMap<String, InferredType>,
}

impl TypeEnvironment {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    pub fn set_type(&mut self, var: &str, ty: InferredType) {
        self.variables.insert(var.to_string(), ty);
    }

    pub fn get_type(&self, var: &str) -> InferredType {
        self.variables
            .get(var)
            .copied()
            .unwrap_or(InferredType::Unknown)
    }

    /// Infer the type of an expression in the current environment
    pub fn infer_expr(&self, expr: &ExprNode) -> InferredType {
        match expr {
            ExprNode::Constant { kind, .. } => match kind {
                ConstantKind::String(_) => InferredType::String,
                ConstantKind::Integer(_) => InferredType::Integer,
                ConstantKind::Float(_) => InferredType::Integer,
                ConstantKind::Boolean(_) => InferredType::Boolean,
                ConstantKind::Null => InferredType::Unknown,
            },
            ExprNode::Identifier { name, .. } => self.get_type(name),
            ExprNode::FormattedString { .. } => InferredType::String,
            ExprNode::List { .. } => InferredType::List,
            ExprNode::BinaryOp {
                op, left, right, ..
            } => {
                let left_ty = self.infer_expr(left);
                let right_ty = self.infer_expr(right);

                match op.as_str() {
                    "==" | "!=" | "<" | "<=" | ">" | ">=" | "and" | "or" | "&&" | "||" | "in"
                    | "not in" => InferredType::Boolean,
                    "+" => {
                        if left_ty == InferredType::String || right_ty == InferredType::String {
                            InferredType::String
                        } else if left_ty == InferredType::List || right_ty == InferredType::List {
                            InferredType::List
                        } else if left_ty == InferredType::Integer
                            && right_ty == InferredType::Integer
                        {
                            InferredType::Integer
                        } else {
                            InferredType::Unknown
                        }
                    }
                    "-" | "*" | "/" | "//" | "%" | "**" | "&" | "|" | "^" | "<<" | ">>" => {
                        InferredType::Integer
                    }
                    _ => InferredType::Unknown,
                }
            }
            ExprNode::Call { callee, args, .. } => {
                let callee_name = callee.to_source_string();
                Self::infer_call_type(&callee_name, args, self)
            }
            ExprNode::Attribute { attr, .. } => match attr.as_str() {
                "encode" => InferredType::Bytes,
                "decode" => InferredType::String,
                _ => InferredType::Unknown,
            },
            ExprNode::Subscript { .. } => InferredType::Unknown,
            ExprNode::Unknown { raw, .. } => Self::infer_from_raw_code(raw),
        }
    }

    fn infer_call_type(callee: &str, args: &[ExprNode], env: &TypeEnvironment) -> InferredType {
        let clean = callee.trim();

        // Integer conversions
        if clean == "int"
            || clean == "parseInt"
            || clean.ends_with(".parseInt")
            || clean == "strconv.Atoi"
            || clean == "Math.floor"
            || clean == "Math.round"
            || clean == "len"
            || clean == "count"
        {
            return InferredType::Integer;
        }

        // Boolean conversions
        if clean == "bool" || clean == "Boolean" || clean == "isinstance" || clean == "hasattr" {
            return InferredType::Boolean;
        }

        // String conversions
        if clean == "str"
            || clean == "String"
            || clean.ends_with(".toString")
            || clean == "fmt.Sprintf"
            || clean.ends_with(".format")
            || clean.ends_with(".replace")
            || clean.ends_with(".join")
        {
            return InferredType::String;
        }

        // Bytes conversions
        if clean == "bytes" || clean.ends_with(".encode") || clean == "[]byte" {
            return InferredType::Bytes;
        }

        // List conversions
        if clean == "list"
            || clean == "Array"
            || clean.ends_with(".split")
            || clean.ends_with(".findall")
        {
            return InferredType::List;
        }

        // Map conversions
        if clean == "dict" || clean == "Map" || clean == "json.loads" {
            return InferredType::Map;
        }

        if let Some(first_arg) = args.first() {
            env.infer_expr(first_arg)
        } else {
            InferredType::Unknown
        }
    }

    pub fn infer_from_raw_code(raw: &str) -> InferredType {
        let trimmed = raw.trim();

        if (trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || trimmed.starts_with("f\"")
            || trimmed.starts_with("f'")
        {
            return InferredType::String;
        }

        if (trimmed.starts_with("b\"") && trimmed.ends_with('"'))
            || (trimmed.starts_with("b'") && trimmed.ends_with('\''))
        {
            return InferredType::Bytes;
        }

        if trimmed == "True" || trimmed == "False" || trimmed == "true" || trimmed == "false" {
            return InferredType::Boolean;
        }

        if trimmed.parse::<i64>().is_ok() {
            return InferredType::Integer;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return InferredType::List;
        }

        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return InferredType::Map;
        }

        if trimmed.starts_with("int(")
            || trimmed.starts_with("parseInt(")
            || trimmed.contains(".parseInt(")
            || trimmed.starts_with("strconv.Atoi(")
        {
            return InferredType::Integer;
        }

        if trimmed.starts_with("str(")
            || trimmed.starts_with("String(")
            || trimmed.contains(".format(")
            || trimmed.contains(".replace(")
        {
            return InferredType::String;
        }

        if trimmed.starts_with("bool(") || trimmed.starts_with("Boolean(") {
            return InferredType::Boolean;
        }

        if trimmed.contains(".encode(") {
            return InferredType::Bytes;
        }

        if trimmed.contains(".decode(") {
            return InferredType::String;
        }

        InferredType::Unknown
    }
}
