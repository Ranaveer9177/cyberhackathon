#![allow(dead_code)]

use crate::ast::types::{ConstantKind, ExprNode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstantValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    NonConstant,
}

impl ConstantValue {
    pub fn is_constant(&self) -> bool {
        !matches!(self, ConstantValue::NonConstant)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            ConstantValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstantEnvironment {
    pub constants: HashMap<String, ConstantValue>,
}

impl ConstantEnvironment {
    pub fn new() -> Self {
        Self {
            constants: HashMap::new(),
        }
    }

    pub fn set_constant(&mut self, var_name: &str, val: ConstantValue) {
        self.constants.insert(var_name.to_string(), val);
    }

    pub fn get_constant(&self, var_name: &str) -> ConstantValue {
        self.constants
            .get(var_name)
            .cloned()
            .unwrap_or(ConstantValue::NonConstant)
    }

    pub fn is_known_constant(&self, var_name: &str) -> bool {
        matches!(
            self.constants.get(var_name),
            Some(ConstantValue::String(_))
                | Some(ConstantValue::Integer(_))
                | Some(ConstantValue::Boolean(_))
        )
    }

    /// Evaluates an expression down to a compile-time constant if possible.
    pub fn eval_expr(&self, expr: &ExprNode) -> ConstantValue {
        match expr {
            ExprNode::Constant { kind, .. } => match kind {
                ConstantKind::String(s) => ConstantValue::String(s.clone()),
                ConstantKind::Integer(i) => ConstantValue::Integer(*i),
                ConstantKind::Boolean(b) => ConstantValue::Boolean(*b),
                _ => ConstantValue::NonConstant,
            },
            ExprNode::Identifier { name, .. } => self.get_constant(name),
            ExprNode::BinaryOp {
                op, left, right, ..
            } => {
                let left_val = self.eval_expr(left);
                let right_val = self.eval_expr(right);

                match (op.as_str(), left_val, right_val) {
                    ("+", ConstantValue::String(l), ConstantValue::String(r)) => {
                        ConstantValue::String(format!("{}{}", l, r))
                    }
                    ("+", ConstantValue::Integer(l), ConstantValue::Integer(r)) => {
                        ConstantValue::Integer(l + r)
                    }
                    ("-", ConstantValue::Integer(l), ConstantValue::Integer(r)) => {
                        ConstantValue::Integer(l - r)
                    }
                    ("*", ConstantValue::Integer(l), ConstantValue::Integer(r)) => {
                        ConstantValue::Integer(l * r)
                    }
                    _ => ConstantValue::NonConstant,
                }
            }
            ExprNode::FormattedString { parts, .. } => {
                let mut accumulated = String::new();
                for part in parts {
                    match self.eval_expr(part) {
                        ConstantValue::String(s) => accumulated.push_str(&s),
                        ConstantValue::Integer(i) => accumulated.push_str(&i.to_string()),
                        ConstantValue::Boolean(b) => accumulated.push_str(&b.to_string()),
                        ConstantValue::NonConstant => return ConstantValue::NonConstant,
                    }
                }
                ConstantValue::String(accumulated)
            }
            ExprNode::Call { callee, args, .. } => {
                let callee_str = callee.to_source_string();
                if (callee_str == "str" || callee_str == "String") && args.len() == 1 {
                    match self.eval_expr(&args[0]) {
                        ConstantValue::String(s) => ConstantValue::String(s),
                        ConstantValue::Integer(i) => ConstantValue::String(i.to_string()),
                        ConstantValue::Boolean(b) => ConstantValue::String(b.to_string()),
                        _ => ConstantValue::NonConstant,
                    }
                } else {
                    ConstantValue::NonConstant
                }
            }
            ExprNode::Unknown { raw, .. } => self.eval_raw(raw),
            _ => ConstantValue::NonConstant,
        }
    }

    /// Evaluates raw code text to determine if it is a constant literal or constant expression.
    pub fn eval_raw(&self, raw: &str) -> ConstantValue {
        let trimmed = raw.trim();

        // String literals: "safe-command" or 'safe-command'
        if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
        {
            let inner = &trimmed[1..trimmed.len() - 1];
            return ConstantValue::String(inner.to_string());
        }

        // Integer literals
        if let Ok(i) = trimmed.parse::<i64>() {
            return ConstantValue::Integer(i);
        }

        // Boolean literals
        if trimmed == "True" || trimmed == "true" {
            return ConstantValue::Boolean(true);
        }
        if trimmed == "False" || trimmed == "false" {
            return ConstantValue::Boolean(false);
        }

        // Variable lookup
        if let Some(val) = self.constants.get(trimmed) {
            return val.clone();
        }

        // Check for request / dynamic source patterns
        if trimmed.contains("request.")
            || trimmed.contains("req.")
            || trimmed.contains("r.")
            || trimmed.contains("params[")
            || trimmed.contains("args[")
            || trimmed.contains("GET[")
            || trimmed.contains("POST[")
        {
            return ConstantValue::NonConstant;
        }

        ConstantValue::NonConstant
    }

    /// Determines if an argument passed to a sink is guaranteed to be a compile-time constant.
    pub fn is_constant_sink_argument(&self, arg: &ExprNode) -> bool {
        self.eval_expr(arg).is_constant()
    }
}
