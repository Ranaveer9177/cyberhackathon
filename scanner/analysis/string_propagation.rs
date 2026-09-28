#![allow(dead_code)]

use crate::ast::types::ExprNode;
use crate::taint::types::{TaintKind, TaintedVariable};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringFragment {
    Literal(String),
    TaintedVar {
        name: String,
        kinds: HashSet<TaintKind>,
    },
    UntaintedVar(String),
    Expression(String),
}

impl StringFragment {
    pub fn is_tainted(&self) -> bool {
        matches!(self, StringFragment::TaintedVar { .. })
    }

    pub fn taint_kinds(&self) -> HashSet<TaintKind> {
        match self {
            StringFragment::TaintedVar { kinds, .. } => kinds.clone(),
            _ => HashSet::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringTransformation {
    Direct(StringFragment),
    Concat(Vec<StringFragment>),
    Format {
        template: String,
        args: Vec<StringFragment>,
    },
    FString(Vec<StringFragment>),
    Join {
        separator: String,
        target: Box<StringFragment>,
    },
    Replace {
        base: Box<StringFragment>,
        from: String,
        to: String,
    },
    Encode {
        target: Box<StringFragment>,
        encoding: String,
    },
    Decode {
        target: Box<StringFragment>,
        encoding: String,
    },
}

impl StringTransformation {
    pub fn is_tainted(&self) -> bool {
        match self {
            StringTransformation::Direct(f) => f.is_tainted(),
            StringTransformation::Concat(fragments) | StringTransformation::FString(fragments) => {
                fragments.iter().any(|f| f.is_tainted())
            }
            StringTransformation::Format { args, .. } => args.iter().any(|f| f.is_tainted()),
            StringTransformation::Join { target, .. } => target.is_tainted(),
            StringTransformation::Replace { base, .. } => base.is_tainted(),
            StringTransformation::Encode { target, .. } => target.is_tainted(),
            StringTransformation::Decode { target, .. } => target.is_tainted(),
        }
    }

    pub fn collect_taints(&self) -> HashSet<TaintKind> {
        let mut kinds = HashSet::new();
        match self {
            StringTransformation::Direct(f) => {
                kinds.extend(f.taint_kinds());
            }
            StringTransformation::Concat(fragments) | StringTransformation::FString(fragments) => {
                for f in fragments {
                    kinds.extend(f.taint_kinds());
                }
            }
            StringTransformation::Format { args, .. } => {
                for a in args {
                    kinds.extend(a.taint_kinds());
                }
            }
            StringTransformation::Join { target, .. }
            | StringTransformation::Replace { base: target, .. }
            | StringTransformation::Encode { target, .. }
            | StringTransformation::Decode { target, .. } => {
                kinds.extend(target.taint_kinds());
            }
        }
        kinds
    }
}

pub struct StringPropagator;

impl StringPropagator {
    /// Analyzes an AST expression to track string transformations:
    /// `+`, `format()`, `f-string`, `join()`, `replace()`, `encoding`, `decoding`
    pub fn analyze(
        expr: &ExprNode,
        taints: &HashMap<String, TaintedVariable>,
    ) -> StringTransformation {
        match expr {
            ExprNode::BinaryOp {
                op, left, right, ..
            } if op == "+" => {
                let mut fragments = Vec::new();
                Self::collect_concat_fragments(left, taints, &mut fragments);
                Self::collect_concat_fragments(right, taints, &mut fragments);
                StringTransformation::Concat(fragments)
            }
            ExprNode::FormattedString { parts, .. } => {
                let fragments = parts.iter().map(|p| Self::to_fragment(p, taints)).collect();
                StringTransformation::FString(fragments)
            }
            ExprNode::Call { callee, args, .. } => {
                let callee_str = callee.to_source_string();

                if callee_str.ends_with(".format") {
                    let template = callee_str
                        .trim_end_matches(".format")
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    let frag_args = args.iter().map(|a| Self::to_fragment(a, taints)).collect();
                    StringTransformation::Format {
                        template,
                        args: frag_args,
                    }
                } else if callee_str.ends_with(".join") {
                    let sep = callee_str
                        .trim_end_matches(".join")
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    let target = if let Some(first_arg) = args.first() {
                        Box::new(Self::to_fragment(first_arg, taints))
                    } else {
                        Box::new(StringFragment::Literal(String::new()))
                    };
                    StringTransformation::Join {
                        separator: sep,
                        target,
                    }
                } else if callee_str.ends_with(".replace") {
                    let base_expr = callee_str.trim_end_matches(".replace");
                    let base_frag = Self::to_fragment_from_str(base_expr, taints);
                    let from = args
                        .first()
                        .map(|a| a.to_source_string())
                        .unwrap_or_default();
                    let to = args
                        .get(1)
                        .map(|a| a.to_source_string())
                        .unwrap_or_default();
                    StringTransformation::Replace {
                        base: Box::new(base_frag),
                        from,
                        to,
                    }
                } else if callee_str.ends_with(".encode") {
                    let base_expr = callee_str.trim_end_matches(".encode");
                    let base_frag = Self::to_fragment_from_str(base_expr, taints);
                    let enc = args
                        .first()
                        .map(|a| a.to_source_string())
                        .unwrap_or_else(|| "utf-8".to_string());
                    StringTransformation::Encode {
                        target: Box::new(base_frag),
                        encoding: enc,
                    }
                } else if callee_str.ends_with(".decode") {
                    let base_expr = callee_str.trim_end_matches(".decode");
                    let base_frag = Self::to_fragment_from_str(base_expr, taints);
                    let enc = args
                        .first()
                        .map(|a| a.to_source_string())
                        .unwrap_or_else(|| "utf-8".to_string());
                    StringTransformation::Decode {
                        target: Box::new(base_frag),
                        encoding: enc,
                    }
                } else {
                    StringTransformation::Direct(Self::to_fragment(expr, taints))
                }
            }
            _ => StringTransformation::Direct(Self::to_fragment(expr, taints)),
        }
    }

    fn collect_concat_fragments(
        expr: &ExprNode,
        taints: &HashMap<String, TaintedVariable>,
        fragments: &mut Vec<StringFragment>,
    ) {
        if let ExprNode::BinaryOp {
            op, left, right, ..
        } = expr
        {
            if op == "+" {
                Self::collect_concat_fragments(left, taints, fragments);
                Self::collect_concat_fragments(right, taints, fragments);
                return;
            }
        }
        fragments.push(Self::to_fragment(expr, taints));
    }

    fn to_fragment(expr: &ExprNode, taints: &HashMap<String, TaintedVariable>) -> StringFragment {
        match expr {
            ExprNode::Constant { raw, .. } => {
                let trimmed = raw.trim();
                let clean = if (trimmed.starts_with('"') && trimmed.ends_with('"'))
                    || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
                {
                    &trimmed[1..trimmed.len() - 1]
                } else {
                    trimmed
                };
                StringFragment::Literal(clean.to_string())
            }
            ExprNode::Identifier { name, .. } => {
                if let Some(t) = taints.get(name) {
                    StringFragment::TaintedVar {
                        name: name.clone(),
                        kinds: t.taints.clone(),
                    }
                } else {
                    StringFragment::UntaintedVar(name.clone())
                }
            }
            _ => {
                let src = expr.to_source_string();
                Self::to_fragment_from_str(&src, taints)
            }
        }
    }

    fn to_fragment_from_str(
        raw: &str,
        taints: &HashMap<String, TaintedVariable>,
    ) -> StringFragment {
        let trimmed = raw.trim();
        if (trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        {
            let clean = &trimmed[1..trimmed.len() - 1];
            return StringFragment::Literal(clean.to_string());
        }

        if let Some(t) = taints.get(trimmed) {
            return StringFragment::TaintedVar {
                name: trimmed.to_string(),
                kinds: t.taints.clone(),
            };
        }

        StringFragment::Expression(trimmed.to_string())
    }
}
