#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstantKind {
    String(String),
    Integer(i64),
    Float(String),
    Boolean(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExprNode {
    Identifier {
        name: String,
        line: usize,
    },
    Constant {
        kind: ConstantKind,
        raw: String,
        line: usize,
    },
    Attribute {
        value: Box<ExprNode>,
        attr: String,
        line: usize,
    },
    Subscript {
        value: Box<ExprNode>,
        slice: Box<ExprNode>,
        line: usize,
    },
    Call {
        callee: Box<ExprNode>,
        args: Vec<ExprNode>,
        line: usize,
    },
    BinaryOp {
        op: String,
        left: Box<ExprNode>,
        right: Box<ExprNode>,
        line: usize,
    },
    FormattedString {
        parts: Vec<ExprNode>,
        raw: String,
        line: usize,
    },
    List {
        elements: Vec<ExprNode>,
        line: usize,
    },
    Unknown {
        raw: String,
        line: usize,
    },
}

impl ExprNode {
    pub fn line(&self) -> usize {
        match self {
            ExprNode::Identifier { line, .. } => *line,
            ExprNode::Constant { line, .. } => *line,
            ExprNode::Attribute { line, .. } => *line,
            ExprNode::Subscript { line, .. } => *line,
            ExprNode::Call { line, .. } => *line,
            ExprNode::BinaryOp { line, .. } => *line,
            ExprNode::FormattedString { line, .. } => *line,
            ExprNode::List { line, .. } => *line,
            ExprNode::Unknown { line, .. } => *line,
        }
    }

    pub fn to_source_string(&self) -> String {
        match self {
            ExprNode::Identifier { name, .. } => name.clone(),
            ExprNode::Constant { raw, .. } => raw.clone(),
            ExprNode::Attribute { value, attr, .. } => {
                format!("{}.{}", value.to_source_string(), attr)
            }
            ExprNode::Subscript { value, slice, .. } => {
                format!("{}[{}]", value.to_source_string(), slice.to_source_string())
            }
            ExprNode::Call { callee, args, .. } => {
                let arg_strs: Vec<String> = args.iter().map(|a| a.to_source_string()).collect();
                format!("{}({})", callee.to_source_string(), arg_strs.join(", "))
            }
            ExprNode::BinaryOp {
                op, left, right, ..
            } => {
                format!(
                    "{} {} {}",
                    left.to_source_string(),
                    op,
                    right.to_source_string()
                )
            }
            ExprNode::FormattedString { raw, .. } => raw.clone(),
            ExprNode::List { elements, .. } => {
                let el_strs: Vec<String> = elements.iter().map(|e| e.to_source_string()).collect();
                format!("[{}]", el_strs.join(", "))
            }
            ExprNode::Unknown { raw, .. } => raw.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportNode {
    pub module: String,
    pub symbols: Vec<String>,
    pub alias: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignmentNode {
    pub target: ExprNode,
    pub value: ExprNode,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnNode {
    pub value: Option<ExprNode>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionNode {
    pub test: ExprNode,
    pub then_body: Vec<StmtNode>,
    pub else_body: Vec<StmtNode>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopNode {
    pub condition: Option<ExprNode>,
    pub body: Vec<StmtNode>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryCatchNode {
    pub try_body: Vec<StmtNode>,
    pub catch_body: Vec<StmtNode>,
    pub finally_body: Vec<StmtNode>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StmtNode {
    Assignment(AssignmentNode),
    Call(ExprNode),
    Return(ReturnNode),
    Condition(ConditionNode),
    Loop(LoopNode),
    TryCatch(TryCatchNode),
    Expression(ExprNode),
}

impl StmtNode {
    pub fn line(&self) -> usize {
        match self {
            StmtNode::Assignment(a) => a.line,
            StmtNode::Call(c) => c.line(),
            StmtNode::Return(r) => r.line,
            StmtNode::Condition(c) => c.line,
            StmtNode::Loop(l) => l.line,
            StmtNode::TryCatch(t) => t.line,
            StmtNode::Expression(e) => e.line(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionNode {
    pub name: String,
    pub params: Vec<String>,
    pub body: Vec<StmtNode>,
    pub is_method: bool,
    pub line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassNode {
    pub name: String,
    pub base_classes: Vec<String>,
    pub methods: Vec<FunctionNode>,
    pub fields: Vec<AssignmentNode>,
    pub line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FileNode {
    pub file_path: String,
    pub language: String,
    pub imports: Vec<ImportNode>,
    pub classes: Vec<ClassNode>,
    pub functions: Vec<FunctionNode>,
    pub statements: Vec<StmtNode>,
}
