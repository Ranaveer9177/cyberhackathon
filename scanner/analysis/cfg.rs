#![allow(dead_code)]

use crate::ast::types::StmtNode;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CfgEdgeKind {
    Sequential,
    TrueBranch,
    FalseBranch,
    LoopBody,
    LoopExit,
    LoopBack,
    ReturnToExit,
    ExceptionCatch,
    Finally,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgNodeKind {
    Entry,
    Exit,
    Statement {
        line: usize,
        summary: String,
    },
    Condition {
        line: usize,
        test: String,
    },
    LoopHeader {
        line: usize,
        condition: Option<String>,
    },
    TryHeader {
        line: usize,
    },
    CatchHeader {
        line: usize,
    },
    FinallyHeader {
        line: usize,
    },
    Return {
        line: usize,
        expr: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgNode {
    pub id: usize,
    pub kind: CfgNodeKind,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub kind: CfgEdgeKind,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        let mut cfg = Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        };
        cfg.add_node(CfgNodeKind::Entry, 0); // node 0: Entry
        cfg.add_node(CfgNodeKind::Exit, usize::MAX); // node 1: Exit
        cfg
    }

    pub fn add_node(&mut self, kind: CfgNodeKind, line: usize) -> usize {
        let id = self.nodes.len();
        self.nodes.push(CfgNode { id, kind, line });
        id
    }

    pub fn add_edge(&mut self, from: usize, to: usize, kind: CfgEdgeKind) {
        self.edges.push(CfgEdge { from, to, kind });
    }

    /// Build CFG from a sequence of AST statements.
    pub fn build_from_statements(stmts: &[StmtNode]) -> Self {
        let mut cfg = Self::new();
        let last_node = cfg.build_block(0, stmts);
        if last_node != 1 {
            cfg.add_edge(last_node, 1, CfgEdgeKind::Sequential);
        }
        cfg
    }

    fn build_block(&mut self, current: usize, stmts: &[StmtNode]) -> usize {
        let mut prev = current;

        for stmt in stmts {
            match stmt {
                StmtNode::Assignment(assign) => {
                    let node = self.add_node(
                        CfgNodeKind::Statement {
                            line: assign.line,
                            summary: format!(
                                "{} = {}",
                                assign.target.to_source_string(),
                                assign.value.to_source_string()
                            ),
                        },
                        assign.line,
                    );
                    if prev != 1 {
                        self.add_edge(prev, node, CfgEdgeKind::Sequential);
                        prev = node;
                    }
                }
                StmtNode::Call(expr) => {
                    let node = self.add_node(
                        CfgNodeKind::Statement {
                            line: expr.line(),
                            summary: expr.to_source_string(),
                        },
                        expr.line(),
                    );
                    if prev != 1 {
                        self.add_edge(prev, node, CfgEdgeKind::Sequential);
                        prev = node;
                    }
                }
                StmtNode::Return(ret) => {
                    let node = self.add_node(
                        CfgNodeKind::Return {
                            line: ret.line,
                            expr: ret.value.as_ref().map(|v| v.to_source_string()),
                        },
                        ret.line,
                    );
                    if prev != 1 {
                        self.add_edge(prev, node, CfgEdgeKind::Sequential);
                    }
                    self.add_edge(node, 1, CfgEdgeKind::ReturnToExit);
                    prev = 1;
                }
                StmtNode::Condition(cond) => {
                    let cond_node = self.add_node(
                        CfgNodeKind::Condition {
                            line: cond.line,
                            test: cond.test.to_source_string(),
                        },
                        cond.line,
                    );
                    if prev != 1 {
                        self.add_edge(prev, cond_node, CfgEdgeKind::Sequential);
                    }

                    // Then branch
                    let then_end = if !cond.then_body.is_empty() {
                        let then_start = self.add_node(
                            CfgNodeKind::Statement {
                                line: cond.line,
                                summary: "<then>".to_string(),
                            },
                            cond.line,
                        );
                        self.add_edge(cond_node, then_start, CfgEdgeKind::TrueBranch);
                        self.build_block(then_start, &cond.then_body)
                    } else {
                        cond_node
                    };

                    // Else branch
                    let else_end = if !cond.else_body.is_empty() {
                        let else_start = self.add_node(
                            CfgNodeKind::Statement {
                                line: cond.line,
                                summary: "<else>".to_string(),
                            },
                            cond.line,
                        );
                        self.add_edge(cond_node, else_start, CfgEdgeKind::FalseBranch);
                        self.build_block(else_start, &cond.else_body)
                    } else {
                        cond_node
                    };

                    // Join node
                    let join_node = self.add_node(
                        CfgNodeKind::Statement {
                            line: cond.line,
                            summary: "<join>".to_string(),
                        },
                        cond.line,
                    );

                    if then_end != 1 {
                        self.add_edge(then_end, join_node, CfgEdgeKind::Sequential);
                    }
                    if else_end != 1 {
                        self.add_edge(else_end, join_node, CfgEdgeKind::Sequential);
                    }

                    if then_end == 1 && else_end == 1 {
                        prev = 1;
                    } else {
                        prev = join_node;
                    }
                }
                StmtNode::Loop(loop_node) => {
                    let header_node = self.add_node(
                        CfgNodeKind::LoopHeader {
                            line: loop_node.line,
                            condition: loop_node.condition.as_ref().map(|c| c.to_source_string()),
                        },
                        loop_node.line,
                    );
                    if prev != 1 {
                        self.add_edge(prev, header_node, CfgEdgeKind::Sequential);
                    }

                    let body_end = self.build_block(header_node, &loop_node.body);
                    if body_end != 1 {
                        self.add_edge(body_end, header_node, CfgEdgeKind::LoopBack);
                    }

                    let exit_node = self.add_node(
                        CfgNodeKind::Statement {
                            line: loop_node.line,
                            summary: "<loop_exit>".to_string(),
                        },
                        loop_node.line,
                    );
                    self.add_edge(header_node, exit_node, CfgEdgeKind::LoopExit);
                    prev = exit_node;
                }
                StmtNode::TryCatch(try_catch) => {
                    let try_node = self.add_node(
                        CfgNodeKind::TryHeader {
                            line: try_catch.line,
                        },
                        try_catch.line,
                    );
                    if prev != 1 {
                        self.add_edge(prev, try_node, CfgEdgeKind::Sequential);
                    }

                    let try_end = self.build_block(try_node, &try_catch.try_body);

                    let catch_node = self.add_node(
                        CfgNodeKind::CatchHeader {
                            line: try_catch.line,
                        },
                        try_catch.line,
                    );
                    self.add_edge(try_node, catch_node, CfgEdgeKind::ExceptionCatch);
                    let catch_end = self.build_block(catch_node, &try_catch.catch_body);

                    let finally_node = self.add_node(
                        CfgNodeKind::FinallyHeader {
                            line: try_catch.line,
                        },
                        try_catch.line,
                    );
                    if try_end != 1 {
                        self.add_edge(try_end, finally_node, CfgEdgeKind::Finally);
                    }
                    if catch_end != 1 {
                        self.add_edge(catch_end, finally_node, CfgEdgeKind::Finally);
                    }

                    let finally_end = self.build_block(finally_node, &try_catch.finally_body);
                    prev = finally_end;
                }
                StmtNode::Expression(expr) => {
                    let node = self.add_node(
                        CfgNodeKind::Statement {
                            line: expr.line(),
                            summary: expr.to_source_string(),
                        },
                        expr.line(),
                    );
                    if prev != 1 {
                        self.add_edge(prev, node, CfgEdgeKind::Sequential);
                        prev = node;
                    }
                }
            }
        }

        prev
    }

    /// Check if target node is reachable from start node.
    pub fn is_reachable(&self, start: usize, target: usize) -> bool {
        if start == target {
            return true;
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);

        while let Some(current) = queue.pop_front() {
            if current == target {
                return true;
            }

            for edge in &self.edges {
                if edge.from == current && !visited.contains(&edge.to) {
                    visited.insert(edge.to);
                    queue.push_back(edge.to);
                }
            }
        }

        false
    }

    /// Check if there is an active execution path from source statement to sink statement.
    pub fn can_flow_to_sink(&self, source_line: usize, sink_line: usize) -> bool {
        if source_line == sink_line {
            return true;
        }

        // Find candidate nodes matching the lines
        let source_nodes: Vec<usize> = self
            .nodes
            .iter()
            .filter(|n| n.line == source_line && n.id != 1)
            .map(|n| n.id)
            .collect();
        let sink_nodes: Vec<usize> = self
            .nodes
            .iter()
            .filter(|n| n.line == sink_line && n.id != 0)
            .map(|n| n.id)
            .collect();

        if source_nodes.is_empty() || sink_nodes.is_empty() {
            // Fallback to true if lines are not explicitly mapped
            return source_line <= sink_line;
        }

        for &src in &source_nodes {
            for &snk in &sink_nodes {
                if self.is_reachable(src, snk) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if an unconditional return occurs between source_line and sink_line.
    pub fn has_unconditional_return_between(&self, source_line: usize, sink_line: usize) -> bool {
        for node in &self.nodes {
            if node.line > source_line && node.line < sink_line {
                if let CfgNodeKind::Return { .. } = &node.kind {
                    // Check if all paths from source must go through this return
                    if !self.can_flow_to_sink(source_line, sink_line) {
                        return true;
                    }
                }
            }
        }
        false
    }
}
