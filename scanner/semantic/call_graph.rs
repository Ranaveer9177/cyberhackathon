#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub id: String,
    pub display_name: String,
    pub file_path: String,
    pub line: usize,
    pub is_sink: bool,
    pub sink_kind: Option<String>,
    pub is_source: bool,
    pub source_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    pub caller_id: String,
    pub callee_id: String,
    pub caller_file: String,
    pub call_line: usize,
    pub callee_file: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallChain {
    pub edges: Vec<CallGraphEdge>,
    pub start_id: String,
    pub sink_id: String,
    pub sink_kind: String,
}

impl CallChain {
    pub fn format_chain(&self, nodes: &HashMap<String, CallGraphNode>) -> String {
        let mut lines = Vec::new();

        if let Some(start_node) = nodes.get(&self.start_id) {
            lines.push(format!(
                "{} [{}:{}]",
                start_node.display_name, start_node.file_path, start_node.line
            ));
        } else {
            lines.push(self.start_id.clone());
        }

        for edge in &self.edges {
            lines.push(" ↓".to_string());
            if let Some(callee_node) = nodes.get(&edge.callee_id) {
                if callee_node.is_sink {
                    lines.push(format!(
                        "{} [{}:{}] (SINK: {})",
                        callee_node.display_name,
                        callee_node.file_path,
                        edge.call_line,
                        self.sink_kind
                    ));
                } else {
                    lines.push(format!(
                        "{} [{}:{}]",
                        callee_node.display_name, callee_node.file_path, callee_node.line
                    ));
                }
            } else {
                lines.push(format!("{} [line {}]", edge.callee_id, edge.call_line));
            }
        }

        lines.join("\n")
    }

    pub fn to_data_flow_list(&self, nodes: &HashMap<String, CallGraphNode>) -> Vec<String> {
        let mut steps = Vec::new();
        if let Some(first) = nodes.get(&self.start_id) {
            steps.push(format!(
                "{}:{}: {}",
                first.file_path, first.line, first.display_name
            ));
        }
        for edge in &self.edges {
            if let Some(n) = nodes.get(&edge.callee_id) {
                steps.push(format!(
                    "{}:{}: {}",
                    n.file_path, edge.call_line, n.display_name
                ));
            }
        }
        steps
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: HashMap<String, CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
    pub outgoing: HashMap<String, Vec<usize>>,
    pub incoming: HashMap<String, Vec<usize>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: CallGraphNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: CallGraphEdge) {
        let edge_idx = self.edges.len();
        self.outgoing
            .entry(edge.caller_id.clone())
            .or_default()
            .push(edge_idx);
        self.incoming
            .entry(edge.callee_id.clone())
            .or_default()
            .push(edge_idx);
        self.edges.push(edge);
    }

    pub fn find_paths_to_sinks(&self, max_depth: usize) -> Vec<CallChain> {
        let mut chains = Vec::new();

        let sink_nodes: Vec<&CallGraphNode> = self.nodes.values().filter(|n| n.is_sink).collect();

        for sink in sink_nodes {
            let sink_kind = sink
                .sink_kind
                .clone()
                .unwrap_or_else(|| "VULNERABILITY_SINK".to_string());

            // Reverse BFS/DFS from sink back to sources or entry functions
            let mut queue: VecDeque<(String, Vec<CallGraphEdge>)> = VecDeque::new();
            queue.push_back((sink.id.clone(), Vec::new()));

            while let Some((curr_node_id, path_so_far)) = queue.pop_front() {
                if path_so_far.len() >= max_depth {
                    continue;
                }

                if let Some(incoming_indices) = self.incoming.get(&curr_node_id) {
                    for &edge_idx in incoming_indices {
                        let edge = &self.edges[edge_idx];
                        let caller_id = &edge.caller_id;

                        // Check cycle in current path
                        if path_so_far.iter().any(|e| &e.caller_id == caller_id) {
                            continue;
                        }

                        let mut new_path = path_so_far.clone();
                        new_path.push(edge.clone());

                        if let Some(caller_node) = self.nodes.get(caller_id) {
                            let has_incoming = self.incoming.contains_key(caller_id);
                            if caller_node.is_source || !has_incoming {
                                // Reached an entrypoint or source!
                                let mut reversed = new_path.clone();
                                reversed.reverse();

                                chains.push(CallChain {
                                    edges: reversed,
                                    start_id: caller_id.clone(),
                                    sink_id: sink.id.clone(),
                                    sink_kind: sink_kind.clone(),
                                });
                            }
                            if has_incoming {
                                queue.push_back((caller_id.clone(), new_path));
                            }
                        }
                    }
                }
            }
        }

        chains
    }

    pub fn find_paths_between(
        &self,
        source_id: &str,
        sink_id: &str,
        max_depth: usize,
    ) -> Vec<CallChain> {
        let mut chains = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = Vec::new();

        self.dfs_paths(
            source_id,
            sink_id,
            &mut visited,
            &mut current_path,
            &mut chains,
            max_depth,
        );

        chains
    }

    fn dfs_paths(
        &self,
        current_id: &str,
        target_id: &str,
        visited: &mut HashSet<String>,
        current_path: &mut Vec<CallGraphEdge>,
        chains: &mut Vec<CallChain>,
        max_depth: usize,
    ) {
        if current_id == target_id {
            if let Some(target_node) = self.nodes.get(target_id) {
                let sink_kind = target_node
                    .sink_kind
                    .clone()
                    .unwrap_or_else(|| "SINK".to_string());
                chains.push(CallChain {
                    edges: current_path.clone(),
                    start_id: current_path
                        .first()
                        .map(|e| e.caller_id.clone())
                        .unwrap_or_else(|| current_id.to_string()),
                    sink_id: target_id.to_string(),
                    sink_kind,
                });
            }
            return;
        }

        if current_path.len() >= max_depth || !visited.insert(current_id.to_string()) {
            return;
        }

        if let Some(edge_indices) = self.outgoing.get(current_id) {
            for &idx in edge_indices {
                let edge = &self.edges[idx];
                current_path.push(edge.clone());
                self.dfs_paths(
                    &edge.callee_id,
                    target_id,
                    visited,
                    current_path,
                    chains,
                    max_depth,
                );
                current_path.pop();
            }
        }

        visited.remove(current_id);
    }
}
