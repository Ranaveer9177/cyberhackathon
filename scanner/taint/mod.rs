pub mod propagator;
pub mod sanitizers;
pub mod sinks;
pub mod sources;
pub mod types;

use crate::ast::types::FileNode;
use crate::semantic::project_model::ProjectModel;
pub use propagator::DeepTaintPropagator;
pub use sanitizers::SanitizerModel;
pub use sinks::SinkModel;
pub use sources::SourceModel;
pub use types::{TaintFlow, TaintKind, TaintStep, TaintStepType};

/// Executes deep multi-hop data-flow and taint analysis:
/// Tracks: SOURCE -> assignment -> transformation -> function parameter -> function call -> return -> another file -> SINK
pub fn analyze_deep_taint(
    project_model: &ProjectModel,
    parsed_files: &[(&str, &FileNode)],
) -> Vec<TaintFlow> {
    let propagator = DeepTaintPropagator::new(project_model, parsed_files);
    propagator.execute()
}
