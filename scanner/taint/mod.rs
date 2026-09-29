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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::ast::parse_file;

    #[test]
    fn test_multi_hop_cross_file_taint_propagation() {
        let code_entry = r#"
from service import step1

def handle_request(user_input):
    step1(user_input)
"#;
        let code_service = r#"
def step1(internal_arg):
    step2(internal_arg)

def step2(final_cmd):
    db.execute(final_cmd)
"#;

        let node_entry = parse_file("routes.py", code_entry).expect("parse failed");
        let node_service = parse_file("service.py", code_service).expect("parse failed");

        let parsed_files = [("routes.py", &node_entry), ("service.py", &node_service)];

        let model = ProjectModel::build(".", &parsed_files);
        let flows = analyze_deep_taint(&model, &parsed_files);

        assert!(
            !flows.is_empty(),
            "Multi-hop cross-file taint flow must be detected"
        );
        let flow = flows
            .iter()
            .find(|f| f.crosses_files)
            .expect("Must find a flow crossing file boundaries");
        assert_eq!(flow.kind, TaintKind::Sql);
        assert!(
            flow.steps.len() >= 3,
            "Flow must trace multi-hop call steps"
        );
    }

    #[test]
    fn test_sanitizer_stops_taint_propagation() {
        let code = r#"
def handle_request(user_input):
    safe_id = int(user_input)
    db.execute(safe_id)
"#;
        let node = parse_file("app.py", code).expect("parse failed");
        let parsed_files = [("app.py", &node)];

        let model = ProjectModel::build(".", &parsed_files);
        let flows = analyze_deep_taint(&model, &parsed_files);

        assert!(
            flows.is_empty(),
            "Sanitized input must cut off taint propagation to sink"
        );
    }

    #[test]
    fn test_safe_constant_input_no_taint() {
        let code = r#"
def handle_request():
    query = "SELECT id, name FROM users"
    db.execute(query)
"#;
        let node = parse_file("app.py", code).expect("parse failed");
        let parsed_files = [("app.py", &node)];

        let model = ProjectModel::build(".", &parsed_files);
        let flows = analyze_deep_taint(&model, &parsed_files);

        assert!(
            flows.is_empty(),
            "Safe constant input must produce 0 taint flows"
        );
    }
}
