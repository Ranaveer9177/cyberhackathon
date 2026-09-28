pub mod call_graph;
pub mod function_resolver;
pub mod module_resolver;
pub mod project_model;
pub mod security;
pub mod symbols;

use crate::ast::types::FileNode;
use crate::types::Finding;
use project_model::ProjectModel;

/// Analyzes an entire project semantically:
/// 1. Extracts symbol tables (modules, imports, functions, classes, variables, parameters, returns)
/// 2. Resolves cross-file module imports (e.g. app.py -> services/user.py -> database/query.py)
/// 3. Resolves function calls to their declarations (foo() -> actual implementation)
/// 4. Builds project-wide Call Graph (A() -> B() -> C() -> sink())
/// 5. Executes interprocedural security analysis and generates normalized findings
pub fn build_model(project_root: &str, parsed_files: &[(&str, &FileNode)]) -> ProjectModel {
    ProjectModel::build(project_root, parsed_files)
}

pub fn analyze_semantic(
    project_root: &str,
    parsed_files: &[(&str, &FileNode)],
    finding_counter: &mut usize,
) -> Vec<Finding> {
    if parsed_files.is_empty() {
        return Vec::new();
    }

    let model = build_model(project_root, parsed_files);
    security::analyze_project_semantic(&model, finding_counter)
}
