#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ModuleResolver {
    pub project_root: String,
    pub known_files: Vec<String>,
    normalized_lookup: HashMap<String, String>,
    pub dependencies: HashMap<String, Vec<String>>,
    pub reverse_dependencies: HashMap<String, Vec<String>>,
}

impl ModuleResolver {
    pub fn new(project_root: &str, known_files: &[String]) -> Self {
        let norm_root = project_root.replace('\\', "/");
        let mut normalized_lookup = HashMap::new();
        let mut normalized_files = Vec::new();

        for f in known_files {
            let norm = f.replace('\\', "/");
            let rel = if norm.starts_with(&norm_root) {
                norm[norm_root.len()..].trim_start_matches('/').to_string()
            } else {
                norm.clone()
            };

            normalized_lookup.insert(rel.to_lowercase(), rel.clone());

            let p = Path::new(&rel);
            if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                normalized_lookup.insert(stem.to_lowercase(), rel.clone());
            }

            let without_ext = p.with_extension("");
            if let Some(s) = without_ext.to_str() {
                let s_norm = s.replace('\\', "/").to_lowercase();
                normalized_lookup.insert(s_norm, rel.clone());
            }

            normalized_files.push(rel);
        }

        Self {
            project_root: norm_root,
            known_files: normalized_files,
            normalized_lookup,
            dependencies: HashMap::new(),
            reverse_dependencies: HashMap::new(),
        }
    }

    pub fn register_import(&mut self, from_file: &str, import_specifier: &str) -> Option<String> {
        let from_norm = self.normalize_file_path(from_file);
        if let Some(target) = self.resolve_import(&from_norm, import_specifier) {
            self.dependencies
                .entry(from_norm.clone())
                .or_default()
                .push(target.clone());

            self.reverse_dependencies
                .entry(target.clone())
                .or_default()
                .push(from_norm);

            Some(target)
        } else {
            None
        }
    }

    pub fn normalize_file_path(&self, file_path: &str) -> String {
        let norm = file_path.replace('\\', "/");
        if norm.starts_with(&self.project_root) {
            norm[self.project_root.len()..]
                .trim_start_matches('/')
                .to_string()
        } else {
            norm
        }
    }

    pub fn resolve_import(&self, from_file: &str, specifier: &str) -> Option<String> {
        let from_norm = self.normalize_file_path(from_file);
        let from_path = Path::new(&from_norm);
        let from_dir = from_path.parent().unwrap_or_else(|| Path::new(""));

        let clean_spec = specifier
            .trim_matches(|c| c == '\'' || c == '"' || c == ';' || c == ' ')
            .replace('\\', "/");

        // 1. Direct match in known files
        if self.known_files.iter().any(|f| f == &clean_spec) {
            return Some(clean_spec);
        }

        // 2. Relative imports (e.g. "./services/user", "../database/query", ".user")
        if clean_spec.starts_with("./")
            || clean_spec.starts_with("../")
            || clean_spec.starts_with('.')
        {
            let mut resolved_candidate = PathBuf::from(from_dir);

            if clean_spec.starts_with('.')
                && !clean_spec.starts_with("./")
                && !clean_spec.starts_with("../")
            {
                // Python relative: ".user" or "..database.query"
                let dots = clean_spec.chars().take_while(|c| *c == '.').count();
                let rest = &clean_spec[dots..].replace('.', "/");
                for _ in 1..dots {
                    resolved_candidate.pop();
                }
                resolved_candidate.push(rest);
            } else {
                resolved_candidate.push(&clean_spec);
            }

            if let Some(target) = self.check_file_candidates(&resolved_candidate) {
                return Some(target);
            }
        }

        // 3. Dotted module path (e.g. "services.user", "database.query", "app")
        let slashed = clean_spec.replace('.', "/");
        let candidate_path = PathBuf::from(&slashed);
        if let Some(target) = self.check_file_candidates(&candidate_path) {
            return Some(target);
        }

        // 4. Check relative to current file's directory (Python implicit intra-package import)
        let relative_to_current = from_dir.join(&slashed);
        if let Some(target) = self.check_file_candidates(&relative_to_current) {
            return Some(target);
        }

        // 5. Lookup by normalized file stem / basename
        let lower = clean_spec.to_lowercase();
        if let Some(matched) = self.normalized_lookup.get(&lower) {
            return Some(matched.clone());
        }

        let lower_slashed = slashed.to_lowercase();
        if let Some(matched) = self.normalized_lookup.get(&lower_slashed) {
            return Some(matched.clone());
        }

        None
    }

    fn check_file_candidates(&self, path: &Path) -> Option<String> {
        let norm_str = path
            .to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches("./")
            .to_string();

        let extensions = [
            "",
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".go",
            ".java",
            "/__init__.py",
            "/index.js",
            "/index.ts",
        ];

        for ext in &extensions {
            let candidate = format!("{}{}", norm_str, ext);
            let cleaned = candidate.trim_start_matches('/').to_string();

            for known in &self.known_files {
                if known.eq_ignore_ascii_case(&cleaned)
                    || known.ends_with(&format!("/{}", cleaned))
                    || cleaned.ends_with(known)
                {
                    return Some(known.clone());
                }
            }
        }

        None
    }

    pub fn get_dependencies(&self, file_path: &str) -> &[String] {
        let norm = self.normalize_file_path(file_path);
        self.dependencies
            .get(&norm)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn get_dependents(&self, file_path: &str) -> &[String] {
        let norm = self.normalize_file_path(file_path);
        self.reverse_dependencies
            .get(&norm)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn build_dependency_chain(
        &self,
        start_file: &str,
        target_file: &str,
    ) -> Option<Vec<String>> {
        let start = self.normalize_file_path(start_file);
        let target = self.normalize_file_path(target_file);

        if start == target {
            return Some(vec![start]);
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent_map = HashMap::new();

        queue.push_back(start.clone());
        visited.insert(start.clone());

        let mut found = false;

        while let Some(current) = queue.pop_front() {
            if current == target {
                found = true;
                break;
            }

            if let Some(neighbors) = self.dependencies.get(&current) {
                for next in neighbors {
                    if visited.insert(next.clone()) {
                        parent_map.insert(next.clone(), current.clone());
                        queue.push_back(next.clone());
                    }
                }
            }
        }

        if !found {
            return None;
        }

        let mut path = Vec::new();
        let mut curr = target;
        while curr != start {
            path.push(curr.clone());
            if let Some(p) = parent_map.get(&curr) {
                curr = p.clone();
            } else {
                break;
            }
        }
        path.push(start);
        path.reverse();

        Some(path)
    }

    pub fn format_dependency_chain(chain: &[String]) -> String {
        chain.join("\n ↓\n")
    }
}
