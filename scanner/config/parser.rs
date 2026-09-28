#![allow(dead_code)]

use crate::config::types::{ConfigEntry, ConfigFormat, ConfigModel};
use std::path::Path;

pub fn detect_format(file_path: &str) -> ConfigFormat {
    let lower_path = file_path.to_lowercase();
    let filename = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if filename == ".env" || filename.starts_with(".env.") || filename.ends_with(".env") {
        ConfigFormat::Env
    } else if lower_path.ends_with(".yaml") || lower_path.ends_with(".yml") {
        ConfigFormat::Yaml
    } else if lower_path.ends_with(".json") {
        ConfigFormat::Json
    } else if lower_path.ends_with(".toml") {
        ConfigFormat::Toml
    } else if lower_path.ends_with(".ini")
        || lower_path.ends_with(".cfg")
        || lower_path.ends_with(".conf")
    {
        ConfigFormat::Ini
    } else {
        ConfigFormat::ApplicationConfig
    }
}

pub fn parse_config(file_path: &str, content: &str) -> ConfigModel {
    let format = detect_format(file_path);
    let mut model = ConfigModel::new(file_path, format);

    match format {
        ConfigFormat::Env => {
            model.entries = parse_env(content);
        }
        ConfigFormat::Yaml => {
            model.entries = parse_yaml(content);
        }
        ConfigFormat::Json => {
            model.entries = parse_json(content);
        }
        ConfigFormat::Toml => {
            model.entries = parse_toml(content);
        }
        ConfigFormat::Ini => {
            model.entries = parse_ini(content);
        }
        ConfigFormat::ApplicationConfig => {
            model.entries = parse_ini(content);
        }
    }

    model
}

pub fn parse_env(content: &str) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let mut trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("export ") {
            trimmed = rest.trim();
        }

        if let Some(eq_idx) = trimmed.find('=') {
            let key = trimmed[..eq_idx].trim().to_string();
            let mut val = trimmed[eq_idx + 1..].trim().to_string();

            // Strip surrounding quotes
            if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
            {
                val = val[1..val.len() - 1].to_string();
            }

            entries.push(ConfigEntry {
                key,
                value: val,
                raw_line: line.to_string(),
                line: line_num,
                section: None,
            });
        }
    }

    entries
}

pub fn parse_yaml(content: &str) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();
    let mut section_stack: Vec<(usize, String)> = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("---") {
            continue;
        }

        let indent = line.len() - line.trim_start().len();

        while let Some(&(prev_indent, _)) = section_stack.last() {
            if indent <= prev_indent {
                section_stack.pop();
            } else {
                break;
            }
        }

        if let Some(colon_idx) = trimmed.find(':') {
            let key_part = trimmed[..colon_idx].trim();
            let val_part = trimmed[colon_idx + 1..].trim();

            let current_section = if section_stack.is_empty() {
                None
            } else {
                Some(
                    section_stack
                        .iter()
                        .map(|(_, s)| s.as_str())
                        .collect::<Vec<&str>>()
                        .join("."),
                )
            };

            if val_part.is_empty() {
                section_stack.push((indent, key_part.to_string()));
            } else {
                let mut val = val_part.to_string();
                if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                    || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
                {
                    val = val[1..val.len() - 1].to_string();
                }

                let full_key = if let Some(ref sec) = current_section {
                    format!("{}.{}", sec, key_part)
                } else {
                    key_part.to_string()
                };

                entries.push(ConfigEntry {
                    key: full_key,
                    value: val,
                    raw_line: line.to_string(),
                    line: line_num,
                    section: current_section,
                });
            }
        }
    }

    entries
}

pub fn parse_json(content: &str) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        flatten_json_value(&value, "", 1, content, &mut entries);
    }

    entries
}

fn flatten_json_value(
    val: &serde_json::Value,
    prefix: &str,
    default_line: usize,
    raw_content: &str,
    entries: &mut Vec<ConfigEntry>,
) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let full_key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };

                // Approximate line number by finding key in text
                let line_num = find_key_line(raw_content, k).unwrap_or(default_line);

                match v {
                    serde_json::Value::String(s) => {
                        entries.push(ConfigEntry {
                            key: full_key,
                            value: s.clone(),
                            raw_line: format!("\"{}\": \"{}\"", k, s),
                            line: line_num,
                            section: if prefix.is_empty() {
                                None
                            } else {
                                Some(prefix.to_string())
                            },
                        });
                    }
                    serde_json::Value::Bool(b) => {
                        entries.push(ConfigEntry {
                            key: full_key,
                            value: b.to_string(),
                            raw_line: format!("\"{}\": {}", k, b),
                            line: line_num,
                            section: if prefix.is_empty() {
                                None
                            } else {
                                Some(prefix.to_string())
                            },
                        });
                    }
                    serde_json::Value::Number(n) => {
                        entries.push(ConfigEntry {
                            key: full_key,
                            value: n.to_string(),
                            raw_line: format!("\"{}\": {}", k, n),
                            line: line_num,
                            section: if prefix.is_empty() {
                                None
                            } else {
                                Some(prefix.to_string())
                            },
                        });
                    }
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        flatten_json_value(v, &full_key, line_num, raw_content, entries);
                    }
                    serde_json::Value::Null => {}
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                let full_key = format!("{}[{}]", prefix, idx);
                flatten_json_value(item, &full_key, default_line, raw_content, entries);
            }
        }
        _ => {}
    }
}

fn find_key_line(content: &str, key: &str) -> Option<usize> {
    let pattern = format!("\"{}\"", key);
    for (line_idx, line) in content.lines().enumerate() {
        if line.contains(&pattern) {
            return Some(line_idx + 1);
        }
    }
    None
}

pub fn parse_toml(content: &str) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();
    let mut current_section: Option<String> = None;

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let sec = trimmed[1..trimmed.len() - 1].trim().to_string();
            current_section = Some(sec);
            continue;
        }

        if let Some(eq_idx) = trimmed.find('=') {
            let key = trimmed[..eq_idx].trim();
            let mut val = trimmed[eq_idx + 1..].trim().to_string();

            if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
            {
                val = val[1..val.len() - 1].to_string();
            }

            let full_key = if let Some(ref sec) = current_section {
                format!("{}.{}", sec, key)
            } else {
                key.to_string()
            };

            entries.push(ConfigEntry {
                key: full_key,
                value: val,
                raw_line: line.to_string(),
                line: line_num,
                section: current_section.clone(),
            });
        }
    }

    entries
}

pub fn parse_ini(content: &str) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();
    let mut current_section: Option<String> = None;

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let sec = trimmed[1..trimmed.len() - 1].trim().to_string();
            current_section = Some(sec);
            continue;
        }

        let delim_pos = trimmed.find('=').or_else(|| trimmed.find(':'));
        if let Some(idx) = delim_pos {
            let key = trimmed[..idx].trim();
            let mut val = trimmed[idx + 1..].trim().to_string();

            if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
                || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
            {
                val = val[1..val.len() - 1].to_string();
            }

            let full_key = if let Some(ref sec) = current_section {
                format!("{}.{}", sec, key)
            } else {
                key.to_string()
            };

            entries.push(ConfigEntry {
                key: full_key,
                value: val,
                raw_line: line.to_string(),
                line: line_num,
                section: current_section.clone(),
            });
        }
    }

    entries
}
