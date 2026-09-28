#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: Option<String>,
    pub host_port: u16,
    pub container_port: u16,
    pub raw: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
    pub raw: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyInstruction {
    pub src: String,
    pub dst: String,
    pub raw: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerfileModel {
    pub file_path: String,
    pub from_images: Vec<(String, Option<String>, usize)>, // (image, tag, line)
    pub copy_instructions: Vec<CopyInstruction>,
    pub env_vars: Vec<(String, String, usize)>,
    pub arg_vars: Vec<(String, Option<String>, usize)>,
    pub user: Option<(String, usize)>,
    pub exposed_ports: Vec<(u16, usize)>,
    pub has_healthcheck: bool,
    pub volumes: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComposeServiceModel {
    pub name: String,
    pub image: Option<String>,
    pub build_context: Option<String>,
    pub user: Option<String>,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<VolumeMount>,
    pub environment: Vec<(String, String, usize)>,
    pub env_file: Vec<String>,
    pub network_mode: Option<String>,
    pub pid: Option<String>,
    pub ipc: Option<String>,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerComposeModel {
    pub file_path: String,
    pub version: String,
    pub services: Vec<ComposeServiceModel>,
}
