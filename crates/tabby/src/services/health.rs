use std::env::consts::ARCH;

use serde::{Deserialize, Serialize};
use sysinfo::System;
use tabby_common::config::{ModelConfig, ModelConfigGroup};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct HealthState {
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_model: Option<String>,
    device: String,

    // Model health status
    models: ModelsHealth,

    // CPU information for Tabby server
    arch: String,
    cpu_info: String,
    cpu_count: usize,

    version: Version,
    webserver: Option<bool>,
}

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct ModelsHealth {
    #[serde(skip_serializing_if = "Option::is_none")]
    completion: Option<ModelHealth>,

    #[serde(skip_serializing_if = "Option::is_none")]
    chat: Option<ModelHealth>,

    embedding: ModelHealth,
}

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct ModelHealth {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_name: Option<String>,
    api_endpoint: String,
}

impl From<&ModelConfig> for ModelHealth {
    fn from(model_config: &ModelConfig) -> Self {
        match model_config {
            ModelConfig::Http(http) => ModelHealth {
                kind: http.kind.clone(),
                model_name: http.model_name.clone(),
                api_endpoint: http.api_endpoint.clone().unwrap_or_default(),
            },
        }
    }
}

impl From<&ModelConfigGroup> for ModelsHealth {
    fn from(model_config: &ModelConfigGroup) -> Self {
        let completion = model_config.completion.as_ref().map(ModelHealth::from);
        let chat = model_config.chat.as_ref().map(ModelHealth::from);
        let embedding = ModelHealth::from(&model_config.embedding);

        Self {
            completion,
            chat,
            embedding,
        }
    }
}

impl HealthState {
    pub fn new(
        model_config: &ModelConfigGroup,
        webserver: Option<bool>,
    ) -> Self {
        let (cpu_info, cpu_count) = read_cpu_info();
        let models = ModelsHealth::from(model_config);

        Self {
            model: to_model_name(&model_config.completion),
            chat_model: to_model_name(&model_config.chat),
            device: "remote".to_string(),
            models,
            arch: ARCH.to_string(),
            cpu_info,
            cpu_count,
            version: Version::new(),
            webserver,
        }
    }
}

fn to_model_name(model: &Option<ModelConfig>) -> Option<String> {
    if let Some(model) = model {
        match model {
            ModelConfig::Http(http) => http
                .model_name
                .clone()
                .or_else(|| Some("Remote".to_string())),
        }
    } else {
        None
    }
}

pub fn read_cpu_info() -> (String, usize) {
    let mut system = System::new_all();
    system.refresh_cpu_all();
    let cpus = system.cpus();
    let count = cpus.len();
    let info = if count > 0 {
        let cpu = &cpus[0];
        cpu.brand().to_string()
    } else {
        "unknown".to_string()
    };

    (info, count)
}

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub struct Version {
    build_date: String,
    build_timestamp: String,
    git_sha: String,
    git_describe: String,
}

impl Version {
    fn new() -> Self {
        Self {
            build_date: env!("VERGEN_BUILD_DATE").to_string(),
            build_timestamp: env!("VERGEN_BUILD_TIMESTAMP").to_string(),
            git_sha: env!("VERGEN_GIT_SHA").to_string(),
            git_describe: env!("VERGEN_GIT_DESCRIBE").to_string(),
        }
    }
}
