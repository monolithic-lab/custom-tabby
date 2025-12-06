use std::sync::Arc;

use tabby_common::config::ModelConfig;
use tabby_inference::{ChatCompletionStream, CodeGeneration, CompletionStream, Embedding};

#[derive(Clone)]
pub struct PromptInfo {
    pub prompt_template: Option<String>,
    pub chat_template: Option<String>,
}

pub async fn load_embedding(config: &ModelConfig) -> Arc<dyn Embedding> {
    match config {
        ModelConfig::Http(http) => http_api_bindings::create_embedding(http).await,
    }
}

pub async fn load_code_generation_and_chat(
    completion_model: Option<ModelConfig>,
    chat_model: Option<ModelConfig>,
) -> (
    Option<Arc<CodeGeneration>>,
    Option<Arc<dyn CompletionStream>>,
    Option<Arc<dyn ChatCompletionStream>>,
    Option<PromptInfo>,
) {
    let (engine, prompt_info, chat) =
        load_completion_and_chat(completion_model.clone(), chat_model).await;
    let code = engine
        .clone()
        .map(|engine| Arc::new(CodeGeneration::new(engine, completion_model)));
    (code, engine, chat, prompt_info)
}

async fn load_completion_and_chat(
    completion_model: Option<ModelConfig>,
    chat_model: Option<ModelConfig>,
) -> (
    Option<Arc<dyn CompletionStream>>,
    Option<PromptInfo>,
    Option<Arc<dyn ChatCompletionStream>>,
) {
    let (completion, prompt) = if let Some(completion_model) = completion_model {
        match completion_model {
            ModelConfig::Http(http) => {
                let engine = http_api_bindings::create(&http).await;
                let (prompt_template, chat_template) =
                    http_api_bindings::build_completion_prompt(&http);
                (
                    Some(engine),
                    Some(PromptInfo {
                        prompt_template,
                        chat_template,
                    }),
                )
            }
        }
    } else {
        (None, None)
    };

    let chat = if let Some(chat_model) = chat_model {
        match chat_model {
            ModelConfig::Http(http) => Some(http_api_bindings::create_chat(&http).await),
        }
    } else {
        None
    };

    (completion, prompt, chat)
}
