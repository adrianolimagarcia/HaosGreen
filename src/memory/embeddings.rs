use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// Embedding engine that calls an OpenAI-compatible /v1/embeddings API.
/// Works with OpenRouter, OpenAI, Ollama, or any compatible provider.
pub struct EmbeddingEngine {
    client: reqwest::Client,
    config: Option<EmbeddingConfig>,
}

/// Configuration for the embedding API
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    pub api_key: String,
    pub base_url: String,
    pub model: String,
    pub dimensions: usize,
}

#[derive(Serialize)]
struct EmbeddingRequest {
    model: String,
    input: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<usize>,
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

/// Default HTTP request timeout for embedding API calls (30 seconds).
pub const DEFAULT_EMBEDDING_TIMEOUT: Duration = Duration::from_secs(30);

impl EmbeddingEngine {
    /// Create an embedding engine with API configuration.
    /// If config is None, embedding features are disabled (FTS5-only fallback).
    pub fn new(config: Option<EmbeddingConfig>) -> Self {
        if let Some(ref cfg) = config {
            info!(
                "Embedding engine configured: model={}, dims={}, url={}",
                cfg.model, cfg.dimensions, cfg.base_url
            );
        } else {
            info!("Embedding engine disabled (no embedding config). Using FTS5-only search.");
        }
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_EMBEDDING_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self { client, config }
    }

    /// Whether vector embeddings are available
    pub fn is_available(&self) -> bool {
        self.config.is_some()
    }

    /// Embedding dimensions (default 384)
    pub fn dimensions(&self) -> usize {
        self.config.as_ref().map(|c| c.dimensions).unwrap_or(384)
    }

    /// Generate a single embedding for one text via API
    pub async fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
        let config = self
            .config
            .as_ref()
            .context("Embedding engine not configured")?;

        let url = format!("{}/embeddings", config.base_url);

        let request = EmbeddingRequest {
            model: config.model.clone(),
            input: vec![text.to_string()],
            dimensions: Some(config.dimensions),
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call embedding API")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Embedding API error ({}): {}", status, body);
        }

        let resp: EmbeddingResponse = response
            .json()
            .await
            .context("Failed to parse embedding response")?;

        let embedding = resp
            .data
            .into_iter()
            .next()
            .map(|d| d.embedding)
            .context("No embedding returned from API")?;

        if embedding.len() != config.dimensions {
            anyhow::bail!(
                "Embedding dimension mismatch: model '{}' returned {} dimensions but config expects {}. \
                 Update [embedding].dimensions in config.toml to {}.",
                config.model, embedding.len(), config.dimensions, embedding.len()
            );
        }

        Ok(embedding)
    }

    /// Try to generate an embedding, returning None if not available or on error
    pub async fn try_embed_one(&self, text: &str) -> Option<Vec<f32>> {
        if !self.is_available() {
            return None;
        }
        match self.embed_one(text).await {
            Ok(embedding) => Some(embedding),
            Err(e) => {
                warn!("Embedding generation failed: {}", e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedding_timeout_constant() {
        assert_eq!(DEFAULT_EMBEDDING_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn test_engine_new_without_config() {
        let engine = EmbeddingEngine::new(None);
        assert!(!engine.is_available());
        assert_eq!(engine.dimensions(), 384);
    }
}
