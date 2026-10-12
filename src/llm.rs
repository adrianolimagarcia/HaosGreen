use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::debug;

use std::sync::Arc;
use std::time::Duration;

/// A single part in a multi-modal message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text { text: String },
    ImageUrl { image_url: ImageUrlContent },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrlContent {
    /// "data:image/jpeg;base64,..." or a URL
    pub url: String,
}

/// Either a plain text string or a list of content parts (multi-modal).
/// Serializes as a plain JSON string for text-only, or as a JSON array for multi-modal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

impl MessageContent {
    /// Extract all text from the content (for logging, RAG, DB storage, etc.)
    pub fn as_text(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Parts(parts) => parts
                .iter()
                .filter_map(|p| {
                    if let ContentPart::Text { text } = p {
                        Some(text.as_str())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        }
    }

    pub fn from_text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(s) => s.is_empty(),
            Self::Parts(parts) => parts.is_empty(),
        }
    }
}

impl Default for MessageContent {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<MessageContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    pub fn has_tool_calls(&self) -> bool {
        self.tool_calls
            .as_ref()
            .is_some_and(|calls| !calls.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: FunctionDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Completion wrapper that preserves metadata alongside the assistant message.
#[derive(Debug, Clone)]
pub struct ChatCompletion {
    pub message: ChatMessage,
    pub finish_reason: Option<String>,
    pub model: String,
}

/// Classifier that detects empty assistant responses (no content and no tool calls).
///
/// Returns `true` when the assistant message has neither meaningful text content
/// nor any tool calls, indicating a potentially problematic response that may
/// warrant retry logic.
pub fn is_empty_assistant_response(message: &ChatMessage) -> bool {
    let has_tool_calls = message
        .tool_calls
        .as_ref()
        .is_some_and(|calls| !calls.is_empty());
    let has_content = message.content.as_ref().is_some_and(|content| {
        let text = content.as_text();
        !text.trim().is_empty()
    });

    !has_tool_calls && !has_content
}

#[derive(Debug, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDefinition>>,
    pub max_tokens: u32,
}

#[derive(Debug, Deserialize)]
pub struct ChatResponse {
    pub choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
pub struct Choice {
    pub message: ChatMessage,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[doc(hidden)]
pub mod internal {
    pub use super::{ChatRequest, ChatResponse, Choice};
}

/// Sanitize a JSON Schema parameter object so it is accepted by strict providers
/// (e.g. Google Gemini via OpenRouter).
///
/// Gemini enforces that every entry in the `required` array corresponds to a key
/// that is actually defined in `properties`.  Some MCP servers return schemas where
/// `required` contains field names that do not exist in `properties` — this causes a
/// 400 INVALID_ARGUMENT from Google AI Studio.
///
/// Additional Gemini restrictions handled here:
/// - `additionalProperties`, `$schema`, `$defs`, `$ref` are not accepted.
/// - `required: []` (empty array) is rejected; the key must be omitted entirely.
/// - `anyOf`/`oneOf`/`allOf` variants with `{"type": "null"}` are stripped because
///   Gemini does not support nullable types expressed as `null` union members.
///   If stripping leaves exactly one variant, it is inlined (unwrapped) into the
///   parent object.  If stripping leaves zero variants, the key is removed entirely.
///
/// This function mutates the schema in-place and recurses into `properties`,
/// `items`, `anyOf`, `oneOf`, and `allOf` sub-schemas.
pub fn sanitize_parameters(schema: &mut serde_json::Value) {
    let obj = match schema.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // Remove fields that Gemini rejects.
    obj.remove("additionalProperties");
    obj.remove("$schema");
    obj.remove("$defs");
    obj.remove("$ref");

    // Collect the set of property names that are actually defined.
    let known_props: std::collections::HashSet<String> = obj
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();

    // Filter `required` so it only lists names that appear in `properties`.
    // Gemini also rejects an empty `required: []`, so remove the key entirely
    // if nothing remains after filtering.
    if let Some(required) = obj.get_mut("required") {
        if let Some(arr) = required.as_array_mut() {
            arr.retain(|v| v.as_str().is_some_and(|s| known_props.contains(s)));
        }
    }
    if obj
        .get("required")
        .and_then(|r| r.as_array())
        .is_some_and(|a| a.is_empty())
    {
        obj.remove("required");
    }

    // Recurse into property sub-schemas.
    if let Some(properties) = obj.get_mut("properties") {
        if let Some(props_obj) = properties.as_object_mut() {
            for prop_schema in props_obj.values_mut() {
                sanitize_parameters(prop_schema);
            }
        }
    }

    // Recurse into array item schema.
    if let Some(items) = obj.get_mut("items") {
        sanitize_parameters(items);
    }

    // Recurse into anyOf / oneOf / allOf variant schemas and strip null variants.
    // Gemini does not support {"type": "null"} as a union member.
    for key in &["anyOf", "oneOf", "allOf"] {
        if let Some(variants) = obj.get_mut(*key) {
            if let Some(arr) = variants.as_array_mut() {
                // Recurse into each variant first.
                for v in arr.iter_mut() {
                    sanitize_parameters(v);
                }
                // Remove variants that are purely {"type": "null"}.
                arr.retain(|v| {
                    v.get("type")
                        .and_then(|t| t.as_str())
                        .map(|t| t != "null")
                        .unwrap_or(true)
                });
            }
        }

        // If only one variant remains, unwrap it by merging into the parent.
        // If zero variants remain, remove the key entirely.
        let variant_count = obj.get(*key).and_then(|v| v.as_array()).map(|a| a.len());
        match variant_count {
            Some(0) => {
                obj.remove(*key);
            }
            Some(1) => {
                if let Some(single) = obj
                    .remove(*key)
                    .and_then(|mut v| v.as_array_mut().and_then(|a| a.pop()))
                {
                    if let Some(inner) = single.as_object() {
                        for (k, v) in inner {
                            obj.entry(k.clone()).or_insert(v.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Parse Kimi's native tool-call text format and convert it into `ToolCall` structs.
///
/// Some models (e.g. `moonshotai/kimi-k2.5`) occasionally leak their internal
/// tool-invocation syntax into the `content` field instead of populating the
/// standard `tool_calls` API field.  The leaked text looks like:
///
/// ```text
/// <|tool_calls_section_begin|> <|tool_call_begin|> functions.my_tool:0
/// <|tool_call_argument_begin|> {"arg": "value"} <|tool_call_end|>
/// <|tool_calls_section_end|>
/// ```
///
/// Returns `Some(Vec<ToolCall>)` with at least one entry when the format is
/// detected, or `None` if the content does not contain the Kimi markers.
pub fn parse_kimi_tool_calls(content: &str) -> Option<Vec<ToolCall>> {
    if !content.contains("<|tool_calls_section_begin|>") {
        return None;
    }

    let mut calls = Vec::new();

    // Split on the per-call begin marker; the first chunk is the preamble/section
    // header and is discarded.
    for block in content.split("<|tool_call_begin|>").skip(1) {
        // Strip everything from the closing marker onwards (handles trailing
        // section-end marker and whitespace).
        let block = block
            .split("<|tool_call_end|>")
            .next()
            .unwrap_or(block)
            .trim();

        // Split into function descriptor and JSON arguments.
        let (descriptor, args_raw) = if let Some(pos) = block.find("<|tool_call_argument_begin|>") {
            let d = block[..pos].trim();
            let a = block[pos + "<|tool_call_argument_begin|>".len()..].trim();
            (d, a)
        } else {
            continue;
        };

        // Descriptor format: `functions.{name}:{index}` or just `functions.{name}`.
        // Extract the plain function name.
        let func_name = descriptor
            .trim_start_matches("functions.")
            .split(':')
            .next()
            .unwrap_or(descriptor)
            .trim()
            .to_string();

        if func_name.is_empty() {
            continue;
        }

        // Use the call index (if present) as part of the synthetic tool-call ID.
        let call_index = descriptor.split(':').nth(1).unwrap_or("0").trim();
        let call_id = format!("kimi_fallback_{func_name}_{call_index}");

        // Preserve malformed arguments: the runner must reject them, not execute {}.
        let arguments = args_raw.to_string();

        calls.push(ToolCall {
            id: call_id,
            call_type: "function".to_string(),
            function: FunctionCall {
                name: func_name,
                arguments,
            },
        });
    }

    if calls.is_empty() {
        None
    } else {
        Some(calls)
    }
}

#[derive(Clone)]
pub struct LlmClient {
    pub client: reqwest::Client,
    pub registry: Arc<crate::provider::ProviderRegistry>,
}

/// Default HTTP request timeout for LLM provider completions (120 seconds).
pub const DEFAULT_LLM_TIMEOUT: Duration = Duration::from_secs(120);

/// Determines if an LLM error is transient/server-side and eligible for fallback.
///
/// Only typed HTTP statuses and reqwest timeout/connect causes qualify.
/// Unknown/deterministic errors and untrusted response-body wording never qualify.
pub fn is_fallback_eligible_error(err: &anyhow::Error) -> bool {
    // 1. Check reqwest::Error downcasts anywhere in the cause chain
    for cause in err.chain() {
        if let Some(http) = cause.downcast_ref::<crate::provider::ProviderHttpError>() {
            return matches!(http.status.as_u16(), 429 | 500 | 502 | 503 | 504);
        }
        if let Some(req_err) = cause.downcast_ref::<reqwest::Error>() {
            if let Some(status) = req_err.status() {
                return matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504);
            }
            if req_err.is_timeout() || req_err.is_connect() {
                return true;
            }
            // Decode/schema failures remain deterministic; a body transport failure
            // and typed reset causes represent interrupted HTTP delivery.
            if req_err.is_body() && !req_err.is_decode() {
                return true;
            }
            let mut source = std::error::Error::source(req_err);
            while let Some(cause) = source {
                if let Some(io) = cause.downcast_ref::<std::io::Error>() {
                    if matches!(
                        io.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    ) {
                        return true;
                    }
                }
                source = cause.source();
            }
        }
    }

    // Only structured causes are authoritative; response bodies are untrusted.
    false
}

impl LlmClient {
    pub fn new(registry: Arc<crate::provider::ProviderRegistry>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_LLM_TIMEOUT)
            .build()
            .expect("LLM HTTP client with bounded timeout must initialize");
        Self { client, registry }
    }

    pub fn registry(&self) -> &crate::provider::ProviderRegistry {
        &self.registry
    }

    /// Core chat method returning full completion metadata (message, finish_reason, model).
    ///
    /// Resolves the model string through the registry to pick the right provider,
    /// then delegates the actual HTTP call to that provider.
    pub async fn chat_completion_with_model(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        model: &str,
    ) -> Result<ChatCompletion> {
        let (provider, actual_model) = self.registry.resolve_model(model);
        let max_tokens = provider.config().max_tokens;

        let mut completion = provider
            .chat_completion(&self.client, messages, tools, actual_model, max_tokens)
            .await?;

        completion.model = model.to_string();
        Ok(completion)
    }

    /// Chat completion with automatic fallback chain execution on eligible transient errors.
    pub async fn chat_completion_with_fallback(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        primary_model: &str,
    ) -> Result<ChatCompletion> {
        match self
            .chat_completion_with_model(messages, tools, primary_model)
            .await
        {
            Ok(completion) => Ok(completion),
            Err(primary_err) => {
                if !is_fallback_eligible_error(&primary_err)
                    || self.registry.fallback_chain().is_empty()
                {
                    return Err(primary_err);
                }

                let (primary_prov, primary_actual) = self.registry.resolve_model(primary_model);
                let primary_prov_name = primary_prov.name();

                let mut fallback_errors = Vec::new();

                for candidate in self.registry.fallback_chain() {
                    let (cand_prov, cand_actual) = self.registry.resolve_model(candidate);
                    if cand_prov.name() == primary_prov_name && cand_actual == primary_actual {
                        continue;
                    }

                    match self
                        .chat_completion_with_model(messages, tools, candidate)
                        .await
                    {
                        Ok(completion) => {
                            tracing::info!(
                                from = %primary_model,
                                to = %candidate,
                                "LLM call succeeded via fallback candidate"
                            );
                            return Ok(completion);
                        }
                        Err(fb_err) => {
                            if !is_fallback_eligible_error(&fb_err) {
                                return Err(fb_err);
                            }
                            fallback_errors.push(format!("{candidate}: {fb_err}"));
                        }
                    }
                }

                if fallback_errors.is_empty() {
                    return Err(primary_err);
                }

                let errors_summary = fallback_errors.join("; ");
                Err(anyhow::anyhow!(
                    "All providers in fallback chain failed. Primary '{}' error: {}. Fallback errors: {}",
                    primary_model,
                    primary_err,
                    errors_summary
                ))
            }
        }
    }

    /// Convenience wrapper that uses the default provider's model with fallback chain execution.
    pub async fn chat(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> Result<ChatMessage> {
        let default_model = self.registry.default_qualified_model();
        self.chat_completion_with_fallback(messages, tools, &default_model)
            .await
            .map(|c| c.message)
    }

    /// Stream an already-complete `content` string through a token channel in small chunks.
    ///
    /// This avoids a second LLM API call when the full response is already available from a
    /// preceding non-streaming call.  The caller still sees tokens arrive progressively,
    /// keeping the Telegram streaming UX intact, but there is no risk of the SSE connection
    /// being dropped mid-stream and silently returning a truncated response.
    pub async fn stream_text(
        content: String,
        token_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<()> {
        const CHUNK_SIZE: usize = 30;

        let chars: Vec<char> = content.chars().collect();
        let mut start = 0;

        while start < chars.len() {
            let end = (start + CHUNK_SIZE).min(chars.len());
            let chunk: String = chars[start..end].iter().collect();
            start = end;

            if token_tx.send(chunk).await.is_err() {
                // Receiver dropped — stop early, this is not an error
                debug!("stream_text: receiver dropped — stopping early");
                return Ok(());
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
        }

        Ok(())
    }
}

/// Information about an OpenRouter model, deserialized from GET /api/v1/models.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_client_timeout_constant() {
        assert_eq!(DEFAULT_LLM_TIMEOUT, Duration::from_secs(120));
    }

    #[test]
    fn test_message_content_text_serializes_as_string() {
        let content = MessageContent::from_text("hello world");
        let json = serde_json::to_string(&content).unwrap();
        assert_eq!(json, r#""hello world""#);
    }

    #[test]
    fn test_message_content_parts_serializes_as_array() {
        let content = MessageContent::Parts(vec![ContentPart::Text {
            text: "hello".to_string(),
        }]);
        let json = serde_json::to_value(&content).unwrap();
        assert!(json.is_array());
        assert_eq!(json[0]["type"], "text");
        assert_eq!(json[0]["text"], "hello");
    }

    #[test]
    fn test_message_content_as_text_from_parts() {
        let content = MessageContent::Parts(vec![
            ContentPart::Text {
                text: "hello".to_string(),
            },
            ContentPart::ImageUrl {
                image_url: ImageUrlContent {
                    url: "data:image/png;base64,abc".to_string(),
                },
            },
        ]);
        assert_eq!(content.as_text(), "hello");
    }

    #[test]
    fn test_chat_request_serializes_model_field() {
        // Verifies the model string will appear in the JSON POST body
        let req = ChatRequest {
            model: "anthropic/claude-sonnet-4-6".to_string(),
            messages: vec![],
            tools: None,
            max_tokens: 100,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "anthropic/claude-sonnet-4-6");
    }

    #[test]
    fn test_chat_request_default_model_is_different_from_override() {
        // Ensures chat_completion_with_model can use a different model than the config default
        let default_req = ChatRequest {
            model: "moonshotai/kimi-k2.5".to_string(),
            messages: vec![],
            tools: None,
            max_tokens: 100,
        };
        let override_req = ChatRequest {
            model: "anthropic/claude-sonnet-4-6".to_string(),
            messages: vec![],
            tools: None,
            max_tokens: 100,
        };
        let json_default = serde_json::to_value(&default_req).unwrap();
        let json_override = serde_json::to_value(&override_req).unwrap();
        assert_ne!(json_default["model"], json_override["model"]);
    }

    #[test]
    fn test_chat_response_deserializes_finish_reason() {
        let json = r#"{
            "choices": [{
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop"
            }]
        }"#;
        let resp: ChatResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.choices[0].finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn test_parse_kimi_tool_calls_single_call() {
        let content = " <|tool_calls_section_begin|> <|tool_call_begin|> functions.read_skill_file:5 \
            <|tool_call_argument_begin|> {\"skill_name\": \"reddit-fetcher\", \"relative_path\": \"SKILL.md\"} \
            <|tool_call_end|> <|tool_calls_section_end|>";
        let calls = parse_kimi_tool_calls(content).expect("should parse");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "read_skill_file");
        assert_eq!(calls[0].call_type, "function");
        let args: serde_json::Value = serde_json::from_str(&calls[0].function.arguments).unwrap();
        assert_eq!(args["skill_name"], "reddit-fetcher");
    }

    #[test]
    fn test_parse_kimi_tool_calls_multiple_calls() {
        let content = "<|tool_calls_section_begin|>\
            <|tool_call_begin|> functions.tool_a:0 <|tool_call_argument_begin|> {\"x\": 1} <|tool_call_end|>\
            <|tool_call_begin|> functions.tool_b:1 <|tool_call_argument_begin|> {\"y\": 2} <|tool_call_end|>\
            <|tool_calls_section_end|>";
        let calls = parse_kimi_tool_calls(content).expect("should parse");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].function.name, "tool_a");
        assert_eq!(calls[1].function.name, "tool_b");
    }

    #[test]
    fn test_parse_kimi_tool_calls_no_markers_returns_none() {
        assert!(parse_kimi_tool_calls("Hello, world!").is_none());
        assert!(parse_kimi_tool_calls("").is_none());
    }

    #[test]
    fn test_parse_kimi_tool_calls_invalid_json_preserves_raw_arguments() {
        let content = "<|tool_calls_section_begin|>\
            <|tool_call_begin|> functions.my_tool:0 \
            <|tool_call_argument_begin|> not valid json <|tool_call_end|>\
            <|tool_calls_section_end|>";
        let calls = parse_kimi_tool_calls(content).expect("should parse");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.arguments, "not valid json");
    }

    #[test]
    fn test_parse_kimi_tool_calls_id_uses_index() {
        let content = "<|tool_calls_section_begin|>\
            <|tool_call_begin|> functions.do_thing:7 \
            <|tool_call_argument_begin|> {} <|tool_call_end|>\
            <|tool_calls_section_end|>";
        let calls = parse_kimi_tool_calls(content).expect("should parse");
        assert!(calls[0].id.contains("7"), "id should embed the call index");
    }

    #[tokio::test]
    async fn test_stream_text_sends_all_content() {
        let content = "Hello, world! This is a test of stream_text.".to_string();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);

        LlmClient::stream_text(content.clone(), tx).await.unwrap();

        let mut received = String::new();
        while let Ok(chunk) = rx.try_recv() {
            received.push_str(&chunk);
        }
        assert_eq!(received, content);
    }

    #[tokio::test]
    async fn test_stream_text_stops_when_receiver_dropped() {
        let content = "A".repeat(1000);
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        // Drop the receiver immediately — stream_text should return Ok without panic
        drop(rx);

        let result = LlmClient::stream_text(content, tx).await;
        assert!(
            result.is_ok(),
            "stream_text must return Ok even when receiver is dropped"
        );
    }

    #[test]
    fn test_sanitize_parameters_removes_undefined_required_entries() {
        // Google Gemini rejects required entries not present in properties.
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "foo": { "type": "string" }
            },
            "required": ["foo", "bar"]  // "bar" is not in properties
        });
        sanitize_parameters(&mut schema);
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "foo");
    }

    #[test]
    fn test_sanitize_parameters_removes_additional_properties() {
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        });
        sanitize_parameters(&mut schema);
        assert!(schema.get("additionalProperties").is_none());
    }

    #[test]
    fn test_sanitize_parameters_removes_schema_metadata_fields() {
        let mut schema = serde_json::json!({
            "type": "object",
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$defs": {},
            "$ref": "#/$defs/SomeType",
            "properties": {}
        });
        sanitize_parameters(&mut schema);
        assert!(schema.get("$schema").is_none());
        assert!(schema.get("$defs").is_none());
        assert!(schema.get("$ref").is_none());
    }

    #[test]
    fn test_sanitize_parameters_recurses_into_properties() {
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "x": { "type": "string" }
                    },
                    "required": ["x", "missing"],
                    "additionalProperties": true
                }
            }
        });
        sanitize_parameters(&mut schema);
        let nested = &schema["properties"]["nested"];
        let required = nested["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "x");
        assert!(nested.get("additionalProperties").is_none());
    }

    #[test]
    fn test_sanitize_parameters_recurses_into_array_items() {
        let mut schema = serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "a": { "type": "number" }
                },
                "required": ["a", "b"],
                "additionalProperties": false
            }
        });
        sanitize_parameters(&mut schema);
        let items = &schema["items"];
        let required = items["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "a");
        assert!(items.get("additionalProperties").is_none());
    }

    #[test]
    fn test_sanitize_parameters_valid_schema_unchanged() {
        // A schema that is already valid should pass through unmodified.
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path" }
            },
            "required": ["path"]
        });
        let original = schema.clone();
        sanitize_parameters(&mut schema);
        assert_eq!(schema, original);
    }

    #[test]
    fn test_sanitize_parameters_removes_empty_required_array() {
        // Gemini rejects required: [] — it must be omitted entirely.
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {},
            "required": ["a", "b"]  // neither "a" nor "b" is in properties
        });
        sanitize_parameters(&mut schema);
        // required should be gone, not left as []
        assert!(schema.get("required").is_none());
    }

    #[test]
    fn test_sanitize_parameters_strips_null_anyof_variants() {
        // Gemini does not support {"type": "null"} as a union member.
        // When only one variant remains after stripping, it is unwrapped.
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {
                    "anyOf": [
                        { "type": "string" },
                        { "type": "null" }
                    ]
                }
            }
        });
        sanitize_parameters(&mut schema);
        let name = &schema["properties"]["name"];
        // The null variant was stripped, leaving one variant which was unwrapped.
        assert!(name.get("anyOf").is_none(), "anyOf should be unwrapped");
        assert_eq!(name["type"], "string");
    }

    #[test]
    fn test_sanitize_parameters_recurses_into_anyof() {
        // Nested schemas inside anyOf/oneOf should also be sanitized.
        // Single-variant anyOf is unwrapped into the parent.
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "val": {
                    "anyOf": [
                        {
                            "type": "object",
                            "properties": { "x": { "type": "string" } },
                            "required": ["x", "missing"],
                            "additionalProperties": false
                        }
                    ]
                }
            }
        });
        sanitize_parameters(&mut schema);
        // Single-variant anyOf is unwrapped: inner object fields are inlined into "val".
        let val = &schema["properties"]["val"];
        assert!(val.get("anyOf").is_none(), "anyOf should be unwrapped");
        let required = val["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "x");
        assert!(val.get("additionalProperties").is_none());
    }

    #[test]
    fn test_empty_assistant_response_detects_null_content_no_tools() {
        let message = ChatMessage {
            role: "assistant".to_string(),
            content: None,
            tool_calls: None,
            tool_call_id: None,
        };
        assert!(is_empty_assistant_response(&message));
    }

    #[test]
    fn test_empty_assistant_response_detects_whitespace_content_no_tools() {
        let message = ChatMessage {
            role: "assistant".to_string(),
            content: Some(MessageContent::Text("  \n\t  ".to_string())),
            tool_calls: Some(vec![]),
            tool_call_id: None,
        };
        assert!(is_empty_assistant_response(&message));
    }

    #[test]
    fn test_empty_assistant_response_false_when_tool_calls_present() {
        let message = ChatMessage {
            role: "assistant".to_string(),
            content: None,
            tool_calls: Some(vec![ToolCall {
                id: "call_1".to_string(),
                call_type: "function".to_string(),
                function: FunctionCall {
                    name: "plan_view".to_string(),
                    arguments: "{}".to_string(),
                },
            }]),
            tool_call_id: None,
        };
        assert!(!is_empty_assistant_response(&message));
    }

    #[test]
    fn test_empty_assistant_response_false_when_content_present() {
        let message = ChatMessage {
            role: "assistant".to_string(),
            content: Some(MessageContent::Text("Done".to_string())),
            tool_calls: None,
            tool_call_id: None,
        };
        assert!(!is_empty_assistant_response(&message));
    }

    #[test]
    fn test_chat_completion_preserves_finish_reason() {
        let json = r#"{
            "choices": [{
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop"
            }]
        }"#;
        let resp: ChatResponse = serde_json::from_str(json).unwrap();
        let choice = resp.choices.into_iter().next().unwrap();
        let completion = ChatCompletion {
            message: choice.message,
            finish_reason: choice.finish_reason,
            model: "test-model".to_string(),
        };
        assert_eq!(completion.finish_reason.as_deref(), Some("stop"));
        assert_eq!(
            completion.message.content.as_ref().map(|c| c.as_text()),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_kimi_fallback_preserves_chat_completion_metadata() {
        // Simulates the Kimi fallback integration path in chat_completion_with_model.
        // When Kimi leaks native tool-call syntax into content, we parse it, clear
        // content, populate tool_calls, and set finish_reason to "tool_calls".
        let json = r#"{
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "<|tool_calls_section_begin|> <|tool_call_begin|> functions.read_skill_file:0 <|tool_call_argument_begin|> {\"skill_name\": \"reddit-fetcher\", \"relative_path\": \"SKILL.md\"} <|tool_call_end|> <|tool_calls_section_end|>"
                },
                "finish_reason": "stop"
            }]
        }"#;
        let resp: ChatResponse = serde_json::from_str(json).unwrap();
        let mut choice = resp.choices.into_iter().next().unwrap();

        // Apply the same Kimi parsing logic used in chat_completion_with_model
        let has_tool_calls = choice
            .message
            .tool_calls
            .as_ref()
            .is_some_and(|t| !t.is_empty());
        if !has_tool_calls {
            if let Some(ref content) = choice.message.content.clone() {
                if let Some(parsed) = parse_kimi_tool_calls(&content.as_text()) {
                    choice.message.tool_calls = Some(parsed);
                    choice.message.content = None;
                    choice.finish_reason = Some("tool_calls".to_string());
                }
            }
        }

        // Construct ChatCompletion as chat_completion_with_model does
        let completion = ChatCompletion {
            message: choice.message,
            finish_reason: choice.finish_reason,
            model: "moonshotai/kimi-k2.5".to_string(),
        };

        // Assert metadata is correctly preserved
        assert_eq!(
            completion.finish_reason.as_deref(),
            Some("tool_calls"),
            "finish_reason must be set to 'tool_calls'"
        );
        assert!(
            completion.message.content.is_none(),
            "content must be cleared when Kimi tool calls are parsed"
        );
        assert!(
            completion.message.tool_calls.is_some(),
            "tool_calls must be populated"
        );
        let tool_calls = completion.message.tool_calls.as_ref().unwrap();
        assert!(
            !tool_calls.is_empty(),
            "tool_calls must contain at least one entry"
        );
        assert_eq!(
            tool_calls[0].function.name, "read_skill_file",
            "parsed tool name must match the Kimi content"
        );
    }

    #[test]
    fn test_is_fallback_eligible_error() {
        for (status, body, expected) in [
            (400, "connection reset 503", false),
            (401, "timeout 503", false),
            (404, "connection reset", false),
            (422, "503", false),
            (503, "401 unauthorized schema invalid api key", true),
            (429, "forbidden", true),
        ] {
            let err = anyhow::Error::new(crate::provider::ProviderHttpError {
                provider: "test".into(),
                status: reqwest::StatusCode::from_u16(status).unwrap(),
                body: body.into(),
            })
            .context("outer context 400");
            assert_eq!(is_fallback_eligible_error(&err), expected);
        }
    }

    #[test]
    fn legacy_string_errors_are_not_authoritative() {
        // Eligible: 503, 429, 500, 502, 504, timeout, connection errors, resets
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!("503")));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "503 Service Unavailable"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "OpenRouter API error (503): Service Unavailable"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!("429")));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "429 Too Many Requests"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "rate limit exceeded"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "500 Internal Server Error"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "502 Bad Gateway"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "504 Gateway Timeout"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!("timeout")));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "request timed out"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "operation timed out after 30s"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "connection reset by peer"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "failed to connect to host"
        )));

        // Ineligible: 400 (bad request), 401/403 (auth errors), tool/schema errors
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!("400")));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "400 Bad Request"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "bad request: missing required field"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!("401")));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "401 Unauthorized"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "invalid api key"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "invalid_api_key"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!("403")));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "403 Forbidden"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "tool error: function not allowed"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "schema validation error: field missing"
        )));
        assert!(!is_fallback_eligible_error(&anyhow::anyhow!(
            "invalid tool schema"
        )));
    }

    #[tokio::test]
    async fn truncated_http_body_is_a_structured_network_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            assert!(socket.read(&mut buf).await.unwrap() > 0);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\npartial",
                )
                .await
                .unwrap();
        });
        let error = reqwest::Client::new()
            .get(format!("http://{addr}"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap_err();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
        assert!(is_fallback_eligible_error(&error.into()));
    }

    #[test]
    fn unknown_errors_do_not_trigger_fallback() {
        for text in [
            "503",
            "connection reset by peer",
            "timeout",
            "schema error 503",
        ] {
            assert!(!is_fallback_eligible_error(&anyhow::anyhow!(text)));
        }
    }

    type MockHandler = Arc<dyn Fn(&str) -> Result<ChatCompletion> + Send + Sync>;

    struct MockTestProvider {
        config: crate::provider::ProviderConfig,
        handler: MockHandler,
    }

    #[async_trait::async_trait]
    impl crate::provider::Provider for MockTestProvider {
        fn name(&self) -> &str {
            &self.config.name
        }
        fn default_model(&self) -> &str {
            &self.config.default_model
        }
        fn supports_vision(&self) -> bool {
            false
        }
        fn config(&self) -> &crate::provider::ProviderConfig {
            &self.config
        }
        async fn chat_completion(
            &self,
            _client: &reqwest::Client,
            _messages: &[ChatMessage],
            _tools: &[ToolDefinition],
            model: &str,
            _max_tokens: u32,
        ) -> Result<ChatCompletion> {
            (self.handler)(model)
        }
        async fn list_models(&self, _client: &reqwest::Client) -> Result<Vec<String>> {
            Ok(vec![self.config.default_model.clone()])
        }
    }

    fn make_mock_provider(
        name: &str,
        default_model: &str,
        handler: impl Fn(&str) -> Result<ChatCompletion> + Send + Sync + 'static,
    ) -> Arc<dyn crate::provider::Provider> {
        let config = crate::provider::ProviderConfig {
            name: name.to_string(),
            provider_type: crate::config::ProviderType::OpenAICompatible,
            base_url: "http://localhost:8080/v1".to_string(),
            api_key: None,
            default_model: default_model.to_string(),
            supports_vision: false,
            max_tokens: 1024,
            discover_models: false,
            context_window: 4096,
            context_window_cache: Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            parse_retry_limit: 0,
        };
        Arc::new(MockTestProvider {
            config,
            handler: Arc::new(handler),
        })
    }

    fn http_error(status: u16, body: &str) -> anyhow::Error {
        crate::provider::ProviderHttpError {
            provider: "mock".into(),
            status: reqwest::StatusCode::from_u16(status).unwrap(),
            body: body.into(),
        }
        .into()
    }

    fn make_user_message(text: &str) -> Vec<ChatMessage> {
        vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::from_text(text)),
            tool_calls: None,
            tool_call_id: None,
        }]
    }

    #[tokio::test]
    async fn test_fallback_503_on_primary_falls_back_to_200_on_fallback_provider() {
        let p1 = make_mock_provider("primary", "primary-model", |_| {
            Err(http_error(503, "401 unauthorized schema invalid api key"))
        });
        let p2 = make_mock_provider("secondary", "secondary-model", |model| {
            Ok(ChatCompletion {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: Some(MessageContent::Text("hello from fallback".into())),
                    tool_calls: None,
                    tool_call_id: None,
                },
                finish_reason: Some("stop".into()),
                model: model.to_string(),
            })
        });

        let mut providers = std::collections::HashMap::new();
        providers.insert("primary".to_string(), p1);
        providers.insert("secondary".to_string(), p2);

        let registry = Arc::new(crate::provider::ProviderRegistry::new_with_fallback(
            providers,
            "primary".to_string(),
            vec!["secondary/secondary-model".to_string()],
        ));
        let llm = LlmClient::new(registry);

        let messages = make_user_message("ping");
        let tools = vec![];
        let completion = llm
            .chat_completion_with_fallback(&messages, &tools, "primary/primary-model")
            .await
            .expect("should succeed via fallback provider");

        assert_eq!(
            completion.message.content.as_ref().map(|c| c.as_text()),
            Some("hello from fallback".to_string())
        );
        assert_eq!(completion.model, "secondary/secondary-model");
    }

    #[tokio::test]
    async fn test_fallback_401_on_primary_does_not_fallback() {
        let p1 = make_mock_provider("primary", "primary-model", |_| {
            Err(http_error(401, "connection reset 503 Unauthorized"))
        });
        let fallback_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fallback_called_clone = fallback_called.clone();
        let p2 = make_mock_provider("secondary", "secondary-model", move |model| {
            fallback_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(ChatCompletion {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: Some(MessageContent::Text("should not reach here".into())),
                    tool_calls: None,
                    tool_call_id: None,
                },
                finish_reason: Some("stop".into()),
                model: model.to_string(),
            })
        });

        let mut providers = std::collections::HashMap::new();
        providers.insert("primary".to_string(), p1);
        providers.insert("secondary".to_string(), p2);

        let registry = Arc::new(crate::provider::ProviderRegistry::new_with_fallback(
            providers,
            "primary".to_string(),
            vec!["secondary/secondary-model".to_string()],
        ));
        let llm = LlmClient::new(registry);

        let messages = make_user_message("ping");
        let tools = vec![];
        let err = llm
            .chat_completion_with_fallback(&messages, &tools, "primary/primary-model")
            .await
            .expect_err("should return 401 without fallback");

        assert!(err.to_string().contains("401"));
        assert!(!fallback_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_fallback_all_failing_produces_aggregated_error_mentioning_both_providers() {
        let p1 = make_mock_provider("primary", "primary-model", |_| {
            Err(http_error(503, "primary outage"))
        });
        let p2 = make_mock_provider("secondary", "secondary-model", |_| {
            Err(http_error(503, "secondary outage"))
        });

        let mut providers = std::collections::HashMap::new();
        providers.insert("primary".to_string(), p1);
        providers.insert("secondary".to_string(), p2);

        let registry = Arc::new(crate::provider::ProviderRegistry::new_with_fallback(
            providers,
            "primary".to_string(),
            vec!["secondary/secondary-model".to_string()],
        ));
        let llm = LlmClient::new(registry);

        let messages = make_user_message("ping");
        let tools = vec![];
        let err = llm
            .chat_completion_with_fallback(&messages, &tools, "primary/primary-model")
            .await
            .expect_err("should return aggregated error");

        let err_str = err.to_string();
        assert!(err_str.contains("All providers in fallback chain failed"));
        assert!(err_str.contains("primary/primary-model"));
        assert!(err_str.contains("secondary/secondary-model"));
        assert!(err_str.contains("primary outage"));
        assert!(err_str.contains("secondary outage"));
    }

    #[tokio::test]
    async fn test_fallback_candidate_returning_non_eligible_error_aborts_chain() {
        let p1 = make_mock_provider("primary", "primary-model", |_| {
            Err(http_error(503, "Service Unavailable"))
        });
        let p2 = make_mock_provider("secondary", "secondary-model", |_| {
            Err(http_error(401, "connection reset 503 Unauthorized"))
        });
        let p3_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let p3_called_clone = p3_called.clone();
        let p3 = make_mock_provider("tertiary", "tertiary-model", move |_| {
            p3_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(anyhow::anyhow!("503"))
        });

        let mut providers = std::collections::HashMap::new();
        providers.insert("primary".to_string(), p1);
        providers.insert("secondary".to_string(), p2);
        providers.insert("tertiary".to_string(), p3);

        let registry = Arc::new(crate::provider::ProviderRegistry::new_with_fallback(
            providers,
            "primary".to_string(),
            vec![
                "secondary/secondary-model".to_string(),
                "tertiary/tertiary-model".to_string(),
            ],
        ));
        let llm = LlmClient::new(registry);

        let messages = make_user_message("ping");
        let tools = vec![];
        let err = llm
            .chat_completion_with_fallback(&messages, &tools, "primary/primary-model")
            .await
            .expect_err("should stop on 401");

        assert!(err.to_string().contains("401"));
        assert!(!p3_called.load(std::sync::atomic::Ordering::SeqCst));
    }
}
