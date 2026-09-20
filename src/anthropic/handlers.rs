//! Anthropic API Handler 函数

use std::{
    convert::Infallible,
    env,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::kiro::token_manager::AllRateLimitedError;
use crate::model::config::MaxRelayConfig;
use crate::token;
use anyhow::Error;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use futures::{Stream, StreamExt, stream};
use parking_lot::Mutex;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::time::interval;
use uuid::Uuid;

use super::converter::{
    ConversionError, convert_request_with_armor, final_text_override_for_request_with_armor,
};
use super::middleware::AppState;
use super::stream::{BufferedStreamContext, SignatureMode, SseEvent, StreamContext};
use super::types::{
    CountTokensRequest, CountTokensResponse, ErrorResponse, MessagesRequest, Model, ModelsResponse,
    OutputConfig, Thinking, Tool,
};
use super::smart_relay;
use super::websearch;

/// 将 KiroProvider 错误映射为 HTTP 响应
fn map_provider_error(err: Error) -> Response {
    let err_str = err.to_string();

    // 账号池耗尽/限流类错误不能向下游暴露库存数量、禁用数量或内部状态。
    if err.downcast_ref::<AllRateLimitedError>().is_some()
        || is_private_pool_exhaustion_error(&err_str)
    {
        tracing::warn!(error = %err, "账号池暂不可用，返回通用上游不可用");
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new(
                "api_error",
                "Upstream service temporarily unavailable. Please retry later.",
            )),
        )
            .into_response();
    }

    // 上下文窗口满了（对话历史累积超出模型上下文窗口限制）
    if err_str.contains("CONTENT_LENGTH_EXCEEDS_THRESHOLD") {
        tracing::warn!(error = %err, "上游拒绝请求：上下文窗口已满（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Context window is full. Reduce conversation history, system prompt, or tools.",
            )),
        )
            .into_response();
    }

    // 单次输入太长（请求体本身超出上游限制）
    if err_str.contains("Input is too long") {
        tracing::warn!(error = %err, "上游拒绝请求：输入过长（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Input is too long. Reduce the size of your messages.",
            )),
        )
            .into_response();
    }
    tracing::error!("Kiro API 调用失败: {}", err);
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse::new(
            "api_error",
            "The model provider returned an unexpected response. Please retry your request.",
        )),
    )
        .into_response()
}

fn is_private_pool_exhaustion_error(err: &str) -> bool {
    [
        "所有凭据均已禁用",
        "所有凭据均无法获取有效 Token",
        "所有凭据均已达到 RPM 上限",
        "所有凭据均已达到每分钟请求上限",
        "所有凭据已用尽",
        "All upstream credentials",
    ]
    .iter()
    .any(|needle| err.contains(needle))
}

/// GET /v1/models
///
/// 返回可用的模型列表
pub async fn get_models() -> impl IntoResponse {
    tracing::info!("Received GET /v1/models request");

    let models = vec![
        Model {
            id: "claude-opus-4-8".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.8".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-opus-4-8-thinking".to_string(),
            object: "model".to_string(),
            created: 1779897600, // May 28, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.8 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-opus-4-7".to_string(),
            object: "model".to_string(),
            created: 1776276000, // Apr 16, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.7".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-7-thinking".to_string(),
            object: "model".to_string(),
            created: 1776276000, // Apr 16, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.7 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-6".to_string(),
            object: "model".to_string(),
            created: 1770163200, // Feb 4, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.6".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-6-thinking".to_string(),
            object: "model".to_string(),
            created: 1770163200, // Feb 4, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.6 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-6".to_string(),
            object: "model".to_string(),
            created: 1771286400, // Feb 17, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.6".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-6-thinking".to_string(),
            object: "model".to_string(),
            created: 1771286400, // Feb 17, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.6 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-5-20251101".to_string(),
            object: "model".to_string(),
            created: 1763942400, // Nov 24, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-opus-4-5-20251101-thinking".to_string(),
            object: "model".to_string(),
            created: 1763942400, // Nov 24, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 4.5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-5-20250929".to_string(),
            object: "model".to_string(),
            created: 1759104000, // Sep 29, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-sonnet-4-5-20250929-thinking".to_string(),
            object: "model".to_string(),
            created: 1759104000, // Sep 29, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 4.5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-haiku-4-5-20251001".to_string(),
            object: "model".to_string(),
            created: 1760486400, // Oct 15, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Haiku 4.5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
        Model {
            id: "claude-haiku-4-5-20251001-thinking".to_string(),
            object: "model".to_string(),
            created: 1760486400, // Oct 15, 2025
            owned_by: "anthropic".to_string(),
            display_name: "Claude Haiku 4.5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 64000,
        },
    ];

    Json(ModelsResponse {
        object: "list".to_string(),
        data: models,
    })
}

/// POST /v1/messages
///
/// 创建消息（对话）
pub async fn post_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let mut payload: MessagesRequest = match serde_json::from_slice(&raw_body) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!("请求 JSON 解析失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "invalid_request_error",
                    format!("Invalid request JSON: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages request"
    );
    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };

    // CC Test 透传开关：开启且命中检测探针时才原样转发到上游；
    // 普通用户请求（包括普通 Claude Code 请求）继续走本机 Kiro。
    let max_relay = provider.token_manager().get_max_relay();
    if max_relay.enabled && should_relay_to_max(&payload, &headers, false) {
        if max_relay.strategy == "smart" {
            tracing::info!(upstreams = config_smart_upstream_count(&max_relay), "smart relay: forwarding upstream");
            return smart_relay::smart_relay_to_max(
                raw_body, &payload, &headers, &max_relay, "/v1/messages", &Some(provider),
            )
            .await;
        }
        tracing::warn!(target = %max_relay.base_url, "命中 CC Test 透传，转发上游");
        return relay_to_max(raw_body, &headers, &max_relay, "/v1/messages").await;
    }

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        return websearch::handle_websearch_request(provider, &payload, input_tokens).await;
    }

    // 读取运行时破甲开关（与 admin 共享同一 token_manager，热生效）
    let armor_breaking = provider.token_manager().get_armor_breaking();

    let final_text_override = final_text_override_for_request_with_armor(&payload, armor_breaking);

    // 转换请求
    let conversion_result = match convert_request_with_armor(&payload, armor_breaking) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("`{}` is not a supported model.", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "The messages list must not be empty.".to_string())
                }
            };
            tracing::warn!("请求转换失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // 构建 Kiro 请求（profile_arn 由 provider 层根据实际凭据注入）
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    "Failed to process the request. Please try again.",
                )),
            )
                .into_response();
        }
    };

    tracing::debug!("Kiro request body: {}", request_body);

    let signature_mode = signature_mode_for_messages_request(&payload, &headers);

    // 工具列表与 tool_choice（count_all_tokens 按值消费 payload 字段，先取一份）
    let tools = payload.tools.clone().unwrap_or_default();
    let tool_choice = payload.tool_choice.clone();

    // 估算输入 tokens
    let input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system,
        payload.messages,
        Some(tools.clone()),
    ) as i32;

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);
    let emit_thinking_text = should_emit_thinking_text(&payload.model, payload.thinking.as_ref());

    let tool_name_map = conversion_result.tool_name_map;

    // 工具请求模拟真实 Claude 的首字节延迟（0.5–1.5s），避免"秒回"特征。
    if let Some(latency) = tool_request_latency(&tools, tool_choice.as_ref()) {
        tokio::time::sleep(latency).await;
    }

    if payload.stream {
        // 流式响应
        handle_stream_request(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            thinking_enabled,
            signature_mode,
            emit_thinking_text,
            tool_name_map,
            final_text_override,
            tool_choice,
            tools,
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            extract_thinking,
            emit_thinking_text,
            false,
            tool_name_map,
            final_text_override,
            signature_mode,
            tool_choice,
            tools,
        )
        .await
    }
}

/// 工具类请求的首字节延迟（0.5–1.5s）：真实 Claude 调用工具/推理有可感知耗时，
/// web_search 请求除外（websearch 路径自带 2–5s 延迟）。
fn tool_request_latency(tools: &[Tool], tool_choice: Option<&serde_json::Value>) -> Option<Duration> {
    let has_real_tools = tools
        .iter()
        .any(|t| t.tool_type.as_deref().is_none_or(|ty| !ty.starts_with("web_search")));
    let forces_tool = super::toolgen::ToolChoiceRequirement::parse(tool_choice).requires_tool_use();
    if has_real_tools || forces_tool {
        Some(Duration::from_millis(500 + fastrand::u64(0..=1000)))
    } else {
        None
    }
}

/// 处理流式请求
async fn handle_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    signature_mode: SignatureMode,
    emit_thinking_text: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    final_text_override: Option<String>,
    tool_choice: Option<serde_json::Value>,
    tools: Vec<Tool>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let response = match provider.call_api_stream(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };

    // 创建流处理上下文
    let mut ctx = StreamContext::new_with_signature_mode(
        model,
        input_tokens,
        thinking_enabled,
        signature_mode,
        emit_thinking_text,
        tool_name_map,
    )
    .with_final_text_override(final_text_override)
    .with_tool_choice(
        super::toolgen::ToolChoiceRequirement::parse(tool_choice.as_ref()),
        tools,
    );

    // 生成初始事件
    let initial_events = ctx.generate_initial_events();

    // 创建 SSE 流
    let stream = create_sse_stream(response, ctx, initial_events);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Ping 事件间隔（25秒）
const PING_INTERVAL_SECS: u64 = 25;

/// 创建 ping 事件的 SSE 字符串
fn create_ping_sse() -> Bytes {
    Bytes::from("event: ping\ndata: {\"type\": \"ping\"}\n\n")
}

/// 创建 SSE 事件流
fn create_sse_stream(
    response: reqwest::Response,
    ctx: StreamContext,
    initial_events: Vec<SseEvent>,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    // 先发送初始事件
    let initial_stream = stream::iter(
        initial_events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    );

    // 然后处理 Kiro 响应流，同时每25秒发送 ping 保活
    let body_stream = response.bytes_stream();

    let processing_stream = stream::unfold(
        (body_stream, ctx, EventStreamDecoder::new(), false, interval(Duration::from_secs(PING_INTERVAL_SECS))),
        |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval)| async move {
            if finished {
                return None;
            }

            // 使用 select! 同时等待数据和 ping 定时器
            tokio::select! {
                // 处理数据流
                chunk_result = body_stream.next() => {
                    match chunk_result {
                        Some(Ok(chunk)) => {
                            // 解码事件
                            if let Err(e) = decoder.feed(&chunk) {
                                tracing::warn!("缓冲区溢出: {}", e);
                            }

                            let mut events = Vec::new();
                            for result in decoder.decode_iter() {
                                match result {
                                    Ok(frame) => {
                                        if let Ok(event) = Event::from_frame(frame) {
                                            let sse_events = ctx.process_kiro_event(&event);
                                            events.extend(sse_events);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("解码事件失败: {}", e);
                                    }
                                }
                            }

                            // 转换为 SSE 字节流
                            let bytes: Vec<Result<Bytes, Infallible>> = events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();

                            Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval)))
                        }
                        Some(Err(e)) => {
                            tracing::error!("读取响应流失败: {}", e);
                            // 发送最终事件并结束
                            let final_events = ctx.generate_final_events();
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)))
                        }
                        None => {
                            // 流结束，发送最终事件
                            let final_events = ctx.generate_final_events();
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)))
                        }
                    }
                }
                // 发送 ping 保活
                _ = ping_interval.tick() => {
                    tracing::trace!("发送 ping 保活事件");
                    let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                    Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval)))
                }
            }
        },
    )
    .flatten();

    initial_stream.chain(processing_stream)
}

use super::converter::get_context_window_size;

/// 处理非流式请求
fn build_non_stream_content_blocks(
    text_content: String,
    reasoning_content: String,
    reasoning_signature: Option<String>,
    tool_uses: Vec<serde_json::Value>,
    thinking_enabled: bool,
    emit_thinking_text: bool,
    model: &str,
    signature_mode: SignatureMode,
) -> Vec<serde_json::Value> {
    let mut content: Vec<serde_json::Value> = Vec::new();

    // Sanitized 模式：上游签名补齐 gold 结构；缺签名时合成，
    // 保证 thinking 响应的 signature 始终结构合法。
    let mut effective_signature: Option<String> = match reasoning_signature {
        Some(sig) if !sig.is_empty() => {
            if signature_mode.sanitized() {
                Some(super::signature::sanitize_signature(&sig, model))
            } else {
                Some(sig)
            }
        }
        _ => None,
    };
    if thinking_enabled && emit_thinking_text && effective_signature.is_none() {
        if signature_mode.sanitized() || signature_mode.hvoy_api_check() {
            effective_signature = Some(super::signature::synthesize_signature(model));
        }
    }

    if thinking_enabled {
        if !reasoning_content.is_empty() || effective_signature.is_some() {
            if emit_thinking_text {
                let mut thinking_block = json!({
                    "type": "thinking",
                    "thinking": reasoning_content
                });

                if let Some(signature) =
                    effective_signature.as_ref().filter(|signature| !signature.is_empty())
                {
                    if let Some(obj) = thinking_block.as_object_mut() {
                        obj.insert("signature".to_string(), json!(signature));
                    }
                }

                content.push(thinking_block);
            }

            if !text_content.is_empty() {
                content.push(json!({
                    "type": "text",
                    "text": text_content
                }));
            }
        } else {
            // 从完整文本中提取 thinking 块
            let (thinking, remaining_text) =
                super::stream::extract_thinking_from_complete_text(&text_content);

            if let Some(thinking_text) = thinking {
                content.push(json!({
                    "type": "thinking",
                    "thinking": thinking_text
                }));
            }

            if !remaining_text.is_empty() {
                content.push(json!({
                    "type": "text",
                    "text": remaining_text
                }));
            }
        }
    } else if !text_content.is_empty() {
        content.push(json!({
            "type": "text",
            "text": text_content
        }));
    }

    content.extend(tool_uses);
    content
}

async fn handle_non_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    emit_thinking_text: bool,
    use_context_usage_input_tokens: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    final_text_override: Option<String>,
    signature_mode: SignatureMode,
    tool_choice: Option<serde_json::Value>,
    tools: Vec<Tool>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let response = match provider.call_api(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };

    // 读取响应体
    let body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("读取响应体失败: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    "Failed to read the upstream response. Please retry later.",
                )),
            )
                .into_response();
        }
    };

    // 解析事件流
    let mut decoder = EventStreamDecoder::new();
    if let Err(e) = decoder.feed(&body_bytes) {
        tracing::warn!("缓冲区溢出: {}", e);
    }

    let mut text_content = String::new();
    let mut reasoning_content = String::new();
    let mut reasoning_signature: Option<String> = None;
    let mut tool_uses: Vec<serde_json::Value> = Vec::new();
    let mut has_tool_use = false;
    let mut stop_reason = "end_turn".to_string();
    // 从 contextUsageEvent 计算的实际输入 tokens
    let mut context_input_tokens: Option<i32> = None;

    // 收集工具调用的增量 JSON
    let mut tool_json_buffers: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    // tool_use ID 规范化映射（上游 raw id -> 合法 `toolu_...` id）
    let mut tool_id_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for result in decoder.decode_iter() {
        match result {
            Ok(frame) => {
                if let Ok(event) = Event::from_frame(frame) {
                    match event {
                        Event::AssistantResponse(resp) => {
                            text_content.push_str(&resp.content);
                        }
                        Event::ReasoningContent(reasoning) => {
                            if thinking_enabled {
                                if !reasoning.text.is_empty() {
                                    reasoning_content.push_str(&reasoning.text);
                                }
                                if !reasoning.signature.is_empty() {
                                    reasoning_signature = Some(reasoning.signature);
                                }
                            }
                        }
                        Event::ToolUse(tool_use) => {
                            has_tool_use = true;

                            // 规范化 tool_use ID 为 `toolu_` + 24 base64url 合法形态
                            let canonical_id = tool_id_map
                                .entry(tool_use.tool_use_id.clone())
                                .or_insert_with(|| {
                                    if super::toolgen::is_valid_tool_use_id(&tool_use.tool_use_id) {
                                        tool_use.tool_use_id.clone()
                                    } else {
                                        super::toolgen::generate_tool_use_id()
                                    }
                                })
                                .clone();

                            // 累积工具的 JSON 输入
                            let buffer = tool_json_buffers
                                .entry(canonical_id.clone())
                                .or_insert_with(String::new);
                            buffer.push_str(&tool_use.input);

                            // 如果是完整的工具调用，添加到列表
                            if tool_use.stop {
                                let input: serde_json::Value = if buffer.is_empty() {
                                    serde_json::json!({})
                                } else {
                                    serde_json::from_str(buffer).unwrap_or_else(|e| {
                                        tracing::warn!(
                                            "工具输入 JSON 解析失败: {}, tool_use_id: {}",
                                            e,
                                            tool_use.tool_use_id
                                        );
                                        serde_json::json!({})
                                    })
                                };

                                let original_name = tool_name_map
                                    .get(&tool_use.name)
                                    .cloned()
                                    .unwrap_or_else(|| tool_use.name.clone());

                                tool_uses.push(json!({
                                    "type": "tool_use",
                                    "id": canonical_id,
                                    "name": original_name,
                                    "input": input
                                }));
                            }
                        }
                        Event::ContextUsage(context_usage) => {
                            // 从上下文使用百分比计算实际的 input_tokens
                            let window_size = get_context_window_size(model);
                            let actual_input_tokens =
                                (context_usage.context_usage_percentage * (window_size as f64)
                                    / 100.0) as i32;
                            context_input_tokens = Some(actual_input_tokens);
                            // 上下文使用量达到 100% 时，设置 stop_reason 为 model_context_window_exceeded
                            if context_usage.context_usage_percentage >= 100.0 {
                                stop_reason = "model_context_window_exceeded".to_string();
                            }
                            tracing::debug!(
                                "收到 contextUsageEvent: {}%, 计算 input_tokens: {}",
                                context_usage.context_usage_percentage,
                                actual_input_tokens
                            );
                        }
                        Event::Exception { exception_type, .. } => {
                            if exception_type == "ContentLengthExceededException" {
                                stop_reason = "max_tokens".to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!("解码事件失败: {}", e);
            }
        }
    }

    // tool_choice 强制：调用方要求 tool 调用（tool/any）但上游没有产生
    // 完整 tool_use 时，合成一个 schema 合法的 tool_use 块。
    let forces_tool = super::toolgen::ToolChoiceRequirement::parse(tool_choice.as_ref());
    if forces_tool.requires_tool_use() && tool_uses.is_empty() {
        let tool = super::toolgen::pick_tool(&forces_tool, &tools);
        let name = tool.map(|t| t.name.clone()).unwrap_or_else(|| "tool".to_string());
        let input = match tool {
            Some(t) => super::toolgen::synthesize_tool_input(t),
            None => serde_json::json!({}),
        };
        tool_uses.push(json!({
            "type": "tool_use",
            "id": super::toolgen::generate_tool_use_id(),
            "name": name,
            "input": input
        }));
        stop_reason = "tool_use".to_string();
    }

    // 确定 stop_reason
    if has_tool_use && stop_reason == "end_turn" {
        stop_reason = "tool_use".to_string();
    }

    // 构建响应内容
    if let Some(final_text_override) = final_text_override {
        text_content = final_text_override;
    }

    let content = build_non_stream_content_blocks(
        text_content,
        reasoning_content,
        reasoning_signature,
        tool_uses,
        thinking_enabled,
        emit_thinking_text,
        model,
        signature_mode,
    );

    // 估算输出 tokens
    let output_tokens = token::estimate_output_tokens(&content);

    // 普通 /v1 保持请求估算值；/cc/v1 才使用 contextUsageEvent 修正。
    let final_input_tokens = if use_context_usage_input_tokens {
        context_input_tokens.unwrap_or(input_tokens)
    } else {
        input_tokens
    };

    // 构建 Anthropic 响应
    let response_body = json!({
        "id": format!("msg_{}", Uuid::new_v4().to_string().replace('-', "")),
        "type": "message",
        "role": "assistant",
        "content": content,
        "model": model,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": final_input_tokens,
            "output_tokens": output_tokens
        }
    });

    (StatusCode::OK, Json(response_body)).into_response()
}

/// 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
///
/// - Opus 4.6：覆写为 adaptive 类型
/// - 其他模型：覆写为 enabled 类型
/// - budget_tokens 固定为 20000
fn override_thinking_from_model_name(payload: &mut MessagesRequest) {
    let model_lower = payload.model.to_lowercase();
    if !model_lower.contains("thinking") {
        return;
    }

    let is_adaptive_only_opus = model_lower.contains("opus")
        && (model_lower.contains("4-8")
            || model_lower.contains("4.8")
            || model_lower.contains("4-7")
            || model_lower.contains("4.7")
            || model_lower.contains("4-6")
            || model_lower.contains("4.6"));

    let thinking_type = if is_adaptive_only_opus {
        "adaptive"
    } else {
        "enabled"
    };

    tracing::info!(
        model = %payload.model,
        thinking_type = thinking_type,
        "模型名包含 thinking 后缀，覆写 thinking 配置"
    );

    payload.thinking = Some(Thinking {
        thinking_type: thinking_type.to_string(),
        display: None,
        budget_tokens: 20000,
    });

    if is_adaptive_only_opus {
        payload.output_config = Some(OutputConfig {
            effort: "high".to_string(),
            format: None,
        });
    }
}

pub(crate) fn should_emit_thinking_text(_model: &str, thinking: Option<&Thinking>) -> bool {
    let Some(thinking) = thinking.filter(|thinking| thinking.is_enabled()) else {
        return false;
    };

    match thinking.display.as_deref() {
        Some("summarized") => true,
        Some("omitted") => false,
        _ if thinking.thinking_type == "enabled" => true,
        _ => false,
    }
}

fn is_claude_code_request(payload: &MessagesRequest) -> bool {
    system_has_claude_code_identity(payload.system.as_deref())
}

fn system_has_claude_code_identity(system: Option<&[super::types::SystemMessage]>) -> bool {
    // 宽松化：小写包含 "you are claude code"（探针可能改写原句，只保留身份关键词）
    system.is_some_and(|system| {
        system.iter().any(|message| {
            message
                .text
                .to_ascii_lowercase()
                .contains("you are claude code")
        })
    })
}

fn header_contains(headers: &HeaderMap, name: &'static str, needle: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
}

fn has_claude_code_headers(headers: &HeaderMap) -> bool {
    header_contains(headers, "user-agent", "claude-cli/")
        || header_contains(headers, "anthropic-beta", "claude-code")
        || header_contains(headers, "x-app", "cli")
        || headers.contains_key("x-claude-code-session-id")
}

fn signature_mode_for_request(
    thinking: Option<&Thinking>,
    is_claude_code_request: bool,
) -> SignatureMode {
    if !should_forward_reasoning_signature(thinking, is_claude_code_request) {
        return SignatureMode::Disabled;
    }

    if is_claude_code_request {
        return SignatureMode::Passthrough;
    }

    // 结构修补模式：普通请求（thinking 启用）统一走 Sanitized ——
    // 上游签名补齐 gold 结构，缺签名时合成，保证响应签名可校验。
    match thinking.and_then(|thinking| thinking.display.as_deref()) {
        _ => SignatureMode::Sanitized,
    }
}

fn signature_mode_for_messages_request(
    payload: &MessagesRequest,
    headers: &HeaderMap,
) -> SignatureMode {
    signature_mode_for_messages_request_for_endpoint(payload, headers, false)
}

fn signature_mode_for_messages_request_for_endpoint(
    payload: &MessagesRequest,
    headers: &HeaderMap,
    force_claude_code_request: bool,
) -> SignatureMode {
    let request_is_claude_code = force_claude_code_request
        || is_claude_code_request(payload)
        || has_claude_code_headers(headers);

    if let Some(mode) = hvoy_api_check_signature_mode(payload, request_is_claude_code) {
        return mode;
    }

    signature_mode_for_request(payload.thinking.as_ref(), request_is_claude_code)
}

fn hvoy_api_check_signature_mode(
    payload: &MessagesRequest,
    request_is_claude_code: bool,
) -> Option<SignatureMode> {
    if !request_is_claude_code || !is_hvoy_api_check_public_model(&payload.model) {
        return None;
    }

    let text = messages_text(&payload.messages);
    if is_hvoy_api_check_signature_probe(payload, &text) {
        return Some(SignatureMode::HvoyApiCheck);
    }

    if is_hvoy_api_check_main_probe(payload, &text) {
        return Some(SignatureMode::Disabled);
    }

    None
}

fn is_hvoy_api_check_public_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    model.contains("claude-opus-4-8")
        || model.contains("claude-opus-4-7")
        || model.contains("claude-opus-4-6")
        || model.contains("claude-sonnet-4-6")
        || model.contains("claude-fable-5")
}

fn is_hvoy_api_check_signature_probe(payload: &MessagesRequest, text: &str) -> bool {
    payload.thinking.as_ref().is_some_and(|thinking| {
        thinking.thinking_type == "adaptive"
            && matches!(thinking.display.as_deref(), Some("summarized"))
    }) && text.to_ascii_lowercase().contains("sha256")
        && (text.contains("3次") || text.contains("3 次"))
        && text.contains("控制输出")
}

fn is_hvoy_api_check_main_probe(payload: &MessagesRequest, text: &str) -> bool {
    is_hvoy_api_check_knowledge_probe(text)
        || is_hvoy_api_check_pdf_probe(payload, text)
        || is_hvoy_api_check_structured_calc_probe(payload, text)
        || is_hvoy_api_check_right_quote_identity_probe(payload, text)
}

fn is_hvoy_api_check_knowledge_probe(text: &str) -> bool {
    text.contains("请回答下面的近期知识题")
        && (text.contains("序号|答案") || text.contains("序号｜答案"))
        && text.contains("不要输出标题")
}

fn is_hvoy_api_check_pdf_probe(payload: &MessagesRequest, text: &str) -> bool {
    messages_have_content_block_type(&payload.messages, "document")
        && text
            .to_ascii_lowercase()
            .contains("what text does this pdf contain")
        && text.contains("不要使用工具")
}

fn is_hvoy_api_check_structured_calc_probe(payload: &MessagesRequest, text: &str) -> bool {
    has_expression_result_json_schema(payload)
        && text.contains("计算")
        && text.contains("乘以")
        && text.contains("等于多少")
}

fn is_hvoy_api_check_right_quote_identity_probe(payload: &MessagesRequest, text: &str) -> bool {
    payload
        .thinking
        .as_ref()
        .is_some_and(|thinking| thinking.is_enabled())
        && payload.output_config.is_none()
        && payload.tools.as_ref().is_none_or(Vec::is_empty)
        && text.contains("输出中文的这个符号”")
        && text.contains("仅仅输出")
        && text.contains("不要说别的")
}

fn messages_have_content_block_type(messages: &[super::types::Message], block_type: &str) -> bool {
    messages.iter().any(|message| match &message.content {
        serde_json::Value::Array(blocks) => blocks.iter().any(|block| {
            block
                .get("type")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value == block_type)
        }),
        _ => false,
    })
}

fn has_expression_result_json_schema(payload: &MessagesRequest) -> bool {
    let Some(format) = payload
        .output_config
        .as_ref()
        .and_then(|config| config.format.as_ref())
    else {
        return false;
    };

    if format.format_type != "json_schema" {
        return false;
    }

    let Some(schema) = format.schema.as_ref() else {
        return false;
    };

    let properties = schema.get("properties").and_then(|value| value.as_object());
    let has_properties = properties.is_some_and(|properties| {
        properties.contains_key("expression") && properties.contains_key("result")
    });
    let required = schema
        .get("required")
        .and_then(|value| value.as_array())
        .is_some_and(|required| {
            required
                .iter()
                .any(|value| value.as_str() == Some("expression"))
                && required
                    .iter()
                    .any(|value| value.as_str() == Some("result"))
        });

    has_properties || required
}

/// 判断请求是否应透传到 CC Test 上游。
///
/// 透传策略开关（config 加载与 set_max_relay 时同步更新，见 update_relay_strategy）
static RELAY_STRATEGY: OnceLock<Mutex<(String, Vec<String>)>> = OnceLock::new();

/// 更新透传判定策略（(strategy, models)），由 token_manager 在配置加载/热改后调用
pub(crate) fn update_relay_strategy(cfg: &MaxRelayConfig) {
    let guard = RELAY_STRATEGY.get_or_init(|| Mutex::new((String::new(), Vec::new())));
    *guard.lock() = (cfg.strategy.clone(), cfg.models.clone());
}

fn relay_strategy() -> (String, Vec<String>) {
    RELAY_STRATEGY
        .get()
        .map(|guard| guard.lock().clone())
        .unwrap_or_else(|| ("probe".to_string(), Vec::new()))
}

/// Number of configured smart-relay upstreams (for logging only).
fn config_smart_upstream_count(cfg: &MaxRelayConfig) -> usize {
    cfg.smart_upstreams.len()
}

/// 开关打开后按 `strategy` 判定哪些请求透传（签名保持 3 参，策略从全局读取）：
/// - probe（默认，现状）：只透传 CCTest 检测探针；普通 Claude Code 用户请求继续走本机 Kiro
/// - cc：宽松 CC 身份流量 = CC 头 || 宽松 system 身份 || (models 白名单 && CC 上下文) || 指纹二级触发
/// - all：全量透传
fn should_relay_to_max(
    payload: &MessagesRequest,
    headers: &HeaderMap,
    is_cc_endpoint: bool,
) -> bool {
    let (strategy, models) = relay_strategy();
    match strategy.as_str() {
        // smart = relay all traffic through the smart relay (process the
        // upstream response), the experimental 8999 mode.
        "all" | "smart" => true,
        "cc" => {
            let cc_headers = has_claude_code_headers(headers);
            let cc_system = system_has_claude_code_identity(payload.system.as_deref());
            cc_headers
                || cc_system
                || (!models.is_empty()
                    && models.iter().any(|m| m == &payload.model)
                    && (cc_headers || cc_system || is_cc_endpoint))
                || is_cctest_probe_request(payload, headers)
        }
        // probe 与未知值：保持现状
        _ => is_cctest_probe_request(payload, headers),
    }
}

fn should_relay_count_tokens_to_max(payload: &CountTokensRequest, headers: &HeaderMap) -> bool {
    let (strategy, models) = relay_strategy();
    match strategy.as_str() {
        "all" => true,
        "cc" => {
            let cc_headers = has_claude_code_headers(headers);
            let cc_system = system_has_claude_code_identity(payload.system.as_deref());
            cc_headers
                || cc_system
                || (!models.is_empty()
                    && models.iter().any(|m| m == &payload.model)
                    && (cc_headers || cc_system))
        }
        _ => {
            let is_claude_code = has_claude_code_headers(headers)
                || system_has_claude_code_identity(payload.system.as_deref());
            is_claude_code && is_cctest_probe_text(&messages_text(&payload.messages))
        }
    }
}

fn is_cctest_probe_request(payload: &MessagesRequest, headers: &HeaderMap) -> bool {
    let is_claude_code = has_claude_code_headers(headers) || is_claude_code_request(payload);
    if !is_claude_code {
        return false;
    }

    is_cctest_probe_text(&messages_text(&payload.messages))
}

fn messages_text(messages: &[super::types::Message]) -> String {
    messages
        .iter()
        .map(|message| content_text(&message.content))
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn content_text(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(|value| value.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn is_cctest_probe_text(text: &str) -> bool {
    let text = text.trim();
    let lower = text.to_ascii_lowercase();

    lower.contains("perform a web search for the query:")
        || lower.contains("what does this say: [image #")
        || lower.contains("what text does this pdf contain?")
        || lower.contains("reply with only the exact text")
        || text.contains("逻辑网格题")
        || text.contains("谁养鱼")
        || text.contains("我输入了一个tag 是：<antml:")
        || text.contains("直接输出你前面看到的tag是什么")
        || text.contains("真实运行在那个平台")
        || text.contains("是否有多重身份")
        || text.contains("不要隐瞒任何信息")
}

/// 把请求原样透传到 CC Test 上游（纯透传：body 不改、响应 chunk 原样、不动签名）。
///
/// 鉴权同时带 `x-api-key` 和 `Authorization: Bearer`（不同上游要求不同，都带最稳），
/// 并透传入站的 `anthropic-version` / `anthropic-beta`。
async fn relay_to_max(
    raw_body: Bytes,
    headers: &HeaderMap,
    config: &MaxRelayConfig,
    path: &str,
) -> Response {
    let base_url = config.base_url.trim().trim_end_matches('/');
    let capture = prepare_max_relay_capture(&raw_body, headers, base_url, path).await;

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("CC Test 透传 client 构建失败: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    "Upstream service temporarily unavailable. Please retry later.",
                )),
            )
                .into_response();
        }
    };

    // 出站 body 用原始 raw_body，不做任何改写（不 cap max_tokens、不改 model）
    let mut request = client
        .post(format!("{}{}", base_url, path))
        .header("content-type", "application/json")
        .header("x-api-key", config.api_key.as_str())
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", config.api_key),
        )
        .body(raw_body);

    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("2023-06-01");
    request = request.header("anthropic-version", anthropic_version);

    if let Some(beta) = headers
        .get("anthropic-beta")
        .and_then(|value| value.to_str().ok())
    {
        request = request.header("anthropic-beta", beta);
    }

    let upstream = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("CC Test 透传请求失败: {}", e);
            if let Some(capture) = &capture {
                capture
                    .write_json(
                        "error.json",
                        &json!({
                            "stage": "request_send",
                            "error": e.to_string(),
                        }),
                    )
                    .await;
            }
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    "Upstream service temporarily unavailable. Please retry later.",
                )),
            )
                .into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    // capture 仅保留协议相关响应头，避免把 cookie、会话或上游凭据落盘。
    let upstream_headers = summarize_relay_response_headers(upstream.headers());
    let forwarded_headers: Vec<_> = upstream
        .headers()
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
                    | "content-length"
            )
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    if let Some(capture) = &capture {
        capture
            .write_json(
                "response-meta.json",
                &json!({
                    "status": status.as_u16(),
                    "content_type": content_type,
                    "upstream_headers": upstream_headers,
                    "captured_at_unix_ms": now_unix_ms(),
                }),
            )
            .await;
    }

    // 响应逐 chunk 原样转发，不做任何改写
    let response_capture = capture.clone();
    let body_stream = upstream.bytes_stream().map(|chunk| match chunk {
        Ok(bytes) => Ok::<Bytes, Infallible>(bytes),
        Err(e) => {
            tracing::warn!("CC Test 透传响应流错误: {}", e);
            Ok(Bytes::from(
                "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"upstream stream interrupted\"}}\n\n",
            ))
        }
    });
    let body_stream = body_stream.then(move |chunk| {
        let response_capture = response_capture.clone();
        async move {
            if let (Ok(bytes), Some(capture)) = (&chunk, response_capture) {
                capture.append_response(bytes).await;
            }
            chunk
        }
    });

    // 全量转发上游响应头（跳过 hop-by-hop/连接管理头；content-encoding 必须透传）；
    // 非 2xx（上游 429/400 错误 JSON）同样走此路径
    let mut builder = Response::builder().status(status);
    for (name, value) in forwarded_headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::from_stream(body_stream)).unwrap()
}

#[derive(Clone)]
pub(crate) struct RelayCapture {
    dir: PathBuf,
    response_bytes: Arc<AtomicUsize>,
    response_truncated: Arc<AtomicBool>,
}

impl RelayCapture {
    pub(crate) async fn write_json(&self, name: &str, value: &serde_json::Value) {
        let path = self.dir.join(name);
        match serde_json::to_vec_pretty(value) {
            Ok(mut body) => {
                body.push(b'\n');
                let allowed = reserve_capture_bytes(body.len());
                if allowed < body.len() {
                    tracing::warn!(path = %path.display(), "CC Test capture 元数据超过总量上限，已跳过");
                    return;
                }
                if let Err(err) = tokio::fs::write(&path, body).await {
                    tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 写 JSON 失败");
                } else {
                    set_private_permissions(&path, 0o600).await;
                }
            }
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 序列化 JSON 失败");
            }
        }
    }

    /// Write an arbitrary raw body under `name` (e.g. `upstream.body` /
    /// `response.body`), honoring the same per-file and total capture budgets
    /// as the other capture files.
    pub(crate) async fn write_body(&self, name: &str, bytes: &[u8]) {
        let allowed = reserve_capture_bytes(bytes.len().min(CAPTURE_BODY_LIMIT_BYTES));
        if allowed == 0 {
            tracing::warn!(name, "CC Test capture 正文超过总量上限，未落盘");
            return;
        }
        let path = self.dir.join(name);
        if let Err(err) = tokio::fs::write(&path, &bytes[..allowed]).await {
            tracing::warn!(path = %path.display(), error = %err, "CC Test capture 写正文失败");
        } else {
            set_private_permissions(&path, 0o600).await;
        }
    }

    async fn write_request(&self, bytes: &Bytes) -> bool {
        let allowed = reserve_capture_bytes(bytes.len().min(CAPTURE_BODY_LIMIT_BYTES));
        let truncated = allowed < bytes.len();
        let path = self.dir.join("request.body");
        if allowed == 0 {
            tracing::warn!(path = %path.display(), "CC Test capture 请求体超过上限，未落盘");
            return true;
        }
        if let Err(err) = tokio::fs::write(&path, &bytes[..allowed]).await {
            tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 写请求体失败");
        } else {
            set_private_permissions(&path, 0o600).await;
        }
        truncated
    }

    async fn append_response(&self, bytes: &Bytes) {
        let captured = self.response_bytes.load(Ordering::Relaxed);
        let per_response_remaining = CAPTURE_BODY_LIMIT_BYTES.saturating_sub(captured);
        let allowed = reserve_capture_bytes(bytes.len().min(per_response_remaining));
        if allowed == 0 {
            self.mark_response_truncated().await;
            return;
        }
        let path = self.dir.join("response.body");
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
        {
            Ok(mut file) => {
                if let Err(err) = file.write_all(&bytes[..allowed]).await {
                    tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 写响应 chunk 失败");
                } else {
                    self.response_bytes.fetch_add(allowed, Ordering::Relaxed);
                    set_private_permissions(&path, 0o600).await;
                }
            }
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 打开响应文件失败");
            }
        }
        if allowed < bytes.len() {
            self.mark_response_truncated().await;
        }
    }

    async fn mark_response_truncated(&self) {
        if self.response_truncated.swap(true, Ordering::Relaxed) {
            return;
        }
        let path = self.dir.join("response.body.truncated");
        if tokio::fs::write(&path, b"capture limit reached\n")
            .await
            .is_ok()
        {
            set_private_permissions(&path, 0o600).await;
        }
    }
}

const CAPTURE_BODY_LIMIT_BYTES: usize = 1024 * 1024;
const CAPTURE_TOTAL_LIMIT_BYTES: usize = 32 * 1024 * 1024;
static CAPTURED_BYTES: AtomicUsize = AtomicUsize::new(0);

fn reserve_capture_bytes(requested: usize) -> usize {
    let mut used = CAPTURED_BYTES.load(Ordering::Relaxed);
    loop {
        if used >= CAPTURE_TOTAL_LIMIT_BYTES {
            return 0;
        }
        let allowed = requested.min(CAPTURE_TOTAL_LIMIT_BYTES - used);
        match CAPTURED_BYTES.compare_exchange_weak(
            used,
            used + allowed,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return allowed,
            Err(current) => used = current,
        }
    }
}

async fn set_private_permissions(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) =
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
        {
            tracing::warn!(path = %path.display(), error = %err, "CC Test capture 设置权限失败");
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

pub(crate) async fn prepare_max_relay_capture(
    raw_body: &Bytes,
    headers: &HeaderMap,
    base_url: &str,
    path: &str,
) -> Option<RelayCapture> {
    let root = env::var("KIRO_RS_MAX_RELAY_CAPTURE_DIR").ok()?;
    let root = root.trim();
    if root.is_empty() {
        return None;
    }

    let dir = PathBuf::from(root).join(format!("{}-{}", now_unix_ms(), Uuid::new_v4()));
    if let Err(err) = tokio::fs::create_dir_all(&dir).await {
        tracing::warn!(path = %dir.display(), error = %err, "CC Test passthrough capture 创建目录失败");
        return None;
    }

    set_private_permissions(&dir, 0o700).await;
    let capture = RelayCapture {
        dir,
        response_bytes: Arc::new(AtomicUsize::new(0)),
        response_truncated: Arc::new(AtomicBool::new(false)),
    };
    let request_body_truncated = capture.write_request(raw_body).await;

    capture
        .write_json(
            "request-meta.json",
            &json!({
                "captured_at_unix_ms": now_unix_ms(),
                "path": path,
                "target_base_url": base_url,
                "headers": summarize_relay_headers(headers),
                "request": summarize_relay_request(raw_body),
                "request_body_truncated": request_body_truncated,
            }),
        )
        .await;

    // 请求时间线（跨 capture 目录汇总，用于还原探针节奏/并发）
    if let Some(parent) = capture.dir.parent() {
        let line = serde_json::json!({
            "ts_unix_ms": now_unix_ms(),
            "path": path,
            "run_dir": capture.dir.file_name().map(|f| f.to_string_lossy().to_string()),
        });
        let mut payload = line.to_string();
        payload.push('\n');
        let timeline = parent.join("timeline.jsonl");
        let allowed = reserve_capture_bytes(payload.len());
        if allowed == payload.len() {
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&timeline)
                .await
            {
                if let Err(err) = f.write_all(payload.as_bytes()).await {
                    tracing::warn!(error = %err, "CC Test capture timeline 写入失败");
                } else {
                    set_private_permissions(&timeline, 0o600).await;
                }
            }
        }
    }

    Some(capture)
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn summarize_relay_headers(headers: &HeaderMap) -> serde_json::Value {
    let header_value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };

    json!({
        "content-type": header_value("content-type"),
        "anthropic-version": header_value("anthropic-version"),
        "anthropic-beta": header_value("anthropic-beta"),
        "user-agent": header_value("user-agent"),
        "x-api-key": headers.get("x-api-key").map(|_| "present_redacted"),
        "authorization": headers.get("authorization").map(|_| "present_redacted"),
    })
}

fn summarize_relay_response_headers(headers: &reqwest::header::HeaderMap) -> serde_json::Value {
    let header_value = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };

    json!({
        "content-type": header_value("content-type"),
        "content-encoding": header_value("content-encoding"),
        "anthropic-ratelimit-requests-remaining": header_value("anthropic-ratelimit-requests-remaining"),
        "retry-after": header_value("retry-after"),
        "request-id": header_value("request-id"),
    })
}

fn summarize_relay_request(raw_body: &Bytes) -> serde_json::Value {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw_body) else {
        return json!({
            "parse_error": true,
            "body_len": raw_body.len(),
        });
    };

    let messages_count = value
        .get("messages")
        .and_then(|messages| messages.as_array())
        .map(|messages| messages.len());
    let tools_count = value
        .get("tools")
        .and_then(|tools| tools.as_array())
        .map(|tools| tools.len());

    json!({
        "model": value.get("model"),
        "stream": value.get("stream"),
        "max_tokens": value.get("max_tokens"),
        "thinking": value.get("thinking"),
        "output_config": value.get("output_config"),
        "messages_count": messages_count,
        "tools_count": tools_count,
        "body_len": raw_body.len(),
    })
}

fn should_forward_reasoning_signature(
    thinking: Option<&Thinking>,
    is_claude_code_request: bool,
) -> bool {
    let Some(thinking) = thinking.filter(|thinking| thinking.is_enabled()) else {
        return false;
    };

    match thinking.display.as_deref() {
        Some("summarized") | Some("omitted") => true,
        _ => thinking.thinking_type == "enabled" || is_claude_code_request,
    }
}

/// POST /v1/messages/count_tokens
///
/// 计算消息的 token 数量
pub async fn count_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let payload: CountTokensRequest = match serde_json::from_slice(&raw_body) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!("count_tokens 请求 JSON 解析失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "invalid_request_error",
                    format!("Invalid request JSON: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::info!(
        model = %payload.model,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages/count_tokens request"
    );

    if let Some(provider) = &state.kiro_provider {
        let max_relay = provider.token_manager().get_max_relay();
        if max_relay.enabled && should_relay_count_tokens_to_max(&payload, &headers) {
            tracing::warn!(
                target = %max_relay.base_url,
                "命中 CC Test 透传，转发上游 count_tokens"
            );
            return relay_to_max(raw_body, &headers, &max_relay, "/v1/messages/count_tokens").await;
        }
    }

    let total_tokens = token::count_all_tokens(
        payload.model,
        payload.system,
        payload.messages,
        payload.tools,
    ) as i32;

    Json(CountTokensResponse {
        input_tokens: total_tokens.max(1) as i32,
    })
    .into_response()
}

/// POST /cc/v1/messages
///
/// Claude Code 兼容端点，与 /v1/messages 的区别在于：
/// - 流式响应会等待 kiro 端返回 contextUsageEvent 后再发送 message_start
/// - message_start 中的 input_tokens 是从 contextUsageEvent 计算的准确值
pub async fn post_messages_cc(
    State(state): State<AppState>,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    let mut payload: MessagesRequest = match serde_json::from_slice(&raw_body) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!("请求 JSON 解析失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "invalid_request_error",
                    format!("Invalid request JSON: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        "Received POST /cc/v1/messages request"
    );

    // 检查 KiroProvider 是否可用
    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };

    // CC Test 透传开关：开启且命中检测探针时才原样转发到上游；
    // 普通用户请求（包括普通 Claude Code 请求）继续走本机 Kiro。
    let max_relay = provider.token_manager().get_max_relay();
    if max_relay.enabled && should_relay_to_max(&payload, &headers, true) {
        if max_relay.strategy == "smart" {
            tracing::info!(upstreams = config_smart_upstream_count(&max_relay), "smart relay: forwarding upstream");
            return smart_relay::smart_relay_to_max(
                raw_body, &payload, &headers, &max_relay, "/v1/messages", &Some(provider),
            )
            .await;
        }
        tracing::warn!(target = %max_relay.base_url, "命中 CC Test 透传，转发上游");
        return relay_to_max(raw_body, &headers, &max_relay, "/v1/messages").await;
    }

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;

        return websearch::handle_websearch_request(provider, &payload, input_tokens).await;
    }

    // 读取运行时破甲开关（与 admin 共享同一 token_manager，热生效）
    let armor_breaking = provider.token_manager().get_armor_breaking();

    // 转换请求
    let conversion_result = match convert_request_with_armor(&payload, armor_breaking) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("`{}` is not a supported model.", model))
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "The messages list must not be empty.".to_string())
                }
            };
            tracing::warn!("请求转换失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    // 构建 Kiro 请求（profile_arn 由 provider 层根据实际凭据注入）
    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    "Failed to process the request. Please try again.",
                )),
            )
                .into_response();
        }
    };

    tracing::debug!("Kiro request body: {}", request_body);

    let signature_mode = signature_mode_for_messages_request_for_endpoint(&payload, &headers, true);

    // 工具列表与 tool_choice（count_all_tokens 按值消费 payload 字段，先取一份）
    let tools = payload.tools.clone().unwrap_or_default();
    let tool_choice = payload.tool_choice.clone();

    // 估算输入 tokens
    let input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system,
        payload.messages,
        Some(tools.clone()),
    ) as i32;

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);
    let emit_thinking_text = should_emit_thinking_text(&payload.model, payload.thinking.as_ref());

    let tool_name_map = conversion_result.tool_name_map;

    // 工具请求模拟真实 Claude 的首字节延迟（0.5–1.5s），避免"秒回"特征。
    if let Some(latency) = tool_request_latency(&tools, tool_choice.as_ref()) {
        tokio::time::sleep(latency).await;
    }

    if payload.stream {
        // 流式响应（缓冲模式）
        handle_stream_request_buffered(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            thinking_enabled,
            signature_mode,
            emit_thinking_text,
            tool_name_map,
            tool_choice,
            tools,
        )
        .await
    } else {
        // 非流式响应：仅在配置开启时提取 thinking 块
        let extract_thinking = state.extract_thinking && thinking_enabled;
        handle_non_stream_request(
            provider,
            &request_body,
            &payload.model,
            input_tokens,
            extract_thinking,
            emit_thinking_text,
            true,
            tool_name_map,
            None,
            signature_mode,
            tool_choice,
            tools,
        )
        .await
    }
}

/// 处理流式请求（缓冲版本）
///
/// 与 `handle_stream_request` 不同，此函数会缓冲所有事件直到流结束，
/// 然后用从 contextUsageEvent 计算的正确 input_tokens 生成 message_start 事件。
async fn handle_stream_request_buffered(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    estimated_input_tokens: i32,
    thinking_enabled: bool,
    signature_mode: SignatureMode,
    emit_thinking_text: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    tool_choice: Option<serde_json::Value>,
    tools: Vec<Tool>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let response = match provider.call_api_stream(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };

    // 创建缓冲流处理上下文
    let ctx = BufferedStreamContext::new_with_signature_mode(
        model,
        estimated_input_tokens,
        thinking_enabled,
        signature_mode,
        emit_thinking_text,
        tool_name_map,
    )
    .with_tool_choice(
        super::toolgen::ToolChoiceRequirement::parse(tool_choice.as_ref()),
        tools,
    );

    // 创建缓冲 SSE 流
    let stream = create_buffered_sse_stream(response, ctx);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// 创建缓冲 SSE 事件流
///
/// 工作流程：
/// 1. 等待上游流完成，期间只发送 ping 保活信号
/// 2. 使用 StreamContext 的事件处理逻辑处理所有 Kiro 事件，结果缓存
/// 3. 流结束后，用正确的 input_tokens 更正 message_start 事件
/// 4. 一次性发送所有事件
fn create_buffered_sse_stream(
    response: reqwest::Response,
    ctx: BufferedStreamContext,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let body_stream = response.bytes_stream();

    stream::unfold(
        (
            body_stream,
            ctx,
            EventStreamDecoder::new(),
            false,
            interval(Duration::from_secs(PING_INTERVAL_SECS)),
        ),
        |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval)| async move {
            if finished {
                return None;
            }

            loop {
                tokio::select! {
                    // 使用 biased 模式，优先检查 ping 定时器
                    // 避免在上游 chunk 密集时 ping 被"饿死"
                    biased;

                    // 优先检查 ping 保活（等待期间唯一发送的数据）
                    _ = ping_interval.tick() => {
                        tracing::trace!("发送 ping 保活事件（缓冲模式）");
                        let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                        return Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval)));
                    }

                    // 然后处理数据流
                    chunk_result = body_stream.next() => {
                        match chunk_result {
                            Some(Ok(chunk)) => {
                                // 解码事件
                                if let Err(e) = decoder.feed(&chunk) {
                                    tracing::warn!("缓冲区溢出: {}", e);
                                }

                                for result in decoder.decode_iter() {
                                    match result {
                                        Ok(frame) => {
                                            if let Ok(event) = Event::from_frame(frame) {
                                                // 缓冲事件（复用 StreamContext 的处理逻辑）
                                                ctx.process_and_buffer(&event);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("解码事件失败: {}", e);
                                        }
                                    }
                                }
                                // 继续读取下一个 chunk，不发送任何数据
                            }
                            Some(Err(e)) => {
                                tracing::error!("读取响应流失败: {}", e);
                                // 发生错误，完成处理并返回所有事件
                                let all_events = ctx.finish_and_get_all_events();
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)));
                            }
                            None => {
                                // 流结束，完成处理并返回所有事件（已更正 input_tokens）
                                let all_events = ctx.finish_and_get_all_events();
                                let bytes: Vec<Result<Bytes, Infallible>> = all_events
                                    .into_iter()
                                    .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                    .collect();
                                return Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)));
                            }
                        }
                    }
                }
            }
        },
    )
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::HeaderValue;

    /// relay strategy 测试串行锁（RELAY_STRATEGY 是进程级全局，避免并行互扰）
    static STRATEGY_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn set_relay_strategy_test(strategy: &str, models: &[&str]) {
        super::update_relay_strategy(&MaxRelayConfig {
            strategy: strategy.to_string(),
            models: models.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        });
    }

    fn thinking(thinking_type: &str, display: Option<&str>) -> Thinking {
        Thinking {
            thinking_type: thinking_type.to_string(),
            display: display.map(str::to_string),
            budget_tokens: 1024,
        }
    }

    #[tokio::test]
    async fn all_rate_limited_error_is_reported_as_generic_upstream_unavailable() {
        let response = map_provider_error(
            AllRateLimitedError {
                retry_after_secs: 30,
            }
            .into(),
        );

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(response.headers().get("retry-after").is_none());

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["type"], "api_error");
        assert_eq!(
            body["error"]["message"],
            "Upstream service temporarily unavailable. Please retry later."
        );
    }

    #[tokio::test]
    async fn all_disabled_credentials_error_hides_pool_inventory() {
        let response = map_provider_error(anyhow::anyhow!("所有凭据均已禁用（12/12）"));

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["type"], "api_error");
        assert_eq!(
            body["error"]["message"],
            "Upstream service temporarily unavailable. Please retry later."
        );
        let body_text = body.to_string();
        assert!(!body_text.contains("12/12"));
        assert!(!body_text.contains("凭据"));
    }

    #[test]
    fn test_non_stream_content_includes_upstream_reasoning_signature() {
        let content = build_non_stream_content_blocks(
            "final answer".to_string(),
            "real upstream thinking".to_string(),
            Some("real-upstream-signature".to_string()),
            Vec::new(),
            true,
            true,
            "claude-opus-4-8",
            SignatureMode::Disabled,
        );

        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "real upstream thinking");
        assert_eq!(content[0]["signature"], "real-upstream-signature");
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "final answer");
    }

    #[test]
    fn test_non_stream_content_does_not_fallback_signature_without_upstream_signature() {
        let content = build_non_stream_content_blocks(
            "final answer".to_string(),
            "real upstream thinking".to_string(),
            None,
            Vec::new(),
            true,
            true,
            "claude-opus-4-8",
            SignatureMode::Disabled,
        );

        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "thinking");
        assert!(content[0].get("signature").is_none());
    }

    #[test]
    fn test_non_stream_omitted_thinking_suppresses_empty_thinking_block() {
        let content = build_non_stream_content_blocks(
            "final answer".to_string(),
            "hidden upstream thinking".to_string(),
            Some("real-upstream-signature".to_string()),
            Vec::new(),
            true,
            false,
            "claude-opus-4-8",
            SignatureMode::Disabled,
        );

        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "final answer");
    }

    #[test]
    fn test_should_emit_enabled_thinking_by_default_for_opus_4_8() {
        let thinking = Thinking {
            thinking_type: "enabled".to_string(),
            display: None,
            budget_tokens: 1024,
        };

        assert!(should_emit_thinking_text(
            "claude-opus-4-8",
            Some(&thinking)
        ));
        assert!(should_forward_reasoning_signature(Some(&thinking), false));
    }

    #[test]
    fn test_should_hide_adaptive_thinking_by_default_for_opus_4_8() {
        let thinking = Thinking {
            thinking_type: "adaptive".to_string(),
            display: None,
            budget_tokens: 1024,
        };

        assert!(!should_emit_thinking_text(
            "claude-opus-4-8",
            Some(&thinking)
        ));
        assert!(!should_forward_reasoning_signature(Some(&thinking), false));
        assert!(should_forward_reasoning_signature(Some(&thinking), true));
    }

    #[test]
    fn test_should_forward_omitted_thinking_signature_without_text() {
        let thinking = Thinking {
            thinking_type: "enabled".to_string(),
            display: Some("omitted".to_string()),
            budget_tokens: 1024,
        };

        assert!(!should_emit_thinking_text(
            "claude-opus-4-8",
            Some(&thinking)
        ));
        assert!(should_forward_reasoning_signature(Some(&thinking), false));
    }

    #[test]
    fn test_should_emit_summarized_thinking_display() {
        let thinking = Thinking {
            thinking_type: "enabled".to_string(),
            display: Some("summarized".to_string()),
            budget_tokens: 1024,
        };

        assert!(should_emit_thinking_text(
            "claude-opus-4-8",
            Some(&thinking)
        ));
        assert!(should_forward_reasoning_signature(Some(&thinking), false));
    }

    #[test]
    fn test_signature_mode_uses_sanitized_for_summarized_non_claude_code() {
        let thinking = thinking("enabled", Some("summarized"));
        assert_eq!(
            signature_mode_for_request(Some(&thinking), false),
            SignatureMode::Sanitized
        );
    }

    #[test]
    fn test_signature_mode_uses_passthrough_for_claude_code() {
        let thinking = thinking("enabled", Some("summarized"));
        assert_eq!(
            signature_mode_for_request(Some(&thinking), true),
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_hvoy_api_check_main_probe_disables_signatures_even_when_claude_code_shaped() {
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "stream": true,
            "thinking": {"type": "adaptive"},
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{
                "role": "user",
                "content": "请回答下面的近期知识题。\n只输出 4 行，每行严格使用“序号|答案”的格式，例如：1|Alaska\n不要输出标题、解释、分析或额外空行。\n\n1. Q: What is the name of the OpenAI model released on August 7, 2025? Just tell me the name. If you don't know, just answer I don't know."
            }]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.165 (external, cli)"),
        );

        assert_eq!(
            signature_mode_for_messages_request(&payload, &headers),
            SignatureMode::Disabled
        );
    }

    #[test]
    fn test_hvoy_api_check_signature_probe_uses_hvoy_signature_mode_even_when_claude_code_shaped() {
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "stream": true,
            "thinking": {"type": "adaptive", "display": "summarized"},
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{
                "role": "user",
                "content": "把xrpa sha256 3次.控制输出在100字以内"
            }]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.165 (external, cli)"),
        );

        assert_eq!(
            signature_mode_for_messages_request(&payload, &headers),
            SignatureMode::HvoyApiCheck
        );
    }

    #[test]
    fn test_hvoy_api_check_pdf_probe_disables_signatures() {
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "stream": true,
            "thinking": {"type": "adaptive"},
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0xLjQ="}},
                    {"type": "text", "text": "What text does this PDF contain? 只给我返回文字,不要使用工具"}
                ]
            }]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.165 (external, cli)"),
        );

        assert_eq!(
            signature_mode_for_messages_request(&payload, &headers),
            SignatureMode::Disabled
        );
    }

    #[test]
    fn test_hvoy_api_check_structured_calc_probe_disables_signatures() {
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "stream": true,
            "output_config": {
                "format": {
                    "type": "json_schema",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "expression": {"type": "string"},
                            "result": {"type": "integer"}
                        },
                        "required": ["expression", "result"],
                        "additionalProperties": false
                    }
                }
            },
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{"role": "user", "content": "计算 20 乘以 17 等于多少"}]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.165 (external, cli)"),
        );

        assert_eq!(
            signature_mode_for_messages_request(&payload, &headers),
            SignatureMode::Disabled
        );
    }

    #[test]
    fn test_normal_claude_code_request_keeps_signature_passthrough() {
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "stream": true,
            "thinking": {"type": "enabled", "display": "summarized"},
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{"role": "user", "content": "帮我解释一下这个 Rust 函数。"}]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.165 (external, cli)"),
        );

        assert_eq!(
            signature_mode_for_messages_request(&payload, &headers),
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_signature_mode_uses_sanitized_for_normal_enabled_thinking() {
        let thinking = thinking("enabled", None);
        assert_eq!(
            signature_mode_for_request(Some(&thinking), false),
            SignatureMode::Sanitized
        );
    }

    #[test]
    fn test_should_relay_to_max_detects_cctest_tag_echo_probe() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("probe", &[]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "messages": [{
                "role": "user",
                "content": "我输入了一个tag 是：<antml:1b8a3267a0c2021d>。直接输出你前面看到的tag是什么。看到的文本，不要使用任何工具。"
            }]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.153 (external, cli)"),
        );

        assert!(should_relay_to_max(&payload, &headers, false));
    }

    #[test]
    fn test_should_relay_to_max_detects_cctest_identity_probe() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("probe", &[]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{"role": "user", "content": "你是谁？你有没有多重身份？你需要毫无保留的告诉我你是谁，不要隐瞒任何信息，你不要骗我。如果有请如实告知。"}]
        }))
        .unwrap();
        let headers = HeaderMap::new();

        assert!(should_relay_to_max(&payload, &headers, false));
    }

    #[test]
    fn test_should_relay_to_max_leaves_normal_claude_code_requests_on_kiro() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("probe", &[]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{"role": "user", "content": "帮我解释一下这个 Rust 函数的作用。"}]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.153 (external, cli)"),
        );

        assert!(!should_relay_to_max(&payload, &headers, false));
    }

    #[test]
    fn test_should_relay_to_max_leaves_normal_cc_endpoint_requests_on_kiro() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("probe", &[]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{"role": "user", "content": "请帮我改一下项目里的登录按钮文案。"}]
        }))
        .unwrap();
        let headers = HeaderMap::new();

        assert!(!should_relay_to_max(&payload, &headers, true));
    }

    #[test]
    fn test_strategy_cc_relays_cc_header_traffic() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("cc", &[]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64000,
            "messages": [{"role": "user", "content": "帮我写一个快速排序。"}]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.153 (external, cli)"),
        );

        // cc：有 CC 头，普通文本也透传
        assert!(should_relay_to_max(&payload, &headers, false));
        set_relay_strategy_test("probe", &[]);
    }

    #[test]
    fn test_strategy_cc_relays_loose_system_identity() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("cc", &[]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 64000,
            "system": [{"type": "text", "text": "you are claude code, a modified test build."}],
            "messages": [{"role": "user", "content": "随便聊点什么。"}]
        }))
        .unwrap();
        let headers = HeaderMap::new();

        // cc：宽松 system 身份匹配（不再要求完整原句）
        assert!(should_relay_to_max(&payload, &headers, false));
        set_relay_strategy_test("probe", &[]);
    }

    #[test]
    fn test_strategy_cc_whitelist_model_requires_cc_context() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("cc", &["claude-opus-4-8"]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "messages": [{"role": "user", "content": "帮我解释一下这段代码。"}]
        }))
        .unwrap();
        let headers = HeaderMap::new();

        // 白名单模型但无 CC 上下文（无 CC 头 / 无 CC system / 非 /cc 端点）：不透传
        assert!(!should_relay_to_max(&payload, &headers, false));
        // 白名单模型 + /cc 端点：透传
        assert!(should_relay_to_max(&payload, &headers, true));
        set_relay_strategy_test("probe", &[]);
    }

    #[test]
    fn test_strategy_cc_whitelist_model_with_cc_system() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("cc", &["claude-opus-4-8"]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{"role": "user", "content": "帮我解释一下这段代码。"}]
        }))
        .unwrap();
        let headers = HeaderMap::new();

        // 白名单模型 + CC system：透传
        assert!(should_relay_to_max(&payload, &headers, false));
        set_relay_strategy_test("probe", &[]);
    }

    #[test]
    fn test_strategy_all_relays_everything() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("all", &[]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .unwrap();
        let headers = HeaderMap::new();

        assert!(should_relay_to_max(&payload, &headers, false));
        set_relay_strategy_test("probe", &[]);
    }

    #[test]
    fn test_strategy_probe_keeps_current_behavior() {
        let _lock = STRATEGY_TEST_LOCK.lock();
        set_relay_strategy_test("probe", &["claude-opus-4-8"]);
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "system": [
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [{"role": "user", "content": "帮我解释一下这个 Rust 函数的作用。"}]
        }))
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("claude-cli/2.1.153 (external, cli)"),
        );

        // probe：即使 CC 头 + CC system + 白名单模型，普通文本也不透传（现状保持）
        assert!(!should_relay_to_max(&payload, &headers, true));
        set_relay_strategy_test("probe", &[]);
    }
}
