//! Anthropic API Handler 函数

use std::{
    convert::Infallible,
    env,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::kiro::provider::{
    DeferredStreamAttempt, KiroByteStream, KiroProvider, KiroStreamResponse,
};
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
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::time::{Interval, interval};
use uuid::Uuid;

use super::converter::{
    ConversionError, convert_request_with_armor, final_text_override_for_request_with_armor,
};
use super::identity_response_guard::rewrite_kiro_self_identity;
use super::middleware::AppState;
use super::stream::{BufferedStreamContext, SignatureMode, SseEvent, StreamContext};
use super::types::{
    CountTokensRequest, CountTokensResponse, ErrorResponse, MessagesRequest, Model, ModelsResponse,
    OutputConfig, Thinking,
};
use super::websearch;

const MAX_ACCEPTED_INPUT_TOKENS: u64 = 1_000_000;

fn reject_if_input_too_large(endpoint: &str, model: &str, input_tokens: u64) -> Option<Response> {
    if input_tokens <= MAX_ACCEPTED_INPUT_TOKENS {
        return None;
    }

    tracing::warn!(
        endpoint = endpoint,
        model = model,
        input_tokens = input_tokens,
        max_input_tokens = MAX_ACCEPTED_INPUT_TOKENS,
        "拒绝超大输入请求，避免进入上游和计费链路"
    );
    Some(
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Input is too long. Reduce the size of your messages.",
            )),
        )
            .into_response(),
    )
}

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
            format!("上游 API 调用失败: {}", err),
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
            id: "gpt-5.6-sol".to_string(),
            object: "model".to_string(),
            created: 1783987200, // Jul 14, 2026
            owned_by: "openai".to_string(),
            display_name: "GPT 5.6 Sol".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "gpt-5.6-terra".to_string(),
            object: "model".to_string(),
            created: 1783987200, // Jul 14, 2026
            owned_by: "openai".to_string(),
            display_name: "GPT 5.6 Terra".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "gpt-5.6-luna".to_string(),
            object: "model".to_string(),
            created: 1783987200, // Jul 14, 2026
            owned_by: "openai".to_string(),
            display_name: "GPT 5.6 Luna".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-sonnet-5".to_string(),
            object: "model".to_string(),
            created: 1782777600, // Jun 30, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-sonnet-5-thinking".to_string(),
            object: "model".to_string(),
            created: 1782777600, // Jun 30, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Sonnet 5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-opus-5".to_string(),
            object: "model".to_string(),
            created: 1784937600, // First verified by FluxNode on Jul 25, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 5".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
        Model {
            id: "claude-opus-5-thinking".to_string(),
            object: "model".to_string(),
            created: 1784937600, // First verified by FluxNode on Jul 25, 2026
            owned_by: "anthropic".to_string(),
            display_name: "Claude Opus 5 (Thinking)".to_string(),
            model_type: "chat".to_string(),
            max_tokens: 128_000,
        },
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
        tracing::warn!(target = %max_relay.base_url, "命中 CC Test 透传，转发上游");
        return relay_to_max(raw_body, &headers, &max_relay, "/v1/messages").await;
    }

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);
    force_adaptive_summarized_thinking(&mut payload);

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        );
        if let Some(resp) = reject_if_input_too_large("/v1/messages", &payload.model, input_tokens)
        {
            return resp;
        }

        return websearch::handle_websearch_request(provider, &payload, input_tokens as i32).await;
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
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::InvalidReasoningEffort(effort) => (
                    "invalid_request_error",
                    format!("reasoning effort 不支持: {}", effort),
                ),
                ConversionError::UnsupportedAttachment(message) => {
                    ("invalid_request_error", message.clone())
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
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
        additional_model_request_fields: conversion_result.additional_model_request_fields,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!("Kiro request body: {}", request_body);

    let signature_mode = signature_mode_for_messages_request(&payload, &headers);
    let guard_empty_stream_success =
        final_text_override.is_none() && should_guard_empty_stream_success(&payload, &headers);

    // 估算输入 tokens
    let input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system,
        payload.messages,
        payload.tools,
    );
    if let Some(resp) = reject_if_input_too_large("/v1/messages", &payload.model, input_tokens) {
        return resp;
    }
    let input_tokens = input_tokens as i32;

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);
    let emit_thinking_text = should_emit_thinking_text(&payload.model, payload.thinking.as_ref());

    let tool_name_map = conversion_result.tool_name_map;

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
            guard_empty_stream_success,
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
        )
        .await
    }
}

/// 处理流式请求
async fn handle_stream_request(
    provider: std::sync::Arc<KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    signature_mode: SignatureMode,
    emit_thinking_text: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    final_text_override: Option<String>,
    guard_empty_stream_success: bool,
) -> Response {
    if guard_empty_stream_success {
        return handle_stream_request_with_empty_retry(
            provider,
            request_body,
            model,
            input_tokens,
            thinking_enabled,
            signature_mode,
            emit_thinking_text,
            tool_name_map,
            final_text_override,
        )
        .await;
    }

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
    .with_final_text_override(final_text_override);

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
const EMPTY_STREAM_MAX_ATTEMPTS: usize = 3;

/// 创建 ping 事件的 SSE 字符串
fn create_ping_sse() -> Bytes {
    Bytes::from("event: ping\ndata: {\"type\": \"ping\"}\n\n")
}

fn create_upstream_unavailable_sse() -> Bytes {
    let data = json!({
        "type": "error",
        "error": {
            "type": "api_error",
            "message": "Upstream service temporarily unavailable. Please retry later."
        }
    });
    Bytes::from(format!("event: error\ndata: {}\n\n", data))
}

async fn handle_stream_request_with_empty_retry(
    provider: std::sync::Arc<KiroProvider>,
    request_body: &str,
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    signature_mode: SignatureMode,
    emit_thinking_text: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    final_text_override: Option<String>,
) -> Response {
    let first_response = match provider.call_api_stream_deferred(request_body).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error(e),
    };

    let stream = create_retrying_buffered_sse_stream(
        provider,
        request_body.to_string(),
        model.to_string(),
        input_tokens,
        thinking_enabled,
        signature_mode,
        emit_thinking_text,
        tool_name_map,
        final_text_override,
        first_response,
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

enum EmptyStreamRetryState {
    Start {
        remaining_attempts: usize,
    },
    Reading {
        body_stream: KiroByteStream,
        ctx: BufferedStreamContext,
        decoder: EventStreamDecoder,
        attempt: DeferredStreamAttempt,
        remaining_attempts: usize,
        ping_interval: Interval,
        gate_open: bool,
    },
    Done,
}

fn new_buffered_context(
    model: &str,
    input_tokens: i32,
    thinking_enabled: bool,
    signature_mode: SignatureMode,
    emit_thinking_text: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    final_text_override: Option<String>,
) -> BufferedStreamContext {
    BufferedStreamContext::new_with_signature_mode(
        model,
        input_tokens,
        thinking_enabled,
        signature_mode,
        emit_thinking_text,
        tool_name_map,
    )
    .with_final_text_override(final_text_override)
}

fn reading_state_for_response(
    response: KiroStreamResponse,
    ctx: BufferedStreamContext,
    remaining_attempts: usize,
) -> EmptyStreamRetryState {
    let (body_stream, attempt) = response.into_deferred_parts();
    EmptyStreamRetryState::Reading {
        body_stream,
        ctx,
        decoder: EventStreamDecoder::new(),
        attempt,
        remaining_attempts,
        ping_interval: interval(Duration::from_secs(PING_INTERVAL_SECS)),
        gate_open: false,
    }
}

fn create_retrying_buffered_sse_stream(
    provider: std::sync::Arc<KiroProvider>,
    request_body: String,
    model: String,
    input_tokens: i32,
    thinking_enabled: bool,
    signature_mode: SignatureMode,
    emit_thinking_text: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    final_text_override: Option<String>,
    first_response: KiroStreamResponse,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let first_ctx = new_buffered_context(
        &model,
        input_tokens,
        thinking_enabled,
        signature_mode,
        emit_thinking_text,
        tool_name_map.clone(),
        final_text_override.clone(),
    );
    let initial_state =
        reading_state_for_response(first_response, first_ctx, EMPTY_STREAM_MAX_ATTEMPTS);

    stream::unfold(initial_state, move |state| {
        let provider = provider.clone();
        let request_body = request_body.clone();
        let model = model.clone();
        let tool_name_map = tool_name_map.clone();
        let final_text_override = final_text_override.clone();

        async move {
            match state {
                EmptyStreamRetryState::Done => None,
                EmptyStreamRetryState::Start { remaining_attempts } => {
                    if remaining_attempts == 0 {
                        return Some((
                            vec![Ok(create_upstream_unavailable_sse())],
                            EmptyStreamRetryState::Done,
                        ));
                    }

                    match provider.call_api_stream_deferred(&request_body).await {
                        Ok(response) => {
                            let ctx = new_buffered_context(
                                &model,
                                input_tokens,
                                thinking_enabled,
                                signature_mode,
                                emit_thinking_text,
                                tool_name_map,
                                final_text_override,
                            );
                            Some((
                                Vec::new(),
                                reading_state_for_response(response, ctx, remaining_attempts),
                            ))
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "空流重试时上游调用失败");
                            Some((
                                vec![Ok(create_upstream_unavailable_sse())],
                                EmptyStreamRetryState::Done,
                            ))
                        }
                    }
                }
                EmptyStreamRetryState::Reading {
                    mut body_stream,
                    mut ctx,
                    mut decoder,
                    mut attempt,
                    remaining_attempts,
                    mut ping_interval,
                    gate_open,
                } => {
                    tokio::select! {
                        _ = ping_interval.tick() => {
                            Some((
                                vec![Ok(create_ping_sse())],
                                EmptyStreamRetryState::Reading {
                                    body_stream,
                                    ctx,
                                    decoder,
                                    attempt,
                                    remaining_attempts,
                                    ping_interval,
                                    gate_open,
                                },
                            ))
                        }
                        chunk_result = body_stream.next() => {
                            match chunk_result {
                                Some(Ok(chunk)) => {
                                    if let Err(e) = decoder.feed(&chunk) {
                                        tracing::warn!("缓冲区溢出: {}", e);
                                    }

                                    for result in decoder.decode_iter() {
                                        match result {
                                            Ok(frame) => {
                                                if let Ok(event) = Event::from_frame(frame) {
                                                    ctx.process_and_buffer(&event);
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("解码事件失败: {}", e);
                                            }
                                        }
                                    }

                                    let mut gate_open = gate_open;
                                    let events = if gate_open {
                                        ctx.take_buffered_events()
                                    } else if ctx.has_deliverable_output() {
                                        attempt.confirm_success();
                                        gate_open = true;
                                        ctx.take_buffered_events()
                                    } else {
                                        Vec::new()
                                    };
                                    let bytes = events
                                        .into_iter()
                                        .map(|event| Ok(Bytes::from(event.to_sse_string())))
                                        .collect();

                                    Some((
                                        bytes,
                                        EmptyStreamRetryState::Reading {
                                            body_stream,
                                            ctx,
                                            decoder,
                                            attempt,
                                            remaining_attempts,
                                            ping_interval,
                                            gate_open,
                                        },
                                    ))
                                }
                                Some(Err(e)) => {
                                    let credential_id = attempt.credential_id();
                                    tracing::warn!(credential_id, error = %e, "读取保护流失败，准备重试");
                                    if gate_open {
                                        let bytes = ctx
                                            .finish_and_get_all_events()
                                            .into_iter()
                                            .map(|event| Ok(Bytes::from(event.to_sse_string())))
                                            .collect();
                                        Some((
                                            bytes,
                                            EmptyStreamRetryState::Done,
                                        ))
                                    } else {
                                        attempt.report_empty_retry();
                                        let remaining_attempts = remaining_attempts.saturating_sub(1);
                                        if remaining_attempts == 0 {
                                            Some((
                                                vec![Ok(create_upstream_unavailable_sse())],
                                                EmptyStreamRetryState::Done,
                                            ))
                                        } else {
                                            Some((
                                                Vec::new(),
                                                EmptyStreamRetryState::Start { remaining_attempts },
                                            ))
                                        }
                                    }
                                }
                                None => {
                                    if gate_open {
                                        let all_events = ctx.finish_and_get_all_events();
                                        let bytes = all_events
                                            .into_iter()
                                            .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                            .collect();
                                        Some((bytes, EmptyStreamRetryState::Done))
                                    } else {
                                        let credential_id = attempt.credential_id();
                                        tracing::warn!(credential_id, "上游 2xx 流结束但没有可交付内容，准备重试");
                                        attempt.report_empty_retry();
                                        let remaining_attempts = remaining_attempts.saturating_sub(1);
                                        if remaining_attempts == 0 {
                                            Some((
                                                vec![Ok(create_upstream_unavailable_sse())],
                                                EmptyStreamRetryState::Done,
                                            ))
                                        } else {
                                            Some((
                                                Vec::new(),
                                                EmptyStreamRetryState::Start { remaining_attempts },
                                            ))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
    .flat_map(stream::iter)
}

/// 创建 SSE 事件流
fn create_sse_stream(
    response: KiroStreamResponse,
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
                            // 异常流不能证明固定句已经完整结束，先原样释放身份护栏缓冲。
                            let mut final_events = ctx.abort_identity_response_guard();
                            final_events.extend(ctx.generate_final_events());
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

fn rewrite_non_stream_kiro_identity_response(text_content: &mut String) -> bool {
    let Some(replacement) = rewrite_kiro_self_identity(text_content) else {
        return false;
    };

    *text_content = replacement;
    true
}

#[derive(Default)]
struct UpstreamReasoningBlock {
    text: String,
    signature: Option<String>,
}

fn push_reasoning_block_if_present(
    blocks: &mut Vec<UpstreamReasoningBlock>,
    current: &mut UpstreamReasoningBlock,
) {
    if !current.text.is_empty() || current.signature.is_some() {
        blocks.push(std::mem::take(current));
    }
}

/// 处理非流式请求
fn build_non_stream_content_blocks(
    text_content: String,
    reasoning_blocks: Vec<UpstreamReasoningBlock>,
    tool_uses: Vec<serde_json::Value>,
    thinking_enabled: bool,
    emit_thinking_text: bool,
    _model: &str,
) -> Vec<serde_json::Value> {
    let mut content: Vec<serde_json::Value> = Vec::new();

    if thinking_enabled {
        if !reasoning_blocks.is_empty() {
            for reasoning_block in reasoning_blocks {
                let upstream_signature = reasoning_block
                    .signature
                    .filter(|signature| !signature.is_empty());
                if !emit_thinking_text && upstream_signature.is_none() {
                    continue;
                }
                let mut thinking_block = json!({
                    "type": "thinking",
                    "thinking": if emit_thinking_text {
                        reasoning_block.text
                    } else {
                        String::new()
                    }
                });

                if let Some(signature) = upstream_signature {
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
                    format!("读取响应失败: {}", e),
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
    let mut reasoning_blocks: Vec<UpstreamReasoningBlock> = Vec::new();
    let mut current_reasoning = UpstreamReasoningBlock::default();
    let mut tool_uses: Vec<serde_json::Value> = Vec::new();
    let mut has_tool_use = false;
    let mut stop_reason = "end_turn".to_string();
    // 从 contextUsageEvent 计算的实际输入 tokens
    let mut context_input_tokens: Option<i32> = None;

    // 收集工具调用的增量 JSON
    let mut tool_json_buffers: std::collections::HashMap<String, String> =
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
                                    if current_reasoning.signature.is_some() {
                                        push_reasoning_block_if_present(
                                            &mut reasoning_blocks,
                                            &mut current_reasoning,
                                        );
                                    }
                                    current_reasoning.text.push_str(&reasoning.text);
                                }
                                if !reasoning.signature.is_empty()
                                    && current_reasoning.signature.is_none()
                                {
                                    current_reasoning.signature = Some(reasoning.signature);
                                }
                            }
                        }
                        Event::ToolUse(tool_use) => {
                            push_reasoning_block_if_present(
                                &mut reasoning_blocks,
                                &mut current_reasoning,
                            );
                            has_tool_use = true;

                            // 累积工具的 JSON 输入
                            let buffer = tool_json_buffers
                                .entry(tool_use.tool_use_id.clone())
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
                                    "id": tool_use.tool_use_id,
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

    push_reasoning_block_if_present(&mut reasoning_blocks, &mut current_reasoning);

    // 确定 stop_reason
    if has_tool_use && stop_reason == "end_turn" {
        stop_reason = "tool_use".to_string();
    }

    // 构建响应内容
    let mut guarded_original_text_for_usage = None;
    if let Some(final_text_override) = final_text_override {
        text_content = final_text_override;
    } else {
        let original_text = text_content.clone();
        if rewrite_non_stream_kiro_identity_response(&mut text_content) {
            guarded_original_text_for_usage = Some(original_text);
            tracing::info!(stream = false, "默认身份响应护栏替换了 Kiro 开头身份句");
        }
    }

    let content = build_non_stream_content_blocks(
        text_content,
        reasoning_blocks,
        tool_uses,
        thinking_enabled,
        emit_thinking_text,
        model,
    );

    // 估算输出 tokens
    let output_tokens = guarded_original_text_for_usage.map_or_else(
        || token::estimate_output_tokens(&content),
        |original_text| {
            token::estimate_output_tokens(&[json!({
                "type": "text",
                "text": original_text
            })])
        },
    );

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

    let is_adaptive_thinking = (model_lower.contains("opus")
        && (model_lower.contains("opus-5")
            || model_lower.contains("opus5")
            || model_lower.contains("5-opus")
            || model_lower.contains("4-8")
            || model_lower.contains("4.8")
            || model_lower.contains("4-7")
            || model_lower.contains("4.7")
            || model_lower.contains("4-6")
            || model_lower.contains("4.6")))
        || model_lower.contains("sonnet-5");

    let thinking_type = if is_adaptive_thinking {
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
    if is_adaptive_thinking {
        payload.output_config = Some(OutputConfig {
            effort: "high".to_string(),
            format: None,
        });
    }
}

/// 新版 Opus / Sonnet 数据交付需要可见的 Thinking 正文。无论调用方是否省略 Thinking，
/// 或明确请求 enabled、disabled、omitted，都统一覆写为 adaptive + summarized。
/// budget_tokens 对 adaptive 模式不会传给上游；已有 effort 保持不变。
fn force_adaptive_summarized_thinking(payload: &mut MessagesRequest) {
    let model = payload.model.to_ascii_lowercase();
    let supports_adaptive_summarized = model.contains("opus")
        || model.contains("sonnet-5")
        || model.contains("sonnet5")
        || model.contains("5-sonnet")
        || model.contains("sonnet-4-6")
        || model.contains("sonnet-4.6");
    if !supports_adaptive_summarized {
        return;
    }

    let thinking = payload.thinking.get_or_insert_with(|| Thinking {
        thinking_type: "adaptive".to_string(),
        display: Some("summarized".to_string()),
        budget_tokens: 20000,
    });
    thinking.thinking_type = "adaptive".to_string();
    thinking.display = Some("summarized".to_string());

    if payload.output_config.is_none() {
        payload.output_config = Some(OutputConfig {
            effort: "high".to_string(),
            format: None,
        });
    }

    tracing::info!(
        model = %payload.model,
        "请求已强制启用 adaptive + summarized Thinking"
    );
}

fn should_emit_thinking_text(_model: &str, thinking: Option<&Thinking>) -> bool {
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

fn should_guard_empty_stream_success(payload: &MessagesRequest, headers: &HeaderMap) -> bool {
    if !payload.stream {
        return false;
    }

    let model = payload.model.to_ascii_lowercase();
    let is_guarded_opus = model.contains("claude-opus-4-7")
        || model.contains("claude-opus-4.7")
        || model.contains("claude-opus-5")
        || model.contains("opus5")
        || model.contains("5-opus");
    if !is_guarded_opus {
        return false;
    }

    let is_claude_cli = is_claude_code_request(payload) || has_claude_code_headers(headers);
    if !is_claude_cli {
        return false;
    }

    let tool_count = payload.tools.as_ref().map_or(0, Vec::len);
    payload.messages.len() >= 40 || tool_count >= 20 || payload.max_tokens >= 32_000
}

fn is_claude_code_request(payload: &MessagesRequest) -> bool {
    system_has_claude_code_identity(payload.system.as_deref())
}

fn system_has_claude_code_identity(system: Option<&[super::types::SystemMessage]>) -> bool {
    system.is_some_and(|system| {
        system.iter().any(|message| {
            message
                .text
                .contains("You are Claude Code, Anthropic's official CLI for Claude.")
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

fn signature_mode_for_request(thinking: Option<&Thinking>) -> SignatureMode {
    match thinking.filter(|thinking| thinking.is_enabled()) {
        Some(_) => SignatureMode::Passthrough,
        None => SignatureMode::Disabled,
    }
}

fn signature_mode_for_messages_request(
    payload: &MessagesRequest,
    _headers: &HeaderMap,
) -> SignatureMode {
    signature_mode_for_request(payload.thinking.as_ref())
}

/// 判断请求是否应透传到 CC Test 上游。
///
/// 开关打开后只透传 CCTest 检测探针；普通 Claude Code 用户请求继续走本机 Kiro。
fn should_relay_to_max(
    payload: &MessagesRequest,
    headers: &HeaderMap,
    _is_cc_endpoint: bool,
) -> bool {
    is_cctest_probe_request(payload, headers)
}

fn should_relay_count_tokens_to_max(payload: &CountTokensRequest, headers: &HeaderMap) -> bool {
    let is_claude_code = has_claude_code_headers(headers)
        || system_has_claude_code_identity(payload.system.as_deref());
    is_claude_code && is_cctest_probe_text(&messages_text(&payload.messages))
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

    if let Some(capture) = &capture {
        capture
            .write_json(
                "response-meta.json",
                &json!({
                    "status": status.as_u16(),
                    "content_type": content_type,
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

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(body_stream))
        .unwrap()
}

#[derive(Clone)]
struct RelayCapture {
    dir: PathBuf,
}

impl RelayCapture {
    async fn write_json(&self, name: &str, value: &serde_json::Value) {
        let path = self.dir.join(name);
        match serde_json::to_vec_pretty(value) {
            Ok(mut body) => {
                body.push(b'\n');
                if let Err(err) = tokio::fs::write(&path, body).await {
                    tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 写 JSON 失败");
                }
            }
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 序列化 JSON 失败");
            }
        }
    }

    async fn append_response(&self, bytes: &Bytes) {
        let path = self.dir.join("response.body");
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
        {
            Ok(mut file) => {
                if let Err(err) = file.write_all(bytes).await {
                    tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 写响应 chunk 失败");
                }
            }
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "CC Test passthrough capture 打开响应文件失败");
            }
        }
    }
}

async fn prepare_max_relay_capture(
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

    let capture = RelayCapture { dir };
    if let Err(err) = tokio::fs::write(capture.dir.join("request.body"), raw_body).await {
        tracing::warn!(path = %capture.dir.display(), error = %err, "CC Test passthrough capture 写请求体失败");
    }

    capture
        .write_json(
            "request-meta.json",
            &json!({
                "captured_at_unix_ms": now_unix_ms(),
                "path": path,
                "target_base_url": base_url,
                "headers": summarize_relay_headers(headers),
                "request": summarize_relay_request(raw_body),
            }),
        )
        .await;

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
        tracing::warn!(target = %max_relay.base_url, "命中 CC Test 透传，转发上游");
        return relay_to_max(raw_body, &headers, &max_relay, "/v1/messages").await;
    }

    // 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
    override_thinking_from_model_name(&mut payload);
    force_adaptive_summarized_thinking(&mut payload);

    // 检查是否为 WebSearch 请求
    if websearch::has_web_search_tool(&payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");

        // 估算输入 tokens
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        );
        if let Some(resp) =
            reject_if_input_too_large("/cc/v1/messages", &payload.model, input_tokens)
        {
            return resp;
        }

        return websearch::handle_websearch_request(provider, &payload, input_tokens as i32).await;
    }

    // 读取运行时破甲开关（与 admin 共享同一 token_manager，热生效）
    let armor_breaking = provider.token_manager().get_armor_breaking();

    // 转换请求
    let conversion_result = match convert_request_with_armor(&payload, armor_breaking) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::UnsupportedModel(model) => {
                    ("invalid_request_error", format!("模型不支持: {}", model))
                }
                ConversionError::InvalidReasoningEffort(effort) => (
                    "invalid_request_error",
                    format!("reasoning effort 不支持: {}", effort),
                ),
                ConversionError::UnsupportedAttachment(message) => {
                    ("invalid_request_error", message.clone())
                }
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
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
        additional_model_request_fields: conversion_result.additional_model_request_fields,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!("Kiro request body: {}", request_body);

    let signature_mode = signature_mode_for_messages_request(&payload, &headers);

    // 估算输入 tokens
    let input_tokens = token::count_all_tokens(
        payload.model.clone(),
        payload.system,
        payload.messages,
        payload.tools,
    );
    if let Some(resp) = reject_if_input_too_large("/cc/v1/messages", &payload.model, input_tokens) {
        return resp;
    }
    let input_tokens = input_tokens as i32;

    // 检查是否启用了thinking
    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);
    let emit_thinking_text = should_emit_thinking_text(&payload.model, payload.thinking.as_ref());

    let tool_name_map = conversion_result.tool_name_map;

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
    response: KiroStreamResponse,
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
    use crate::anthropic::identity_response_guard::{CLAUDE_GREETING, KIRO_GREETING};
    use crate::anthropic::types::MessagesRequest;
    use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
    use crate::kiro::model::credentials::KiroCredentials;
    use crate::kiro::token_manager::MultiTokenManager;
    use crate::model::config::Config;
    use axum::body::to_bytes;
    use axum::http::HeaderValue;
    use axum::{Router, routing::post};
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::time::timeout;

    struct DelayedTestEndpoint {
        base_url: String,
    }

    impl KiroEndpoint for DelayedTestEndpoint {
        fn name(&self) -> &'static str {
            "delayed-test"
        }

        fn api_url(&self, _ctx: &RequestContext<'_>) -> String {
            format!("{}/api", self.base_url)
        }

        fn mcp_url(&self, _ctx: &RequestContext<'_>) -> String {
            format!("{}/mcp", self.base_url)
        }

        fn decorate_api(
            &self,
            request: reqwest::RequestBuilder,
            _ctx: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            request
        }

        fn decorate_mcp(
            &self,
            request: reqwest::RequestBuilder,
            _ctx: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            request
        }

        fn transform_api_body(&self, body: &str, _ctx: &RequestContext<'_>) -> String {
            body.to_string()
        }
    }

    fn append_event_stream_string_header(out: &mut Vec<u8>, name: &str, value: &str) {
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.push(7);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }

    fn assistant_response_frame(content: &str) -> Bytes {
        let mut headers = Vec::new();
        append_event_stream_string_header(&mut headers, ":message-type", "event");
        append_event_stream_string_header(&mut headers, ":event-type", "assistantResponseEvent");
        let payload = serde_json::to_vec(&json!({"content": content})).unwrap();
        let total_length = 12 + headers.len() + payload.len() + 4;

        let mut frame = Vec::with_capacity(total_length);
        frame.extend_from_slice(&(total_length as u32).to_be_bytes());
        frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        let prelude_crc = crate::kiro::parser::crc::crc32(&frame);
        frame.extend_from_slice(&prelude_crc.to_be_bytes());
        frame.extend_from_slice(&headers);
        frame.extend_from_slice(&payload);
        let message_crc = crate::kiro::parser::crc::crc32(&frame);
        frame.extend_from_slice(&message_crc.to_be_bytes());
        Bytes::from(frame)
    }

    async fn delayed_assistant_stream() -> Response {
        let chunks = stream::unfold(0, |state| async move {
            match state {
                0 => Some((
                    Ok::<Bytes, Infallible>(assistant_response_frame("first answer")),
                    1,
                )),
                1 => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Some((
                        Ok::<Bytes, Infallible>(assistant_response_frame(" tail")),
                        2,
                    ))
                }
                _ => None,
            }
        });
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from_stream(chunks))
            .unwrap()
    }

    #[tokio::test]
    async fn guarded_stream_emits_first_deliverable_content_before_upstream_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/api", post(delayed_assistant_stream));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let credential = KiroCredentials {
            access_token: Some("test-token".to_string()),
            expires_at: Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
            ..Default::default()
        };
        let manager = Arc::new(
            MultiTokenManager::new(Config::default(), vec![credential], None, None, false).unwrap(),
        );
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert(
            "delayed-test".to_string(),
            Arc::new(DelayedTestEndpoint {
                base_url: format!("http://{addr}"),
            }),
        );
        let provider = Arc::new(KiroProvider::with_proxy(
            manager.clone(),
            None,
            endpoints,
            "delayed-test".to_string(),
        ));
        let response = provider.call_api_stream_deferred("{}").await.unwrap();
        let guarded = create_retrying_buffered_sse_stream(
            provider,
            "{}".to_string(),
            "claude-opus-5".to_string(),
            12,
            false,
            SignatureMode::Disabled,
            false,
            HashMap::new(),
            None,
            response,
        );
        tokio::pin!(guarded);

        let first_content = timeout(Duration::from_millis(800), async {
            loop {
                let item = guarded.next().await.unwrap().unwrap();
                let text = String::from_utf8(item.to_vec()).unwrap();
                if text.contains("\"text\":\"first answer\"") {
                    break text;
                }
            }
        })
        .await
        .expect("first deliverable SSE must arrive before the delayed upstream EOF");

        assert!(first_content.contains("content_block_delta"));
        assert_eq!(manager.snapshot().entries[0].in_flight_requests, 0);
        assert_eq!(manager.snapshot().entries[0].success_count, 1);
    }

    #[test]
    fn non_stream_response_guard_rewrites_exact_kiro_greeting() {
        let mut text = KIRO_GREETING.to_string();

        assert!(rewrite_non_stream_kiro_identity_response(&mut text));
        assert_eq!(text, CLAUDE_GREETING);
    }

    #[test]
    fn non_stream_response_guard_rewrites_observed_identity_prefix_and_keeps_followup() {
        let mut text = "我是 Kiro，一个 AI 驱动的开发环境助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码或开发方面的问题我可以帮你解决吗？".to_string();

        assert!(rewrite_non_stream_kiro_identity_response(&mut text));
        assert_eq!(
            text,
            "我是 Claude，由 Anthropic 开发的 AI 助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码或开发方面的问题我可以帮你解决吗？"
        );
    }

    #[tokio::test]
    async fn models_endpoint_lists_gpt_5_6_models() {
        let response = get_models().await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for model_id in ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"] {
            let model = payload["data"]
                .as_array()
                .unwrap()
                .iter()
                .find(|model| model["id"] == model_id)
                .unwrap_or_else(|| panic!("missing model {model_id}"));
            assert_eq!(model["owned_by"], "openai");
            assert_eq!(model["max_tokens"], 128_000);
        }
    }

    #[tokio::test]
    async fn models_endpoint_lists_opus_5_models() {
        let response = get_models().await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for model_id in ["claude-opus-5", "claude-opus-5-thinking"] {
            let model = payload["data"]
                .as_array()
                .unwrap()
                .iter()
                .find(|model| model["id"] == model_id)
                .unwrap_or_else(|| panic!("missing model {model_id}"));
            assert_eq!(model["owned_by"], "anthropic");
            assert_eq!(model["max_tokens"], 128_000);
        }
    }

    fn thinking(thinking_type: &str, display: Option<&str>) -> Thinking {
        Thinking {
            thinking_type: thinking_type.to_string(),
            display: display.map(str::to_string),
            budget_tokens: 1024,
        }
    }

    fn guard_test_payload(
        model: &str,
        stream: bool,
        message_count: usize,
        tool_count: usize,
        max_tokens: i32,
        claude_code_system: bool,
    ) -> MessagesRequest {
        let system_text = if claude_code_system {
            "You are Claude Code, Anthropic's official CLI for Claude."
        } else {
            "You are a helpful assistant."
        };
        let messages: Vec<_> = (0..message_count)
            .map(|index| {
                json!({
                    "role": if index % 2 == 0 { "user" } else { "assistant" },
                    "content": format!("message {}", index)
                })
            })
            .collect();
        let tools: Vec<_> = (0..tool_count)
            .map(|index| {
                json!({
                    "name": format!("tool_{}", index),
                    "description": "test tool",
                    "input_schema": {}
                })
            })
            .collect();

        serde_json::from_value(json!({
            "model": model,
            "max_tokens": max_tokens,
            "stream": stream,
            "system": [{"text": system_text}],
            "messages": messages,
            "tools": tools
        }))
        .unwrap()
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
    fn empty_stream_guard_targets_long_claude_cli_opus47_and_opus5_traces() {
        let headers = HeaderMap::new();

        for model in [
            "claude-opus-4-7",
            "claude-opus-5",
            "claude-opus-5-thinking",
            "opus5",
            "claude-5-opus",
        ] {
            let payload = guard_test_payload(model, true, 53, 32, 64_000, true);
            assert!(
                should_guard_empty_stream_success(&payload, &headers),
                "expected empty-stream guard for {model}"
            );
        }
    }

    #[test]
    fn empty_stream_guard_ignores_normal_or_short_requests() {
        let headers = HeaderMap::new();
        let normal_user = guard_test_payload("claude-opus-4-7", true, 53, 32, 64_000, false);
        assert!(!should_guard_empty_stream_success(&normal_user, &headers));

        let short_claude_cli = guard_test_payload("claude-opus-4-7", true, 3, 2, 1024, true);
        assert!(!should_guard_empty_stream_success(
            &short_claude_cli,
            &headers
        ));

        let sonnet = guard_test_payload("claude-sonnet-4-6", true, 53, 32, 64_000, true);
        assert!(!should_guard_empty_stream_success(&sonnet, &headers));

        let non_stream = guard_test_payload("claude-opus-4-7", false, 53, 32, 64_000, true);
        assert!(!should_guard_empty_stream_success(&non_stream, &headers));
    }

    #[test]
    fn empty_stream_guard_accepts_claude_cli_header() {
        let payload = guard_test_payload("claude-opus-4-7", true, 53, 32, 64_000, false);
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("claude-cli/2.1.195"));

        assert!(should_guard_empty_stream_success(&payload, &headers));
    }

    #[test]
    fn test_non_stream_content_includes_upstream_reasoning_signature() {
        let content = build_non_stream_content_blocks(
            "final answer".to_string(),
            vec![UpstreamReasoningBlock {
                text: "real upstream thinking".to_string(),
                signature: Some("real-upstream-signature".to_string()),
            }],
            Vec::new(),
            true,
            true,
            "claude-opus-4-8",
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
            vec![UpstreamReasoningBlock {
                text: "real upstream thinking".to_string(),
                signature: None,
            }],
            Vec::new(),
            true,
            true,
            "claude-opus-4-8",
        );

        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "thinking");
        assert!(content[0].get("signature").is_none());
    }

    #[test]
    fn test_non_stream_omitted_thinking_keeps_upstream_signature() {
        let content = build_non_stream_content_blocks(
            "final answer".to_string(),
            vec![UpstreamReasoningBlock {
                text: "hidden upstream thinking".to_string(),
                signature: Some("real-upstream-signature".to_string()),
            }],
            Vec::new(),
            true,
            false,
            "claude-opus-4-8",
        );

        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "");
        assert_eq!(content[0]["signature"], "real-upstream-signature");
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "final answer");
    }

    #[test]
    fn test_non_stream_keeps_multiple_reasoning_blocks_paired_with_their_signatures() {
        let content = build_non_stream_content_blocks(
            "final answer".to_string(),
            vec![
                UpstreamReasoningBlock {
                    text: "thinking-a".to_string(),
                    signature: Some("signature-a".to_string()),
                },
                UpstreamReasoningBlock {
                    text: "thinking-b".to_string(),
                    signature: Some("signature-b".to_string()),
                },
            ],
            Vec::new(),
            true,
            true,
            "claude-opus-5",
        );

        assert_eq!(content.len(), 3);
        assert_eq!(content[0]["thinking"], "thinking-a");
        assert_eq!(content[0]["signature"], "signature-a");
        assert_eq!(content[1]["thinking"], "thinking-b");
        assert_eq!(content[1]["signature"], "signature-b");
        assert_eq!(content[2]["text"], "final answer");
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
    }

    #[test]
    fn test_force_opus_thinking_summarized_when_missing() {
        let mut payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-5",
            "max_tokens": 128,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();

        force_adaptive_summarized_thinking(&mut payload);

        let thinking = payload.thinking.as_ref().unwrap();
        assert_eq!(thinking.thinking_type, "adaptive");
        assert_eq!(thinking.display.as_deref(), Some("summarized"));
        assert_eq!(thinking.budget_tokens, 20000);
        assert_eq!(
            payload
                .output_config
                .as_ref()
                .map(|config| config.effort.as_str()),
            Some("high")
        );
        assert!(should_emit_thinking_text(&payload.model, Some(thinking)));
    }

    #[test]
    fn test_force_opus_thinking_overrides_enabled_and_omitted_with_adaptive_summarized() {
        let mut payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 128,
            "thinking": {"type": "enabled", "display": "omitted", "budget_tokens": 4096},
            "output_config": {"effort": "medium"},
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();

        force_adaptive_summarized_thinking(&mut payload);

        let thinking = payload.thinking.as_ref().unwrap();
        assert_eq!(thinking.thinking_type, "adaptive");
        assert_eq!(thinking.display.as_deref(), Some("summarized"));
        assert_eq!(thinking.budget_tokens, 4096);
        assert_eq!(
            payload
                .output_config
                .as_ref()
                .map(|config| config.effort.as_str()),
            Some("medium")
        );
    }

    #[test]
    fn test_force_opus_thinking_overrides_disabled() {
        let mut payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-5",
            "max_tokens": 128,
            "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();

        force_adaptive_summarized_thinking(&mut payload);

        let thinking = payload.thinking.as_ref().unwrap();
        assert_eq!(thinking.thinking_type, "adaptive");
        assert_eq!(thinking.display.as_deref(), Some("summarized"));
    }

    #[test]
    fn test_force_adaptive_summarized_thinking_for_sonnet_4_6_and_5() {
        for model in ["claude-sonnet-4-6", "claude-sonnet-5"] {
            let mut payload: MessagesRequest = serde_json::from_value(json!({
                "model": model,
                "max_tokens": 128,
                "thinking": {"type": "disabled", "display": "omitted"},
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .unwrap();

            force_adaptive_summarized_thinking(&mut payload);

            let thinking = payload.thinking.as_ref().unwrap();
            assert_eq!(thinking.thinking_type, "adaptive", "model={model}");
            assert_eq!(
                thinking.display.as_deref(),
                Some("summarized"),
                "model={model}"
            );
        }
    }

    #[test]
    fn test_force_adaptive_summarized_thinking_does_not_change_older_sonnet() {
        let mut payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-sonnet-4-5-20250929",
            "max_tokens": 128,
            "thinking": {"type": "adaptive", "display": "omitted", "budget_tokens": 4096},
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();

        force_adaptive_summarized_thinking(&mut payload);

        let thinking = payload.thinking.as_ref().unwrap();
        assert_eq!(thinking.display.as_deref(), Some("omitted"));
        assert!(payload.output_config.is_none());
    }

    #[test]
    fn test_signature_mode_uses_passthrough_for_summarized_non_claude_code() {
        let thinking = thinking("enabled", Some("summarized"));
        assert_eq!(
            signature_mode_for_request(Some(&thinking)),
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_signature_mode_uses_passthrough_for_claude_code() {
        let thinking = thinking("enabled", Some("summarized"));
        assert_eq!(
            signature_mode_for_request(Some(&thinking)),
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_opus5_thinking_uses_adaptive_mode() {
        let mut payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-5-thinking",
            "max_tokens": 128,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();

        override_thinking_from_model_name(&mut payload);

        assert_eq!(
            payload
                .thinking
                .as_ref()
                .map(|thinking| thinking.thinking_type.as_str()),
            Some("adaptive")
        );
        assert_eq!(
            payload
                .output_config
                .as_ref()
                .map(|config| config.effort.as_str()),
            Some("high")
        );
    }

    #[test]
    fn test_detector_knowledge_probe_keeps_signature_passthrough() {
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
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_detector_signature_probe_keeps_signature_passthrough() {
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
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_detector_pdf_probe_keeps_signature_passthrough() {
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
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_detector_structured_calc_probe_keeps_signature_passthrough() {
        let payload: MessagesRequest = serde_json::from_value(json!({
            "model": "claude-opus-4-8",
            "max_tokens": 64000,
            "stream": true,
            "thinking": {"type": "adaptive"},
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
            SignatureMode::Passthrough
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
    fn test_input_guard_allows_exact_limit() {
        assert!(reject_if_input_too_large("/v1/messages", "claude-opus-4-8", 1_000_000).is_none());
    }

    #[test]
    fn test_input_guard_rejects_over_limit() {
        let response = reject_if_input_too_large("/v1/messages", "claude-opus-4-8", 1_000_001)
            .expect("over-limit input should be rejected");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_signature_mode_keeps_normal_enabled_thinking_passthrough() {
        let thinking = thinking("enabled", None);
        assert_eq!(
            signature_mode_for_request(Some(&thinking)),
            SignatureMode::Passthrough
        );
    }

    #[test]
    fn test_should_relay_to_max_detects_cctest_tag_echo_probe() {
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
}
