//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多凭据故障转移和重试
//! 支持按凭据级 endpoint 切换不同 Kiro API 端点

use bytes::Bytes;
use futures::Stream;
use reqwest::{Client, header::RETRY_AFTER};
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::{AllRateLimitedError, MultiTokenManager};
use crate::model::config::TlsBackend;
use parking_lot::Mutex;

/// 每个凭据的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
const MAX_TOTAL_RETRIES: usize = 9;

/// 上游失败日志中的 body 摘要最大字符数。
const BODY_SUMMARY_MAX_CHARS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamFailureClass {
    SendError,
    Upstream5xx,
    Upstream429,
    Upstream401403,
    Upstream400,
    Upstream408,
    Upstream4xx,
    QuotaExhausted,
    AllRateLimited,
    AcquireContextError,
    UpstreamOther,
}

impl UpstreamFailureClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::SendError => "send_error",
            Self::Upstream5xx => "upstream_5xx",
            Self::Upstream429 => "upstream_429",
            Self::Upstream401403 => "upstream_401_403",
            Self::Upstream400 => "upstream_400",
            Self::Upstream408 => "upstream_408",
            Self::Upstream4xx => "upstream_4xx",
            Self::QuotaExhausted => "quota_exhausted",
            Self::AllRateLimited => "all_rate_limited",
            Self::AcquireContextError => "acquire_context_error",
            Self::UpstreamOther => "upstream_other",
        }
    }
}

struct SafeBodySummary {
    original_len: usize,
    summary_len: usize,
    truncated: bool,
    text: String,
}

struct FailureAttemptLog<'a> {
    credential_id: Option<u64>,
    import_note: Option<&'a str>,
    model: Option<&'a str>,
    api_type: &'a str,
    is_stream: bool,
    attempt: usize,
    max_retries: usize,
    elapsed_ms: u64,
    upstream_status: Option<reqwest::StatusCode>,
    retry_after: Option<Duration>,
    error_class: UpstreamFailureClass,
    body: Option<&'a str>,
    error_message: Option<&'a str>,
}

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多凭据故障转移和重试机制
/// 按凭据 `endpoint` 字段选择 [`KiroEndpoint`] 实现
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于凭据无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// Client 缓存：key = effective proxy config, value = reqwest::Client
    /// 不同代理配置的凭据使用不同的 Client，共享相同代理的凭据复用 Client
    client_cache: Mutex<HashMap<Option<ProxyConfig>, Client>>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 端点实现注册表（key: endpoint 名称）
    endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
    /// 默认端点名称（凭据未指定 endpoint 时使用）
    default_endpoint: String,
}

pub type KiroByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

pub struct KiroStreamResponse {
    response: reqwest::Response,
    credential_id: u64,
}

impl KiroStreamResponse {
    fn new(response: reqwest::Response, credential_id: u64) -> Self {
        Self {
            response,
            credential_id,
        }
    }

    pub fn credential_id(&self) -> u64 {
        self.credential_id
    }

    pub fn bytes_stream(self) -> KiroByteStream {
        Box::pin(self.response.bytes_stream())
    }
}

impl KiroProvider {
    /// 创建带代理配置和端点注册表的 KiroProvider 实例
    ///
    /// # Arguments
    /// * `token_manager` - 多凭据 Token 管理器
    /// * `proxy` - 全局代理配置
    /// * `endpoints` - 端点名 → 实现的注册表（至少包含 `default_endpoint` 对应条目）
    /// * `default_endpoint` - 凭据未显式指定 endpoint 时使用的名称
    pub fn with_proxy(
        token_manager: Arc<MultiTokenManager>,
        proxy: Option<ProxyConfig>,
        endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
        default_endpoint: String,
    ) -> Self {
        assert!(
            endpoints.contains_key(&default_endpoint),
            "默认端点 {} 未在 endpoints 注册表中",
            default_endpoint
        );
        let tls_backend = token_manager.config().tls_backend;
        // 预热：构建全局代理对应的 Client
        let initial_client =
            build_client(proxy.as_ref(), 720, tls_backend).expect("创建 HTTP 客户端失败");
        let mut cache = HashMap::new();
        cache.insert(proxy.clone(), initial_client);

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(cache),
            tls_backend,
            endpoints,
            default_endpoint,
        }
    }

    /// 暴露底层 token_manager（只读），供请求路径读取运行时开关状态（如破甲模式）
    pub fn token_manager(&self) -> &Arc<MultiTokenManager> {
        &self.token_manager
    }

    /// 根据凭据的代理配置获取（或创建并缓存）对应的 reqwest::Client
    fn client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client.clone());
        }
        let client = build_client(effective.as_ref(), 720, self.tls_backend)?;
        cache.insert(effective, client.clone());
        Ok(client)
    }

    /// 根据凭据选择 endpoint 实现
    fn endpoint_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        let name = credentials
            .endpoint
            .as_deref()
            .unwrap_or(&self.default_endpoint);
        self.endpoints
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未知端点: {}", name))
    }

    fn credential_import_note(credentials: &KiroCredentials) -> &str {
        credentials.import_note.as_deref().unwrap_or("")
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多凭据故障转移（见 [`Self::call_api_with_retry`]）
    pub async fn call_api(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_api_with_retry(request_body, false, true)
            .await
            .map(|(response, _)| response)
    }

    /// 发送流式 API 请求
    pub async fn call_api_stream(&self, request_body: &str) -> anyhow::Result<KiroStreamResponse> {
        self.call_api_with_retry(request_body, true, true)
            .await
            .map(|(response, credential_id)| KiroStreamResponse::new(response, credential_id))
    }

    /// 发送需要在流结束后确认语义成功的流式请求。
    ///
    /// HTTP 2xx 只说明上游接受了请求，不代表流里有可交付内容。调用方必须在
    /// 验证到非空文本或完整 tool_use 后调用 [`Self::report_stream_success`]；空流
    /// 或读取失败则调用 [`Self::report_empty_stream_retry`] 释放本次 in-flight。
    pub async fn call_api_stream_deferred(
        &self,
        request_body: &str,
    ) -> anyhow::Result<KiroStreamResponse> {
        self.call_api_with_retry(request_body, true, false)
            .await
            .map(|(response, credential_id)| KiroStreamResponse::new(response, credential_id))
    }

    pub fn report_stream_success(&self, credential_id: u64) {
        self.token_manager.report_success(credential_id);
    }

    pub fn report_empty_stream_retry(&self, credential_id: u64) -> bool {
        self.token_manager.report_transient_cooldown(
            credential_id,
            Duration::from_secs(1),
            "上游 2xx 空流",
        )
    }

    /// 发送 MCP API 请求（WebSearch 等工具调用）
    pub async fn call_mcp(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_mcp_with_retry(request_body).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();

        for attempt in 0..max_retries {
            let attempt_number = attempt + 1;
            // MCP 调用（WebSearch 等工具）不涉及模型选择，无需按模型过滤凭据
            let ctx = match self.token_manager.acquire_context(None).await {
                Ok(c) => c,
                Err(e) => {
                    let error_message = e.to_string();
                    if e.downcast_ref::<AllRateLimitedError>().is_some() {
                        Self::log_upstream_failure(FailureAttemptLog {
                            credential_id: None,
                            import_note: None,
                            model: None,
                            api_type: "mcp",
                            is_stream: false,
                            attempt: attempt_number,
                            max_retries,
                            elapsed_ms: 0,
                            upstream_status: None,
                            retry_after: None,
                            error_class: UpstreamFailureClass::AllRateLimited,
                            body: None,
                            error_message: Some(&error_message),
                        });
                    } else {
                        Self::log_upstream_failure(FailureAttemptLog {
                            credential_id: None,
                            import_note: None,
                            model: None,
                            api_type: "mcp",
                            is_stream: false,
                            attempt: attempt_number,
                            max_retries,
                            elapsed_ms: 0,
                            upstream_status: None,
                            retry_after: None,
                            error_class: UpstreamFailureClass::AcquireContextError,
                            body: None,
                            error_message: Some(&error_message),
                        });
                    }
                    last_error = Some(e);
                    continue;
                }
            };

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    // endpoint 解析失败：记为失败，换下一张凭据
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.mcp_url(&rctx);
            let body = endpoint.transform_mcp_body(request_body, &rctx);

            let client = match self.client_for(&ctx.credentials) {
                Ok(client) => client,
                Err(e) => {
                    self.token_manager
                        .report_attempt_finished_without_success(ctx.id);
                    return Err(e);
                }
            };

            let start = std::time::Instant::now();
            let base = client
                .post(&url)
                .body(body)
                .header("content-type", "application/json")
                .header("Connection", "close");
            let request = endpoint.decorate_mcp(base, &rctx);

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    let error_message = e.to_string();
                    Self::log_upstream_failure(FailureAttemptLog {
                        credential_id: Some(ctx.id),
                        import_note: Some(Self::credential_import_note(&ctx.credentials)),
                        model: None,
                        api_type: "mcp",
                        is_stream: false,
                        attempt: attempt_number,
                        max_retries,
                        elapsed_ms: start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                        upstream_status: None,
                        retry_after: None,
                        error_class: UpstreamFailureClass::SendError,
                        body: None,
                        error_message: Some(&error_message),
                    });
                    self.token_manager
                        .report_attempt_finished_without_success(ctx.id);
                    last_error = Some(e.into());
                    if attempt_number < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();
            // 成功响应
            if status.is_success() {
                tracing::info!(
                    request_outcome = "success",
                    credential_id = ctx.id,
                    import_note = %Self::credential_import_note(&ctx.credentials),
                    upstream_status = status.as_u16(),
                    ttfb_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    api_type = "mcp",
                    is_stream = false,
                    attempt = attempt_number,
                    max_retries = max_retries,
                    "上游响应成功"
                );
                self.token_manager.report_success(ctx.id);
                return Ok(response);
            }

            let retry_after = Self::retry_after_delay(response.headers());

            // 失败响应
            let body = response.text().await.unwrap_or_default();
            let is_quota_exhausted =
                status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body);
            let failure_class =
                Self::classify_upstream_failure(Some(status), false, is_quota_exhausted, false);
            Self::log_upstream_failure(FailureAttemptLog {
                credential_id: Some(ctx.id),
                import_note: Some(Self::credential_import_note(&ctx.credentials)),
                model: None,
                api_type: "mcp",
                is_stream: false,
                attempt: attempt_number,
                max_retries,
                elapsed_ms: start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                upstream_status: Some(status),
                retry_after,
                error_class: failure_class,
                body: Some(&body),
                error_message: None,
            });
            let detail = format!("{} {}", status, body);

            // 402 额度用尽
            if is_quota_exhausted {
                // AWS 侧 overage=ENABLED 且全局开关开启：放行软冷却轮换，不永久禁用
                if self.token_manager.is_overage_enabled(ctx.id) {
                    let has_available = self.token_manager.report_rate_limited(ctx.id, None);
                    if !has_available {
                        anyhow::bail!("MCP 请求失败（所有凭据超额冷却中）: {}", detail);
                    }
                    last_error = Some(anyhow::anyhow!("MCP 超额放行轮换: {}", detail));
                    continue;
                }

                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {}", detail);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {}", detail));
                continue;
            }

            // 400 Bad Request
            if status.as_u16() == 400 {
                self.token_manager
                    .report_attempt_finished_without_success(ctx.id);
                anyhow::bail!("MCP 请求失败: {}", detail);
            }

            // 401/403 凭据问题
            if matches!(status.as_u16(), 401 | 403) {
                if Self::is_upstream_security_suspension(&body) {
                    let has_available = self.token_manager.report_upstream_suspended(ctx.id);
                    if !has_available {
                        anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {}", detail);
                    }
                    last_error = Some(anyhow::anyhow!("MCP 请求失败: {}", detail));
                    continue;
                }
                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!(
                        credential_id = ctx.id,
                        import_note = %Self::credential_import_note(&ctx.credentials),
                        "凭据 #{} token 疑似被上游失效，尝试强制刷新",
                        ctx.id
                    );
                    if self
                        .token_manager
                        .force_refresh_token_for(ctx.id)
                        .await
                        .is_ok()
                    {
                        tracing::info!(
                            credential_id = ctx.id,
                            import_note = %Self::credential_import_note(&ctx.credentials),
                            "凭据 #{} token 强制刷新成功，重试请求",
                            ctx.id
                        );
                        self.token_manager
                            .report_attempt_finished_without_success(ctx.id);
                        continue;
                    }
                    tracing::warn!(
                        credential_id = ctx.id,
                        import_note = %Self::credential_import_note(&ctx.credentials),
                        "凭据 #{} token 强制刷新失败，计入失败",
                        ctx.id
                    );
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {}", detail);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {}", detail));
                continue;
            }

            // 瞬态错误
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                if status.as_u16() == 429 {
                    self.token_manager.report_rate_limited(ctx.id, retry_after);
                } else {
                    self.token_manager
                        .report_attempt_finished_without_success(ctx.id);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {}", detail));
                if attempt_number < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx
            if status.is_client_error() {
                self.token_manager
                    .report_attempt_finished_without_success(ctx.id);
                anyhow::bail!("MCP 请求失败: {}", detail);
            }

            // 兜底
            last_error = Some(anyhow::anyhow!("MCP 请求失败: {}", detail));
            self.token_manager
                .report_attempt_finished_without_success(ctx.id);
            if attempt_number < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("MCP 请求失败：已达到最大重试次数（{}次）", max_retries)
        }))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个凭据最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(凭据数量 × 每凭据重试次数, MAX_TOTAL_RETRIES)
    /// - 硬上限 9 次，避免无限重试
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
        report_success_on_headers: bool,
    ) -> anyhow::Result<(reqwest::Response, u64)> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 尝试从请求体中提取模型信息
        let model = Self::extract_model_from_request(request_body);

        for attempt in 0..max_retries {
            let attempt_number = attempt + 1;
            // 获取调用上下文（绑定 index、credentials、token）
            let ctx = match self.token_manager.acquire_context(model.as_deref()).await {
                Ok(c) => c,
                Err(e) => {
                    let error_message = e.to_string();
                    // RPM 全限：立即终止重试，交由 HTTP 层映射为通用上游不可用。
                    if e.downcast_ref::<AllRateLimitedError>().is_some() {
                        Self::log_upstream_failure(FailureAttemptLog {
                            credential_id: None,
                            import_note: None,
                            model: model.as_deref(),
                            api_type,
                            is_stream,
                            attempt: attempt_number,
                            max_retries,
                            elapsed_ms: 0,
                            upstream_status: None,
                            retry_after: None,
                            error_class: UpstreamFailureClass::AllRateLimited,
                            body: None,
                            error_message: Some(&error_message),
                        });
                        return Err(e);
                    }
                    Self::log_upstream_failure(FailureAttemptLog {
                        credential_id: None,
                        import_note: None,
                        model: model.as_deref(),
                        api_type,
                        is_stream,
                        attempt: attempt_number,
                        max_retries,
                        elapsed_ms: 0,
                        upstream_status: None,
                        retry_after: None,
                        error_class: UpstreamFailureClass::AcquireContextError,
                        body: None,
                        error_message: Some(&error_message),
                    });
                    last_error = Some(e);
                    continue;
                }
            };

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.api_url(&rctx);
            let body = endpoint.transform_api_body(request_body, &rctx);

            let client = match self.client_for(&ctx.credentials) {
                Ok(client) => client,
                Err(e) => {
                    self.token_manager
                        .report_attempt_finished_without_success(ctx.id);
                    return Err(e);
                }
            };

            let start = std::time::Instant::now();
            let base = client
                .post(&url)
                .body(body)
                .header("content-type", "application/json")
                .header("Connection", "close");
            let request = endpoint.decorate_api(base, &rctx);

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    let error_message = e.to_string();
                    Self::log_upstream_failure(FailureAttemptLog {
                        credential_id: Some(ctx.id),
                        import_note: Some(Self::credential_import_note(&ctx.credentials)),
                        model: model.as_deref(),
                        api_type,
                        is_stream,
                        attempt: attempt_number,
                        max_retries,
                        elapsed_ms: start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                        upstream_status: None,
                        retry_after: None,
                        error_class: UpstreamFailureClass::SendError,
                        body: None,
                        error_message: Some(&error_message),
                    });
                    // 网络错误通常是上游/链路瞬态问题，不应导致"禁用凭据"或"切换凭据"
                    // （否则一段时间网络抖动会把所有凭据都误禁用，需要重启才能恢复）
                    self.token_manager
                        .report_attempt_finished_without_success(ctx.id);
                    last_error = Some(e.into());
                    if attempt_number < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();
            // 成功响应
            if status.is_success() {
                let request_outcome = if report_success_on_headers {
                    "success"
                } else {
                    "pending_stream_validation"
                };
                tracing::info!(
                    request_outcome = request_outcome,
                    credential_id = ctx.id,
                    import_note = %Self::credential_import_note(&ctx.credentials),
                    upstream_status = status.as_u16(),
                    ttfb_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    model = model.as_deref().unwrap_or("?"),
                    api_type = api_type,
                    is_stream = is_stream,
                    attempt = attempt_number,
                    max_retries = max_retries,
                    "上游响应成功"
                );
                if report_success_on_headers {
                    self.token_manager.report_success(ctx.id);
                }
                return Ok((response, ctx.id));
            }

            let retry_after = Self::retry_after_delay(response.headers());

            // 失败响应：读取 body 用于日志/错误信息
            let body = response.text().await.unwrap_or_default();
            let is_quota_exhausted =
                status.as_u16() == 402 && endpoint.is_monthly_request_limit(&body);
            let failure_class =
                Self::classify_upstream_failure(Some(status), false, is_quota_exhausted, false);
            Self::log_upstream_failure(FailureAttemptLog {
                credential_id: Some(ctx.id),
                import_note: Some(Self::credential_import_note(&ctx.credentials)),
                model: model.as_deref(),
                api_type,
                is_stream,
                attempt: attempt_number,
                max_retries,
                elapsed_ms: start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                upstream_status: Some(status),
                retry_after,
                error_class: failure_class,
                body: Some(&body),
                error_message: None,
            });
            let detail = format!("{} {}", status, body);

            // 402 Payment Required 且额度用尽：禁用凭据并故障转移
            if is_quota_exhausted {
                // AWS 侧 overage=ENABLED 且全局开关开启：放行软冷却轮换，不永久禁用
                if self.token_manager.is_overage_enabled(ctx.id) {
                    let has_available = self.token_manager.report_rate_limited(ctx.id, None);
                    if !has_available {
                        anyhow::bail!(
                            "{} API 请求失败（所有凭据超额冷却中）: {}",
                            api_type,
                            detail
                        );
                    }
                    last_error = Some(anyhow::anyhow!("{} 超额放行轮换: {}", api_type, detail));
                    continue;
                }

                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!("{} API 请求失败（所有凭据已用尽）: {}", api_type, detail);
                }

                last_error = Some(anyhow::anyhow!("{} API 请求失败: {}", api_type, detail));
                continue;
            }

            // 400 Bad Request - 请求问题，重试/切换凭据无意义
            if status.as_u16() == 400 {
                self.token_manager
                    .report_attempt_finished_without_success(ctx.id);
                anyhow::bail!("{} API 请求失败: {}", api_type, detail);
            }

            // 401/403 - 更可能是凭据/权限问题：计入失败并允许故障转移
            if matches!(status.as_u16(), 401 | 403) {
                if Self::is_upstream_security_suspension(&body) {
                    let has_available = self.token_manager.report_upstream_suspended(ctx.id);
                    if !has_available {
                        anyhow::bail!("{} API 请求失败（所有凭据已用尽）: {}", api_type, detail);
                    }
                    last_error = Some(anyhow::anyhow!("{} API 请求失败: {}", api_type, detail));
                    continue;
                }
                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!(
                        credential_id = ctx.id,
                        import_note = %Self::credential_import_note(&ctx.credentials),
                        "凭据 #{} token 疑似被上游失效，尝试强制刷新",
                        ctx.id
                    );
                    if self
                        .token_manager
                        .force_refresh_token_for(ctx.id)
                        .await
                        .is_ok()
                    {
                        tracing::info!(
                            credential_id = ctx.id,
                            import_note = %Self::credential_import_note(&ctx.credentials),
                            "凭据 #{} token 强制刷新成功，重试请求",
                            ctx.id
                        );
                        self.token_manager
                            .report_attempt_finished_without_success(ctx.id);
                        continue;
                    }
                    tracing::warn!(
                        credential_id = ctx.id,
                        import_note = %Self::credential_import_note(&ctx.credentials),
                        "凭据 #{} token 强制刷新失败，计入失败",
                        ctx.id
                    );
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!("{} API 请求失败（所有凭据已用尽）: {}", api_type, detail);
                }

                last_error = Some(anyhow::anyhow!("{} API 请求失败: {}", api_type, detail));
                continue;
            }

            // 429/408/5xx - 瞬态上游错误：429 只冷却当前凭据并尝试其他凭据，
            // 其他瞬态错误只退避重试，避免把账号池永久锁死。
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                if status.as_u16() == 429 {
                    self.token_manager.report_rate_limited(ctx.id, retry_after);
                } else {
                    self.token_manager
                        .report_attempt_finished_without_success(ctx.id);
                }
                last_error = Some(anyhow::anyhow!("{} API 请求失败: {}", api_type, detail));
                if attempt_number < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx - 通常为请求/配置问题：直接返回，不计入凭据失败
            if status.is_client_error() {
                self.token_manager
                    .report_attempt_finished_without_success(ctx.id);
                anyhow::bail!("{} API 请求失败: {}", api_type, detail);
            }

            // 兜底：当作可重试的瞬态错误处理（不切换凭据）
            last_error = Some(anyhow::anyhow!("{} API 请求失败: {}", api_type, detail));
            self.token_manager
                .report_attempt_finished_without_success(ctx.id);
            if attempt_number < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        // 所有重试都失败
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "{} API 请求失败：已达到最大重试次数（{}次）",
                api_type,
                max_retries
            )
        }))
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 2_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }

    fn retry_after_delay(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
        headers
            .get(RETRY_AFTER)?
            .to_str()
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
    }

    fn classify_upstream_failure(
        status: Option<reqwest::StatusCode>,
        is_send_error: bool,
        is_quota_exhausted: bool,
        is_all_rate_limited: bool,
    ) -> UpstreamFailureClass {
        if is_all_rate_limited {
            return UpstreamFailureClass::AllRateLimited;
        }
        if is_send_error {
            return UpstreamFailureClass::SendError;
        }
        if is_quota_exhausted {
            return UpstreamFailureClass::QuotaExhausted;
        }

        match status.map(|s| s.as_u16()) {
            Some(500..=599) => UpstreamFailureClass::Upstream5xx,
            Some(429) => UpstreamFailureClass::Upstream429,
            Some(401 | 403) => UpstreamFailureClass::Upstream401403,
            Some(400) => UpstreamFailureClass::Upstream400,
            Some(408) => UpstreamFailureClass::Upstream408,
            Some(402..=499) => UpstreamFailureClass::Upstream4xx,
            _ => UpstreamFailureClass::UpstreamOther,
        }
    }

    fn is_upstream_security_suspension(body: &str) -> bool {
        body.contains("temporarily is suspended") && body.contains("security precaution")
    }

    fn safe_body_summary(body: &str) -> SafeBodySummary {
        let redacted = Self::redact_sensitive_text(body);
        let (text, truncated) = Self::truncate_for_log(&redacted, BODY_SUMMARY_MAX_CHARS);

        SafeBodySummary {
            original_len: body.len(),
            summary_len: text.len(),
            truncated,
            text,
        }
    }

    fn log_upstream_failure(event: FailureAttemptLog<'_>) {
        let body_summary = Self::safe_body_summary(event.body.unwrap_or_default());
        let error_summary = Self::safe_body_summary(event.error_message.unwrap_or_default());
        let upstream_status = event.upstream_status.map(|status| status.as_u16());
        let retry_after_secs = event.retry_after.map(|duration| duration.as_secs());

        tracing::warn!(
            request_outcome = "failure_attempt",
            credential_id = event.credential_id.unwrap_or_default(),
            credential_id_present = event.credential_id.is_some(),
            import_note = event.import_note.unwrap_or(""),
            model = event.model.unwrap_or("?"),
            api_type = event.api_type,
            is_stream = event.is_stream,
            attempt = event.attempt,
            max_retries = event.max_retries,
            elapsed_ms = event.elapsed_ms,
            upstream_status = upstream_status.unwrap_or_default(),
            upstream_status_present = upstream_status.is_some(),
            retry_after_secs = retry_after_secs.unwrap_or_default(),
            retry_after_present = retry_after_secs.is_some(),
            error_class = event.error_class.as_str(),
            body_len = body_summary.original_len,
            body_summary_len = body_summary.summary_len,
            body_summary_truncated = body_summary.truncated,
            body_summary = %body_summary.text,
            error_message_len = error_summary.original_len,
            error_message_summary_len = error_summary.summary_len,
            error_message_truncated = error_summary.truncated,
            error_message = %error_summary.text,
            "上游失败尝试"
        );
    }

    fn redact_sensitive_text(text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }

        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) {
            Self::redact_sensitive_json_value(&mut value);
            if let Ok(redacted) = serde_json::to_string(&value) {
                return redacted;
            }
        }

        text.lines()
            .map(|line| {
                if Self::line_contains_sensitive_key(line) {
                    "[REDACTED_SENSITIVE_LINE]".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn redact_sensitive_json_value(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map.iter_mut() {
                    if Self::is_sensitive_key(key) {
                        *value = serde_json::Value::String("[REDACTED]".to_string());
                    } else {
                        Self::redact_sensitive_json_value(value);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    Self::redact_sensitive_json_value(item);
                }
            }
            _ => {}
        }
    }

    fn line_contains_sensitive_key(line: &str) -> bool {
        let lowered = line.to_ascii_lowercase();
        [
            "authorization",
            "cookie",
            "set-cookie",
            "refresh_token",
            "refreshtoken",
            "access_token",
            "accesstoken",
            "id_token",
            "api_key",
            "apikey",
            "x-api-key",
            "secret",
            "session",
        ]
        .iter()
        .any(|needle| lowered.contains(needle))
    }

    fn is_sensitive_key(key: &str) -> bool {
        let normalized: String = key
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .flat_map(|ch| ch.to_lowercase())
            .collect();

        [
            "authorization",
            "cookie",
            "setcookie",
            "token",
            "accesstoken",
            "refreshtoken",
            "idtoken",
            "apikey",
            "secret",
            "session",
        ]
        .iter()
        .any(|needle| normalized.contains(needle))
    }

    fn truncate_for_log(text: &str, max_chars: usize) -> (String, bool) {
        let mut iter = text.chars();
        let truncated: String = iter.by_ref().take(max_chars).collect();
        let was_truncated = iter.next().is_some();
        (truncated, was_truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::model::config::Config;

    struct TestEndpoint {
        base_url: String,
    }

    impl KiroEndpoint for TestEndpoint {
        fn name(&self) -> &'static str {
            "test"
        }

        fn api_url(&self, _ctx: &RequestContext<'_>) -> String {
            format!("{}/api", self.base_url)
        }

        fn mcp_url(&self, _ctx: &RequestContext<'_>) -> String {
            format!("{}/mcp", self.base_url)
        }

        fn decorate_api(
            &self,
            req: reqwest::RequestBuilder,
            ctx: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            req.header("x-test-token", ctx.token)
        }

        fn decorate_mcp(
            &self,
            req: reqwest::RequestBuilder,
            ctx: &RequestContext<'_>,
        ) -> reqwest::RequestBuilder {
            req.header("x-test-token", ctx.token)
        }

        fn transform_api_body(&self, body: &str, _ctx: &RequestContext<'_>) -> String {
            body.to_string()
        }
    }

    #[test]
    fn test_classify_upstream_failure() {
        assert_eq!(
            KiroProvider::classify_upstream_failure(None, true, false, false).as_str(),
            "send_error"
        );
        assert_eq!(
            KiroProvider::classify_upstream_failure(None, false, false, true).as_str(),
            "all_rate_limited"
        );
        assert_eq!(
            KiroProvider::classify_upstream_failure(
                Some(reqwest::StatusCode::BAD_GATEWAY),
                false,
                false,
                false
            )
            .as_str(),
            "upstream_5xx"
        );
        assert_eq!(
            KiroProvider::classify_upstream_failure(
                Some(reqwest::StatusCode::TOO_MANY_REQUESTS),
                false,
                false,
                false
            )
            .as_str(),
            "upstream_429"
        );
        assert_eq!(
            KiroProvider::classify_upstream_failure(
                Some(reqwest::StatusCode::FORBIDDEN),
                false,
                false,
                false
            )
            .as_str(),
            "upstream_401_403"
        );
        assert_eq!(
            KiroProvider::classify_upstream_failure(
                Some(reqwest::StatusCode::BAD_REQUEST),
                false,
                false,
                false
            )
            .as_str(),
            "upstream_400"
        );
        assert_eq!(
            KiroProvider::classify_upstream_failure(
                Some(reqwest::StatusCode::PAYMENT_REQUIRED),
                false,
                true,
                false
            )
            .as_str(),
            "quota_exhausted"
        );
    }

    #[test]
    fn test_detects_only_explicit_kiro_security_suspension() {
        assert!(KiroProvider::is_upstream_security_suspension(
            "Your User ID (example) temporarily is suspended. We've locked your account as a security precaution."
        ));
        assert!(!KiroProvider::is_upstream_security_suspension(
            "The bearer token included in the request is invalid"
        ));
        assert!(!KiroProvider::is_upstream_security_suspension(
            "Access denied for this model"
        ));
    }

    #[test]
    fn test_safe_body_summary_redacts_json_sensitive_fields() {
        let body = r#"{
            "message":"Invalid token provided",
            "refresh_token":"rt_secret",
            "Authorization":"Bearer access_secret",
            "cookie":"session_id=secret_cookie",
            "nested":{"apiKey":"kiro_secret"}
        }"#;

        let summary = KiroProvider::safe_body_summary(body);

        assert!(summary.text.contains("Invalid token provided"));
        assert!(summary.text.contains("[REDACTED]"));
        assert!(!summary.text.contains("rt_secret"));
        assert!(!summary.text.contains("Bearer access_secret"));
        assert!(!summary.text.contains("secret_cookie"));
        assert!(!summary.text.contains("kiro_secret"));
    }

    #[test]
    fn test_safe_body_summary_redacts_plain_sensitive_lines() {
        let body = "error=bad\nauthorization: Bearer access_secret\ncookie=session_id=secret_cookie\nnormal message";

        let summary = KiroProvider::safe_body_summary(body);

        assert!(summary.text.contains("error=bad"));
        assert!(summary.text.contains("normal message"));
        assert!(summary.text.contains("[REDACTED_SENSITIVE_LINE]"));
        assert!(!summary.text.contains("Bearer access_secret"));
        assert!(!summary.text.contains("secret_cookie"));
    }

    #[test]
    fn test_safe_body_summary_truncates_long_body() {
        let body = "x".repeat(BODY_SUMMARY_MAX_CHARS + 50);

        let summary = KiroProvider::safe_body_summary(&body);

        assert_eq!(summary.original_len, BODY_SUMMARY_MAX_CHARS + 50);
        assert_eq!(summary.summary_len, BODY_SUMMARY_MAX_CHARS);
        assert!(summary.truncated);
    }

    async fn rate_limit_first_credential(headers: HeaderMap) -> Response {
        let token = headers
            .get("x-test-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        if token == "t1" {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "30")],
                "limited",
            )
                .into_response()
        } else {
            (StatusCode::OK, "ok").into_response()
        }
    }

    async fn fail_once_then_ok(State(count): State<Arc<AtomicUsize>>) -> Response {
        if count.fetch_add(1, Ordering::SeqCst) == 0 {
            (StatusCode::INTERNAL_SERVER_ERROR, "temporary").into_response()
        } else {
            (StatusCode::OK, "ok").into_response()
        }
    }

    async fn always_ok() -> Response {
        (StatusCode::OK, "ok").into_response()
    }

    /// token=t1 返回 402 MONTHLY_REQUEST_COUNT（额度用尽），其余返回 200 OK。
    /// 用于验证 overage 放行后软冷却轮换到兄弟凭据并最终成功。
    async fn quota_exhausted_first_credential(headers: HeaderMap) -> Response {
        let token = headers
            .get("x-test-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        if token == "t1" {
            (
                StatusCode::PAYMENT_REQUIRED,
                r#"{"reason":"MONTHLY_REQUEST_COUNT"}"#,
            )
                .into_response()
        } else {
            (StatusCode::OK, "ok").into_response()
        }
    }

    /// 始终返回 402 MONTHLY_REQUEST_COUNT。
    async fn always_quota_exhausted() -> Response {
        (
            StatusCode::PAYMENT_REQUIRED,
            r#"{"reason":"MONTHLY_REQUEST_COUNT"}"#,
        )
            .into_response()
    }

    #[tokio::test]
    async fn test_deferred_stream_success_waits_for_semantic_confirmation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/api", post(always_ok));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = Config::default();
        let mut cred = KiroCredentials::default();
        cred.access_token = Some("token".to_string());
        cred.expires_at = Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339());

        let manager =
            Arc::new(MultiTokenManager::new(config, vec![cred], None, None, false).unwrap());
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert(
            "test".to_string(),
            Arc::new(TestEndpoint {
                base_url: format!("http://{}", addr),
            }),
        );
        let provider = KiroProvider::with_proxy(manager.clone(), None, endpoints, "test".into());

        let response = provider.call_api_stream_deferred("{}").await.unwrap();
        let credential_id = response.credential_id();
        assert_eq!(manager.snapshot().entries[0].success_count, 0);

        provider.report_stream_success(credential_id);
        assert_eq!(manager.snapshot().entries[0].success_count, 1);
    }

    #[tokio::test]
    async fn test_402_overage_enabled_keeps_credential() {
        // 两个 overage_status=ENABLED 的号；mock 对 t1 回 402 额度用尽、t2 回 200。
        // 期望：t1 不被永久禁用（仅软冷却），放行轮换到 t2 后请求成功，两号都仍在池。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/api", post(quota_exhausted_first_credential));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = Config::default(); // overage_passthrough 默认 true

        let mut cred1 = KiroCredentials::default();
        cred1.access_token = Some("t1".to_string());
        cred1.expires_at = Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        cred1.priority = 0; // 优先选中
        cred1.overage_status = Some("ENABLED".to_string());
        let mut cred2 = KiroCredentials::default();
        cred2.access_token = Some("t2".to_string());
        cred2.expires_at = Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        cred2.priority = 1;
        cred2.overage_status = Some("ENABLED".to_string());

        let manager = Arc::new(
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap(),
        );
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert(
            "test".to_string(),
            Arc::new(TestEndpoint {
                base_url: format!("http://{}", addr),
            }),
        );
        let provider = KiroProvider::with_proxy(manager.clone(), None, endpoints, "test".into());

        let response = provider.call_api("{}").await.unwrap();

        // 放行轮换到 t2 后请求成功
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");

        // t1（overage=ENABLED）未被永久禁用（仅软冷却），两号都仍在池、均未 disabled。
        // 注意：available_count 统计的是「当前可立即选中」的凭据，会把冷却中的 t1 排除，
        // 因此判断「未永久禁用」要看 snapshot 的 disabled 标志，而非 available_count。
        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        let second = snapshot.entries.iter().find(|e| e.id == 2).unwrap();
        assert!(
            !first.disabled,
            "overage=ENABLED 的号 402 后不应被永久禁用（应仅软冷却轮换）"
        );
        assert!(!second.disabled, "轮换目标号不应被禁用");
        // 两号都未被永久禁用，仍在凭据池中
        assert_eq!(
            snapshot.entries.iter().filter(|e| !e.disabled).count(),
            2,
            "两个 overage=ENABLED 的号都应保留在池中（未 disabled）"
        );
    }

    #[tokio::test]
    async fn test_402_overage_disabled_disables_credential() {
        // 非 ENABLED（overage_status=None）的号遇到 402 额度用尽：维持现状，永久禁用。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/api", post(always_quota_exhausted));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = Config::default();

        let mut cred = KiroCredentials::default();
        cred.access_token = Some("t1".to_string());
        cred.expires_at = Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        // overage_status 未设置（None）

        let manager =
            Arc::new(MultiTokenManager::new(config, vec![cred], None, None, false).unwrap());
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert(
            "test".to_string(),
            Arc::new(TestEndpoint {
                base_url: format!("http://{}", addr),
            }),
        );
        let provider = KiroProvider::with_proxy(manager.clone(), None, endpoints, "test".into());

        // 所有凭据额度用尽 → 调用最终失败
        let err = provider.call_api("{}").await.unwrap_err().to_string();
        assert!(
            err.contains("所有凭据已用尽") || err.contains("MONTHLY_REQUEST_COUNT"),
            "expected quota-exhausted failure, got: {}",
            err
        );

        // 该号被永久禁用
        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled, "非 ENABLED 的号 402 后应被禁用");
        assert_eq!(manager.available_count(), 0);
    }

    #[tokio::test]
    async fn test_call_api_rate_limits_current_credential_and_tries_next() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/api", post(rate_limit_first_credential));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut cred1 = KiroCredentials::default();
        cred1.access_token = Some("t1".to_string());
        cred1.expires_at = Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        let mut cred2 = KiroCredentials::default();
        cred2.access_token = Some("t2".to_string());
        cred2.expires_at = Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339());

        let manager = Arc::new(
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap(),
        );
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert(
            "test".to_string(),
            Arc::new(TestEndpoint {
                base_url: format!("http://{}", addr),
            }),
        );
        let provider = KiroProvider::with_proxy(manager.clone(), None, endpoints, "test".into());

        let response = provider.call_api("{}").await.unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
        assert_eq!(manager.available_count(), 1);

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(!first.disabled);
        assert_eq!(first.failure_count, 0);
    }

    #[tokio::test]
    async fn test_call_api_does_not_retry_when_failed_attempt_exhausts_rpm() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/api", post(fail_once_then_ok))
            .with_state(attempt_count.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = Config::default();
        config.default_rpm = Some(1);

        let mut cred = KiroCredentials::default();
        cred.access_token = Some("token".to_string());
        cred.expires_at = Some((Utc::now() + chrono::Duration::hours(1)).to_rfc3339());

        let manager =
            Arc::new(MultiTokenManager::new(config, vec![cred], None, None, false).unwrap());
        let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
        endpoints.insert(
            "test".to_string(),
            Arc::new(TestEndpoint {
                base_url: format!("http://{}", addr),
            }),
        );
        let provider = KiroProvider::with_proxy(manager.clone(), None, endpoints, "test".into());

        let err = provider.call_api("{}").await.unwrap_err().to_string();

        assert!(
            err.contains("每分钟请求上限") || err.contains("temporarily unavailable"),
            "expected failed attempt to exhaust RPM before retrying, got: {}",
            err
        );
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.entries[0].current_rpm, 1);
    }
}
