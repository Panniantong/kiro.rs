//! Admin API 业务逻辑服务

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::MultiTokenManager;

use super::error::AdminServiceError;
use super::types::{
    AddCredentialRequest, AddCredentialResponse, AddProxyPoolEntriesRequest, ArmorBreakingResponse,
    BalanceResponse, BatchSetCredentialProxyRequest, CredentialProxyTestResponse,
    CredentialStatusItem, CredentialsStatusResponse, DefaultRpmResponse, LoadBalancingModeResponse,
    MaxRelayResponse, OveragePassthroughResponse, ProxyPoolEntryStatus, ProxyPoolResponse,
    RemoveProxyPoolEntriesRequest, SetArmorBreakingRequest, SetCredentialProxyRequest,
    SetLoadBalancingModeRequest, SetMaxRelayRequest, SetOveragePassthroughRequest,
};
use crate::model::config::MaxRelayConfig;

/// 余额缓存过期时间（秒），5 分钟
const BALANCE_CACHE_TTL_SECS: i64 = 300;
/// 浮点余额接近 0 时视为额度耗尽
const BALANCE_EXHAUSTED_EPSILON: f64 = 0.000001;
/// 用户要求：一个住宅 IP 最多同时挂两个账号。
const MAX_ACCOUNTS_PER_PROXY: usize = 2;

/// 缓存的余额条目（含时间戳）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedBalance {
    /// 缓存时间（Unix 秒）
    cached_at: f64,
    /// 缓存的余额数据
    data: BalanceResponse,
}

/// 代理池持久化格式。凭据本身继续保存最终代理绑定，避免引入运行时依赖。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ProxyPool {
    #[serde(default)]
    proxies: Vec<ProxyPoolEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyPoolEntry {
    proxy_url: String,
    proxy_username: Option<String>,
    proxy_password: Option<String>,
}

/// Admin 服务
///
/// 封装所有 Admin API 的业务逻辑
pub struct AdminService {
    token_manager: Arc<MultiTokenManager>,
    balance_cache: Mutex<HashMap<u64, CachedBalance>>,
    cache_path: Option<PathBuf>,
    proxy_pool_path: Option<PathBuf>,
    proxy_pool: Mutex<ProxyPool>,
    /// 自动分配与写入凭据必须串行，防止并发导入突破每 IP 两号的上限。
    allocation_lock: tokio::sync::Mutex<()>,
    /// 已注册的端点名称集合（用于 add_credential 校验）
    known_endpoints: HashSet<String>,
}

impl AdminService {
    pub fn new(
        token_manager: Arc<MultiTokenManager>,
        known_endpoints: impl IntoIterator<Item = String>,
    ) -> Self {
        let cache_path = token_manager
            .cache_dir()
            .map(|d| d.join("kiro_balance_cache.json"));
        let proxy_pool_path = token_manager
            .cache_dir()
            .map(|d| d.join("kiro_proxy_pool.json"));

        let balance_cache = Self::load_balance_cache_from(&cache_path);
        let proxy_pool = Self::load_proxy_pool_from(&proxy_pool_path);

        Self {
            token_manager,
            balance_cache: Mutex::new(balance_cache),
            cache_path,
            proxy_pool_path,
            proxy_pool: Mutex::new(proxy_pool),
            allocation_lock: tokio::sync::Mutex::new(()),
            known_endpoints: known_endpoints.into_iter().collect(),
        }
    }

    /// 获取所有凭据状态
    pub fn get_all_credentials(&self) -> CredentialsStatusResponse {
        let snapshot = self.token_manager.snapshot();
        let default_endpoint = self.token_manager.config().default_endpoint.clone();

        let mut credentials: Vec<CredentialStatusItem> = snapshot
            .entries
            .into_iter()
            .map(|entry| CredentialStatusItem {
                id: entry.id,
                priority: entry.priority,
                disabled: entry.disabled,
                failure_count: entry.failure_count,
                is_current: entry.id == snapshot.current_id,
                expires_at: entry.expires_at,
                auth_method: entry.auth_method,
                has_profile_arn: entry.has_profile_arn,
                refresh_token_hash: entry.refresh_token_hash,
                api_key_hash: entry.api_key_hash,
                masked_api_key: entry.masked_api_key,
                email: entry.email,
                import_note: entry.import_note,
                success_count: entry.success_count,
                last_used_at: entry.last_used_at.clone(),
                has_proxy: entry.has_proxy,
                proxy_url: entry.proxy_url.as_deref().map(Self::redact_proxy_url),
                refresh_failure_count: entry.refresh_failure_count,
                disabled_reason: entry.disabled_reason,
                endpoint: entry.endpoint.unwrap_or_else(|| default_endpoint.clone()),
                rpm: entry.rpm,
                effective_rpm: entry.effective_rpm,
                rpm_follows_default: entry.rpm_follows_default,
                current_rpm: entry.current_rpm,
                peak_rpm_1h: entry.peak_rpm_1h,
                throttled_1h: entry.throttled_1h,
                overage_status: entry.overage_status,
            })
            .collect();

        // 按优先级排序（数字越小优先级越高）
        credentials.sort_by_key(|c| c.priority);

        CredentialsStatusResponse {
            total: snapshot.total,
            available: snapshot.available,
            current_id: snapshot.current_id,
            default_rpm: snapshot.default_rpm,
            credentials,
        }
    }

    /// 设置凭据禁用状态
    pub fn set_disabled(&self, id: u64, disabled: bool) -> Result<(), AdminServiceError> {
        // 先获取当前凭据 ID，用于判断是否需要切换
        let snapshot = self.token_manager.snapshot();
        let current_id = snapshot.current_id;

        self.token_manager
            .set_disabled(id, disabled)
            .map_err(|e| self.classify_error(e, id))?;

        // 只有禁用的是当前凭据时才尝试切换到下一个
        if disabled && id == current_id {
            let _ = self.token_manager.switch_to_next();
        }
        Ok(())
    }

    /// 设置凭据优先级
    pub fn set_priority(&self, id: u64, priority: u32) -> Result<(), AdminServiceError> {
        self.token_manager
            .set_priority(id, priority)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 绑定、清除或显式直连单个凭据的代理。
    pub fn set_credential_proxy(
        &self,
        id: u64,
        req: SetCredentialProxyRequest,
    ) -> Result<(), AdminServiceError> {
        let (proxy_url, proxy_username, proxy_password) =
            Self::validate_proxy_binding(req.proxy_url, req.proxy_username, req.proxy_password)?;
        self.token_manager
            .set_credential_proxy(id, proxy_url, proxy_username, proxy_password)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 把相同代理批量绑定给多个凭据。
    ///
    /// ponytail: 不引入代理池表。住宅 IP 直接保存在需要共用它的两个账号上；换 IP
    /// 时调用同一个接口即可批量覆盖。若未来需要跨大量账号复用、过期和库存管理，再升级为独立代理资源。
    pub fn set_credentials_proxy_batch(
        &self,
        req: BatchSetCredentialProxyRequest,
    ) -> Result<usize, AdminServiceError> {
        let (proxy_url, proxy_username, proxy_password) =
            Self::validate_proxy_binding(req.proxy_url, req.proxy_username, req.proxy_password)?;
        let ids = req.ids;
        self.token_manager
            .set_credentials_proxy_batch(&ids, proxy_url, proxy_username, proxy_password)
            .map(|_| ids.len())
            .map_err(|e| {
                let message = e.to_string();
                match message
                    .strip_prefix("凭据不存在: ")
                    .and_then(|id| id.parse::<u64>().ok())
                {
                    Some(id) => AdminServiceError::NotFound { id },
                    None => AdminServiceError::InvalidCredential(message),
                }
            })
    }

    /// 获取代理池及当前账号占用情况。已绑定但后来从池移除的账号不计入可分配池。
    pub fn get_proxy_pool(&self) -> ProxyPoolResponse {
        let snapshot = self.token_manager.snapshot();
        let pool = self.proxy_pool.lock();
        let proxies = pool
            .proxies
            .iter()
            .map(|entry| {
                let assigned_credential_ids: Vec<u64> = snapshot
                    .entries
                    .iter()
                    .filter(|credential| {
                        credential.proxy_url.as_deref() == Some(entry.proxy_url.as_str())
                    })
                    .map(|credential| credential.id)
                    .collect();
                let assigned_count = assigned_credential_ids.len();
                ProxyPoolEntryStatus {
                    proxy_url: Self::redact_proxy_url(&entry.proxy_url),
                    assigned_credential_ids,
                    assigned_count,
                    remaining_slots: MAX_ACCOUNTS_PER_PROXY.saturating_sub(assigned_count),
                }
            })
            .collect::<Vec<_>>();
        let available_slots = proxies.iter().map(|entry| entry.remaining_slots).sum();

        ProxyPoolResponse {
            max_accounts_per_proxy: MAX_ACCOUNTS_PER_PROXY,
            total: proxies.len(),
            available_slots,
            proxies,
        }
    }

    /// 追加代理池条目。重复 URL 会更新认证信息但不会产生重复槽位。
    pub fn add_proxy_pool_entries(
        &self,
        req: AddProxyPoolEntriesRequest,
    ) -> Result<usize, AdminServiceError> {
        if req.proxies.is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "代理池不能为空".to_string(),
            ));
        }

        let mut candidates = Vec::with_capacity(req.proxies.len());
        for proxy in req.proxies {
            let (proxy_url, proxy_username, proxy_password) = Self::validate_proxy_binding(
                proxy.proxy_url,
                proxy.proxy_username,
                proxy.proxy_password,
            )?;
            let proxy_url = proxy_url.ok_or_else(|| {
                AdminServiceError::InvalidCredential("代理池条目必须提供 proxyUrl".to_string())
            })?;
            if proxy_url.eq_ignore_ascii_case(KiroCredentials::PROXY_DIRECT) {
                return Err(AdminServiceError::InvalidCredential(
                    "代理池不能包含 direct".to_string(),
                ));
            }
            candidates.push(ProxyPoolEntry {
                proxy_url,
                proxy_username,
                proxy_password,
            });
        }

        let mut pool = self.proxy_pool.lock();
        for candidate in candidates {
            if let Some(existing) = pool
                .proxies
                .iter_mut()
                .find(|entry| entry.proxy_url == candidate.proxy_url)
            {
                *existing = candidate;
            } else {
                pool.proxies.push(candidate);
            }
        }
        self.persist_proxy_pool(&pool)?;
        Ok(pool.proxies.len())
    }

    /// 移除未使用的代理池条目，不触碰已经绑定到账号的出口配置。
    pub fn remove_proxy_pool_entries(
        &self,
        req: RemoveProxyPoolEntriesRequest,
    ) -> Result<usize, AdminServiceError> {
        if req.proxy_urls.is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "至少提供一个 proxyUrl".to_string(),
            ));
        }
        let urls: HashSet<String> = req
            .proxy_urls
            .into_iter()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect();
        if urls.is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "至少提供一个非空 proxyUrl".to_string(),
            ));
        }

        let mut pool = self.proxy_pool.lock();
        let before = pool.proxies.len();
        pool.proxies
            .retain(|entry| !urls.contains(&entry.proxy_url));
        let removed = before - pool.proxies.len();
        self.persist_proxy_pool(&pool)?;
        Ok(removed)
    }

    /// 以指定凭据实际会使用的代理访问出口探针，不触发 Kiro Token 刷新或上游模型调用。
    pub async fn test_credential_proxy(
        &self,
        id: u64,
    ) -> Result<CredentialProxyTestResponse, AdminServiceError> {
        let (credentials, effective_proxy) = self
            .token_manager
            .credential_and_effective_proxy(id)
            .map_err(|e| self.classify_error(e, id))?;
        let client = crate::http_client::build_client(
            effective_proxy.as_ref(),
            15,
            self.token_manager.config().tls_backend,
        )
        .map_err(|e| AdminServiceError::InvalidCredential(format!("代理配置无效: {}", e)))?;
        let response = client
            .get("https://api.ipify.org?format=json")
            .send()
            .await
            .map_err(|e| AdminServiceError::UpstreamError(format!("代理出口测试失败: {}", e)))?;
        let response = response
            .error_for_status()
            .map_err(|e| AdminServiceError::UpstreamError(format!("代理出口测试失败: {}", e)))?;
        let body: serde_json::Value = response.json().await.map_err(|e| {
            AdminServiceError::UpstreamError(format!("代理出口测试响应无效: {}", e))
        })?;
        let egress_ip = body
            .get("ip")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AdminServiceError::UpstreamError("代理出口测试未返回 IP".to_string()))?
            .to_string();

        Ok(CredentialProxyTestResponse {
            credential_id: id,
            uses_proxy: effective_proxy.is_some(),
            uses_credential_proxy: credentials.proxy_url.is_some(),
            proxy_url: credentials.proxy_url.as_deref().map(Self::redact_proxy_url),
            egress_ip,
            tested_at: Utc::now().to_rfc3339(),
        })
    }

    fn validate_proxy_binding(
        proxy_url: Option<String>,
        proxy_username: Option<String>,
        proxy_password: Option<String>,
    ) -> Result<(Option<String>, Option<String>, Option<String>), AdminServiceError> {
        let proxy_url = proxy_url
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());
        let proxy_username = proxy_username
            .map(|username| username.trim().to_string())
            .filter(|username| !username.is_empty());
        let proxy_password = proxy_password.filter(|password| !password.is_empty());

        match proxy_url.as_deref() {
            None => {
                if proxy_username.is_some() || proxy_password.is_some() {
                    return Err(AdminServiceError::InvalidCredential(
                        "清除代理时不能携带代理用户名或密码".to_string(),
                    ));
                }
            }
            Some(url) if url.eq_ignore_ascii_case(KiroCredentials::PROXY_DIRECT) => {
                if proxy_username.is_some() || proxy_password.is_some() {
                    return Err(AdminServiceError::InvalidCredential(
                        "direct 不能携带代理用户名或密码".to_string(),
                    ));
                }
            }
            Some(url) => {
                let parsed = Url::parse(url).map_err(|_| {
                    AdminServiceError::InvalidCredential("proxyUrl 必须是完整代理 URL".to_string())
                })?;
                if !matches!(parsed.scheme(), "http" | "https" | "socks5")
                    || parsed.host_str().is_none()
                {
                    return Err(AdminServiceError::InvalidCredential(
                        "proxyUrl 仅支持 http、https、socks5，且必须包含主机".to_string(),
                    ));
                }
                if proxy_username.is_some() != proxy_password.is_some() {
                    return Err(AdminServiceError::InvalidCredential(
                        "代理用户名和密码必须同时提供".to_string(),
                    ));
                }
            }
        }

        Ok((proxy_url, proxy_username, proxy_password))
    }

    fn redact_proxy_url(value: &str) -> String {
        if value.eq_ignore_ascii_case(KiroCredentials::PROXY_DIRECT) {
            return KiroCredentials::PROXY_DIRECT.to_string();
        }
        match Url::parse(value) {
            Ok(mut url) => {
                if !url.username().is_empty() || url.password().is_some() {
                    let _ = url.set_username("***");
                    let _ = url.set_password(Some("***"));
                }
                url.to_string()
            }
            Err(_) => "[invalid proxy URL]".to_string(),
        }
    }

    /// 在池内按录入顺序选择第一个未满两个账号的代理。
    ///
    /// ponytail: 代理清单独立落盘，但实际绑定仍随 credentials.json 保存；这让旧部署
    /// 和手工绑定保持兼容。库存过期、健康度或调度策略需要时再升级为完整资源模型。
    fn next_proxy_pool_entry(&self) -> Result<Option<ProxyPoolEntry>, AdminServiceError> {
        let snapshot = self.token_manager.snapshot();
        let pool = self.proxy_pool.lock();
        if pool.proxies.is_empty() {
            return Ok(None);
        }
        pool.proxies
            .iter()
            .find(|entry| {
                snapshot
                    .entries
                    .iter()
                    .filter(|credential| {
                        credential.proxy_url.as_deref() == Some(entry.proxy_url.as_str())
                    })
                    .count()
                    < MAX_ACCOUNTS_PER_PROXY
            })
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                AdminServiceError::InvalidCredential(format!(
                    "代理池已满：每个代理最多绑定 {} 个账号，请先添加新代理或显式指定 proxyUrl",
                    MAX_ACCOUNTS_PER_PROXY
                ))
            })
    }

    fn load_proxy_pool_from(path: &Option<PathBuf>) -> ProxyPool {
        let Some(path) = path else {
            return ProxyPool::default();
        };
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(pool) => pool,
                Err(error) => {
                    tracing::warn!("代理池文件解析失败，将以空池启动: {}", error);
                    ProxyPool::default()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProxyPool::default(),
            Err(error) => {
                tracing::warn!("代理池文件读取失败，将以空池启动: {}", error);
                ProxyPool::default()
            }
        }
    }

    fn persist_proxy_pool(&self, pool: &ProxyPool) -> Result<(), AdminServiceError> {
        let Some(path) = &self.proxy_pool_path else {
            return Err(AdminServiceError::InternalError(
                "凭据未配置持久化路径，无法保存代理池".to_string(),
            ));
        };
        let json = serde_json::to_string_pretty(pool).map_err(|error| {
            AdminServiceError::InternalError(format!("序列化代理池失败: {}", error))
        })?;
        std::fs::write(path, json)
            .map_err(|error| AdminServiceError::InternalError(format!("保存代理池失败: {}", error)))
    }

    /// 重置失败计数并重新启用
    pub fn reset_and_enable(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .reset_and_enable(id)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 获取凭据余额（带缓存）
    pub async fn get_balance(&self, id: u64) -> Result<BalanceResponse, AdminServiceError> {
        // 先查缓存
        let cached_balance = {
            let cache = self.balance_cache.lock();
            if let Some(cached) = cache.get(&id) {
                let now = Utc::now().timestamp() as f64;
                if (now - cached.cached_at) < BALANCE_CACHE_TTL_SECS as f64 {
                    tracing::debug!("凭据 #{} 余额命中缓存", id);
                    Some(cached.data.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(balance) = cached_balance {
            self.disable_if_quota_exhausted_balance(&balance);
            return Ok(balance);
        }

        // 缓存未命中或已过期，从上游获取
        let balance = self.fetch_balance(id).await?;

        // 更新缓存
        {
            let mut cache = self.balance_cache.lock();
            cache.insert(
                id,
                CachedBalance {
                    cached_at: Utc::now().timestamp() as f64,
                    data: balance.clone(),
                },
            );
        }
        self.save_balance_cache();
        self.disable_if_quota_exhausted_balance(&balance);

        Ok(balance)
    }

    fn disable_if_quota_exhausted_balance(&self, balance: &BalanceResponse) {
        if !Self::is_quota_exhausted_balance(balance) {
            return;
        }

        // AWS 侧 overage=ENABLED 且全局开关开启：进入超额、保持启用，不永久禁用
        if self.token_manager.is_overage_enabled(balance.id) {
            tracing::info!(
                "凭据 #{} 余额耗尽但 overage=ENABLED，进入超额、保持启用",
                balance.id
            );
            return;
        }

        let has_available = self.token_manager.report_quota_exhausted(balance.id);
        if has_available {
            tracing::warn!(
                "凭据 #{} 余额已耗尽（remaining={} usageLimit={}），已自动禁用",
                balance.id,
                balance.remaining,
                balance.usage_limit
            );
        } else {
            tracing::error!(
                "凭据 #{} 余额已耗尽（remaining={} usageLimit={}），已自动禁用；当前无可用凭据",
                balance.id,
                balance.remaining,
                balance.usage_limit
            );
        }
    }

    fn is_quota_exhausted_balance(balance: &BalanceResponse) -> bool {
        if balance.usage_limit <= 0.0 || balance.remaining > BALANCE_EXHAUSTED_EPSILON {
            return false;
        }

        if let Some(next_reset_at) = balance.next_reset_at {
            let now = Utc::now().timestamp() as f64;
            if next_reset_at <= now {
                return false;
            }
        }

        true
    }

    /// 从上游获取余额（无缓存）
    async fn fetch_balance(&self, id: u64) -> Result<BalanceResponse, AdminServiceError> {
        let usage = self
            .token_manager
            .get_usage_limits_for(id)
            .await
            .map_err(|e| self.classify_balance_error(e, id))?;

        let current_usage = usage.current_usage();
        let usage_limit = usage.usage_limit();
        let remaining = (usage_limit - current_usage).max(0.0);
        let usage_percentage = if usage_limit > 0.0 {
            (current_usage / usage_limit * 100.0).min(100.0)
        } else {
            0.0
        };

        Ok(BalanceResponse {
            id,
            subscription_title: usage.subscription_title().map(|s| s.to_string()),
            current_usage,
            usage_limit,
            remaining,
            usage_percentage,
            next_reset_at: usage.next_date_reset,
            overage_status: usage.overage_status().map(|s| s.to_string()),
            current_overages: usage.current_overages(),
            overage_cap: usage.overage_cap(),
            overage_rate: usage.overage_rate(),
        })
    }

    /// 添加新凭据
    pub async fn add_credential(
        &self,
        req: AddCredentialRequest,
    ) -> Result<AddCredentialResponse, AdminServiceError> {
        // 校验端点名：未指定则默认合法，指定则必须已注册
        if let Some(ref name) = req.endpoint {
            if !self.known_endpoints.contains(name) {
                let mut known: Vec<&str> =
                    self.known_endpoints.iter().map(|s| s.as_str()).collect();
                known.sort();
                return Err(AdminServiceError::InvalidCredential(format!(
                    "未知端点 \"{}\"，已注册端点: {:?}",
                    name, known
                )));
            }
        }

        // 序列化分配到实际写入，防止两个并发导入拿到同一个最后的空槽。
        let _allocation_guard = self.allocation_lock.lock().await;

        // 显式代理优先；未提供时自动从池中领取。未配置代理池时保持原有行为。
        let explicit_proxy = req.proxy_url.is_some();
        let assign_from_pool = req.assign_proxy_from_pool.unwrap_or(true);
        let assigned_proxy = if explicit_proxy || !assign_from_pool {
            None
        } else {
            self.next_proxy_pool_entry()?
        };

        // 构建凭据对象
        let email = req.email.clone();
        let import_note = req
            .import_note
            .map(|note| note.trim().to_string())
            .filter(|note| !note.is_empty());
        let new_cred = KiroCredentials {
            id: None,
            access_token: None,
            refresh_token: req.refresh_token,
            profile_arn: None,
            expires_at: None,
            auth_method: Some(req.auth_method),
            client_id: req.client_id,
            client_secret: req.client_secret,
            priority: req.priority,
            region: req.region,
            auth_region: req.auth_region,
            api_region: req.api_region,
            machine_id: req.machine_id,
            email: req.email,
            import_note,
            subscription_title: None, // 将在首次获取使用额度时自动更新
            overage_status: None,     // 将在首次获取使用额度时自动同步
            proxy_url: assigned_proxy
                .as_ref()
                .map(|entry| entry.proxy_url.clone())
                .or(req.proxy_url),
            proxy_username: assigned_proxy
                .as_ref()
                .and_then(|entry| entry.proxy_username.clone())
                .or(req.proxy_username),
            proxy_password: assigned_proxy
                .as_ref()
                .and_then(|entry| entry.proxy_password.clone())
                .or(req.proxy_password),
            disabled: false, // 新添加的凭据默认启用
            kiro_api_key: req.kiro_api_key,
            endpoint: req.endpoint,
            rpm: None,
        };

        // 调用 token_manager 添加凭据
        let credential_id = self
            .token_manager
            .add_credential(new_cred)
            .await
            .map_err(|e| self.classify_add_error(e))?;

        // 主动获取订阅等级，避免首次请求时 Free 账号绕过 Opus 模型过滤
        if let Err(e) = self.token_manager.get_usage_limits_for(credential_id).await {
            tracing::warn!("添加凭据后获取订阅等级失败（不影响凭据添加）: {}", e);
        }

        Ok(AddCredentialResponse {
            success: true,
            message: format!("凭据添加成功，ID: {}", credential_id),
            credential_id,
            email,
            assigned_proxy_url: assigned_proxy
                .as_ref()
                .map(|entry| Self::redact_proxy_url(&entry.proxy_url)),
            assigned_proxy_from_pool: assigned_proxy.is_some(),
        })
    }

    /// 删除凭据
    pub fn delete_credential(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .delete_credential(id)
            .map_err(|e| self.classify_delete_error(e, id))?;

        // 清理已删除凭据的余额缓存
        {
            let mut cache = self.balance_cache.lock();
            cache.remove(&id);
        }
        self.save_balance_cache();

        Ok(())
    }

    /// 获取负载均衡模式
    pub fn get_load_balancing_mode(&self) -> LoadBalancingModeResponse {
        LoadBalancingModeResponse {
            mode: self.token_manager.get_load_balancing_mode(),
        }
    }

    /// 设置负载均衡模式
    pub fn set_load_balancing_mode(
        &self,
        req: SetLoadBalancingModeRequest,
    ) -> Result<LoadBalancingModeResponse, AdminServiceError> {
        // 验证模式值
        if req.mode != "priority" && req.mode != "balanced" {
            return Err(AdminServiceError::InvalidCredential(
                "mode 必须是 'priority' 或 'balanced'".to_string(),
            ));
        }

        self.token_manager
            .set_load_balancing_mode(req.mode.clone())
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        Ok(LoadBalancingModeResponse { mode: req.mode })
    }

    /// 设置单个凭据的 RPM 上限
    pub fn set_rpm(&self, id: u64, rpm: Option<u32>) -> Result<(), AdminServiceError> {
        self.token_manager
            .set_credential_rpm(id, rpm)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 批量设置多个凭据的 RPM 上限，返回成功更新的数量
    pub fn batch_set_rpm(&self, ids: &[u64], rpm: Option<u32>) -> Result<usize, AdminServiceError> {
        self.token_manager
            .set_credentials_rpm_batch(ids, rpm)
            .map(|updated| updated.len())
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))
    }

    /// 获取全局默认 RPM
    pub fn get_default_rpm(&self) -> DefaultRpmResponse {
        DefaultRpmResponse {
            default_rpm: self.token_manager.get_default_rpm(),
        }
    }

    /// 设置全局默认 RPM
    pub fn set_default_rpm(&self, default_rpm: Option<u32>) -> Result<(), AdminServiceError> {
        self.token_manager
            .set_default_rpm(default_rpm)
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))
    }

    /// 获取破甲模式
    pub fn get_armor_breaking(&self) -> ArmorBreakingResponse {
        ArmorBreakingResponse {
            enabled: self.token_manager.get_armor_breaking(),
        }
    }

    /// 设置破甲模式
    pub fn set_armor_breaking(
        &self,
        req: SetArmorBreakingRequest,
    ) -> Result<ArmorBreakingResponse, AdminServiceError> {
        self.token_manager
            .set_armor_breaking(req.enabled)
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        Ok(ArmorBreakingResponse {
            enabled: req.enabled,
        })
    }

    /// 获取超额放行开关
    pub fn get_overage_passthrough(&self) -> OveragePassthroughResponse {
        OveragePassthroughResponse {
            enabled: self.token_manager.get_overage_passthrough(),
        }
    }

    /// 设置超额放行开关
    pub fn set_overage_passthrough(
        &self,
        req: SetOveragePassthroughRequest,
    ) -> Result<OveragePassthroughResponse, AdminServiceError> {
        self.token_manager
            .set_overage_passthrough(req.enabled)
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        Ok(OveragePassthroughResponse {
            enabled: req.enabled,
        })
    }

    /// 获取 CC Test 透传配置
    pub fn get_max_relay(&self) -> MaxRelayResponse {
        let cfg = self.token_manager.get_max_relay();
        MaxRelayResponse {
            enabled: cfg.enabled,
            base_url: cfg.base_url,
            api_key: cfg.api_key,
        }
    }

    /// 设置 CC Test 透传配置
    pub fn set_max_relay(
        &self,
        req: SetMaxRelayRequest,
    ) -> Result<MaxRelayResponse, AdminServiceError> {
        let cfg = MaxRelayConfig {
            enabled: req.enabled,
            base_url: req.base_url.trim().to_string(),
            api_key: req.api_key.trim().to_string(),
        };

        self.token_manager
            .set_max_relay(cfg.clone())
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        Ok(MaxRelayResponse {
            enabled: cfg.enabled,
            base_url: cfg.base_url,
            api_key: cfg.api_key,
        })
    }

    /// 强制刷新指定凭据的 Token
    pub async fn force_refresh_token(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .force_refresh_token_for(id)
            .await
            .map_err(|e| self.classify_balance_error(e, id))
    }

    // ============ 余额缓存持久化 ============

    fn load_balance_cache_from(cache_path: &Option<PathBuf>) -> HashMap<u64, CachedBalance> {
        let path = match cache_path {
            Some(p) => p,
            None => return HashMap::new(),
        };

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        // 文件中使用字符串 key 以兼容 JSON 格式
        let map: HashMap<String, CachedBalance> = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("解析余额缓存失败，将忽略: {}", e);
                return HashMap::new();
            }
        };

        let now = Utc::now().timestamp() as f64;
        map.into_iter()
            .filter_map(|(k, v)| {
                let id = k.parse::<u64>().ok()?;
                // 丢弃超过 TTL 的条目
                if (now - v.cached_at) < BALANCE_CACHE_TTL_SECS as f64 {
                    Some((id, v))
                } else {
                    None
                }
            })
            .collect()
    }

    fn save_balance_cache(&self) {
        let path = match &self.cache_path {
            Some(p) => p,
            None => return,
        };

        // 持有锁期间完成序列化和写入，防止并发损坏
        let cache = self.balance_cache.lock();
        let map: HashMap<String, &CachedBalance> =
            cache.iter().map(|(k, v)| (k.to_string(), v)).collect();

        match serde_json::to_string_pretty(&map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::warn!("保存余额缓存失败: {}", e);
                }
            }
            Err(e) => tracing::warn!("序列化余额缓存失败: {}", e),
        }
    }

    // ============ 错误分类 ============

    /// 分类简单操作错误（set_disabled, set_priority, reset_and_enable）
    fn classify_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();
        if msg.contains("不存在") {
            AdminServiceError::NotFound { id }
        } else {
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类余额查询错误（可能涉及上游 API 调用）
    fn classify_balance_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();

        // 1. 凭据不存在
        if msg.contains("不存在") {
            return AdminServiceError::NotFound { id };
        }

        // 2. API Key 凭据不支持刷新：客户端请求错误，映射为 400
        if msg.contains("API Key 凭据不支持刷新") {
            return AdminServiceError::InvalidCredential(msg);
        }

        // 3. 上游服务错误特征：HTTP 响应错误或网络错误
        let is_upstream_error =
            // HTTP 响应错误（来自 refresh_*_token 的错误消息）
            msg.contains("凭证已过期或无效") ||
            msg.contains("权限不足") ||
            msg.contains("已被限流") ||
            msg.contains("服务器错误") ||
            msg.contains("Token 刷新失败") ||
            msg.contains("暂时不可用") ||
            // 网络错误（reqwest 错误）
            msg.contains("error trying to connect") ||
            msg.contains("connection") ||
            msg.contains("timeout") ||
            msg.contains("timed out");

        if is_upstream_error {
            AdminServiceError::UpstreamError(msg)
        } else {
            // 4. 默认归类为内部错误（本地验证失败、配置错误等）
            // 包括：缺少 refreshToken、refreshToken 已被截断、无法生成 machineId 等
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类添加凭据错误
    fn classify_add_error(&self, e: anyhow::Error) -> AdminServiceError {
        let msg = e.to_string();

        // 凭据验证失败（refreshToken 无效、格式错误等）
        let is_invalid_credential = msg.contains("缺少 refreshToken")
            || msg.contains("refreshToken 为空")
            || msg.contains("refreshToken 已被截断")
            || msg.contains("凭据已存在")
            || msg.contains("refreshToken 重复")
            || msg.contains("kiroApiKey 重复")
            || msg.contains("缺少 kiroApiKey")
            || msg.contains("kiroApiKey 为空")
            || msg.contains("凭证已过期或无效")
            || msg.contains("权限不足")
            || msg.contains("已被限流");

        if is_invalid_credential {
            AdminServiceError::InvalidCredential(msg)
        } else if msg.contains("error trying to connect")
            || msg.contains("connection")
            || msg.contains("timeout")
        {
            AdminServiceError::UpstreamError(msg)
        } else {
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类删除凭据错误
    fn classify_delete_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();
        if msg.contains("不存在") {
            AdminServiceError::NotFound { id }
        } else if msg.contains("只能删除已禁用的凭据") || msg.contains("请先禁用凭据")
        {
            AdminServiceError::InvalidCredential(msg)
        } else {
            AdminServiceError::InternalError(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config::Config;

    fn balance_response(id: u64, usage_limit: f64, remaining: f64) -> BalanceResponse {
        BalanceResponse {
            id,
            subscription_title: Some("KIRO POWER".to_string()),
            current_usage: (usage_limit - remaining).max(0.0),
            usage_limit,
            remaining,
            usage_percentage: if usage_limit > 0.0 {
                ((usage_limit - remaining).max(0.0) / usage_limit * 100.0).min(100.0)
            } else {
                0.0
            },
            next_reset_at: Some((Utc::now() + chrono::Duration::hours(1)).timestamp() as f64),
            overage_status: None,
            current_overages: 0.0,
            overage_cap: 0.0,
            overage_rate: 0.0,
        }
    }

    #[test]
    fn test_quota_exhausted_balance_detection() {
        assert!(AdminService::is_quota_exhausted_balance(&balance_response(
            1, 10000.0, 0.0,
        )));
        assert!(AdminService::is_quota_exhausted_balance(&balance_response(
            1, 10000.0, 0.0000005,
        )));
        assert!(!AdminService::is_quota_exhausted_balance(
            &balance_response(1, 10000.0, 1.0,)
        ));
        assert!(!AdminService::is_quota_exhausted_balance(
            &balance_response(1, 0.0, 0.0,)
        ));

        let mut expired_reset = balance_response(1, 10000.0, 0.0);
        expired_reset.next_reset_at =
            Some((Utc::now() - chrono::Duration::seconds(1)).timestamp() as f64);
        assert!(!AdminService::is_quota_exhausted_balance(&expired_reset));
    }

    #[test]
    fn test_shared_proxy_binding_allows_two_credentials_and_persists() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-shared-proxy-{}.json",
            uuid::Uuid::new_v4()
        ));
        let mut first = KiroCredentials::default();
        first.id = Some(1);
        first.machine_id = Some("machine-1".to_string());
        let mut second = KiroCredentials::default();
        second.id = Some(2);
        second.machine_id = Some("machine-2".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![first.clone(), second.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![first, second],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager, Vec::<String>::new());
        let proxy_url = "http://residential.example:8080".to_string();

        assert_eq!(
            service
                .set_credentials_proxy_batch(BatchSetCredentialProxyRequest {
                    ids: vec![1, 2],
                    proxy_url: Some(proxy_url.clone()),
                    proxy_username: Some("buyer".to_string()),
                    proxy_password: Some("secret".to_string()),
                })
                .unwrap(),
            2
        );

        let persisted: Vec<KiroCredentials> =
            serde_json::from_str(&std::fs::read_to_string(&credentials_path).unwrap()).unwrap();
        for id in [1, 2] {
            let credential = persisted
                .iter()
                .find(|credential| credential.id == Some(id))
                .unwrap();
            assert_eq!(credential.proxy_url.as_deref(), Some(proxy_url.as_str()));
            assert_eq!(credential.proxy_username.as_deref(), Some("buyer"));
            assert_eq!(credential.proxy_password.as_deref(), Some("secret"));
        }

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[test]
    fn test_proxy_binding_rejects_partial_authentication() {
        let result = AdminService::validate_proxy_binding(
            Some("http://residential.example:8080".to_string()),
            Some("buyer".to_string()),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_exhausted_balance_disables_and_persists_credential() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-exhausted-balance-{}.json",
            uuid::Uuid::new_v4()
        ));

        let mut cred1 = KiroCredentials::default();
        cred1.id = Some(1);
        cred1.machine_id = Some("machine-1".to_string());
        let mut cred2 = KiroCredentials::default();
        cred2.id = Some(2);
        cred2.machine_id = Some("machine-2".to_string());

        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![cred1.clone(), cred2.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![cred1, cred2],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        service.disable_if_quota_exhausted_balance(&balance_response(1, 10000.0, 0.0));

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled);
        assert_eq!(first.disabled_reason.as_deref(), Some("QuotaExceeded"));
        assert_eq!(snapshot.available, 1);

        let persisted: Vec<KiroCredentials> =
            serde_json::from_str(&std::fs::read_to_string(&credentials_path).unwrap()).unwrap();
        assert!(persisted.iter().find(|c| c.id == Some(1)).unwrap().disabled);
        assert!(!persisted.iter().find(|c| c.id == Some(2)).unwrap().disabled);

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[test]
    fn test_non_exhausted_balance_does_not_disable_credential() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-non-exhausted-balance-{}.json",
            uuid::Uuid::new_v4()
        ));

        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.machine_id = Some("machine-1".to_string());

        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![cred.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![cred],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        service.disable_if_quota_exhausted_balance(&balance_response(1, 10000.0, 5.0));

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(!first.disabled);

        let persisted: Vec<KiroCredentials> =
            serde_json::from_str(&std::fs::read_to_string(&credentials_path).unwrap()).unwrap();
        assert!(!persisted.iter().find(|c| c.id == Some(1)).unwrap().disabled);

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[test]
    fn test_overage_enabled_balance_not_disabled() {
        // AWS 侧 overage=ENABLED 的号，余额耗尽时不应被禁用（默认全局开关开启）
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-overage-enabled-{}.json",
            uuid::Uuid::new_v4()
        ));

        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.machine_id = Some("machine-1".to_string());
        cred.overage_status = Some("ENABLED".to_string());

        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![cred.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![cred],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        // 余额耗尽
        service.disable_if_quota_exhausted_balance(&balance_response(1, 10000.0, 0.0));

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(!first.disabled, "overage=ENABLED 的号余额耗尽不应被禁用");
        assert_eq!(snapshot.available, 1);

        // 持久化文件中也不应标记为 disabled
        let persisted: Vec<KiroCredentials> =
            serde_json::from_str(&std::fs::read_to_string(&credentials_path).unwrap()).unwrap();
        assert!(!persisted.iter().find(|c| c.id == Some(1)).unwrap().disabled);

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[test]
    fn test_overage_disabled_still_disabled() {
        // overage_status=None（未知/未开启）的号，余额耗尽时维持现状：永久禁用
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-overage-disabled-{}.json",
            uuid::Uuid::new_v4()
        ));

        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.machine_id = Some("machine-1".to_string());
        // overage_status 未设置（None）

        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![cred.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![cred],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        service.disable_if_quota_exhausted_balance(&balance_response(1, 10000.0, 0.0));

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled, "非 ENABLED 的号余额耗尽应被禁用");
        assert_eq!(first.disabled_reason.as_deref(), Some("QuotaExceeded"));

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_proxy_pool_assigns_two_accounts_before_rotating_and_persists() {
        let test_dir =
            std::env::temp_dir().join(format!("kiro-admin-proxy-pool-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        std::fs::write(&credentials_path, "[]").unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![
                    SetCredentialProxyRequest {
                        proxy_url: Some("http://proxy-one.example:443".to_string()),
                        proxy_username: Some("user-one".to_string()),
                        proxy_password: Some("pass-one".to_string()),
                    },
                    SetCredentialProxyRequest {
                        proxy_url: Some("http://proxy-two.example:443".to_string()),
                        proxy_username: Some("user-two".to_string()),
                        proxy_password: Some("pass-two".to_string()),
                    },
                ],
            })
            .unwrap();

        for index in 0..3 {
            let response = service
                .add_credential(AddCredentialRequest {
                    refresh_token: None,
                    auth_method: "api_key".to_string(),
                    client_id: None,
                    client_secret: None,
                    priority: 0,
                    region: None,
                    auth_region: None,
                    api_region: None,
                    machine_id: None,
                    email: None,
                    import_note: None,
                    proxy_url: None,
                    proxy_username: None,
                    proxy_password: None,
                    assign_proxy_from_pool: None,
                    kiro_api_key: Some(format!("ksk-proxy-pool-{}", index)),
                    endpoint: None,
                })
                .await
                .unwrap();
            assert!(response.assigned_proxy_from_pool);
            assert_eq!(
                response.assigned_proxy_url.as_deref(),
                Some(if index < 2 {
                    "http://proxy-one.example:443/"
                } else {
                    "http://proxy-two.example:443/"
                })
            );
        }

        let pool = service.get_proxy_pool();
        assert_eq!(pool.total, 2);
        assert_eq!(pool.available_slots, 1);
        assert_eq!(pool.proxies[0].assigned_count, 2);
        assert_eq!(pool.proxies[1].assigned_count, 1);

        let proxy_pool_path = credentials_path
            .parent()
            .unwrap()
            .join("kiro_proxy_pool.json");
        let reloaded = AdminService::load_proxy_pool_from(&Some(proxy_pool_path.clone()));
        assert_eq!(reloaded.proxies.len(), 2);
        assert_eq!(
            reloaded.proxies[0].proxy_username.as_deref(),
            Some("user-one")
        );

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(&proxy_pool_path).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_proxy_pool_refuses_a_third_account_when_all_slots_are_full() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-proxy-pool-full-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credentials = Vec::new();
        for id in 1..=2 {
            let mut credential = KiroCredentials::default();
            credential.id = Some(id);
            credential.machine_id = Some(format!("machine-{}", id));
            credential.proxy_url = Some("http://full.example:443".to_string());
            credentials.push(credential);
        }
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&credentials).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                credentials,
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager, Vec::<String>::new());
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![SetCredentialProxyRequest {
                    proxy_url: Some("http://full.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();

        let result = service
            .add_credential(AddCredentialRequest {
                refresh_token: None,
                auth_method: "api_key".to_string(),
                client_id: None,
                client_secret: None,
                priority: 0,
                region: None,
                auth_region: None,
                api_region: None,
                machine_id: None,
                email: None,
                import_note: None,
                proxy_url: None,
                proxy_username: None,
                proxy_password: None,
                assign_proxy_from_pool: None,
                kiro_api_key: Some("ksk-proxy-pool-full".to_string()),
                endpoint: None,
            })
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("代理池已满"));

        let proxy_pool_path = credentials_path
            .parent()
            .unwrap()
            .join("kiro_proxy_pool.json");
        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(&proxy_pool_path).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }
}
