//! Admin API 业务逻辑服务

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::usage_limits::UsageLimitsResponse;
use crate::kiro::token_manager::{DisabledReason, MultiTokenManager};

use super::error::AdminServiceError;
use super::types::{
    AddCredentialRequest, AddCredentialResponse, AddProxyPoolEntriesRequest, ArmorBreakingResponse,
    AssignCredentialProxyFromPoolRequest, AssignCredentialProxyFromPoolResponse, BalanceResponse,
    BatchSetCredentialProxyRequest, CredentialProxyTestResponse, CredentialStatusItem,
    CredentialsStatusResponse, DefaultRpmResponse, LoadBalancingModeResponse, MaxRelayResponse,
    OveragePassthroughResponse, ProPlusProxyGateResponse, ProxyPoolAssignmentSkip,
    ProxyPoolEligibility, ProxyPoolEntryStatus, ProxyPoolResponse, RemoveProxyPoolEntriesRequest,
    SetArmorBreakingRequest, SetCredentialProxyRequest, SetLoadBalancingModeRequest,
    SetMaxRelayRequest, SetOveragePassthroughRequest, SetProPlusProxyGateRequest,
};
use crate::model::config::MaxRelayConfig;

/// 余额缓存过期时间（秒），5 分钟
const BALANCE_CACHE_TTL_SECS: i64 = 300;
/// PRO+ / PRO MAX 账号剩余额度低于 50 时退出代理池。
const PRO_PLUS_MIN_REMAINING: f64 = 50.0;
/// 每分钟检查一次；余额缓存确保同一账号最多每 5 分钟访问一次上游额度接口。
const PRO_PLUS_QUOTA_GUARD_INTERVAL_SECS: u64 = 60;
/// 浮点余额接近 0 时视为额度耗尽
const BALANCE_EXHAUSTED_EPSILON: f64 = 0.000001;
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
    /// 因代理容量或出口验证未通过而等待补绑的 PRO+ 凭据。
    #[serde(default)]
    pending_credential_ids: Vec<u64>,
    /// 额度耗尽后永久退役的 PRO+。它们不再参与代理补位或额度重置复活。
    #[serde(default)]
    retired_quota_credential_ids: Vec<u64>,
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
    /// 自动分配与写入凭据必须串行，防止并发导入突破单 IP 动态上限。
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

        let service = Self {
            token_manager,
            balance_cache: Mutex::new(balance_cache),
            cache_path,
            proxy_pool_path,
            proxy_pool: Mutex::new(proxy_pool),
            allocation_lock: tokio::sync::Mutex::new(()),
            known_endpoints: known_endpoints.into_iter().collect(),
        };
        service.disable_unbound_kiro_pro_plus();
        service
    }

    /// 获取所有凭据状态
    pub fn get_all_credentials(&self) -> CredentialsStatusResponse {
        let snapshot = self.token_manager.snapshot();
        let default_endpoint = self.token_manager.config().default_endpoint.clone();
        let retired_quota_ids: HashSet<u64> = self
            .proxy_pool
            .lock()
            .retired_quota_credential_ids
            .iter()
            .copied()
            .collect();

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
                subscription_title: entry.subscription_title,
                success_count: entry.success_count,
                last_used_at: entry.last_used_at.clone(),
                has_proxy: entry.has_proxy,
                proxy_url: entry.proxy_url.as_deref().map(Self::redact_proxy_url),
                refresh_failure_count: entry.refresh_failure_count,
                disabled_reason: if retired_quota_ids.contains(&entry.id) {
                    Some("QuotaExceeded".to_string())
                } else {
                    entry.disabled_reason
                },
                endpoint: entry.endpoint.unwrap_or_else(|| default_endpoint.clone()),
                rpm: entry.rpm,
                effective_rpm: entry.effective_rpm,
                rpm_follows_default: entry.rpm_follows_default,
                current_rpm: entry.current_rpm,
                in_flight_requests: entry.in_flight_requests,
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
        if !disabled {
            self.ensure_can_enable(id)?;
        }

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

    /// 设置凭据禁用状态，并在 PRO+ 进入稳定禁用状态后释放代理、触发等待队列补位。
    ///
    /// 手动禁用是终态：账号不会重新进入等待队列。以后若要恢复，必须重新分配
    /// 账号级代理并完成出口验证后再启用。
    pub async fn set_disabled_and_reconcile(
        &self,
        id: u64,
        disabled: bool,
    ) -> Result<(), AdminServiceError> {
        self.set_disabled(id, disabled)?;
        if disabled && self.release_disabled_credential_proxy(id, true)? {
            self.reconcile_pending_pro_plus().await?;
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
        if let Some(url) = proxy_url.as_deref() {
            self.ensure_proxy_binding_capacity(url, &[id])?;
        }
        self.token_manager
            .set_credential_proxy(id, proxy_url, proxy_username, proxy_password)
            .map_err(|e| self.classify_error(e, id))
    }

    /// Admin HTTP 单绑入口：与自动分配共用同一把锁，防止并发突破容量。
    pub async fn set_credential_proxy_guarded(
        &self,
        id: u64,
        req: SetCredentialProxyRequest,
    ) -> Result<(), AdminServiceError> {
        let _guard = self.allocation_lock.lock().await;
        self.set_credential_proxy(id, req)
    }

    /// 把相同代理批量绑定给多个凭据。
    ///
    /// ponytail: 不引入代理池表。住宅 IP 直接保存在需要共用它的账号上；换 IP
    /// 时调用同一个接口即可批量覆盖。若未来需要跨大量账号复用、过期和库存管理，再升级为独立代理资源。
    pub fn set_credentials_proxy_batch(
        &self,
        req: BatchSetCredentialProxyRequest,
    ) -> Result<usize, AdminServiceError> {
        let (proxy_url, proxy_username, proxy_password) =
            Self::validate_proxy_binding(req.proxy_url, req.proxy_username, req.proxy_password)?;
        let ids = req.ids;
        if let Some(url) = proxy_url.as_deref() {
            self.ensure_proxy_binding_capacity(url, &ids)?;
        }
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

    /// Admin HTTP 批量绑定入口：与自动分配共用同一把锁，防止并发突破容量。
    pub async fn set_credentials_proxy_batch_guarded(
        &self,
        req: BatchSetCredentialProxyRequest,
    ) -> Result<usize, AdminServiceError> {
        let _guard = self.allocation_lock.lock().await;
        self.set_credentials_proxy_batch(req)
    }

    fn ensure_proxy_binding_capacity(
        &self,
        proxy_url: &str,
        target_ids: &[u64],
    ) -> Result<(), AdminServiceError> {
        if !self.token_manager.get_require_pro_plus_credential_proxy()
            || proxy_url.eq_ignore_ascii_case(KiroCredentials::PROXY_DIRECT)
        {
            return Ok(());
        }

        let snapshot = self.token_manager.snapshot();
        let already_assigned: HashSet<u64> = snapshot
            .entries
            .iter()
            .filter(|entry| entry.proxy_url.as_deref() == Some(proxy_url))
            .map(|entry| entry.id)
            .collect();
        let new_ids: HashSet<u64> = target_ids
            .iter()
            .copied()
            .filter(|id| !already_assigned.contains(id))
            .collect();
        let prospective = already_assigned.len() + new_ids.len();
        let limit = self.token_manager.get_max_accounts_per_proxy();
        if prospective > limit {
            return Err(AdminServiceError::InvalidCredential(format!(
                "该代理最多允许绑定 {} 个账号，绑定后将达到 {} 个",
                limit, prospective
            )));
        }
        Ok(())
    }

    /// 为已导入且未显式绑定代理的凭据补领自动代理池出口。
    ///
    /// ponytail: 沿用导入时的 subscriptionTitle 与单 IP 动态容量规则，认证信息只从服务端池文件
    /// 读取，接口不接收、不返回代理密码。当前绑定的凭据一律跳过，避免覆盖人工配置。
    pub async fn assign_credentials_proxy_from_pool(
        &self,
        req: AssignCredentialProxyFromPoolRequest,
    ) -> Result<AssignCredentialProxyFromPoolResponse, AdminServiceError> {
        if req.ids.is_empty() {
            return Err(AdminServiceError::InvalidCredential(
                "至少需要一个凭据 ID".to_string(),
            ));
        }

        let mut assigned_credential_ids = Vec::new();
        let mut skipped = Vec::new();
        for id in req.ids {
            let credentials = self
                .token_manager
                .credential_and_effective_proxy(id)
                .map_err(|error| self.classify_error(error, id))?
                .0;

            if credentials.proxy_url.is_some() {
                skipped.push(ProxyPoolAssignmentSkip {
                    credential_id: id,
                    reason: "凭据已有显式代理，未覆盖".to_string(),
                });
                continue;
            }

            let usage = self
                .token_manager
                .get_usage_limits_for(id)
                .await
                .map_err(|error| self.classify_balance_error(error, id))?;
            let eligibility = Self::proxy_pool_eligibility(&usage);
            if !eligibility.eligible {
                skipped.push(ProxyPoolAssignmentSkip {
                    credential_id: id,
                    reason: eligibility.reason,
                });
                continue;
            }

            // 分配与写入需要在同一临界区内，避免并发补绑突破单 IP 动态上限。
            let _allocation_guard = self.allocation_lock.lock().await;
            let still_unbound = self
                .token_manager
                .credential_and_effective_proxy(id)
                .map_err(|error| self.classify_error(error, id))?
                .0
                .proxy_url
                .is_none();
            if !still_unbound {
                skipped.push(ProxyPoolAssignmentSkip {
                    credential_id: id,
                    reason: "凭据在分配期间已绑定代理，未覆盖".to_string(),
                });
                continue;
            }
            let Some(proxy) = self.next_proxy_pool_entry()? else {
                skipped.push(ProxyPoolAssignmentSkip {
                    credential_id: id,
                    reason: "代理池为空，未分配".to_string(),
                });
                continue;
            };
            self.token_manager
                .set_credential_proxy(
                    id,
                    Some(proxy.proxy_url),
                    proxy.proxy_username,
                    proxy.proxy_password,
                )
                .map_err(|error| self.classify_error(error, id))?;
            assigned_credential_ids.push(id);
        }

        Ok(AssignCredentialProxyFromPoolResponse {
            assigned_credential_ids,
            skipped,
        })
    }

    /// 为因容量不足或出口验证失败而等待的 PRO+ 自动补绑；只有验出口通过才启用。
    pub async fn reconcile_pending_pro_plus(&self) -> Result<(usize, usize), AdminServiceError> {
        if !self.token_manager.get_require_pro_plus_credential_proxy() {
            return Ok((0, self.pending_proxy_ids().len()));
        }

        let mut enabled_count = 0;
        for id in self.pending_proxy_ids() {
            let credentials = match self.token_manager.credential_and_effective_proxy(id) {
                Ok((credentials, _)) => credentials,
                Err(_) => {
                    self.clear_proxy_pending(id)?;
                    continue;
                }
            };
            if !Self::is_kiro_pro_plus(credentials.subscription_title.as_deref()) {
                self.clear_proxy_pending(id)?;
                continue;
            }

            if !Self::has_credential_proxy(&credentials) {
                let _allocation_guard = self.allocation_lock.lock().await;
                let proxy = match self.next_proxy_pool_entry() {
                    Ok(Some(proxy)) => proxy,
                    Ok(None) => break,
                    Err(AdminServiceError::InvalidCredential(message))
                        if message.starts_with("代理池已满") =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                };
                self.token_manager
                    .set_credential_proxy(
                        id,
                        Some(proxy.proxy_url),
                        proxy.proxy_username,
                        proxy.proxy_password,
                    )
                    .map_err(|error| self.classify_error(error, id))?;
            }

            match self.test_credential_proxy(id).await {
                Ok(result) if Self::proxy_test_matches_expected_egress(&result) => {
                    self.set_disabled(id, false)?;
                    self.clear_proxy_pending(id)?;
                    enabled_count += 1;
                }
                Ok(_) | Err(_) => {
                    // 验证失败继续等待，但释放失败绑定，避免禁用账号长期占槽；绝不回退直连。
                    self.token_manager
                        .set_disabled_without_release_event(id, true)
                        .map_err(|error| self.classify_error(error, id))?;
                    self.release_disabled_credential_proxy(id, false)?;
                }
            }
        }

        Ok((enabled_count, self.pending_proxy_ids().len()))
    }

    /// 监听真实请求与余额策略产生的退役事件，永久退役旧 PRO+ 后立即补位。
    pub async fn run_quota_rotation_worker(
        self: Arc<Self>,
        mut events: tokio::sync::broadcast::Receiver<u64>,
    ) {
        loop {
            let id = match events.recv().await {
                Ok(id) => id,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "PRO+ 额度耗尽事件处理滞后，将继续处理最新事件");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            if !self.token_manager.get_require_pro_plus_credential_proxy() {
                continue;
            }
            match self.retire_quota_exhausted_pool_credential(id) {
                Ok(true) => match self.reconcile_pending_pro_plus().await {
                    Ok((enabled, pending)) => tracing::info!(
                        credential_id = id,
                        enabled,
                        pending,
                        "额度失效的代理池账号已永久退役并完成补位"
                    ),
                    Err(error) => tracing::error!(
                        credential_id = id,
                        "额度失效的代理池账号已退役，但补位失败: {}",
                        error
                    ),
                },
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(credential_id = id, "代理池账号永久退役失败: {}", error)
                }
            }
        }
    }

    /// 定期刷新启用中的 PRO+ 额度；低于 50 时由额度退役事件释放代理并补位。
    pub async fn run_pro_plus_quota_guard(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            PRO_PLUS_QUOTA_GUARD_INTERVAL_SECS,
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            let ids: Vec<u64> = self
                .token_manager
                .snapshot()
                .entries
                .into_iter()
                .filter(|entry| {
                    !entry.disabled && Self::is_kiro_pro_plus(entry.subscription_title.as_deref())
                })
                .map(|entry| entry.id)
                .collect();

            for id in ids {
                if let Err(error) = self.get_balance(id).await {
                    tracing::warn!(credential_id = id, "PRO+ 自动额度检查失败: {}", error);
                }
            }
        }
    }

    /// 监听手动禁用和确定性凭据失效事件，释放 PRO+ 代理并立即补位。
    pub async fn run_stable_disabled_proxy_release_worker(
        self: Arc<Self>,
        mut events: tokio::sync::broadcast::Receiver<u64>,
    ) {
        loop {
            let id = match events.recv().await {
                Ok(id) => id,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "PRO+ 稳定禁用事件处理滞后，执行全量历史收口");
                    match self.release_stale_disabled_proxy_bindings() {
                        Ok(released) if released > 0 => {
                            let _ = self.reconcile_pending_pro_plus().await;
                        }
                        Ok(_) => {}
                        Err(error) => tracing::error!("PRO+ 稳定禁用全量收口失败: {}", error),
                    }
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            if !self.token_manager.get_require_pro_plus_credential_proxy() {
                continue;
            }
            match self.release_disabled_credential_proxy(id, true) {
                Ok(true) => match self.reconcile_pending_pro_plus().await {
                    Ok((enabled, pending)) => tracing::info!(
                        credential_id = id,
                        enabled,
                        pending,
                        "稳定禁用账号已释放代理并完成补位"
                    ),
                    Err(error) => tracing::error!(
                        credential_id = id,
                        "稳定禁用账号已释放代理，但补位失败: {}",
                        error
                    ),
                },
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(credential_id = id, "稳定禁用账号释放代理失败: {}", error)
                }
            }
        }
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
                    remaining_slots: self
                        .token_manager
                        .get_max_accounts_per_proxy()
                        .saturating_sub(assigned_count),
                }
            })
            .collect::<Vec<_>>();
        let available_slots = proxies.iter().map(|entry| entry.remaining_slots).sum();

        ProxyPoolResponse {
            max_accounts_per_proxy: self.token_manager.get_max_accounts_per_proxy(),
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

    /// PRO+ 自动启用只接受账号级代理，且出口 IP 必须与代理 URL 中的 IP 一致。
    fn proxy_test_matches_expected_egress(result: &CredentialProxyTestResponse) -> bool {
        if !result.uses_proxy || !result.uses_credential_proxy {
            return false;
        }
        let expected_ip = result
            .proxy_url
            .as_deref()
            .and_then(|url| Url::parse(url).ok())
            .and_then(|url| url.host_str().map(str::to_owned))
            .and_then(|host| host.parse::<std::net::IpAddr>().ok());
        let actual_ip = result.egress_ip.parse::<std::net::IpAddr>().ok();
        expected_ip.is_some() && expected_ip == actual_ip
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

    /// 在池内按录入顺序选择第一个未达到动态账号上限的代理。
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
                    < self.token_manager.get_max_accounts_per_proxy()
            })
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                AdminServiceError::InvalidCredential(format!(
                    "代理池已满：每个代理最多绑定 {} 个账号，请先添加新代理或显式指定 proxyUrl",
                    self.token_manager.get_max_accounts_per_proxy()
                ))
            })
    }

    fn has_proxy_pool_entries(&self) -> bool {
        !self.proxy_pool.lock().proxies.is_empty()
    }

    fn should_assign_proxy_from_pool(gate_enabled: bool, requested: Option<bool>) -> bool {
        gate_enabled || requested.unwrap_or(true)
    }

    /// 只按 Kiro 官方返回的付费 Pro 套餐名识别，不猜邮箱域名、余额或赠送额度。
    /// 当前代理池覆盖 KIRO PRO+ 与 KIRO PRO MAX；若官方再变更套餐名，再显式扩展。
    fn proxy_pool_eligibility(usage: &UsageLimitsResponse) -> ProxyPoolEligibility {
        let subscription_title = usage.subscription_title().map(str::to_owned);
        let eligible = Self::is_kiro_pro_plus(subscription_title.as_deref());
        let reason = if eligible {
            "官方 subscriptionTitle 为受支持的付费 KIRO PRO，允许自动分配代理".to_string()
        } else if let Some(title) = subscription_title.as_deref() {
            format!("官方 subscriptionTitle 为 {title:?}，不自动分配代理")
        } else {
            "官方 getUsageLimits 未返回 subscriptionTitle，不自动分配代理".to_string()
        };
        ProxyPoolEligibility {
            eligible,
            subscription_title,
            reason,
        }
    }

    fn is_kiro_pro_plus(subscription_title: Option<&str>) -> bool {
        subscription_title
            .map(|title| {
                matches!(
                    title.trim().to_ascii_uppercase().as_str(),
                    "KIRO PRO+" | "KIRO PRO MAX"
                )
            })
            .unwrap_or(false)
    }

    /// `direct`、全局代理和格式无效的地址都不算账号已经绑定住宅 IP。
    fn has_bound_proxy_url(proxy_url: Option<&str>) -> bool {
        proxy_url
            .and_then(|url| {
                (!url
                    .trim()
                    .eq_ignore_ascii_case(KiroCredentials::PROXY_DIRECT))
                .then(|| Url::parse(url).ok())
                .flatten()
            })
            .is_some_and(|url| {
                matches!(url.scheme(), "http" | "https" | "socks5") && url.host_str().is_some()
            })
    }

    fn has_credential_proxy(credentials: &KiroCredentials) -> bool {
        Self::has_bound_proxy_url(credentials.proxy_url.as_deref())
    }

    fn has_proxy_pool_binding(&self, credentials: &KiroCredentials) -> bool {
        let Some(proxy_url) = credentials.proxy_url.as_deref() else {
            return false;
        };
        self.proxy_pool_contains_url(proxy_url)
    }

    fn proxy_pool_contains_url(&self, proxy_url: &str) -> bool {
        self.proxy_pool
            .lock()
            .proxies
            .iter()
            .any(|proxy| proxy.proxy_url == proxy_url)
    }

    fn requires_proxy_before_enable(&self, credentials: &KiroCredentials) -> bool {
        self.token_manager.get_require_pro_plus_credential_proxy()
            && Self::is_kiro_pro_plus(credentials.subscription_title.as_deref())
            && !Self::has_credential_proxy(credentials)
    }

    /// 释放稳定禁用账号占用的自动代理池资源。
    ///
    /// `clear_pending=true` 用于人工或确定性失效禁用，表示该账号不能自动复活；
    /// `clear_pending=false` 用于代理验证失败，账号继续等待下次分配，但不长期占槽。
    fn release_disabled_credential_proxy(
        &self,
        id: u64,
        clear_pending: bool,
    ) -> Result<bool, AdminServiceError> {
        if !self.token_manager.get_require_pro_plus_credential_proxy() {
            return Ok(false);
        }
        let snapshot = self.token_manager.snapshot();
        let Some(entry) = snapshot.entries.into_iter().find(|entry| entry.id == id) else {
            return Err(AdminServiceError::NotFound { id });
        };
        if !entry.disabled {
            return Ok(false);
        }
        let credentials = self
            .token_manager
            .credential_and_effective_proxy(id)
            .map_err(|error| self.classify_error(error, id))?
            .0;
        if !Self::is_kiro_pro_plus(credentials.subscription_title.as_deref())
            && !self.has_proxy_pool_binding(&credentials)
        {
            return Ok(false);
        }
        if !Self::has_credential_proxy(&credentials) {
            if clear_pending {
                self.clear_proxy_pending(id)?;
            }
            return Ok(false);
        }

        self.token_manager
            .set_credential_proxy(id, None, None, None)
            .map_err(|error| self.classify_error(error, id))?;
        if clear_pending {
            self.clear_proxy_pending(id)?;
        }
        Ok(true)
    }

    /// 服务启动时清理旧版本遗留的“已稳定禁用但仍占代理”账号。
    ///
    /// `TooManyFailures` 是五分钟自动恢复的瞬时冷却，不属于稳定禁用；额度耗尽由
    /// 专用退役流程处理。其余稳定禁用均释放代理。历史代理验证失败账号若仍在
    /// pending 队列，则保留等待身份但释放失败绑定。
    pub fn release_stale_disabled_proxy_bindings(&self) -> Result<usize, AdminServiceError> {
        if !self.token_manager.get_require_pro_plus_credential_proxy() {
            return Ok(0);
        }
        let pending_ids: HashSet<u64> = self.pending_proxy_ids().into_iter().collect();
        let proxy_pool_urls: HashSet<String> = self
            .proxy_pool
            .lock()
            .proxies
            .iter()
            .map(|proxy| proxy.proxy_url.clone())
            .collect();
        let ids: Vec<u64> = self
            .token_manager
            .snapshot()
            .entries
            .into_iter()
            .filter(|entry| {
                entry.disabled
                    && entry.has_proxy
                    && (Self::is_kiro_pro_plus(entry.subscription_title.as_deref())
                        || entry
                            .proxy_url
                            .as_ref()
                            .map(|proxy_url| proxy_pool_urls.contains(proxy_url))
                            .unwrap_or(false))
                    && !matches!(
                        entry.disabled_reason.as_deref(),
                        Some("TooManyFailures" | "QuotaExceeded")
                    )
            })
            .map(|entry| entry.id)
            .collect();

        let mut released = 0;
        for id in ids {
            if self.release_disabled_credential_proxy(id, !pending_ids.contains(&id))? {
                released += 1;
            }
        }
        Ok(released)
    }

    fn ensure_can_enable(&self, id: u64) -> Result<(), AdminServiceError> {
        if self
            .proxy_pool
            .lock()
            .retired_quota_credential_ids
            .contains(&id)
        {
            return Err(AdminServiceError::InvalidCredential(format!(
                "凭据 #{} 已因额度耗尽永久退役，禁止重新启用",
                id
            )));
        }
        let credentials = self
            .token_manager
            .credential_and_effective_proxy(id)
            .map_err(|error| self.classify_error(error, id))?
            .0;
        if self.requires_proxy_before_enable(&credentials) {
            return Err(AdminServiceError::InvalidCredential(format!(
                "凭据 #{} 已识别为 KIRO PRO+，请先绑定账号级代理 IP 后再启用",
                id
            )));
        }
        Ok(())
    }

    /// HTTP 启用入口的最终门禁：PRO+ 不仅要有账号级代理，还必须验证实际出口一致。
    pub async fn ensure_proxy_verified_before_enable(
        &self,
        id: u64,
    ) -> Result<(), AdminServiceError> {
        if !self.token_manager.get_require_pro_plus_credential_proxy() {
            return Ok(());
        }
        let credentials = self
            .token_manager
            .credential_and_effective_proxy(id)
            .map_err(|error| self.classify_error(error, id))?
            .0;
        if !Self::is_kiro_pro_plus(credentials.subscription_title.as_deref()) {
            return Ok(());
        }
        self.ensure_can_enable(id)?;
        let result = self.test_credential_proxy(id).await?;
        if !Self::proxy_test_matches_expected_egress(&result) {
            return Err(AdminServiceError::InvalidCredential(format!(
                "凭据 #{} 的账号级代理出口 IP 与绑定 IP 不一致，禁止启用",
                id
            )));
        }
        Ok(())
    }

    /// 兼容已有凭据：服务启动时把已经识别为 PRO+、却没有账号级代理的活跃账号
    /// 收口为禁用状态，避免旧数据绕过新规则。
    fn disable_unbound_kiro_pro_plus(&self) {
        if !self.token_manager.get_require_pro_plus_credential_proxy() {
            return;
        }
        let ids: Vec<u64> = self
            .token_manager
            .snapshot()
            .entries
            .into_iter()
            .filter(|entry| {
                !entry.disabled
                    && Self::is_kiro_pro_plus(entry.subscription_title.as_deref())
                    && !Self::has_bound_proxy_url(entry.proxy_url.as_deref())
            })
            .map(|entry| entry.id)
            .collect();
        for id in ids {
            if let Err(error) = self
                .token_manager
                .set_disabled_without_release_event(id, true)
                .map_err(|error| self.classify_error(error, id))
            {
                tracing::warn!(
                    credential_id = id,
                    "KIRO PRO+ 无账号级代理，启动收口禁用失败: {}",
                    error
                );
            } else {
                if let Err(error) = self.mark_proxy_pending(id) {
                    tracing::warn!(credential_id = id, "记录 PRO+ 代理等待状态失败: {}", error);
                }
                tracing::warn!(credential_id = id, "KIRO PRO+ 无账号级代理，已禁止启用");
            }
        }
    }

    fn mark_proxy_pending(&self, id: u64) -> Result<(), AdminServiceError> {
        let mut pool = self.proxy_pool.lock();
        if pool.retired_quota_credential_ids.contains(&id) {
            return Ok(());
        }
        if !pool.pending_credential_ids.contains(&id) {
            pool.pending_credential_ids.push(id);
            self.persist_proxy_pool(&pool)?;
        }
        Ok(())
    }

    /// 永久退役额度耗尽的代理池账号：保持禁用、释放账号代理，并确保永不重新排队。
    /// 套餐失效后可能从 PRO+ 降成 FREE，因此以“是否占用代理池槽位”为准。
    fn retire_quota_exhausted_pool_credential(&self, id: u64) -> Result<bool, AdminServiceError> {
        let already_disabled = self
            .token_manager
            .snapshot()
            .entries
            .into_iter()
            .find(|entry| entry.id == id)
            .ok_or(AdminServiceError::NotFound { id })?
            .disabled;
        let credentials = self
            .token_manager
            .credential_and_effective_proxy(id)
            .map_err(|error| self.classify_error(error, id))?
            .0;
        if !Self::is_kiro_pro_plus(credentials.subscription_title.as_deref())
            && !self.has_proxy_pool_binding(&credentials)
        {
            return Ok(false);
        }

        if !already_disabled {
            self.token_manager
                .set_disabled_without_release_event(id, true)
                .map_err(|error| self.classify_error(error, id))?;
        }
        if Self::has_credential_proxy(&credentials) {
            self.token_manager
                .set_credential_proxy(id, None, None, None)
                .map_err(|error| self.classify_error(error, id))?;
        }

        let mut pool = self.proxy_pool.lock();
        pool.pending_credential_ids
            .retain(|pending_id| *pending_id != id);
        if !pool.retired_quota_credential_ids.contains(&id) {
            pool.retired_quota_credential_ids.push(id);
        }
        self.persist_proxy_pool(&pool)?;
        Ok(true)
    }

    /// 启动时利用已持久化的余额缓存收口低于 50 的 PRO+，以及额度归零但
    /// 套餐标签已经变化的代理池账号。人工禁用但额度仍可用的账号保持原样。
    pub fn retire_cached_nonviable_pool_credentials(&self) -> Result<usize, AdminServiceError> {
        if !self.token_manager.get_require_pro_plus_credential_proxy() {
            return Ok(0);
        }
        let proxy_pool_urls: HashSet<String> = self
            .proxy_pool
            .lock()
            .proxies
            .iter()
            .map(|proxy| proxy.proxy_url.clone())
            .collect();
        let cache = self.balance_cache.lock();
        let ids: Vec<u64> = self
            .token_manager
            .snapshot()
            .entries
            .into_iter()
            .filter(|entry| {
                entry.disabled
                    && entry.has_proxy
                    && cache
                        .get(&entry.id)
                        .map(|cached| {
                            Self::is_pro_plus_below_quota_threshold(&cached.data)
                                || (entry
                                    .proxy_url
                                    .as_ref()
                                    .map(|proxy_url| proxy_pool_urls.contains(proxy_url))
                                    .unwrap_or(false)
                                    && Self::is_quota_exhausted_balance(&cached.data))
                        })
                        .unwrap_or(false)
            })
            .map(|entry| entry.id)
            .collect();
        drop(cache);

        let mut retired = 0;
        for id in ids {
            if self.retire_quota_exhausted_pool_credential(id)? {
                retired += 1;
            }
        }
        Ok(retired)
    }

    fn clear_proxy_pending(&self, id: u64) -> Result<(), AdminServiceError> {
        let mut pool = self.proxy_pool.lock();
        let before = pool.pending_credential_ids.len();
        pool.pending_credential_ids
            .retain(|pending_id| *pending_id != id);
        if pool.pending_credential_ids.len() != before {
            self.persist_proxy_pool(&pool)?;
        }
        Ok(())
    }

    fn clear_proxy_tracking(&self, id: u64) -> Result<(), AdminServiceError> {
        let mut pool = self.proxy_pool.lock();
        let pending_before = pool.pending_credential_ids.len();
        let retired_before = pool.retired_quota_credential_ids.len();
        pool.pending_credential_ids
            .retain(|pending_id| *pending_id != id);
        pool.retired_quota_credential_ids
            .retain(|retired_id| *retired_id != id);
        if pool.pending_credential_ids.len() != pending_before
            || pool.retired_quota_credential_ids.len() != retired_before
        {
            self.persist_proxy_pool(&pool)?;
        }
        Ok(())
    }

    fn pending_proxy_ids(&self) -> Vec<u64> {
        self.proxy_pool.lock().pending_credential_ids.clone()
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
        self.ensure_can_enable(id)?;
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
            self.backfill_disabled_reason(id, &balance);
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
        self.backfill_disabled_reason(id, &balance);

        Ok(balance)
    }

    fn disable_if_quota_exhausted_balance(&self, balance: &BalanceResponse) {
        let pro_plus_below_threshold = Self::is_pro_plus_below_quota_threshold(balance);
        if !pro_plus_below_threshold && !Self::is_quota_exhausted_balance(balance) {
            return;
        }

        // PRO+ 的 50 额度规则优先于付费超额；其他套餐维持原有 overage 行为。
        if !pro_plus_below_threshold && self.token_manager.is_overage_enabled(balance.id) {
            tracing::info!(
                "凭据 #{} 余额耗尽但 overage=ENABLED，进入超额、保持启用",
                balance.id
            );
            return;
        }

        let has_available = self.token_manager.report_quota_exhausted(balance.id);
        let reason = if pro_plus_below_threshold {
            "PRO+ 剩余额度低于 50"
        } else {
            "余额已耗尽"
        };
        if has_available {
            tracing::warn!(
                "凭据 #{} {}（remaining={} usageLimit={}），已自动禁用",
                balance.id,
                reason,
                balance.remaining,
                balance.usage_limit
            );
        } else {
            tracing::error!(
                "凭据 #{} {}（remaining={} usageLimit={}），已自动禁用；当前无可用凭据",
                balance.id,
                reason,
                balance.remaining,
                balance.usage_limit
            );
        }
    }

    fn is_pro_plus_below_quota_threshold(balance: &BalanceResponse) -> bool {
        if !Self::is_kiro_pro_plus(balance.subscription_title.as_deref())
            || balance.usage_limit <= 0.0
        {
            return false;
        }

        if let Some(next_reset_at) = balance.next_reset_at {
            let now = Utc::now().timestamp() as f64;
            if next_reset_at <= now {
                return false;
            }
        }

        balance.remaining < PRO_PLUS_MIN_REMAINING
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
        let usage = match self.token_manager.get_usage_limits_for(id).await {
            Ok(usage) => usage,
            Err(error) => {
                let message = error.to_string();
                if Self::is_token_dead_balance_error(&message) {
                    if let Err(reason_error) = self
                        .token_manager
                        .set_disabled_reason(id, DisabledReason::InvalidRefreshToken)
                    {
                        tracing::warn!(
                            credential_id = id,
                            "Token 失效原因标记失败: {}",
                            reason_error
                        );
                    }
                }
                return Err(self.classify_balance_error(error, id));
            }
        };

        let current_usage = usage.current_usage();
        let usage_limit = usage.usage_limit();
        let remaining = (usage_limit - current_usage).max(0.0);
        let usage_percentage = if usage_limit > 0.0 {
            (current_usage / usage_limit * 100.0).min(100.0)
        } else {
            0.0
        };

        let response = BalanceResponse {
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
        };

        if self.token_manager.get_require_pro_plus_credential_proxy()
            && Self::is_kiro_pro_plus(response.subscription_title.as_deref())
        {
            let credentials = self
                .token_manager
                .credential_and_effective_proxy(id)
                .map_err(|error| self.classify_error(error, id))?
                .0;
            if !Self::has_credential_proxy(&credentials) {
                self.token_manager
                    .set_disabled_without_release_event(id, true)
                    .map_err(|error| self.classify_error(error, id))?;
                self.mark_proxy_pending(id)?;
                let _ = self.reconcile_pending_pro_plus().await?;
            }
        }

        Ok(response)
    }

    /// 余额查询错误中表示"上游 token 已失效/无权限"的特征。
    fn is_token_dead_balance_error(message: &str) -> bool {
        message.contains("权限不足")
            || message.contains("凭证已过期或无效")
            || message.contains("403")
            || message.contains("Forbidden")
    }

    /// 给"已禁用但无原因"的账号补记原因：额度用尽 / 手动禁用。
    fn backfill_disabled_reason(&self, id: u64, balance: &BalanceResponse) {
        let entry = self
            .token_manager
            .snapshot()
            .entries
            .into_iter()
            .find(|entry| entry.id == id);
        let Some(entry) = entry else {
            return;
        };
        if !entry.disabled || entry.disabled_reason.is_some() {
            return;
        }
        let reason = if balance.remaining <= BALANCE_EXHAUSTED_EPSILON {
            DisabledReason::QuotaExceeded
        } else {
            DisabledReason::Manual
        };
        if let Err(error) = self.token_manager.set_disabled_reason(id, reason) {
            tracing::warn!(credential_id = id, "禁用原因补记失败: {}", error);
        }
    }

    /// 启动时对"已禁用但无原因"的账号逐个刷新余额，补记具体禁用原因。
    pub async fn backfill_disabled_reasons(&self) -> Result<usize, AdminServiceError> {
        let ids: Vec<u64> = self
            .token_manager
            .snapshot()
            .entries
            .into_iter()
            .filter(|entry| entry.disabled && entry.disabled_reason.is_none())
            .map(|entry| entry.id)
            .collect();
        let mut backfilled = 0;
        for id in ids {
            match self.get_balance(id).await {
                Ok(_) => backfilled += 1,
                Err(error) => {
                    tracing::warn!(credential_id = id, "禁用原因启动回填失败: {}", error)
                }
            }
        }
        Ok(backfilled)
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

        // 显式代理优先；未提供时才考虑代理池。导入入口也复用代理校验，避免把
        // `direct` 或不完整 URL 当成已绑定 IP。
        let (proxy_url, proxy_username, proxy_password) =
            Self::validate_proxy_binding(req.proxy_url, req.proxy_username, req.proxy_password)?;
        let explicit_proxy = proxy_url.is_some();
        let gate_enabled = self.token_manager.get_require_pro_plus_credential_proxy();
        // 门禁开启时，PRO+ 自动分配是系统不变量，调用方不能用 false 绕过。
        let assign_from_pool =
            Self::should_assign_proxy_from_pool(gate_enabled, req.assign_proxy_from_pool);

        // 先构建未绑定代理的凭据，使用官方 getUsageLimits 的 subscriptionTitle 判断资格。
        let email = req.email.clone();
        let import_note = req
            .import_note
            .map(|note| note.trim().to_string())
            .filter(|note| !note.is_empty());
        let mut new_cred = KiroCredentials {
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
            proxy_url,
            proxy_username,
            proxy_password,
            // 门禁开启时先以禁用状态入库，完成套餐识别与代理出口验证后再启用。
            disabled: gate_enabled,
            disabled_reason: None,
            kiro_api_key: req.kiro_api_key,
            endpoint: req.endpoint,
            rpm: None,
        };

        let should_check_pool =
            !explicit_proxy && assign_from_pool && (gate_enabled || self.has_proxy_pool_entries());
        let (proxy_pool_eligibility, inspected_usage) = if should_check_pool {
            match self
                .token_manager
                .get_usage_limits_for_candidate(&new_cred)
                .await
            {
                Ok(candidate) => {
                    new_cred = candidate.credentials;
                    (
                        Some(Self::proxy_pool_eligibility(&candidate.usage_limits)),
                        Some(candidate.usage_limits),
                    )
                }
                Err(error) => (
                    Some(ProxyPoolEligibility {
                        eligible: false,
                        subscription_title: None,
                        reason: format!("官方 getUsageLimits 查询失败，不自动分配代理: {error}"),
                    }),
                    None,
                ),
            }
        } else {
            (None, None)
        };

        // 序列化分配到实际写入，防止两个并发导入拿到同一个最后的空槽。
        let _allocation_guard = self.allocation_lock.lock().await;
        let mut assigned_proxy = if proxy_pool_eligibility
            .as_ref()
            .map(|eligibility| eligibility.eligible)
            .unwrap_or(false)
        {
            match self.next_proxy_pool_entry() {
                Ok(proxy) => proxy,
                // 池满时仍保存 PRO+ 凭据为待绑定禁用状态，而不是丢弃导入。
                Err(AdminServiceError::InvalidCredential(message))
                    if message.starts_with("代理池已满") =>
                {
                    None
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        if let Some(proxy) = &assigned_proxy {
            new_cred.proxy_url = Some(proxy.proxy_url.clone());
            new_cred.proxy_username = proxy.proxy_username.clone();
            new_cred.proxy_password = proxy.proxy_password.clone();
        }

        // 候选查询已经拿到官方套餐时，在持久化前写入元数据。这样代理池满、
        // 没有分到代理的 PRO+ 不会短暂进入可调度状态。
        let mut subscription_inspected = inspected_usage.is_some();
        if let Some(usage) = inspected_usage.as_ref() {
            new_cred.subscription_title = usage.subscription_title().map(str::to_owned);
            new_cred.overage_status = usage.overage_status().map(str::to_owned);
        }

        // KIRO PRO+ 必须有账号级代理才允许进入调度；未绑定的号保留在库中，
        // 方便后续加入代理池或人工绑定后再启用。
        let mut activation_requires_proxy = self.requires_proxy_before_enable(&new_cred);
        if activation_requires_proxy {
            new_cred.disabled = true;
        }

        // 调用 token_manager 添加凭据
        let credential_id = self
            .token_manager
            .add_credential(new_cred)
            .await
            .map_err(|e| self.classify_add_error(e))?;
        drop(_allocation_guard);

        // 自动分配前已经查询过的结果直接保存，避免重复请求官方接口。
        if let Some(usage) = inspected_usage.as_ref() {
            self.token_manager
                .store_usage_metadata(credential_id, usage);
        } else {
            match self.token_manager.get_usage_limits_for(credential_id).await {
                Ok(_) => {
                    subscription_inspected = true;
                    // 候选查询偶发失败、但添加后的官方查询成功时，也不能让刚识别
                    // 为 PRO+ 的无代理账号继续处于启用状态。
                    let credentials = self
                        .token_manager
                        .credential_and_effective_proxy(credential_id)
                        .map_err(|error| self.classify_error(error, credential_id))?
                        .0;
                    activation_requires_proxy = self.requires_proxy_before_enable(&credentials);
                    if activation_requires_proxy {
                        self.token_manager
                            .set_disabled_without_release_event(credential_id, true)
                            .map_err(|error| self.classify_error(error, credential_id))?;
                    }
                }
                Err(error) => {
                    tracing::warn!("添加凭据后获取订阅等级失败（不影响凭据添加）: {}", error);
                }
            }
        }

        let mut proxy_test_failed = false;
        if gate_enabled {
            let credentials = self
                .token_manager
                .credential_and_effective_proxy(credential_id)
                .map_err(|error| self.classify_error(error, credential_id))?
                .0;
            if Self::is_kiro_pro_plus(credentials.subscription_title.as_deref()) {
                activation_requires_proxy = true;
                if Self::has_credential_proxy(&credentials) {
                    match self.test_credential_proxy(credential_id).await {
                        Ok(result) if Self::proxy_test_matches_expected_egress(&result) => {
                            self.set_disabled(credential_id, false)?;
                            self.clear_proxy_pending(credential_id)?;
                            activation_requires_proxy = false;
                        }
                        Ok(_) | Err(_) => {
                            proxy_test_failed = true;
                            self.token_manager
                                .set_disabled_without_release_event(credential_id, true)
                                .map_err(|error| self.classify_error(error, credential_id))?;
                            self.release_disabled_credential_proxy(credential_id, false)?;
                            assigned_proxy = None;
                            self.mark_proxy_pending(credential_id)?;
                        }
                    }
                } else {
                    self.mark_proxy_pending(credential_id)?;
                }
            } else if subscription_inspected {
                // 非 PRO+ 不受门禁影响，套餐识别完成后恢复默认启用行为。
                self.token_manager
                    .set_disabled(credential_id, false)
                    .map_err(|error| self.classify_error(error, credential_id))?;
            }
        }

        Ok(AddCredentialResponse {
            success: true,
            message: if proxy_test_failed {
                format!(
                    "凭据添加成功，ID: {}；账号级代理出口验证失败，凭据保持禁用",
                    credential_id
                )
            } else if activation_requires_proxy {
                format!(
                    "凭据添加成功，ID: {}；KIRO PRO+ 待绑定账号级代理后启用",
                    credential_id
                )
            } else if gate_enabled && !subscription_inspected {
                format!(
                    "凭据添加成功，ID: {}；套餐识别失败，凭据保持禁用",
                    credential_id
                )
            } else {
                format!("凭据添加成功，ID: {}", credential_id)
            },
            credential_id,
            email,
            assigned_proxy_url: assigned_proxy
                .as_ref()
                .map(|entry| Self::redact_proxy_url(&entry.proxy_url)),
            assigned_proxy_from_pool: assigned_proxy.is_some(),
            activation_requires_proxy,
            proxy_pool_eligibility,
        })
    }

    /// 删除凭据
    pub fn delete_credential(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .delete_credential(id)
            .map_err(|e| self.classify_delete_error(e, id))?;
        self.clear_proxy_tracking(id)?;

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

    /// 获取 PRO+ 账号级代理门禁配置。
    pub fn get_pro_plus_proxy_gate(&self) -> ProPlusProxyGateResponse {
        ProPlusProxyGateResponse {
            enabled: self.token_manager.get_require_pro_plus_credential_proxy(),
            max_accounts_per_proxy: self.token_manager.get_max_accounts_per_proxy(),
        }
    }

    /// 热更新 PRO+ 账号级代理门禁配置。
    pub fn set_pro_plus_proxy_gate(
        &self,
        req: SetProPlusProxyGateRequest,
    ) -> Result<ProPlusProxyGateResponse, AdminServiceError> {
        if req.max_accounts_per_proxy == 0 {
            return Err(AdminServiceError::InvalidCredential(
                "每个代理账号数必须大于 0".to_string(),
            ));
        }

        let mut assignments_by_proxy: HashMap<String, usize> = HashMap::new();
        for entry in self.token_manager.snapshot().entries {
            if let Some(proxy_url) = entry.proxy_url {
                if !proxy_url.eq_ignore_ascii_case(KiroCredentials::PROXY_DIRECT) {
                    *assignments_by_proxy.entry(proxy_url).or_default() += 1;
                }
            }
        }
        let current_max_assigned = assignments_by_proxy.values().copied().max().unwrap_or(0);
        if req.max_accounts_per_proxy < current_max_assigned {
            return Err(AdminServiceError::InvalidCredential(format!(
                "无法把每个代理账号数降到 {}：当前单个代理最大已绑定 {} 个账号",
                req.max_accounts_per_proxy, current_max_assigned
            )));
        }

        let was_enabled = self.token_manager.get_require_pro_plus_credential_proxy();
        self.token_manager
            .set_pro_plus_proxy_gate(req.enabled, req.max_accounts_per_proxy)
            .map_err(|error| AdminServiceError::InternalError(error.to_string()))?;

        if req.enabled && !was_enabled {
            self.disable_unbound_kiro_pro_plus();
        }
        Ok(self.get_pro_plus_proxy_gate())
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

    fn pro_plus_balance_response(id: u64, usage_limit: f64, remaining: f64) -> BalanceResponse {
        let mut balance = balance_response(id, usage_limit, remaining);
        balance.subscription_title = Some("KIRO PRO+".to_string());
        balance
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
    fn test_pro_plus_quota_threshold_is_strictly_below_fifty() {
        assert!(AdminService::is_pro_plus_below_quota_threshold(
            &pro_plus_balance_response(1, 2000.0, 49.99)
        ));
        assert!(!AdminService::is_pro_plus_below_quota_threshold(
            &pro_plus_balance_response(1, 2000.0, 50.0)
        ));
        assert!(!AdminService::is_pro_plus_below_quota_threshold(
            &pro_plus_balance_response(1, 2000.0, 199.99)
        ));
        assert!(!AdminService::is_pro_plus_below_quota_threshold(
            &balance_response(1, 10000.0, 1.0)
        ));
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
    fn test_manual_proxy_binding_cannot_exceed_configured_capacity() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-manual-proxy-capacity-{}.json",
            uuid::Uuid::new_v4()
        ));
        let mut credentials = Vec::new();
        for id in 1..=3 {
            let mut credential = KiroCredentials::default();
            credential.id = Some(id);
            credential.machine_id = Some(format!("machine-{id}"));
            credentials.push(credential);
        }
        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&credentials).unwrap(),
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

        let error = service
            .set_credentials_proxy_batch(BatchSetCredentialProxyRequest {
                ids: vec![1, 2, 3],
                proxy_url: Some("http://shared.example:443".to_string()),
                proxy_username: None,
                proxy_password: None,
            })
            .unwrap_err();
        assert!(error.to_string().contains("最多允许绑定 2 个账号"));

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
    fn test_proxy_gate_requires_credential_proxy_with_matching_egress_ip() {
        let matching = CredentialProxyTestResponse {
            credential_id: 1,
            uses_proxy: true,
            uses_credential_proxy: true,
            proxy_url: Some("http://203.0.113.10:443".to_string()),
            egress_ip: "203.0.113.10".to_string(),
            tested_at: Utc::now().to_rfc3339(),
        };
        assert!(AdminService::proxy_test_matches_expected_egress(&matching));

        let mismatch = CredentialProxyTestResponse {
            egress_ip: "203.0.113.11".to_string(),
            ..matching.clone()
        };
        assert!(!AdminService::proxy_test_matches_expected_egress(&mismatch));

        let global_only = CredentialProxyTestResponse {
            uses_credential_proxy: false,
            ..matching
        };
        assert!(!AdminService::proxy_test_matches_expected_egress(
            &global_only
        ));
    }

    #[test]
    fn test_kiro_pro_plus_requires_credential_proxy_before_enable() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-pro-plus-proxy-gate-{}.json",
            uuid::Uuid::new_v4()
        ));
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.machine_id = Some("machine-1".to_string());
        credential.subscription_title = Some(" KIRO PRO+ ".to_string());
        credential.disabled = true;
        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        let error = service.set_disabled(1, false).unwrap_err();
        assert!(error.to_string().contains("先绑定账号级代理"));
        assert!(manager.snapshot().entries[0].disabled);

        service
            .set_credential_proxy(
                1,
                SetCredentialProxyRequest {
                    proxy_url: Some("http://residential.example:443".to_string()),
                    proxy_username: Some("buyer".to_string()),
                    proxy_password: Some("secret".to_string()),
                },
            )
            .unwrap();
        service.set_disabled(1, false).unwrap();
        let snapshot = manager.snapshot();
        assert!(!snapshot.entries[0].disabled);
        assert!(snapshot.entries[0].has_proxy);

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[test]
    fn test_kiro_pro_plus_can_enable_without_credential_proxy_when_gate_is_off() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-pro-plus-proxy-gate-off-{}.json",
            uuid::Uuid::new_v4()
        ));
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.machine_id = Some("machine-1".to_string());
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.disabled = true;
        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();

        let mut config = Config::default();
        config.require_pro_plus_credential_proxy = false;
        let manager = Arc::new(
            MultiTokenManager::new(
                config,
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        service.set_disabled(1, false).unwrap();
        assert!(!manager.snapshot().entries[0].disabled);

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[test]
    fn test_pro_plus_proxy_gate_can_be_disabled_at_runtime_and_persists() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-pro-plus-runtime-gate-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let config_path = test_dir.join("config.json");
        let credentials_path = test_dir.join("credentials.json");
        std::fs::write(
            &config_path,
            serde_json::to_string(&Config::default()).unwrap(),
        )
        .unwrap();

        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.machine_id = Some("machine-1".to_string());
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.disabled = true;
        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::load(&config_path).unwrap(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        service
            .set_pro_plus_proxy_gate(SetProPlusProxyGateRequest {
                enabled: false,
                max_accounts_per_proxy: 2,
            })
            .unwrap();
        service.set_disabled(1, false).unwrap();

        let persisted = Config::load(&config_path).unwrap();
        assert!(!persisted.require_pro_plus_credential_proxy);
        assert_eq!(persisted.max_accounts_per_proxy, 2);
        assert!(!manager.snapshot().entries[0].disabled);

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(&config_path).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_startup_disables_existing_unbound_kiro_pro_plus() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-pro-plus-startup-gate-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.machine_id = Some("machine-1".to_string());
        credential.subscription_title = Some("KIRO PRO+".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string_pretty(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();

        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());
        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert_eq!(
            snapshot.entries[0].disabled_reason.as_deref(),
            Some("Manual")
        );
        assert_eq!(service.pending_proxy_ids(), vec![1]);
        drop(service);

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
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
    fn test_overage_enabled_pro_plus_below_fifty_is_disabled() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-overage-pro-plus-low-quota-{}.json",
            uuid::Uuid::new_v4()
        ));

        let mut cred = KiroCredentials::default();
        cred.id = Some(1);
        cred.machine_id = Some("machine-1".to_string());
        cred.subscription_title = Some("KIRO PRO+".to_string());
        cred.overage_status = Some("ENABLED".to_string());
        cred.proxy_url = Some("http://pro-plus-low-quota.example:443".to_string());
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

        service.disable_if_quota_exhausted_balance(&pro_plus_balance_response(1, 2000.0, 49.99));

        let first = manager.snapshot().entries.into_iter().next().unwrap();
        assert!(first.disabled);
        assert_eq!(first.disabled_reason.as_deref(), Some("QuotaExceeded"));

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

    #[test]
    fn test_backfill_disabled_reason_marks_quota_or_manual_without_overwrite() {
        let credentials_path = std::env::temp_dir().join(format!(
            "kiro-admin-backfill-reason-{}.json",
            uuid::Uuid::new_v4()
        ));

        let mut cred1 = KiroCredentials::default();
        cred1.id = Some(1);
        cred1.disabled = true; // 禁用但无原因（加载时派生 Manual）
        let mut cred2 = KiroCredentials::default();
        cred2.id = Some(2);
        cred2.disabled = true;
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

        // 加载后禁用账号派生为 Manual（既有行为）
        assert_eq!(
            manager
                .snapshot()
                .entries
                .iter()
                .find(|e| e.id == 1)
                .unwrap()
                .disabled_reason
                .as_deref(),
            Some("Manual")
        );

        // backfill 不覆盖已有原因
        service.backfill_disabled_reason(1, &balance_response(1, 10000.0, 0.0));
        service.backfill_disabled_reason(2, &balance_response(2, 10000.0, 500.0));
        let snapshot = manager.snapshot();
        assert_eq!(
            snapshot.entries.iter().find(|e| e.id == 1).unwrap().disabled_reason.as_deref(),
            Some("Manual")
        );
        assert_eq!(
            snapshot.entries.iter().find(|e| e.id == 2).unwrap().disabled_reason.as_deref(),
            Some("Manual")
        );

        // set_disabled_reason 可写入具体原因并持久化
        manager
            .set_disabled_reason(1, DisabledReason::QuotaExceeded)
            .unwrap();
        manager
            .set_disabled_reason(2, DisabledReason::InvalidRefreshToken)
            .unwrap();
        let persisted: Vec<KiroCredentials> =
            serde_json::from_str(&std::fs::read_to_string(&credentials_path).unwrap()).unwrap();
        let p1 = persisted.iter().find(|c| c.id == Some(1)).unwrap();
        let p2 = persisted.iter().find(|c| c.id == Some(2)).unwrap();
        assert_eq!(p1.disabled_reason.as_deref(), Some("QuotaExceeded"));
        assert_eq!(p2.disabled_reason.as_deref(), Some("InvalidRefreshToken"));

        // 重新加载后原因不丢失
        let reloaded = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                persisted.clone(),
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        assert_eq!(
            reloaded
                .snapshot()
                .entries
                .iter()
                .find(|e| e.id == 1)
                .unwrap()
                .disabled_reason
                .as_deref(),
            Some("QuotaExceeded")
        );
        assert_eq!(
            reloaded
                .snapshot()
                .entries
                .iter()
                .find(|e| e.id == 2)
                .unwrap()
                .disabled_reason
                .as_deref(),
            Some("InvalidRefreshToken")
        );

        std::fs::remove_file(&credentials_path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_proxy_pool_tracks_two_accounts_before_rotating_and_persists() {
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

        for (index, proxy_url) in [
            "http://proxy-one.example:443",
            "http://proxy-one.example:443",
            "http://proxy-two.example:443",
        ]
        .iter()
        .enumerate()
        {
            let mut credential = KiroCredentials::default();
            credential.auth_method = Some("api_key".to_string());
            credential.kiro_api_key = Some(format!("ksk-proxy-pool-{index}"));
            credential.proxy_url = Some((*proxy_url).to_string());
            manager.add_credential(credential).await.unwrap();
        }

        let pool = service.get_proxy_pool();
        assert_eq!(pool.total, 2);
        assert_eq!(pool.available_slots, 1);
        assert_eq!(pool.proxies[0].assigned_count, 2);
        assert_eq!(pool.proxies[1].assigned_count, 1);
        assert_eq!(
            service.next_proxy_pool_entry().unwrap().unwrap().proxy_url,
            "http://proxy-two.example:443"
        );

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

    #[test]
    fn test_proxy_pool_refuses_a_third_account_when_all_slots_are_full() {
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

        let result = service.next_proxy_pool_entry();
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

    #[test]
    fn test_proxy_pool_uses_configured_accounts_per_proxy_limit() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-proxy-pool-dynamic-limit-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credentials = Vec::new();
        for id in 1..=3 {
            let mut credential = KiroCredentials::default();
            credential.id = Some(id);
            credential.machine_id = Some(format!("machine-{id}"));
            credential.proxy_url = Some("http://shared.example:443".to_string());
            credentials.push(credential);
        }
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&credentials).unwrap(),
        )
        .unwrap();
        let mut config = Config::default();
        config.max_accounts_per_proxy = 3;
        let manager = Arc::new(
            MultiTokenManager::new(
                config,
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
                    proxy_url: Some("http://shared.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();

        let pool = service.get_proxy_pool();
        assert_eq!(pool.max_accounts_per_proxy, 3);
        assert_eq!(pool.proxies[0].assigned_count, 3);
        assert_eq!(pool.available_slots, 0);
        assert!(service.next_proxy_pool_entry().is_err());

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_proxy_gate_rejects_lower_limit_below_existing_assignment() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-proxy-gate-reject-lower-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credentials = Vec::new();
        for id in 1..=2 {
            let mut credential = KiroCredentials::default();
            credential.id = Some(id);
            credential.machine_id = Some(format!("machine-{id}"));
            credential.proxy_url = Some("http://shared.example:443".to_string());
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
                    proxy_url: Some("http://shared.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();

        let error = service
            .set_pro_plus_proxy_gate(SetProPlusProxyGateRequest {
                enabled: true,
                max_accounts_per_proxy: 1,
            })
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("当前单个代理最大已绑定 2 个账号")
        );
        assert_eq!(service.get_pro_plus_proxy_gate().max_accounts_per_proxy, 2);

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_proxy_pool_only_accepts_kiro_pro_plus_subscription_title() {
        let pro_plus: UsageLimitsResponse = serde_json::from_value(serde_json::json!({
            "subscriptionInfo": {"subscriptionTitle": " Kiro Pro+ "}
        }))
        .unwrap();
        let pro_max: UsageLimitsResponse = serde_json::from_value(serde_json::json!({
            "subscriptionInfo": {"subscriptionTitle": "kiro pro max"}
        }))
        .unwrap();
        let free: UsageLimitsResponse = serde_json::from_value(serde_json::json!({
            "subscriptionInfo": {"subscriptionTitle": "KIRO FREE"}
        }))
        .unwrap();
        let missing: UsageLimitsResponse = serde_json::from_value(serde_json::json!({})).unwrap();

        let eligible = AdminService::proxy_pool_eligibility(&pro_plus);
        assert!(eligible.eligible);
        assert_eq!(eligible.subscription_title.as_deref(), Some(" Kiro Pro+ "));
        assert!(AdminService::proxy_pool_eligibility(&pro_max).eligible);
        assert!(!AdminService::proxy_pool_eligibility(&free).eligible);
        assert!(!AdminService::proxy_pool_eligibility(&missing).eligible);
    }

    #[test]
    fn test_enabled_gate_cannot_be_bypassed_by_assign_proxy_false() {
        assert!(AdminService::should_assign_proxy_from_pool(
            true,
            Some(false)
        ));
        assert!(!AdminService::should_assign_proxy_from_pool(
            false,
            Some(false)
        ));
        assert!(AdminService::should_assign_proxy_from_pool(false, None));
    }

    #[test]
    fn test_quota_exhausted_pro_plus_releases_proxy_and_never_requeues() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-quota-retirement-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.proxy_url = Some("http://retired.example:443".to_string());
        credential.disabled = true;
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![SetCredentialProxyRequest {
                    proxy_url: Some("http://retired.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();
        service.mark_proxy_pending(1).unwrap();

        assert!(service.retire_quota_exhausted_pool_credential(1).unwrap());

        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert!(!snapshot.entries[0].has_proxy);
        assert!(service.pending_proxy_ids().is_empty());
        assert_eq!(
            service.proxy_pool.lock().retired_quota_credential_ids,
            vec![1]
        );
        assert_eq!(service.get_proxy_pool().available_slots, 2);
        assert_eq!(
            service.get_all_credentials().credentials[0]
                .disabled_reason
                .as_deref(),
            Some("QuotaExceeded")
        );
        assert!(
            service
                .ensure_can_enable(1)
                .unwrap_err()
                .to_string()
                .contains("永久退役")
        );

        service.delete_credential(1).unwrap();
        assert!(
            service
                .proxy_pool
                .lock()
                .retired_quota_credential_ids
                .is_empty()
        );

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        std::fs::remove_file(test_dir.join("kiro_balance_cache.json")).unwrap();
        std::fs::remove_file(test_dir.join("kiro_stats.json")).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_quota_exhausted_pool_account_releases_proxy_after_plan_downgrade() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-downgraded-quota-retirement-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO FREE".to_string());
        credential.proxy_url = Some("http://downgraded.example:443".to_string());
        credential.disabled = true;
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![SetCredentialProxyRequest {
                    proxy_url: Some("http://downgraded.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();

        assert!(service.retire_quota_exhausted_pool_credential(1).unwrap());

        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert!(!snapshot.entries[0].has_proxy);
        assert_eq!(
            service.proxy_pool.lock().retired_quota_credential_ids,
            vec![1]
        );

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        if test_dir.join("kiro_stats.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_stats.json")).unwrap();
        }
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_manual_disable_releases_pro_plus_proxy_without_requeueing() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-manual-disabled-proxy-release-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.proxy_url = Some("http://manual-disabled.example:443".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        service.set_disabled_and_reconcile(1, true).await.unwrap();

        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert!(!snapshot.entries[0].has_proxy);
        assert!(service.pending_proxy_ids().is_empty());

        std::fs::remove_file(&credentials_path).unwrap();
        if test_dir.join("kiro_proxy_pool.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        }
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_manual_disable_releases_pool_proxy_after_plan_downgrade() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-downgraded-manual-release-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO FREE".to_string());
        credential.proxy_url = Some("http://downgraded-manual.example:443".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![SetCredentialProxyRequest {
                    proxy_url: Some("http://downgraded-manual.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();

        service.set_disabled_and_reconcile(1, true).await.unwrap();

        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert!(!snapshot.entries[0].has_proxy);
        assert_eq!(service.get_proxy_pool().available_slots, 2);

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_startup_releases_stale_disabled_pro_plus_proxy() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-stale-disabled-proxy-release-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.proxy_url = Some("http://stale-disabled.example:443".to_string());
        credential.disabled = true;
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        assert_eq!(service.release_stale_disabled_proxy_bindings().unwrap(), 1);
        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert!(!snapshot.entries[0].has_proxy);
        assert!(service.pending_proxy_ids().is_empty());

        std::fs::remove_file(&credentials_path).unwrap();
        if test_dir.join("kiro_proxy_pool.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        }
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_invalid_refresh_token_event_releases_pro_plus_proxy() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-invalid-refresh-proxy-release-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.proxy_url = Some("http://invalid-refresh.example:443".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let events = manager.subscribe_stable_disabled();
        let service = Arc::new(AdminService::new(manager.clone(), Vec::<String>::new()));
        let worker = tokio::spawn(
            service
                .clone()
                .run_stable_disabled_proxy_release_worker(events),
        );

        manager.report_refresh_token_invalid(1);

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !manager.snapshot().entries[0].has_proxy {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        let _ = worker.await;
        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert_eq!(
            snapshot.entries[0].disabled_reason.as_deref(),
            Some("InvalidRefreshToken")
        );
        assert!(!snapshot.entries[0].has_proxy);

        std::fs::remove_file(&credentials_path).unwrap();
        if test_dir.join("kiro_proxy_pool.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        }
        if test_dir.join("kiro_stats.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_stats.json")).unwrap();
        }
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_upstream_suspension_event_releases_downgraded_pool_proxy() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-suspended-downgraded-release-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO FREE".to_string());
        credential.proxy_url = Some("http://suspended-downgraded.example:443".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let events = manager.subscribe_stable_disabled();
        let service = Arc::new(AdminService::new(manager.clone(), Vec::<String>::new()));
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![SetCredentialProxyRequest {
                    proxy_url: Some("http://suspended-downgraded.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();
        let worker = tokio::spawn(
            service
                .clone()
                .run_stable_disabled_proxy_release_worker(events),
        );

        manager.report_upstream_suspended(1);

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !manager.snapshot().entries[0].has_proxy {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        let _ = worker.await;
        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert_eq!(
            snapshot.entries[0].disabled_reason.as_deref(),
            Some("UpstreamSuspended")
        );
        assert!(!snapshot.entries[0].has_proxy);

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        if test_dir.join("kiro_stats.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_stats.json")).unwrap();
        }
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_transient_failure_cooldown_keeps_pro_plus_proxy() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-transient-disabled-proxy-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.proxy_url = Some("http://transient-failure.example:443".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());

        manager.report_failure(1);
        manager.report_failure(1);
        manager.report_failure(1);

        assert_eq!(service.release_stale_disabled_proxy_bindings().unwrap(), 0);
        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert_eq!(
            snapshot.entries[0].disabled_reason.as_deref(),
            Some("TooManyFailures")
        );
        assert!(snapshot.entries[0].has_proxy);

        std::fs::remove_file(&credentials_path).unwrap();
        if test_dir.join("kiro_stats.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_stats.json")).unwrap();
        }
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_quota_exhausted_event_automatically_retires_pro_plus() {
        let test_dir =
            std::env::temp_dir().join(format!("kiro-admin-quota-event-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO PRO+".to_string());
        credential.proxy_url = Some("http://event.example:443".to_string());
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let events = manager.subscribe_quota_exhausted();
        let service = Arc::new(AdminService::new(manager.clone(), Vec::<String>::new()));
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![SetCredentialProxyRequest {
                    proxy_url: Some("http://event.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();
        let worker = tokio::spawn(service.clone().run_quota_rotation_worker(events));

        manager.report_quota_exhausted(1);

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if !manager.snapshot().entries[0].has_proxy
                    && service
                        .proxy_pool
                        .lock()
                        .retired_quota_credential_ids
                        .contains(&1)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        let snapshot = manager.snapshot();
        assert!(snapshot.entries[0].disabled);
        assert_eq!(
            snapshot.entries[0].disabled_reason.as_deref(),
            Some("QuotaExceeded")
        );
        assert_eq!(
            service.proxy_pool.lock().retired_quota_credential_ids,
            vec![1]
        );

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        if test_dir.join("kiro_stats.json").exists() {
            std::fs::remove_file(test_dir.join("kiro_stats.json")).unwrap();
        }
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_startup_retires_only_cached_exhausted_pro_plus() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-startup-retirement-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let credentials: Vec<KiroCredentials> = (1..=2)
            .map(|id| {
                let mut credential = KiroCredentials::default();
                credential.id = Some(id);
                credential.subscription_title = Some("KIRO PRO+".to_string());
                credential.proxy_url = Some(format!("http://startup-{id}.example:443"));
                credential.disabled = true;
                credential
            })
            .collect();
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
        let service = AdminService::new(manager.clone(), Vec::<String>::new());
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![
                    SetCredentialProxyRequest {
                        proxy_url: Some("http://startup-1.example:443".to_string()),
                        proxy_username: None,
                        proxy_password: None,
                    },
                    SetCredentialProxyRequest {
                        proxy_url: Some("http://startup-2.example:443".to_string()),
                        proxy_username: None,
                        proxy_password: None,
                    },
                ],
            })
            .unwrap();
        service.balance_cache.lock().insert(
            1,
            CachedBalance {
                cached_at: Utc::now().timestamp() as f64,
                data: pro_plus_balance_response(1, 2000.0, 49.99),
            },
        );
        service.balance_cache.lock().insert(
            2,
            CachedBalance {
                cached_at: Utc::now().timestamp() as f64,
                data: pro_plus_balance_response(2, 2000.0, 500.0),
            },
        );

        assert_eq!(
            service.retire_cached_nonviable_pool_credentials().unwrap(),
            1
        );

        let snapshot = manager.snapshot();
        assert!(
            !snapshot
                .entries
                .iter()
                .find(|e| e.id == 1)
                .unwrap()
                .has_proxy
        );
        assert!(
            snapshot
                .entries
                .iter()
                .find(|e| e.id == 2)
                .unwrap()
                .has_proxy
        );
        assert_eq!(
            service.proxy_pool.lock().retired_quota_credential_ids,
            vec![1]
        );

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }

    #[test]
    fn test_startup_retires_cached_exhausted_pool_account_after_plan_downgrade() {
        let test_dir = std::env::temp_dir().join(format!(
            "kiro-admin-startup-downgraded-retirement-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let credentials_path = test_dir.join("credentials.json");
        let mut credential = KiroCredentials::default();
        credential.id = Some(1);
        credential.subscription_title = Some("KIRO FREE".to_string());
        credential.proxy_url = Some("http://startup-downgraded.example:443".to_string());
        credential.disabled = true;
        std::fs::write(
            &credentials_path,
            serde_json::to_string(&vec![credential.clone()]).unwrap(),
        )
        .unwrap();
        let manager = Arc::new(
            MultiTokenManager::new(
                Config::default(),
                vec![credential],
                None,
                Some(credentials_path.clone()),
                true,
            )
            .unwrap(),
        );
        let service = AdminService::new(manager.clone(), Vec::<String>::new());
        service
            .add_proxy_pool_entries(AddProxyPoolEntriesRequest {
                proxies: vec![SetCredentialProxyRequest {
                    proxy_url: Some("http://startup-downgraded.example:443".to_string()),
                    proxy_username: None,
                    proxy_password: None,
                }],
            })
            .unwrap();
        service.mark_proxy_pending(1).unwrap();
        service.balance_cache.lock().insert(
            1,
            CachedBalance {
                cached_at: Utc::now().timestamp() as f64,
                data: BalanceResponse {
                    id: 1,
                    subscription_title: Some("KIRO FREE".to_string()),
                    current_usage: 50.0,
                    usage_limit: 50.0,
                    remaining: 0.0,
                    usage_percentage: 100.0,
                    next_reset_at: Some(
                        (Utc::now() + chrono::Duration::hours(1)).timestamp() as f64
                    ),
                    overage_status: Some("DISABLED".to_string()),
                    current_overages: 0.0,
                    overage_cap: 0.0,
                    overage_rate: 0.0,
                },
            },
        );

        assert_eq!(
            service.retire_cached_nonviable_pool_credentials().unwrap(),
            1
        );

        assert!(!manager.snapshot().entries[0].has_proxy);
        assert!(service.pending_proxy_ids().is_empty());
        assert_eq!(
            service.proxy_pool.lock().retired_quota_credential_ids,
            vec![1]
        );

        std::fs::remove_file(&credentials_path).unwrap();
        std::fs::remove_file(test_dir.join("kiro_proxy_pool.json")).unwrap();
        std::fs::remove_dir(&test_dir).unwrap();
    }
}
