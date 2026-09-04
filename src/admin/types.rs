//! Admin API 类型定义

use serde::{Deserialize, Serialize};

// ============ 凭据状态 ============

/// 所有凭据状态响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsStatusResponse {
    /// 凭据总数
    pub total: usize,
    /// 可用凭据数量（未禁用）
    pub available: usize,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 全局默认 RPM（None 或 0 表示不限制）
    pub default_rpm: Option<u32>,
    /// 各凭据状态列表
    pub credentials: Vec<CredentialStatusItem>,
}

/// 单个凭据的状态信息
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusItem {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级（数字越小优先级越高）
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 是否为当前活跃凭据
    pub is_current: bool,
    /// Token 过期时间（RFC3339 格式）
    pub expires_at: Option<String>,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
    /// refreshToken 的 SHA-256 哈希（仅 OAuth 凭据，用于前端去重）
    pub refresh_token_hash: Option<String>,
    /// kiroApiKey 的 SHA-256 哈希（仅 API Key 凭据，用于前端去重）
    pub api_key_hash: Option<String>,
    /// kiroApiKey 的脱敏展示（仅 API Key 凭据，用于前端显示）
    pub masked_api_key: Option<String>,
    /// 用户邮箱（用于前端显示）
    pub email: Option<String>,
    /// 导入备注（用于标记批次、导入时间或账号性质）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_note: Option<String>,
    /// 已同步的官方订阅等级（KIRO PRO+ / KIRO FREE 等）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_title: Option<String>,
    /// API 调用成功次数
    pub success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    pub last_used_at: Option<String>,
    /// 是否配置了凭据级代理
    pub has_proxy: bool,
    /// 代理 URL（用于前端展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Token 刷新连续失败次数
    pub refresh_failure_count: u32,
    /// 禁用原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// 当前禁用生命周期开始时间
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<String>,
    /// 后端统一恢复判定分类：none / never / conditional / manual
    pub recovery_class: String,
    /// 恢复前置检查代码
    pub recovery_checks: Vec<String>,
    /// 当前余额探针状态
    pub balance_state: String,
    pub balance_checked_at: Option<String>,
    pub balance_source: Option<String>,
    pub balance_error_class: Option<String>,
    pub balance_remaining: Option<f64>,
    pub balance_usage_limit: Option<f64>,
    pub balance_next_reset_at: Option<f64>,
    /// 端点名称（决定该凭据走哪套 Kiro API，已回退到默认端点）
    pub endpoint: String,
    /// 凭据级 RPM 配置原值（None 表示跟随全局默认）
    pub rpm: Option<u32>,
    /// 有效 RPM 上限（凭据级优先，回退全局默认；None 表示不限制）
    pub effective_rpm: Option<u32>,
    /// 是否跟随全局默认（凭据级未单独配置 rpm）
    pub rpm_follows_default: bool,
    /// 当前滑动窗口上游尝试数（瞬时上游尝试 RPM）
    pub current_rpm: u32,
    /// 当前尚未完成的上游请求数
    pub in_flight_requests: u32,
    /// 近 1h 峰值上游尝试 RPM
    pub peak_rpm_1h: u32,
    /// 近 1h 因 RPM 受限被跳过次数
    pub throttled_1h: u32,
    /// AWS 侧超额（overage）状态（ENABLED / DISABLED；None 表示未知/未同步）
    pub overage_status: Option<String>,
}
/// 账号日志搜索参数。
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccountLogSearchQuery {
    pub query: String,
    pub limit: Option<usize>,
}

/// 单账号日志查询参数。
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CredentialLogQuery {
    pub severity: Option<String>,
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<usize>,
    pub before: Option<String>,
}

/// 日志中心的账号搜索结果。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLogAccount {
    pub id: u64,
    pub email: Option<String>,
    pub import_note: Option<String>,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
}

/// 账号搜索响应。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLogAccountsResponse {
    pub accounts: Vec<AccountLogAccount>,
}

/// 单账号日志响应。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialLogsResponse {
    pub credential_id: u64,
    pub items: Vec<crate::account_logs::AccountLogItem>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// 账号余额缓存/探针状态摘要。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceProbeSummary {
    /// notChecked / fresh / stale / failed
    pub state: String,
    pub checked_at: Option<String>,
    pub source: Option<String>,
    pub error_class: Option<String>,
}

/// 批量查询账号余额。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchBalanceRequest {
    pub ids: Vec<u64>,
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceProbeResult {
    pub credential_id: u64,
    pub state: String,
    pub balance: Option<BalanceResponse>,
    pub checked_at: Option<String>,
    pub source: Option<String>,
    pub error_class: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchBalanceResponse {
    pub results: Vec<BalanceProbeResult>,
}

// ============ 操作请求 ============

/// 启用/禁用凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDisabledRequest {
    /// 是否禁用
    pub disabled: bool,
}

/// 修改优先级请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPriorityRequest {
    /// 新优先级值
    pub priority: u32,
}

/// 更新单个凭据的代理绑定。
///
/// `proxy_url = null` 清除凭据级绑定并回退到全局代理；
/// `proxy_url = "direct"` 显式直连；其余值必须是 HTTP/HTTPS/SOCKS5 代理 URL。
/// 相同代理的绑定数量受全局 `maxAccountsPerProxy` 限制。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCredentialProxyRequest {
    pub proxy_url: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
}

/// 将同一代理绑定批量写入多个凭据。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSetCredentialProxyRequest {
    pub ids: Vec<u64>,
    pub proxy_url: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
}

/// 让已导入但尚未绑定代理的凭据按自动代理池规则领取出口。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignCredentialProxyFromPoolRequest {
    pub ids: Vec<u64>,
}

/// 已有凭据从自动代理池领取代理的结果。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignCredentialProxyFromPoolResponse {
    pub assigned_credential_ids: Vec<u64>,
    pub skipped: Vec<ProxyPoolAssignmentSkip>,
}

/// 未领取代理的凭据及原因。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolAssignmentSkip {
    pub credential_id: u64,
    pub reason: String,
}

/// 向自动分配代理池追加住宅代理。
///
/// 代理认证信息只会写入服务端的代理池文件，所有读取接口均不会回显。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddProxyPoolEntriesRequest {
    pub proxies: Vec<SetCredentialProxyRequest>,
}

/// 从自动分配代理池移除代理。
///
/// 仅阻止后续自动分配，不会改变已绑定账号的出口代理。
/// 代理出口探针的非敏感摘要。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyProbeSummary {
    /// notTested / passed / failed
    pub state: String,
    pub egress_ip: Option<String>,
    pub expected_ip: Option<String>,
    pub latency_ms: Option<u64>,
    pub failure_class: Option<String>,
    pub tested_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolTestRequest {
    pub proxy_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolTestResponse {
    pub proxy_url: String,
    #[serde(flatten)]
    pub probe: ProxyProbeSummary,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveProxyPoolEntriesRequest {
    pub proxy_urls: Vec<String>,
}

/// 自动分配代理池状态。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolResponse {
    /// 每个代理最多绑定的账号数。
    pub max_accounts_per_proxy: usize,
    pub total: usize,
    pub total_capacity: usize,
    pub assigned_slots: usize,
    pub available_slots: usize,
    pub empty_proxy_count: usize,
    pub partial_proxy_count: usize,
    pub full_proxy_count: usize,
    pub healthy_assigned_count: usize,
    pub abnormal_assigned_count: usize,
    pub unknown_assigned_count: usize,
    pub pending_credential_count: usize,
    pub unbound_enabled_count: usize,
    pub empty_reason: Option<String>,
    pub proxies: Vec<ProxyPoolEntryStatus>,
}

/// PRO+ 账号级代理门禁配置。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProPlusProxyGateResponse {
    pub enabled: bool,
    pub max_accounts_per_proxy: usize,
}

/// 更新 PRO+ 账号级代理门禁配置。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetProPlusProxyGateRequest {
    pub enabled: bool,
    pub max_accounts_per_proxy: usize,
}

/// 单个代理的脱敏状态。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolEntryStatus {
    pub proxy_url: String,
    pub assigned_credential_ids: Vec<u64>,
    pub assigned_credentials: Vec<ProxyAssignedCredentialStatus>,
    pub assigned_count: usize,
    pub remaining_slots: usize,
    pub healthy_count: usize,
    pub abnormal_count: usize,
    pub unknown_count: usize,
    pub last_test: Option<ProxyProbeSummary>,
}

/// 代理下绑定账号的健康摘要。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyAssignedCredentialStatus {
    pub credential_id: u64,
    pub email: Option<String>,
    pub subscription_title: Option<String>,
    pub import_note: Option<String>,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
    pub remaining: Option<f64>,
    pub usage_limit: Option<f64>,
    pub balance_cached_at: Option<f64>,
    pub proxy_probe_state: String,
    pub account_probe_state: String,
    pub recovery_state: String,
    pub health: String,
}

/// 批量代理测试的目标凭据。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualProxyBindRequest {
    pub proxy_url: String,
    pub credential_ids: Vec<u64>,
}

/// 从账号手动解除代理池占用。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualProxyUnbindRequest {
    pub credential_ids: Vec<u64>,
}

/// 手动代理操作结果。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualProxyOperationResponse {
    pub updated_credential_ids: Vec<u64>,
    pub failed: Vec<ProxyPoolAssignmentSkip>,
    pub pending_credential_ids: Vec<u64>,
}
/// 代理池手动操作请求使用独立类型，避免与批量代理测试混淆。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchCredentialIdsRequest {
    pub ids: Vec<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverQuotaRetiredRequest {
    pub ids: Vec<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverQuotaRetiredResponse {
    pub recovered_credential_ids: Vec<u64>,
    pub skipped: Vec<ProxyPoolAssignmentSkip>,
}

/// 一次账号级代理出口测试结果。
///
/// 不回显代理用户名或密码；`proxy_url` 已脱敏。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProxyTestResponse {
    pub credential_id: u64,
    pub uses_proxy: bool,
    pub uses_credential_proxy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    pub egress_ip: String,
    pub tested_at: String,
}

/// 添加凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialRequest {
    /// 刷新令牌（OAuth 凭据必填，API Key 凭据不需要）
    pub refresh_token: Option<String>,

    /// 认证方式（可选，默认 social）
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// OIDC Client ID（IdC 认证需要）
    pub client_id: Option<String>,

    /// OIDC Client Secret（IdC 认证需要）
    pub client_secret: Option<String>,

    /// 优先级（可选，默认 0）
    #[serde(default)]
    pub priority: u32,

    /// 凭据级 Region 配置（用于 OIDC token 刷新）
    /// 未配置时回退到 config.json 的全局 region
    pub region: Option<String>,

    /// 凭据级 Auth Region（用于 Token 刷新）
    pub auth_region: Option<String>,

    /// 凭据级 API Region（用于 API 请求）
    pub api_region: Option<String>,

    /// 凭据级 Machine ID（可选，64 位字符串）
    /// 未配置时回退到 config.json 的 machineId
    pub machine_id: Option<String>,

    /// 用户邮箱（可选，用于前端显示）
    pub email: Option<String>,

    /// 导入备注（可选，用于标记批次、导入时间或账号性质）
    pub import_note: Option<String>,

    /// 凭据级代理 URL（可选，特殊值 "direct" 表示不使用代理）
    pub proxy_url: Option<String>,

    /// 凭据级代理认证用户名（可选）
    pub proxy_username: Option<String>,

    /// 凭据级代理认证密码（可选）
    pub proxy_password: Option<String>,

    /// 未显式传入 proxyUrl 时，是否允许从代理池自动领取一个代理。
    /// 缺省时：池非空且官方 getUsageLimits 返回的 subscriptionTitle 为 KIRO PRO+ 才自动分配；
    /// 传 false 可保留原来的全局代理/直连行为。
    #[serde(default)]
    pub assign_proxy_from_pool: Option<bool>,

    /// Kiro API Key（API Key 凭据必填，格式: ksk_xxxxxxxx）
    /// 设置后直接作为 Bearer Token 使用，无需 refreshToken
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kiro_api_key: Option<String>,

    /// 端点名称（可选，未配置时使用 config.defaultEndpoint）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

fn default_auth_method() -> String {
    "social".to_string()
}

/// 添加凭据成功响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialResponse {
    pub success: bool,
    pub message: String,
    /// 新添加的凭据 ID
    pub credential_id: u64,
    /// 用户邮箱（如果获取成功）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// 本次导入由自动代理池分配的代理 URL（不含认证信息）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_proxy_url: Option<String>,
    pub assigned_proxy_from_pool: bool,
    /// 已识别为 KIRO PRO+ 但尚未绑定账号级代理；该账号以禁用状态导入。
    pub activation_requires_proxy: bool,
    /// 自动代理池资格判定。仅在本次请求尝试自动从池分配时返回。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_pool_eligibility: Option<ProxyPoolEligibility>,
}

/// 自动代理池的订阅资格判定。
///
/// 只使用 Kiro 官方 getUsageLimits 返回的 subscriptionTitle，不依赖邮箱或额度。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolEligibility {
    /// 是否符合自动分配代理的订阅条件（KIRO PRO+）。
    pub eligible: bool,
    /// 官方 getUsageLimits 返回的订阅标题。查询失败或字段缺失时为 None。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_title: Option<String>,
    /// 判定结果或未分配原因。
    pub reason: String,
}

// ============ 余额查询 ============

/// 余额查询响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    /// 凭据 ID
    pub id: u64,
    /// 订阅类型
    pub subscription_title: Option<String>,
    /// 当前使用量
    pub current_usage: f64,
    /// 使用限额
    pub usage_limit: f64,
    /// 剩余额度
    pub remaining: f64,
    /// 使用百分比
    pub usage_percentage: f64,
    /// 下次重置时间（Unix 时间戳）
    pub next_reset_at: Option<f64>,
    /// AWS 侧超额（overage）状态（ENABLED / DISABLED；None 表示未知/未同步）
    #[serde(default)]
    pub overage_status: Option<String>,
    /// 当前已产生的超额用量（次数）
    #[serde(default)]
    pub current_overages: f64,
    /// 超额上限（次数，0 表示无明确上限）
    #[serde(default)]
    pub overage_cap: f64,
    /// 超额单价（美元 / 次）
    #[serde(default)]
    pub overage_rate: f64,
}

// ============ 负载均衡配置 ============

/// 负载均衡模式响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancingModeResponse {
    /// 当前模式（"priority" 或 "balanced"）
    pub mode: String,
}

/// 设置负载均衡模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetLoadBalancingModeRequest {
    /// 模式（"priority" 或 "balanced"）
    pub mode: String,
}

// ============ RPM 限流配置 ============

/// 设置单个凭据 RPM 请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRpmRequest {
    /// RPM 上限。null/缺省 = 跟随全局默认；0 = 不限制
    #[serde(default)]
    pub rpm: Option<u32>,
}

/// 批量设置凭据 RPM 请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSetRpmRequest {
    /// 目标凭据 ID 列表
    pub ids: Vec<u64>,
    /// RPM 上限。null/缺省 = 跟随全局默认；0 = 不限制
    #[serde(default)]
    pub rpm: Option<u32>,
}

/// 批量更新凭据备注和/或优先级。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUpdateCredentialsRequest {
    /// 目标凭据 ID 列表。
    pub ids: Vec<u64>,
    /// 新备注；缺省表示不修改。传入后会覆盖原 importNote。
    #[serde(default)]
    pub import_note: Option<String>,
    /// 新优先级；缺省表示不修改。
    #[serde(default)]
    pub priority: Option<u32>,
}

/// 全局默认 RPM 响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultRpmResponse {
    /// 全局默认 RPM（None 或 0 表示不限制）
    pub default_rpm: Option<u32>,
}

/// 设置全局默认 RPM 请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDefaultRpmRequest {
    /// 全局默认 RPM。null/缺省 = 不限制；0 = 不限制
    #[serde(default)]
    pub default_rpm: Option<u32>,
}

// ============ 破甲模式配置 ============

/// 破甲模式响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArmorBreakingResponse {
    /// 当前是否开启破甲
    pub enabled: bool,
}

/// 设置破甲模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetArmorBreakingRequest {
    /// 是否开启破甲
    pub enabled: bool,
}

/// 超额放行开关响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OveragePassthroughResponse {
    /// 当前是否开启超额放行
    pub enabled: bool,
}

/// 设置超额放行开关请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetOveragePassthroughRequest {
    /// 是否开启超额放行
    pub enabled: bool,
}

// ============ CC Test 透传配置 ============

/// CC Test 透传响应
///
/// `api_key` 整串返回（仅 Admin API Key 认证后可见，便于前端回填编辑）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaxRelayResponse {
    /// 是否开启透传
    pub enabled: bool,
    /// CC Test 透传上游 base_url
    pub base_url: String,
    /// CC Test 透传上游 api_key（整串返回）
    pub api_key: String,
}

/// 设置 CC Test 透传请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetMaxRelayRequest {
    /// 是否开启透传
    #[serde(default)]
    pub enabled: bool,
    /// CC Test 透传上游 base_url
    #[serde(default)]
    pub base_url: String,
    /// CC Test 透传上游 api_key
    #[serde(default)]
    pub api_key: String,
}

// ============ 通用响应 ============

/// 操作成功响应
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

impl SuccessResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
        }
    }
}

/// 错误响应
#[derive(Debug, Serialize)]
pub struct AdminErrorResponse {
    pub error: AdminError,
}

#[derive(Debug, Serialize)]
pub struct AdminError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

impl AdminErrorResponse {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: AdminError {
                error_type: error_type.into(),
                message: message.into(),
            },
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("invalid_request", message)
    }

    pub fn authentication_error() -> Self {
        Self::new("authentication_error", "Invalid or missing admin API key")
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn api_error(message: impl Into<String>) -> Self {
        Self::new("api_error", message)
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new("internal_error", message)
    }
}
