use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    Rustls,
    NativeTls,
}

impl Default for TlsBackend {
    fn default() -> Self {
        Self::Rustls
    }
}

/// CC Test 检测请求透传配置
///
/// 开启后，只有识别为 CC Test 检测探针的请求会被原样透传到配置的上游渠道；
/// 普通用户请求（包括普通 Claude Code 请求）仍走本机 Kiro。
/// 运行时可经 Admin API `/config/max-relay` 热切换。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MaxRelayConfig {
    /// 是否开启透传（默认 false = 不影响任何现状）
    #[serde(default)]
    pub enabled: bool,

    /// CC Test 透传上游 base_url（如 https://api.example.com，不带尾斜杠也可）
    #[serde(default)]
    pub base_url: String,

    /// CC Test 透传上游 api_key（同时用作 x-api-key 和 Authorization: Bearer）
    #[serde(default)]
    pub api_key: String,
}

/// KNA 应用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_region")]
    pub region: String,

    /// Auth Region（用于 Token 刷新），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_region: Option<String>,

    /// API Region（用于 API 请求），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_region: Option<String>,

    #[serde(default = "default_kiro_version")]
    pub kiro_version: String,

    #[serde(default)]
    pub machine_id: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_system_version")]
    pub system_version: String,

    #[serde(default = "default_node_version")]
    pub node_version: String,

    #[serde(default = "default_tls_backend")]
    pub tls_backend: TlsBackend,

    /// 外部 count_tokens API 地址（可选）
    #[serde(default)]
    pub count_tokens_api_url: Option<String>,

    /// count_tokens API 密钥（可选）
    #[serde(default)]
    pub count_tokens_api_key: Option<String>,

    /// count_tokens API 认证类型（可选，"x-api-key" 或 "bearer"，默认 "x-api-key"）
    #[serde(default = "default_count_tokens_auth_type")]
    pub count_tokens_auth_type: String,

    /// HTTP 代理地址（可选）
    /// 支持格式: http://host:port, https://host:port, socks5://host:port
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// 代理认证用户名（可选）
    #[serde(default)]
    pub proxy_username: Option<String>,

    /// 代理认证密码（可选）
    #[serde(default)]
    pub proxy_password: Option<String>,

    /// Admin API 密钥（可选，启用 Admin API 功能）
    #[serde(default)]
    pub admin_api_key: Option<String>,

    /// 负载均衡模式（"priority" 或 "balanced"）
    #[serde(default = "default_load_balancing_mode")]
    pub load_balancing_mode: String,

    /// 全局默认 RPM 上限（每分钟最大请求数）
    ///
    /// 凭据未单独配置 `rpm` 时沿用此值。`None` 或 `0` = 不限制。
    #[serde(default)]
    pub default_rpm: Option<u32>,

    /// 破甲模式：去除/绕过 Kiro 上游自带系统提示词与身份痕迹（默认 false = 最小满分版）
    ///
    /// 运行时可经 Admin API `/config/armor-breaking` 热切换。关闭时网关只保留
    /// HVOY/API-CHECK 检测兼容能力，对正常客户请求行为等价于未破甲基线；
    /// 开启时才注入身份合约、隐藏上游痕迹等破甲逻辑。
    #[serde(default = "default_armor_breaking")]
    pub armor_breaking: bool,

    /// 超额放行全局开关（默认 true = 开启）
    ///
    /// 运行时可经 Admin API `/config/overage-passthrough` 热切换。开启时，
    /// AWS 侧 `overageStatus=ENABLED` 的凭据在额度用尽（402 MONTHLY_REQUEST_COUNT
    /// 或余额耗尽）时走软冷却轮换、保持启用；关闭则回退到旧行为（永久禁用）。
    /// DISABLED/未知的凭据不受此开关影响，始终维持永久禁用。
    #[serde(default = "default_overage_passthrough")]
    pub overage_passthrough: bool,

    /// PRO+ 账号级代理门禁（默认开启）。
    ///
    /// 开启时，KIRO PRO+ 必须绑定有效的账号级代理才能启用；关闭时回到旧逻辑。
    #[serde(default = "default_require_pro_plus_credential_proxy")]
    pub require_pro_plus_credential_proxy: bool,

    /// 自动代理池中单个代理允许绑定的最大账号数（默认 2）。
    #[serde(default = "default_max_accounts_per_proxy")]
    pub max_accounts_per_proxy: usize,

    /// CC Test 检测请求透传配置（默认关闭）
    ///
    /// 运行时可经 Admin API `/config/max-relay` 热切换。开启后只有 CC Test 检测探针
    /// 会原样转发到配置的上游渠道；其它请求仍走本机 Kiro。
    #[serde(default)]
    pub max_relay: MaxRelayConfig,

    /// 是否开启非流式响应的 thinking 块提取（默认 true）
    ///
    /// 启用后，非流式响应中的 `<thinking>...</thinking>` 标签会被解析为
    /// 独立的 `{"type": "thinking", ...}` 内容块,与流式响应行为一致。
    #[serde(default = "default_extract_thinking")]
    pub extract_thinking: bool,

    /// 默认端点名称（凭据未显式指定 endpoint 时使用，默认 "ide"）
    #[serde(default = "default_endpoint")]
    pub default_endpoint: String,

    /// 端点特定的配置
    ///
    /// 键为端点名（如 "ide" / "cli"），值为该端点自由定义的参数对象。
    /// 未在此表出现的端点沿用实现内置默认值。
    #[serde(default)]
    pub endpoints: HashMap<String, serde_json::Value>,

    /// 配置文件路径（运行时元数据，不写入 JSON）
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_kiro_version() -> String {
    // 上游对客户端版本号设了准入门槛（KiroIDE ≥ 0.12.155），低版本会被拒 403
    "0.12.155".to_string()
}

fn default_system_version() -> String {
    const SYSTEM_VERSIONS: &[&str] = &["darwin#24.6.0", "win32#10.0.22631"];
    SYSTEM_VERSIONS[fastrand::usize(..SYSTEM_VERSIONS.len())].to_string()
}

fn default_node_version() -> String {
    "22.22.0".to_string()
}

fn default_count_tokens_auth_type() -> String {
    "x-api-key".to_string()
}

fn default_tls_backend() -> TlsBackend {
    TlsBackend::Rustls
}

fn default_load_balancing_mode() -> String {
    "priority".to_string()
}

fn default_armor_breaking() -> bool {
    false
}

fn default_overage_passthrough() -> bool {
    true
}

fn default_require_pro_plus_credential_proxy() -> bool {
    true
}

fn default_max_accounts_per_proxy() -> usize {
    2
}

fn default_extract_thinking() -> bool {
    true
}

fn default_endpoint() -> String {
    crate::kiro::endpoint::ide::IDE_ENDPOINT_NAME.to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            region: default_region(),
            auth_region: None,
            api_region: None,
            kiro_version: default_kiro_version(),
            machine_id: None,
            api_key: None,
            system_version: default_system_version(),
            node_version: default_node_version(),
            tls_backend: default_tls_backend(),
            count_tokens_api_url: None,
            count_tokens_api_key: None,
            count_tokens_auth_type: default_count_tokens_auth_type(),
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            admin_api_key: None,
            load_balancing_mode: default_load_balancing_mode(),
            default_rpm: None,
            armor_breaking: default_armor_breaking(),
            overage_passthrough: default_overage_passthrough(),
            require_pro_plus_credential_proxy: default_require_pro_plus_credential_proxy(),
            max_accounts_per_proxy: default_max_accounts_per_proxy(),
            max_relay: MaxRelayConfig::default(),
            extract_thinking: default_extract_thinking(),
            default_endpoint: default_endpoint(),
            endpoints: HashMap::new(),
            config_path: None,
        }
    }
}

impl Config {
    /// 获取默认配置文件路径
    pub fn default_config_path() -> &'static str {
        "config.json"
    }

    /// 获取有效的 Auth Region（用于 Token 刷新）
    /// 优先使用 auth_region，未配置时回退到 region
    pub fn effective_auth_region(&self) -> &str {
        self.auth_region.as_deref().unwrap_or(&self.region)
    }

    /// 获取有效的 API Region（用于 API 请求）
    /// 优先使用 api_region，未配置时回退到 region
    pub fn effective_api_region(&self) -> &str {
        self.api_region.as_deref().unwrap_or(&self.region)
    }

    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            // 配置文件不存在，返回默认配置
            let mut config = Self::default();
            config.config_path = Some(path.to_path_buf());
            return Ok(config);
        }

        let content = fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&content)?;
        if config.max_accounts_per_proxy == 0 {
            anyhow::bail!("maxAccountsPerProxy 必须大于 0");
        }
        config.config_path = Some(path.to_path_buf());
        Ok(config)
    }

    /// 获取配置文件路径（如果有）
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// 将当前配置写回原始配置文件
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self
            .config_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("配置文件路径未知，无法保存配置"))?;

        let content = serde_json::to_string_pretty(self).context("序列化配置失败")?;
        let temp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
        fs::write(&temp_path, content)
            .with_context(|| format!("写入临时配置文件失败: {}", temp_path.display()))?;
        if let Ok(metadata) = fs::metadata(path) {
            fs::set_permissions(&temp_path, metadata.permissions())
                .with_context(|| format!("继承配置文件权限失败: {}", temp_path.display()))?;
        }
        if let Err(error) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error).with_context(|| format!("原子替换配置文件失败: {}", path.display()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pro_plus_proxy_gate_defaults_to_enabled_with_two_accounts_per_proxy() {
        let config = Config::default();

        assert!(config.require_pro_plus_credential_proxy);
        assert_eq!(config.max_accounts_per_proxy, 2);
    }

    #[test]
    fn missing_pro_plus_proxy_gate_fields_use_safe_defaults() {
        let config: Config = serde_json::from_value(serde_json::json!({})).unwrap();

        assert!(config.require_pro_plus_credential_proxy);
        assert_eq!(config.max_accounts_per_proxy, 2);
    }

    #[test]
    fn config_load_rejects_zero_accounts_per_proxy() {
        let path = std::env::temp_dir().join(format!(
            "kiro-invalid-proxy-capacity-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, r#"{"maxAccountsPerProxy":0}"#).unwrap();

        let error = Config::load(&path).unwrap_err();
        assert!(error.to_string().contains("maxAccountsPerProxy 必须大于 0"));

        std::fs::remove_file(path).unwrap();
    }
}
