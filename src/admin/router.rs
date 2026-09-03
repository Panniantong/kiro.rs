//! Admin API 路由配置

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};

use super::{
    handlers::{
        add_credential, batch_set_credential_rpm, delete_credential, force_refresh_token,
        get_all_credentials, get_armor_breaking, get_credential_balance, get_credential_logs,
        get_default_rpm, get_load_balancing_mode, get_max_relay, get_overage_passthrough,
        reset_failure_count, search_log_accounts, set_armor_breaking, set_credential_disabled,
        set_credential_priority, set_credential_rpm, set_default_rpm, set_load_balancing_mode,
        set_max_relay, set_overage_passthrough,
    },
    middleware::{admin_auth_middleware, AdminState},
};

/// 创建 Admin API 路由
///
/// # 端点
/// - `GET /credentials` - 获取所有凭据状态
/// - `POST /credentials` - 添加新凭据
/// - `DELETE /credentials/:id` - 删除凭据
/// - `POST /credentials/:id/disabled` - 设置凭据禁用状态
/// - `POST /credentials/:id/priority` - 设置凭据优先级
/// - `POST /credentials/:id/reset` - 重置失败计数
/// - `POST /credentials/:id/refresh` - 强制刷新 Token
/// - `GET /credentials/:id/balance` - 获取凭据余额
/// - `GET /logs/accounts` - 搜索日志账号
/// - `GET /credentials/:id/logs` - 查询账号日志（最多 100 条/页）
/// - `GET /config/load-balancing` - 获取负载均衡模式
/// - `PUT /config/load-balancing` - 设置负载均衡模式
///
/// # 认证
/// 需要 Admin API Key 认证，支持：
/// - `x-api-key` header
/// - `Authorization: Bearer <token>` header
pub fn create_admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/logs/accounts", get(search_log_accounts))
        .route(
            "/credentials",
            get(get_all_credentials).post(add_credential),
        )
        .route("/credentials/{id}", delete(delete_credential))
        .route("/credentials/{id}/logs", get(get_credential_logs))
        .route("/credentials/{id}/disabled", post(set_credential_disabled))
        .route("/credentials/{id}/priority", post(set_credential_priority))
        .route("/credentials/{id}/reset", post(reset_failure_count))
        .route("/credentials/{id}/refresh", post(force_refresh_token))
        .route("/credentials/{id}/balance", get(get_credential_balance))
        .route("/credentials/{id}/rpm", post(set_credential_rpm))
        .route("/credentials/batch-rpm", post(batch_set_credential_rpm))
        .route(
            "/config/load-balancing",
            get(get_load_balancing_mode).put(set_load_balancing_mode),
        )
        .route(
            "/config/default-rpm",
            get(get_default_rpm).put(set_default_rpm),
        )
        .route(
            "/config/armor-breaking",
            get(get_armor_breaking).put(set_armor_breaking),
        )
        .route("/config/max-relay", get(get_max_relay).put(set_max_relay))
        .route(
            "/config/overage-passthrough",
            get(get_overage_passthrough).put(set_overage_passthrough),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .with_state(state)
}
