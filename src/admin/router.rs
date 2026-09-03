//! Admin API 路由配置

use axum::{
    Router, middleware,
    routing::{delete, get, post},
};

use super::{
    handlers::{
        add_credential, add_proxy_pool_entries, assign_credential_proxy_from_pool, batch_balance,
        batch_set_credential_proxy, batch_set_credential_rpm, batch_test_credential_proxy,
        batch_update_credentials, delete_credential, force_refresh_token, get_all_credentials,
        get_armor_breaking, get_credential_balance, get_default_rpm, get_load_balancing_mode,
        get_max_relay, get_overage_passthrough, get_pro_plus_proxy_gate, get_proxy_pool,
        manual_bind_proxy, manual_unbind_proxy, recover_quota_retired, remove_proxy_pool_entries,
        reset_failure_count, set_armor_breaking, set_credential_disabled, set_credential_priority,
        set_credential_proxy, set_credential_rpm, set_default_rpm, set_load_balancing_mode,
        set_max_relay, set_overage_passthrough, set_pro_plus_proxy_gate, test_credential_proxy,
        test_proxy_pool_entry,
    },
    middleware::{AdminState, admin_auth_middleware},
};

/// 创建 Admin API 路由
///
/// # 端点
/// - `GET /credentials` - 获取所有凭据状态
/// - `POST /credentials` - 添加新凭据
/// - `DELETE /credentials/:id` - 删除凭据
/// - `POST /credentials/:id/disabled` - 设置凭据禁用状态
/// - `POST /credentials/:id/priority` - 设置凭据优先级
/// - `POST /credentials/:id/proxy` - 绑定、清除或显式直连账号代理
/// - `POST /credentials/batch-proxy` - 将同一代理批量绑定给多个账号
/// - `POST /credentials/assign-proxy-from-pool` - 为现有未绑定账号按池规则补绑代理
/// - `GET|POST|DELETE /proxy-pool` - 自动分配代理池（单 IP 容量可配置）
/// - `POST /credentials/:id/proxy/test` - 测试账号实际出口 IP
/// - `POST /credentials/batch-proxy/test` - 批量测试账号出口 IP
/// - `POST /credentials/:id/reset` - 重置失败计数
/// - `POST /credentials/:id/refresh` - 强制刷新 Token
/// - `GET /credentials/:id/balance` - 获取凭据余额
/// - `GET /config/load-balancing` - 获取负载均衡模式
/// - `PUT /config/load-balancing` - 设置负载均衡模式
///
/// # 认证
/// 需要 Admin API Key 认证，支持：
/// - `x-api-key` header
/// - `Authorization: Bearer <token>` header
pub fn create_admin_router(state: AdminState) -> Router {
    Router::new()
        .route(
            "/credentials",
            get(get_all_credentials).post(add_credential),
        )
        .route("/credentials/{id}", delete(delete_credential))
        .route("/credentials/{id}/disabled", post(set_credential_disabled))
        .route("/credentials/{id}/priority", post(set_credential_priority))
        .route("/credentials/{id}/proxy", post(set_credential_proxy))
        .route("/credentials/batch-proxy", post(batch_set_credential_proxy))
        .route(
            "/credentials/assign-proxy-from-pool",
            post(assign_credential_proxy_from_pool),
        )
        .route(
            "/proxy-pool",
            get(get_proxy_pool)
                .post(add_proxy_pool_entries)
                .delete(remove_proxy_pool_entries),
        )
        .route("/proxy-pool/test", post(test_proxy_pool_entry))
        .route("/credentials/{id}/proxy/test", post(test_credential_proxy))
        .route(
            "/credentials/batch-proxy/test",
            post(batch_test_credential_proxy),
        )
        .route("/credentials/{id}/reset", post(reset_failure_count))
        .route(
            "/credentials/batch-recover-quota-retired",
            post(recover_quota_retired),
        )
        .route("/credentials/{id}/refresh", post(force_refresh_token))
        .route("/credentials/{id}/balance", get(get_credential_balance))
        .route("/credentials/batch-balance", post(batch_balance))
        .route("/credentials/{id}/rpm", post(set_credential_rpm))
        .route("/credentials/batch-rpm", post(batch_set_credential_rpm))
        .route("/credentials/batch-update", post(batch_update_credentials))
        .route("/proxy-pool/bind", post(manual_bind_proxy))
        .route("/proxy-pool/unbind", post(manual_unbind_proxy))
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
        .route(
            "/config/pro-plus-proxy-gate",
            get(get_pro_plus_proxy_gate).put(set_pro_plus_proxy_gate),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .with_state(state)
}
