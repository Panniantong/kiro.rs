//! Admin API HTTP 处理器

use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};

use super::{
    middleware::AdminState,
    types::{
        AddCredentialRequest, BatchSetRpmRequest, SetArmorBreakingRequest, SetDefaultRpmRequest,
        SetDisabledRequest, SetLoadBalancingModeRequest, SetMaxRelayRequest, SetPriorityRequest,
        SetRpmRequest, SuccessResponse,
    },
};

/// GET /api/admin/credentials
/// 获取所有凭据状态
pub async fn get_all_credentials(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_all_credentials();
    Json(response)
}

/// POST /api/admin/credentials/:id/disabled
/// 设置凭据禁用状态
pub async fn set_credential_disabled(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetDisabledRequest>,
) -> impl IntoResponse {
    match state.service.set_disabled(id, payload.disabled) {
        Ok(_) => {
            let action = if payload.disabled { "禁用" } else { "启用" };
            Json(SuccessResponse::new(format!("凭据 #{} 已{}", id, action))).into_response()
        }
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/priority
/// 设置凭据优先级
pub async fn set_credential_priority(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetPriorityRequest>,
) -> impl IntoResponse {
    match state.service.set_priority(id, payload.priority) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 优先级已设置为 {}",
            id, payload.priority
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/reset
/// 重置失败计数并重新启用
pub async fn reset_failure_count(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.reset_and_enable(id) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 失败计数已重置并重新启用",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/credentials/:id/balance
/// 获取指定凭据的余额
pub async fn get_credential_balance(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.get_balance(id).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials
/// 添加新凭据
pub async fn add_credential(
    State(state): State<AdminState>,
    Json(payload): Json<AddCredentialRequest>,
) -> impl IntoResponse {
    match state.service.add_credential(payload).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// DELETE /api/admin/credentials/:id
/// 删除凭据
pub async fn delete_credential(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.delete_credential(id) {
        Ok(_) => Json(SuccessResponse::new(format!("凭据 #{} 已删除", id))).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/refresh
/// 强制刷新凭据 Token
pub async fn force_refresh_token(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.force_refresh_token(id).await {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} Token 已强制刷新",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/load-balancing
/// 获取负载均衡模式
pub async fn get_load_balancing_mode(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_load_balancing_mode();
    Json(response)
}

/// PUT /api/admin/config/load-balancing
/// 设置负载均衡模式
pub async fn set_load_balancing_mode(
    State(state): State<AdminState>,
    Json(payload): Json<SetLoadBalancingModeRequest>,
) -> impl IntoResponse {
    match state.service.set_load_balancing_mode(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/rpm
/// 设置单个凭据 RPM 上限（rpm=null 跟随全局默认；0 不限制）
pub async fn set_credential_rpm(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetRpmRequest>,
) -> impl IntoResponse {
    match state.service.set_rpm(id, payload.rpm) {
        Ok(_) => Json(SuccessResponse::new(format!("凭据 #{} RPM 已更新", id))).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/batch-rpm
/// 批量设置凭据 RPM 上限
pub async fn batch_set_credential_rpm(
    State(state): State<AdminState>,
    Json(payload): Json<BatchSetRpmRequest>,
) -> impl IntoResponse {
    match state.service.batch_set_rpm(&payload.ids, payload.rpm) {
        Ok(count) => Json(SuccessResponse::new(format!(
            "已更新 {} 个凭据的 RPM",
            count
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/default-rpm
/// 获取全局默认 RPM
pub async fn get_default_rpm(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_default_rpm())
}

/// PUT /api/admin/config/default-rpm
/// 设置全局默认 RPM
pub async fn set_default_rpm(
    State(state): State<AdminState>,
    Json(payload): Json<SetDefaultRpmRequest>,
) -> impl IntoResponse {
    match state.service.set_default_rpm(payload.default_rpm) {
        Ok(_) => Json(SuccessResponse::new("全局默认 RPM 已更新")).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/armor-breaking
/// 获取破甲模式
pub async fn get_armor_breaking(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_armor_breaking();
    Json(response)
}

/// PUT /api/admin/config/armor-breaking
/// 设置破甲模式
pub async fn set_armor_breaking(
    State(state): State<AdminState>,
    Json(payload): Json<SetArmorBreakingRequest>,
) -> impl IntoResponse {
    match state.service.set_armor_breaking(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/max-relay
/// 获取 CC Test 透传配置
pub async fn get_max_relay(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_max_relay();
    Json(response)
}

/// PUT /api/admin/config/max-relay
/// 设置 CC Test 透传配置
pub async fn set_max_relay(
    State(state): State<AdminState>,
    Json(payload): Json<SetMaxRelayRequest>,
) -> impl IntoResponse {
    match state.service.set_max_relay(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}
