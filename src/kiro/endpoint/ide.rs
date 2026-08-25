//! Kiro IDE 端点
//!
//! 对应 Kiro IDE 客户端目前使用的 AWS CodeWhisperer 端点：
//! - API: `https://q.{api_region}.amazonaws.com/generateAssistantResponse`
//! - MCP: `https://q.{api_region}.amazonaws.com/mcp`
//!
//! 请求头使用 aws-sdk-js User-Agent 标识。请求体会在根对象上注入 `profileArn`。

use reqwest::RequestBuilder;
use uuid::Uuid;

use super::{KiroEndpoint, RequestContext};

/// Kiro IDE 端点名称
pub const IDE_ENDPOINT_NAME: &str = "ide";

/// Kiro IDE 端点
pub struct IdeEndpoint;

impl IdeEndpoint {
    pub fn new() -> Self {
        Self
    }

    fn api_region<'a>(&self, ctx: &'a RequestContext<'_>) -> &'a str {
        ctx.credentials.effective_api_region(ctx.config)
    }

    fn host(&self, ctx: &RequestContext<'_>) -> String {
        format!("q.{}.amazonaws.com", self.api_region(ctx))
    }

    fn x_amz_user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-js/1.0.34 KiroIDE-{}-{}",
            ctx.config.kiro_version, ctx.machine_id
        )
    }

    fn user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-js/1.0.34 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#1.0.34 m/E KiroIDE-{}-{}",
            ctx.config.system_version,
            ctx.config.node_version,
            ctx.config.kiro_version,
            ctx.machine_id
        )
    }
}

impl Default for IdeEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroEndpoint for IdeEndpoint {
    fn name(&self) -> &'static str {
        IDE_ENDPOINT_NAME
    }

    fn api_url(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "https://q.{}.amazonaws.com/generateAssistantResponse",
            self.api_region(ctx)
        )
    }

    fn mcp_url(&self, ctx: &RequestContext<'_>) -> String {
        format!("https://q.{}.amazonaws.com/mcp", self.api_region(ctx))
    }

    fn decorate_api(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amzn-codewhisperer-optout", "true")
            .header("x-amzn-kiro-agent-mode", "vibe")
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        }
        req
    }

    fn decorate_mcp(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        // profileArn 必填（Builder ID / 社交 / IdC）；API Key 账号返回 None 不注入。
        if let Some(arn) = crate::kiro::model::credentials::effective_profile_arn(ctx.credentials)
        {
            req = req.header("x-amzn-kiro-profile-arn", arn);
        }
        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        }
        req
    }

    fn transform_api_body(&self, body: &str, ctx: &RequestContext<'_>) -> String {
        inject_profile_arn(body, &ctx.credentials.profile_arn, ctx.credentials)
    }
}

/// 将 profile_arn 注入到请求体 JSON 根对象。
/// 优先用账号存的有效 ARN；没存则按登录方式补占位符（Builder ID / 社交）；
/// API Key 账号不注入（上游对它的准入口径不同）。
fn inject_profile_arn(
    request_body: &str,
    stored_profile_arn: &Option<String>,
    credentials: &crate::kiro::model::credentials::KiroCredentials,
) -> String {
    let arn = crate::kiro::model::credentials::effective_profile_arn(credentials)
        .or_else(|| stored_profile_arn.clone());
    let Some(arn) = arn else {
        return request_body.to_string();
    };
    if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(request_body) {
        json["profileArn"] = serde_json::Value::String(arn);
        if let Ok(body) = serde_json::to_string(&json) {
            return body;
        }
    }
    request_body.to_string()
}

#[cfg(test)]
mod tests {
    use super::inject_profile_arn;
    use crate::kiro::model::credentials::KiroCredentials;
    use serde_json::Value;

    fn make_credentials(auth_method: Option<&str>, profile_arn: Option<&str>) -> KiroCredentials {
        let mut c = KiroCredentials::default();
        c.auth_method = auth_method.map(|s| s.to_string());
        c.profile_arn = profile_arn.map(|s| s.to_string());
        c
    }

    #[test]
    fn test_inject_profile_arn_with_some() {
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let creds = make_credentials(
            Some("social"),
            Some("arn:aws:codewhisperer:us-east-1:123:profile/ABC"),
        );
        let result = inject_profile_arn(body, &creds.profile_arn, &creds);
        let json: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            json["profileArn"],
            "arn:aws:codewhisperer:us-east-1:123:profile/ABC"
        );
        assert_eq!(json["conversationState"]["conversationId"], "c1");
    }

    #[test]
    fn test_inject_profile_arn_api_key_not_injected() {
        // API Key 账号没有 profile 概念，不注入（上游对它的准入口径不同）
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let creds = make_credentials(Some("api_key"), None);
        let result = inject_profile_arn(body, &creds.profile_arn, &creds);
        let json: Value = serde_json::from_str(&result).unwrap();
        assert!(json.get("profileArn").is_none());
    }

    #[test]
    fn test_inject_profile_arn_social_fallback() {
        // 社交账号未存 ARN 时补社交固定占位符
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let creds = make_credentials(Some("social"), None);
        let result = inject_profile_arn(body, &creds.profile_arn, &creds);
        let json: Value = serde_json::from_str(&result).unwrap();
        assert!(json["profileArn"].as_str().unwrap().contains("codewhisperer"));
    }

    #[test]
    fn test_inject_profile_arn_builder_fallback() {
        // Builder ID / 未知账号未存 ARN 时补 Builder ID 占位符
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let creds = make_credentials(Some("builder-id"), None);
        let result = inject_profile_arn(body, &creds.profile_arn, &creds);
        let json: Value = serde_json::from_str(&result).unwrap();
        assert!(json["profileArn"]
            .as_str()
            .unwrap()
            .contains("638616132270"));
    }

    #[test]
    fn test_inject_profile_arn_overwrites_existing() {
        let body = r#"{"conversationState":{},"profileArn":"old-arn"}"#;
        let creds = make_credentials(Some("social"), Some("new-arn"));
        let result = inject_profile_arn(body, &creds.profile_arn, &creds);
        let json: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["profileArn"], "new-arn");
    }

    #[test]
    fn test_inject_profile_arn_invalid_json() {
        let body = "not-valid-json";
        let creds = make_credentials(Some("social"), Some("arn:test"));
        let result = inject_profile_arn(body, &creds.profile_arn, &creds);
        assert_eq!(result, "not-valid-json");
    }
}
