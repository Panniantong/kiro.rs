//! Token 计算模块
//!
//! 提供文本 token 数量计算功能。
//!
//! # 计算规则
//! - 非西文字符：每个计 4.5 个字符单位
//! - 西文字符：每个计 1 个字符单位
//! - 4 个字符单位 = 1 token（四舍五入）

use crate::anthropic::types::{
    CountTokensRequest, CountTokensResponse, Message, SystemMessage, Tool,
};
use crate::http_client::{ProxyConfig, build_client};
use crate::model::config::TlsBackend;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use std::sync::OnceLock;

/// Count Tokens API 配置
#[derive(Clone, Default)]
pub struct CountTokensConfig {
    /// 外部 count_tokens API 地址
    pub api_url: Option<String>,
    /// count_tokens API 密钥
    pub api_key: Option<String>,
    /// count_tokens API 认证类型（"x-api-key" 或 "bearer"）
    pub auth_type: String,
    /// 代理配置
    pub proxy: Option<ProxyConfig>,

    pub tls_backend: TlsBackend,
}

/// 全局配置存储
static COUNT_TOKENS_CONFIG: OnceLock<CountTokensConfig> = OnceLock::new();

/// 初始化 count_tokens 配置
///
/// 应在应用启动时调用一次
pub fn init_config(config: CountTokensConfig) {
    let _ = COUNT_TOKENS_CONFIG.set(config);
}

/// 获取配置
fn get_config() -> Option<&'static CountTokensConfig> {
    COUNT_TOKENS_CONFIG.get()
}

/// 判断字符是否为非西文字符
///
/// 西文字符包括：
/// - ASCII 字符 (U+0000..U+007F)
/// - 拉丁字母扩展 (U+0080..U+024F)
/// - 拉丁字母扩展附加 (U+1E00..U+1EFF)
///
/// 返回 true 表示该字符是非西文字符（如中文、日文、韩文、阿拉伯文等）
fn is_non_western_char(c: char) -> bool {
    !matches!(c,
        // 基本 ASCII
        '\u{0000}'..='\u{007F}' |
        // 拉丁字母扩展-A (Latin Extended-A)
        '\u{0080}'..='\u{00FF}' |
        // 拉丁字母扩展-B (Latin Extended-B)
        '\u{0100}'..='\u{024F}' |
        // 拉丁字母扩展附加 (Latin Extended Additional)
        '\u{1E00}'..='\u{1EFF}' |
        // 拉丁字母扩展-C/D/E
        '\u{2C60}'..='\u{2C7F}' |
        '\u{A720}'..='\u{A7FF}' |
        '\u{AB30}'..='\u{AB6F}'
    )
}

/// 计算文本的 token 数量
///
/// # 计算规则
/// - 非西文字符：每个计 4.5 个字符单位
/// - 西文字符：每个计 1 个字符单位
/// - 4 个字符单位 = 1 token（四舍五入）
/// ```
pub fn count_tokens(text: &str) -> u64 {
    // println!("text: {}", text);

    let char_units: f64 = text
        .chars()
        .map(|c| if is_non_western_char(c) { 4.0 } else { 1.0 })
        .sum();

    let tokens = char_units / 4.0;

    let acc_token = if tokens < 100.0 {
        tokens * 1.5
    } else if tokens < 200.0 {
        tokens * 1.3
    } else if tokens < 300.0 {
        tokens * 1.25
    } else if tokens < 800.0 {
        tokens * 1.2
    } else {
        tokens * 1.0
    } as u64;

    // println!("tokens: {}, acc_tokens: {}", tokens, acc_token);
    acc_token
}

/// 估算请求的输入 tokens
///
/// 优先调用远程 API，失败时回退到本地计算
pub(crate) fn count_all_tokens(
    model: String,
    system: Option<Vec<SystemMessage>>,
    messages: Vec<Message>,
    tools: Option<Vec<Tool>>,
) -> u64 {
    // 检查是否配置了远程 API
    if let Some(config) = get_config() {
        if let Some(api_url) = &config.api_url {
            // 尝试调用远程 API
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(call_remote_count_tokens(
                    api_url, config, model, &system, &messages, &tools,
                ))
            });

            match result {
                Ok(tokens) => {
                    tracing::debug!("远程 count_tokens API 返回: {}", tokens);
                    return tokens;
                }
                Err(e) => {
                    tracing::warn!("远程 count_tokens API 调用失败，回退到本地计算: {}", e);
                }
            }
        }
    }

    // 本地计算
    count_all_tokens_local(system, messages, tools)
}

/// 调用远程 count_tokens API
async fn call_remote_count_tokens(
    api_url: &str,
    config: &CountTokensConfig,
    model: String,
    system: &Option<Vec<SystemMessage>>,
    messages: &Vec<Message>,
    tools: &Option<Vec<Tool>>,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let client = build_client(config.proxy.as_ref(), 300, config.tls_backend)?;

    // 构建请求体
    let request = CountTokensRequest {
        model: model, // 模型名称用于 token 计算
        messages: messages.clone(),
        system: system.clone(),
        tools: tools.clone(),
    };

    // 构建请求
    let mut req_builder = client.post(api_url);

    // 设置认证头
    if let Some(api_key) = &config.api_key {
        if config.auth_type == "bearer" {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", api_key));
        } else {
            req_builder = req_builder.header("x-api-key", api_key);
        }
    }

    // 发送请求
    let response = req_builder
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("API 返回错误状态: {}", response.status()).into());
    }

    let result: CountTokensResponse = response.json().await?;
    Ok(result.input_tokens as u64)
}

/// 本地计算请求的输入 tokens
fn count_all_tokens_local(
    system: Option<Vec<SystemMessage>>,
    messages: Vec<Message>,
    tools: Option<Vec<Tool>>,
) -> u64 {
    let mut total = 0;

    // 系统消息
    if let Some(ref system) = system {
        for msg in system {
            total += count_tokens(&msg.text);
        }
    }

    // 用户消息
    for msg in &messages {
        if let serde_json::Value::String(s) = &msg.content {
            total += count_tokens(s);
        } else if let serde_json::Value::Array(arr) = &msg.content {
            for item in arr {
                if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                    total += count_tokens(text);
                }
                total += estimate_visual_tokens(item);
            }
        }
    }

    // 工具定义
    if let Some(ref tools) = tools {
        for tool in tools {
            total += count_tokens(&tool.name);
            total += count_tokens(&tool.description);
            let input_schema_json = serde_json::to_string(&tool.input_schema).unwrap_or_default();
            total += count_tokens(&input_schema_json);
        }
    }

    total.max(1)
}

fn estimate_visual_tokens(block: &serde_json::Value) -> u64 {
    if block.get("type").and_then(|v| v.as_str()) == Some("tool_result") {
        return match block.get("content") {
            Some(serde_json::Value::Array(items)) => items.iter().map(estimate_visual_tokens).sum(),
            Some(item @ serde_json::Value::Object(_)) => estimate_visual_tokens(item),
            _ => 0,
        };
    }

    let Some(bytes) = inline_image_bytes(block) else {
        return 0;
    };
    let Some((width, height)) = image_dimensions(&bytes) else {
        return 0;
    };
    visual_tokens_for_dimensions(width, height)
}

fn inline_image_bytes(block: &serde_json::Value) -> Option<Vec<u8>> {
    if let Some(source) = block.get("source").and_then(|v| v.as_object()) {
        let media_type = source
            .get("media_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let data = source.get("data").and_then(|v| v.as_str())?;
        if media_type.starts_with("image/") {
            return BASE64_STANDARD.decode(data).ok();
        }
        if media_type == "application/pdf" {
            let (_, image_data) = crate::anthropic::converter::extract_pdf_image(media_type, data)?;
            return BASE64_STANDARD.decode(image_data).ok();
        }
    }

    let image_url = match block.get("image_url") {
        Some(serde_json::Value::String(url)) => Some(url.as_str()),
        Some(serde_json::Value::Object(map)) => map.get("url").and_then(|v| v.as_str()),
        _ => None,
    }?;
    if let Some(data) = image_url.strip_prefix("data:application/pdf;base64,") {
        let (_, image_data) =
            crate::anthropic::converter::extract_pdf_image("application/pdf", data)?;
        return BASE64_STANDARD.decode(image_data).ok();
    }
    let rest = image_url.strip_prefix("data:image/")?;
    let (_, data) = rest.split_once(',')?;
    BASE64_STANDARD.decode(data).ok()
}

fn image_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() >= 24 {
        return Some((
            u32::from_be_bytes(bytes[16..20].try_into().ok()?),
            u32::from_be_bytes(bytes[20..24].try_into().ok()?),
        ));
    }
    if (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) && bytes.len() >= 10 {
        return Some((
            u32::from(u16::from_le_bytes(bytes[6..8].try_into().ok()?)),
            u32::from(u16::from_le_bytes(bytes[8..10].try_into().ok()?)),
        ));
    }
    if bytes.starts_with(b"RIFF")
        && bytes.get(8..12) == Some(b"WEBP")
        && bytes.get(12..16) == Some(b"VP8X")
        && bytes.len() >= 30
    {
        let width =
            1 + u32::from(bytes[24]) + (u32::from(bytes[25]) << 8) + (u32::from(bytes[26]) << 16);
        let height =
            1 + u32::from(bytes[27]) + (u32::from(bytes[28]) << 8) + (u32::from(bytes[29]) << 16);
        return Some((width, height));
    }
    jpeg_dimensions(bytes)
}

fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut cursor = 2usize;
    while cursor + 4 <= bytes.len() {
        while bytes.get(cursor) == Some(&0xff) {
            cursor += 1;
        }
        let marker = *bytes.get(cursor)?;
        cursor += 1;
        if marker == 0xd8 || marker == 0xd9 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = usize::from(u16::from_be_bytes(
            bytes.get(cursor..cursor + 2)?.try_into().ok()?,
        ));
        if length < 2 || cursor + length > bytes.len() {
            return None;
        }
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            let height = u32::from(u16::from_be_bytes(
                bytes.get(cursor + 3..cursor + 5)?.try_into().ok()?,
            ));
            let width = u32::from(u16::from_be_bytes(
                bytes.get(cursor + 5..cursor + 7)?.try_into().ok()?,
            ));
            return (width > 0 && height > 0).then_some((width, height));
        }
        cursor += length;
    }
    None
}

fn visual_tokens_for_dimensions(width: u32, height: u32) -> u64 {
    if width == 0 || height == 0 {
        return 0;
    }
    let width = f64::from(width);
    let height = f64::from(height);
    let long_edge_scale = 1568.0 / width.max(height);
    let area_scale = (1_150_000.0 / (width * height)).sqrt();
    let scale = 1.0_f64.min(long_edge_scale).min(area_scale);
    let resized_area = (width * scale).round() * (height * scale).round();
    (resized_area / 750.0).ceil().max(1.0) as u64
}

/// 估算输出 tokens
pub(crate) fn estimate_output_tokens(content: &[serde_json::Value]) -> i32 {
    let mut total = 0;

    for block in content {
        if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
            total += count_tokens(text) as i32;
        }
        if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
            // 工具调用开销
            if let Some(input) = block.get("input") {
                let input_str = serde_json::to_string(input).unwrap_or_default();
                total += count_tokens(&input_str) as i32;
            }
        }
    }

    total.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    #[test]
    fn image_input_tokens_are_based_on_dimensions_not_base64_bytes() {
        let jpeg = vec![
            0xff, 0xd8, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x01, 0x66, 0x06, 0x34, 0x01, 0x01, 0x11,
            0x00, 0xff, 0xd9,
        ];
        let messages = vec![Message {
            role: "user".to_string(),
            content: serde_json::json!([
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": BASE64_STANDARD.encode(jpeg)
                    }
                },
                {"type": "text", "text": "describe it"}
            ]),
        }];

        let tokens = count_all_tokens_local(None, messages, None);

        assert!(
            (700..=800).contains(&tokens),
            "unexpected visual token estimate: {tokens}"
        );
    }

    #[test]
    fn image_pdf_input_tokens_use_the_embedded_image_dimensions() {
        let jpeg = vec![
            0xff, 0xd8, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x01, 0x66, 0x06, 0x34, 0x01, 0x01, 0x11,
            0x00, 0xff, 0xd9,
        ];
        let mut pdf = format!(
            "%PDF-1.3\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 1588 /Height 358 /Length {} /Filter /DCTDecode >>\nstream\n",
            jpeg.len()
        )
        .into_bytes();
        pdf.extend_from_slice(&jpeg);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
        let messages = vec![Message {
            role: "user".to_string(),
            content: serde_json::json!([
                {
                    "type": "image_url",
                    "image_url": {
                        "url": format!("data:application/pdf;base64,{}", BASE64_STANDARD.encode(pdf))
                    }
                },
                {"type": "text", "text": "describe it"}
            ]),
        }];

        let tokens = count_all_tokens_local(None, messages, None);

        assert!(
            (700..=800).contains(&tokens),
            "unexpected PDF visual token estimate: {tokens}"
        );
    }

    #[test]
    fn webp_image_dimensions_are_tokenized() {
        let mut webp = vec![0u8; 30];
        webp[0..4].copy_from_slice(b"RIFF");
        webp[8..12].copy_from_slice(b"WEBP");
        webp[12..16].copy_from_slice(b"VP8X");
        webp[24..27].copy_from_slice(&[0xe7, 0x03, 0x00]);
        webp[27..30].copy_from_slice(&[0xf3, 0x01, 0x00]);

        assert_eq!(image_dimensions(&webp), Some((1000, 500)));
        assert!(visual_tokens_for_dimensions(1000, 500) > 0);
    }
}
