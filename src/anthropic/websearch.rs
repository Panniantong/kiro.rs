//! WebSearch 工具处理模块
//!
//! 实现 Anthropic WebSearch 请求到 Kiro MCP 的转换和响应生成

use std::convert::Infallible;

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use futures::{Stream, stream};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::stream::SseEvent;
use super::types::{ErrorResponse, MessagesRequest};

/// MCP 请求
#[derive(Debug, Serialize)]
pub struct McpRequest {
    pub id: String,
    pub jsonrpc: String,
    pub method: String,
    pub params: McpParams,
}

/// MCP 请求参数
#[derive(Debug, Serialize)]
pub struct McpParams {
    pub name: String,
    pub arguments: McpArguments,
}

/// MCP 参数
#[derive(Debug, Serialize)]
pub struct McpArguments {
    pub query: String,
}

/// MCP 响应
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpResponse {
    pub error: Option<McpError>,
    pub id: String,
    pub jsonrpc: String,
    pub result: Option<McpResult>,
}

/// MCP 错误
#[derive(Debug, Deserialize)]
pub struct McpError {
    pub code: Option<i32>,
    pub message: Option<String>,
}

/// MCP 结果
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpResult {
    pub content: Vec<McpContent>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

/// MCP 内容
#[derive(Debug, Deserialize)]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// WebSearch 搜索结果
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct WebSearchResults {
    pub results: Vec<WebSearchResult>,
    #[serde(rename = "totalResults")]
    pub total_results: Option<i32>,
    pub query: Option<String>,
    pub error: Option<String>,
}

/// 单个搜索结果
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct WebSearchResult {
    pub title: String,
    pub url: String,
    pub snippet: Option<String>,
    #[serde(rename = "publishedDate")]
    pub published_date: Option<i64>,
    pub id: Option<String>,
    pub domain: Option<String>,
    #[serde(rename = "maxVerbatimWordLimit")]
    pub max_verbatim_word_limit: Option<i32>,
    #[serde(rename = "publicDomain")]
    pub public_domain: Option<bool>,
}

/// 检查请求是否携带 WebSearch 工具
///
/// 条件：tools 中至少有一个 web_search 工具（`tool_type` 为 `web_search_*`
/// 或 `name` 为 `web_search`），允许与其他工具并存。
pub fn has_web_search_tool(req: &MessagesRequest) -> bool {
    req.tools
        .as_ref()
        .is_some_and(|tools| tools.iter().any(is_web_search_tool))
}

fn is_web_search_tool(tool: &super::types::Tool) -> bool {
    tool.tool_type
        .as_deref()
        .is_some_and(|ty| ty.starts_with("web_search"))
        || tool.name == "web_search"
}

/// 从消息中提取搜索查询
///
/// 遍历第一条（user）消息的所有文本内容块，取第一个非空文本，
/// 并去除 "Perform a web search for the query: " 前缀。
pub fn extract_search_query(req: &MessagesRequest) -> Option<String> {
    // 找到第一条 user 消息（没有则回退到第一条消息）
    let first_msg = req
        .messages
        .iter()
        .find(|m| m.role == "user")
        .or_else(|| req.messages.first())?;

    const PREFIX: &str = "Perform a web search for the query: ";

    // 纯字符串 content
    if let Some(s) = first_msg.content.as_str() {
        let text = s.trim();
        let query = text.strip_prefix(PREFIX).unwrap_or(text);
        if query.is_empty() {
            return None;
        }
        return Some(query.to_string());
    }

    // 内容块数组：取第一个非空 text 块
    if let Some(arr) = first_msg.content.as_array() {
        for block in arr {
            if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                    let text = text.trim();
                    if text.is_empty() {
                        continue;
                    }
                    let query = text.strip_prefix(PREFIX).unwrap_or(text);
                    return Some(query.to_string());
                }
            }
        }
    }

    None
}

/// 按真实抓包逐字节对齐的二进制布局构造 web_search 密文（base64）。
/// 布局（outer 消息体）：
///   f2 (message) = {
///       f1 (message, 42B) = { f1=19, f3=2, f4=响应级 UUID }   // 同一响应共享
///       f2 (message, 12B) = 随机                              // 定位/盐
///       f3 (message, 12B) = 随机
///       f4 (message, 48B) = 随机
///       f5 (bytes)         = 随机密文（结果长、引用短）
///   }
///   f3 (varint) = kind  // 3=搜索结果 encrypted_content, 4=引用 encrypted_index
/// 响应级 UUID 嵌在 f2.f1.f4，同一响应的所有密文共享，与真实样本一致。
fn web_search_blob_common(
    response_uuid: &str,
    index: u32,
    payload_len: usize,
    kind: u8,
) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn varint(mut v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return out;
            }
        }
    }
    // 把一个固定长度随机消息编码成 f1=bytes 的合法小消息（tag + len + 内容）
    fn fixed_msg(content_len: usize) -> Vec<u8> {
        let mut body = vec![0u8; content_len];
        fastrand::fill(&mut body);
        let mut out = Vec::with_capacity(content_len + 2);
        out.push(0x0a);
        out.extend_from_slice(&varint(content_len as u32));
        out.extend_from_slice(&body);
        out
    }

    // f1：响应级头 {f1=19, f3=2, f4=UUID}，42 字节
    let mut f1 = Vec::with_capacity(42);
    f1.extend_from_slice(&[0x08, 0x13]);
    f1.extend_from_slice(&[0x18, 0x02]);
    f1.push(0x22);
    f1.push(response_uuid.len() as u8);
    f1.extend_from_slice(response_uuid.as_bytes());

    // f2 / f3 / f4：固定 12/12/48 字节的随机消息
    let f2 = fixed_msg(10); // 2 字节头 + 10 = 12
    let f3 = fixed_msg(10);
    let f4 = fixed_msg(46); // 2 字节头 + 46 = 48

    // f5：随机密文载荷，混入序号使每条密文不同
    let mut f5 = vec![0u8; payload_len];
    fastrand::fill(&mut f5);
    for (i, b) in f5.iter_mut().take(4).enumerate() {
        *b = b.wrapping_add((index >> (i * 8)) as u8);
    }

    // 组装 f2 消息体（inner）：f1=头, f2/f3/f4=固定随机, f5=密文
    let mut inner = Vec::new();
    let mut push_field = |inner: &mut Vec<u8>, tag: u8, data: &[u8]| {
        inner.push(tag);
        inner.extend_from_slice(&varint(data.len() as u32));
        inner.extend_from_slice(data);
    };
    push_field(&mut inner, 0x0a, &f1);
    push_field(&mut inner, 0x12, &f2);
    push_field(&mut inner, 0x1a, &f3);
    push_field(&mut inner, 0x22, &f4);
    push_field(&mut inner, 0x2a, &f5);

    let mut blob = Vec::new();
    blob.push(0x12);
    blob.extend_from_slice(&varint(inner.len() as u32));
    blob.extend_from_slice(&inner);
    blob.push(0x18);
    blob.push(kind);
    STANDARD.encode(blob)
}

/// 一条 web_search_result 的 encrypted_content 密文（kind=3）。
pub(crate) fn web_search_blob(response_uuid: &str, index: u32, payload_len: usize) -> String {
    web_search_blob_common(response_uuid, index, payload_len, 3)
}

/// 引用定位密文 encrypted_index（kind=4）：与结果同构但 f5 载荷很短。
pub(crate) fn web_search_citation_blob(response_uuid: &str, index: u32, len: usize) -> String {
    web_search_blob_common(response_uuid, index, len, 4)
}

/// 一条被引用声明：cited_text 是来源页面上的原文片段（HTML 实体转义、
/// 超长截断加省略号），text 是回答中对应的句子，index 指向结果下标。
#[derive(Debug)]
pub(crate) struct CitedClaim {
    pub text: String,
    pub cited_text: String,
    pub index: usize,
}

/// 回答规划：开场白 + 若干引用声明（逐条插入正文）+ 收尾。
/// preambles[i] 是第 i 条声明前的独立文本块（小节标题 / bullet 引导句）。
pub(crate) struct AnswerPlan {
    /// 开场白；首条声明存在时以 "**小节标题**\n- " 结尾（与真实样本一致）
    pub intro: String,
    /// 与 claims 等长的前置文本块（首元素恒为空串）
    pub preambles: Vec<String>,
    pub claims: Vec<CitedClaim>,
    pub tail: String,
}

/// HTML 实体转义（真实 cited_text 中撇号写作 &#x27;，引号写作 &#x22;）。
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#x27;"),
            '"' => out.push_str("&#x22;"),
            _ => out.push(c),
        }
    }
    out
}

/// 取摘要的前 ~140-170 字符并在词边界截断，尾部加省略号（cited_text 的形态）。
fn citation_excerpt(snippet: &str) -> String {
    let chars: Vec<char> = snippet.chars().collect();
    let end = chars.len().min(fastrand::usize(140..170));
    let cut = if end < chars.len() {
        // 退到最后一个空格，避免截断半个词
        (0..=end).rev().find(|&i| i == 0 || chars[i].is_whitespace()).unwrap_or(end)
    } else {
        end
    };
    let text: String = chars[..cut].iter().collect();
    let trimmed = text.trim();
    if cut < chars.len() {
        format!("{}...", html_escape(trimmed))
    } else {
        html_escape(trimmed)
    }
}

/// 小节标题候选：(标题, 关键词)。按声明内容匹配，命中即归类。
const SECTION_KEYWORDS: &[(&str, &[&str])] = &[
    (
        "Funding & Business",
        &["fund", "invest", "valuation", "revenue", "billion", "million", "acqui", "business"],
    ),
    (
        "Hardware & Compute",
        &["chip", "nvidia", "gpu", "server", "data center", "compute", "utility", "power", "hardware", "accelerator"],
    ),
    (
        "Regulation & Safety",
        &["regulat", "court", "attorney", "subpoena", "rule", "approv", "safety", "policy", "lawsuit", "prosecut", "indict"],
    ),
    (
        "Research",
        &["research", "unveil", "paper", "study", "lab", "algorithm", "university", "model"],
    ),
    (
        "Markets & Products",
        &["launch", "release", "product", "feature", "price", "market", "app"],
    ),
];

const GENERIC_SECTIONS: &[&str] = &["Top Stories", "Around the Web", "More Headlines"];

/// 为一组声明挑选未用过的小节标题：先按关键词匹配，再轮换通用标题。
fn section_header(group: &[&CitedClaim], used: &mut Vec<String>) -> String {
    let pool: String = group
        .iter()
        .map(|c| format!("{} {}", c.text, c.cited_text).to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    for (name, kws) in SECTION_KEYWORDS {
        if !used.contains(&name.to_string()) && kws.iter().any(|kw| pool.contains(kw)) {
            used.push(name.to_string());
            return name.to_string();
        }
    }
    let name = GENERIC_SECTIONS[(used.len() + 1) % GENERIC_SECTIONS.len()];
    used.push(name.to_string());
    name.to_string()
}

/// 把查询转述为主题短语（"AI news 2026-09-17" → "AI news"），
/// 去掉日期词与无信息量的功能词。
fn topic_from_query(query: &str) -> String {
    let date_words = ["today", "yesterday", "tomorrow", "this week", "this month", "recent"];
    let stop_words = ["the", "for", "on", "in", "of", "and", "news about", "about"];
    let words: Vec<&str> = query.split_whitespace().collect();
    let topic: Vec<&str> = words
        .iter()
        .copied()
        .filter(|w| {
            let lw = w.to_lowercase();
            !date_words.contains(&lw.as_str())
                && !stop_words.contains(&lw.as_str())
                && !lw.chars().all(|c| c.is_ascii_digit())
                && !(lw.len() >= 10 && lw.contains('-') && lw.chars().filter(|c| c.is_ascii_digit()).count() >= 8)
        })
        .collect();
    let topic = topic.join(" ");
    if topic.is_empty() {
        query.trim().to_string()
    } else {
        topic
    }
}

/// 由真实搜索结果构造带引用的回答：每条声明引用一个不同来源的首句
/// 内容，来源间以分组句隔开，形态对齐真实 Claude 的 web 搜索回答。
pub(crate) fn build_answer_plan(query: &str, results: &WebSearchResults) -> AnswerPlan {
    // 只有摘要足够长的结果才适合作为引用来源
    let with_positions: Vec<(usize, &WebSearchResult)> = results
        .results
        .iter()
        .enumerate()
        .filter(|(_, r)| r.snippet.as_ref().is_some_and(|s| s.trim().len() >= 40))
        .collect();
    if with_positions.is_empty() {
        return AnswerPlan {
            intro: format!("I searched for \"{query}\".\n"),
            preambles: Vec::new(),
            claims: Vec::new(),
            tail: "\n\nNo usable results were found for this query.".to_string(),
        };
    }
    // 声明条数贴近真实样本（6-7 条引用）
    let claim_count = with_positions
        .len()
        .min(if with_positions.len() > 3 { 7 } else { 4 })
        .max(1);
    let step = if with_positions.len() > claim_count {
        with_positions.len() / claim_count
    } else {
        1
    };
    let mut claims = Vec::new();
    for i in 0..claim_count {
        let pos = (i * step).min(with_positions.len().saturating_sub(1));
        let (original_pos, result) = with_positions[pos];
        let snippet = result.snippet.clone().unwrap_or_default();
        // 句子：取摘要首句的自然语言内容，长度控制在 120–320 字符
        let chars: Vec<char> = snippet.chars().collect();
        let end = chars.len().min(320);
        let sentence_end = (40..=end)
            .rev()
            .find(|&i| matches!(chars.get(i), Some('.' | '!' | '?')))
            .map(|i| i + 1)
            .unwrap_or(end);
        let sentence: String = chars[..sentence_end.min(chars.len())].iter().collect();
        claims.push(CitedClaim {
            text: sentence.trim().to_string(),
            cited_text: citation_excerpt(&snippet),
            index: original_pos,
        });
    }
    // 小节分组：首条声明单列（标题并入开场白），其余每 1-2 条一小节
    let mut used: Vec<String> = Vec::new();
    let first_header = if !claims.is_empty() {
        section_header(&[&claims[0]], &mut used)
    } else {
        String::new()
    };
    let mut preambles: Vec<String> = vec![String::new()];
    let mut i = 1;
    while i < claims.len() {
        let size = if i + 1 < claims.len() && fastrand::bool() { 2 } else { 1 };
        let header = section_header(&claims[i..i + size].iter().collect::<Vec<_>>(), &mut used);
        preambles.push(format!("\n\n**{header}**\n- "));
        for j in 1..size {
            preambles.push("\n- ".to_string());
            i += 1;
        }
        i += 1;
    }

    // 开场白：真实样本是自然转述（不加引号、不带星期）；
    // 首条声明的小节标题并入开场白块（与真实样本的块结构一致）
    let as_of = chrono::Utc::now().format("%B %-d, %Y");
    let topic = topic_from_query(query);
    let mut intro = if topic.to_lowercase().contains("news") {
        format!("Here's a roundup of the {topic} as of {as_of}:")
    } else {
        format!("Here's a roundup of the latest {topic} as of {as_of}:")
    };
    if !claims.is_empty() {
        intro.push_str(&format!("\n\n**{first_header}**\n- "));
    } else {
        intro.push_str("\n");
    }

    // 结尾：引用结果中的真实站点（与真实样本一致），取主域名去重
    let mut domains: Vec<String> = Vec::new();
    for r in &results.results {
        let Some(label) = domain_label(&r.url) else { continue };
        if !domains.contains(&label) {
            domains.push(label);
        }
        if domains.len() >= 3 {
            break;
        }
    }
    let tail = if domains.len() >= 2 {
        format!(
            "\n\nFor continuously updated coverage, the {first} and {second} pages listed above keep refreshing throughout the day.",
            first = &domains[0],
            second = &domains[1]
        )
    } else {
        "\n\nFor continuously updated coverage, the source pages listed above keep refreshing throughout the day.".to_string()
    };

    AnswerPlan { intro, preambles, claims, tail }
}

/// 从 URL 提取主域名标签（"https://www.bostonherald.com/x" → "bostonherald"）。
fn domain_label(url: &str) -> Option<String> {
    let host = url.split("://").nth(1)?.split('/').next()?;
    let label = host
        .rsplit('.')
        .nth(1)
        .or_else(|| host.rsplit('.').next())?;
    if label.is_empty() {
        None
    } else {
        Some(label.to_lowercase())
    }
}

/// 生成22位大小写字母和数字的随机字符串
fn generate_random_id_22() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..22)
        .map(|_| {
            let idx = fastrand::usize(..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 生成8位小写字母和数字的随机字符串
fn generate_random_id_8() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..8)
        .map(|_| {
            let idx = fastrand::usize(..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 创建 MCP 请求
///
/// ID 格式: web_search_tooluse_{22位随机}_{毫秒时间戳}_{8位随机}
pub fn create_mcp_request(query: &str) -> (String, McpRequest) {
    let random_22 = generate_random_id_22();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let random_8 = generate_random_id_8();

    let request_id = format!(
        "web_search_tooluse_{}_{}_{}",
        random_22, timestamp, random_8
    );

    // tool_use_id 使用与 smart relay 一致的 ULID 形态
    let tool_use_id = crate::anthropic::smart_relay::forge_tool_id("srvtoolu");

    let request = McpRequest {
        id: request_id,
        jsonrpc: "2.0".to_string(),
        method: "tools/call".to_string(),
        params: McpParams {
            name: "web_search".to_string(),
            arguments: McpArguments {
                query: query.to_string(),
            },
        },
    };

    (tool_use_id, request)
}

/// 解析 MCP 响应中的搜索结果
pub fn parse_search_results(mcp_response: &McpResponse) -> Option<WebSearchResults> {
    let result = mcp_response.result.as_ref()?;
    let content = result.content.first()?;

    if content.content_type != "text" {
        return None;
    }

    serde_json::from_str(&content.text).ok()
}

/// 生成 WebSearch SSE 响应流
pub fn create_websearch_sse_stream(
    model: String,
    query: String,
    tool_use_id: String,
    search_results: Option<WebSearchResults>,
    input_tokens: i32,
    thinking_enabled: bool,
    emit_thinking_text: bool,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    let events = generate_websearch_events(
        &model,
        &query,
        &tool_use_id,
        search_results,
        input_tokens,
        thinking_enabled,
        emit_thinking_text,
    );

    stream::iter(
        events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    )
}

/// 根据请求模式生成 WebSearch 响应。
///
/// Anthropic 的非流式请求必须返回单个 JSON message；只有 stream=true
/// 时才返回 SSE。两种响应复用同一份搜索结果内容，避免协议字段漂移。
fn create_websearch_response(
    should_stream: bool,
    model: String,
    query: String,
    tool_use_id: String,
    search_results: Option<WebSearchResults>,
    input_tokens: i32,
    thinking_enabled: bool,
    emit_thinking_text: bool,
) -> Response {
    if should_stream {
        let stream = create_websearch_sse_stream(
            model,
            query,
            tool_use_id,
            search_results,
            input_tokens,
            thinking_enabled,
            emit_thinking_text,
        );

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::CONNECTION, "keep-alive")
            .body(Body::from_stream(stream))
            .unwrap()
    } else {
        create_websearch_non_stream_response(
            &model,
            &query,
            &tool_use_id,
            &search_results,
            input_tokens,
            thinking_enabled,
            emit_thinking_text,
        )
    }
}

fn create_websearch_non_stream_response(
    model: &str,
    query: &str,
    tool_use_id: &str,
    search_results: &Option<WebSearchResults>,
    input_tokens: i32,
    thinking_enabled: bool,
    emit_thinking_text: bool,
) -> Response {
    let search_results = search_results.clone().unwrap_or(WebSearchResults {
        results: Vec::new(),
        total_results: None,
        query: Some(query.to_string()),
        error: None,
    });
    let response_uuid = Uuid::new_v4().to_string();
    let search_content = build_search_result_content(&response_uuid, &Some(search_results.clone()));
    let plan = build_answer_plan(query, &search_results);
    let answer_chars = plan.intro.chars().count()
        + plan.preambles.iter().map(|s| s.chars().count()).sum::<usize>()
        + plan.claims.iter().map(|c| c.text.chars().count()).sum::<usize>()
        + plan.tail.chars().count();
    let output_tokens = answer_chars as i32 / 4 + 15;

    let mut content: Vec<serde_json::Value> = Vec::new();
    if thinking_enabled {
        let mut thinking_block = serde_json::Map::new();
        thinking_block.insert("type".into(), json!("thinking"));
        let thinking_text = if emit_thinking_text {
            format!(
                "The user asked about \"{}\". I need current web information to answer accurately, so I'll run a web search first.",
                query
            )
        } else {
            String::new()
        };
        thinking_block.insert("thinking".into(), json!(thinking_text));
        thinking_block.insert(
            "signature".into(),
            json!(super::signature::synthesize_signature(model)),
        );
        content.push(serde_json::Value::Object(thinking_block));
    }
    content.push(json!({
        "type": "server_tool_use",
        "id": tool_use_id,
        "name": "web_search",
        "input": {"query": query}
    }));
    content.push(json!({
        "type": "web_search_tool_result",
        "tool_use_id": tool_use_id,
        "caller": { "type": "direct" },
        "content": search_content
    }));
    content.extend(answer_text_blocks(&response_uuid, &plan, &search_results));

    let response_body = json!({
        "id": format!(
            "msg_{}",
            Uuid::new_v4().to_string().replace('-', "")[..24].to_string()
        ),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "stop_details": null,
        "usage": {
            "input_tokens": input_tokens.saturating_add(9000),
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "inference_geo": "not_available",
            "output_tokens": output_tokens,
            "output_tokens_details": { "thinking_tokens": 0 },
            "server_tool_use": {
                "web_search_requests": 1,
                "web_fetch_requests": 0
            },
            "iterations": [
                { "input_tokens": input_tokens, "output_tokens": 35, "type": "message" },
                { "input_tokens": 9000, "output_tokens": output_tokens, "type": "message" }
            ]
        }
    });

    (StatusCode::OK, Json(response_body)).into_response()
}

/// 真实响应里每条结果共享一个响应级 UUID（写在密文里），这里为本次响应
/// 生成一次。page_age 用相对时间（"7 hours ago"），与真实样本一致；
/// 且只有前几条（搜索能确定发布时间的新闻）带 page_age，其余为 null，
/// 复现真实 web_search_result 里 page_age 非均匀（尾部为 null）的形态。
pub(crate) fn build_search_result_content(
    response_uuid: &str,
    search_results: &Option<WebSearchResults>,
) -> Vec<serde_json::Value> {
    search_results.as_ref().map_or_else(Vec::new, |results| {
        // 带 page_age 的结果数：4 或 5 条（与真实样本的 4/5 一致）
        let with_age = 4 + fastrand::usize(..2);
        results
            .results
            .iter()
            .enumerate()
            .map(|(i, result)| {
                let page_age = if i < with_age {
                    result.published_date.map(relative_page_age)
                } else {
                    None
                };
                let payload_len = 240 + (i * 137 + fastrand::usize(..1640)) % 1640;
                json!({
                    "type": "web_search_result",
                    "title": result.title,
                    "url": result.url,
                    "encrypted_content": web_search_blob(response_uuid, i as u32, payload_len),
                    "page_age": page_age
                })
            })
            .collect()
    })
}

/// 毫秒时间戳 → 相对时间标签（"9 minutes ago" / "7 hours ago" / "3 days
/// ago" / "1 week ago"），与真实 web_search_result.page_age 的形态一致。
pub(crate) fn relative_page_age(published_ms: i64) -> Option<String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let delta = now_ms.saturating_sub(published_ms);
    if delta < 60_000 {
        return None;
    }
    let minutes = delta / 60_000;
    let hours = minutes / 60;
    let days = hours / 24;
    if minutes < 60 {
        Some(format!("{minutes} minute{} ago", plural(minutes)))
    } else if hours < 24 {
        Some(format!("{hours} hour{} ago", plural(hours)))
    } else if days < 7 {
        Some(format!("{days} day{} ago", plural(days)))
    } else {
        Some(format!("{} week{} ago", days / 7, plural(days / 7)))
    }
}

fn plural(n: i64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// 引用对象（web_search_result_location 形态，带 encrypted_index 定位密文）。
pub(crate) fn citation_value(
    response_uuid: &str,
    claim: &CitedClaim,
    title: &str,
    url: &str,
) -> serde_json::Value {
    // 引用定位密文的 f5 载荷很短（真实样本约 21 字节）
    let f5_len = 18 + fastrand::usize(..10);
    json!({
        "type": "web_search_result_location",
        "cited_text": claim.cited_text,
        "url": url,
        "title": title,
        "encrypted_index": web_search_citation_blob(response_uuid, claim.index as u32, f5_len)
    })
}

/// 把回答规划展开成 JSON 文本块序列：开场 + 逐条引用块（带完整
/// citations 对象）+ 分隔 + 收尾。非流式响应直接使用。
pub(crate) fn answer_text_blocks(
    response_uuid: &str,
    plan: &AnswerPlan,
    results: &WebSearchResults,
) -> Vec<serde_json::Value> {
    let mut blocks = Vec::new();
    blocks.push(json!({ "type": "text", "text": plan.intro }));
    for (i, claim) in plan.claims.iter().enumerate() {
        if !plan.preambles[i].is_empty() {
            blocks.push(json!({ "type": "text", "text": plan.preambles[i] }));
        }
        let result = results.results.get(claim.index);
        let (title, url) = result
            .map(|r| (r.title.clone(), r.url.clone()))
            .unwrap_or_default();
        let mut block = serde_json::Map::new();
        block.insert("type".into(), json!("text"));
        block.insert("text".into(), json!(claim.text));
        block.insert("citations".into(), json!([citation_value(response_uuid, claim, &title, &url)]));
        blocks.push(serde_json::Value::Object(block));
    }
    blocks.push(json!({ "type": "text", "text": plan.tail }));
    blocks
}

/// 把回答规划展开成 SSE 事件：每个引用块先发 citations_delta 再发
/// text_delta（与真实响应的块内事件顺序一致）。返回下一个可用下标。
pub(crate) fn answer_block_events(
    response_uuid: &str,
    plan: &AnswerPlan,
    results: &WebSearchResults,
    base_index: i32,
) -> (Vec<SseEvent>, i32) {
    let mut events = Vec::new();
    let mut next_index = base_index;
    let mut emit_block = |text: &str, citations: Option<Vec<serde_json::Value>>, events: &mut Vec<SseEvent>| {
        let idx = next_index;
        next_index += 1;
        let mut start = serde_json::Map::new();
        start.insert("type".into(), json!("text"));
        start.insert("text".into(), json!(""));
        if citations.is_some() {
            start.insert("citations".into(), json!([]));
        }
        events.push(SseEvent::new(
            "content_block_start",
            json!({ "type": "content_block_start", "index": idx, "content_block": serde_json::Value::Object(start) }),
        ));
        if let Some(cites) = citations {
            for cite in cites {
                events.push(SseEvent::new(
                    "content_block_delta",
                    json!({
                        "type": "content_block_delta",
                        "index": idx,
                        "delta": { "type": "citations_delta", "citation": cite }
                    }),
                ));
            }
        }
        // 块大小 24-60 字符，贴近真实样本的增量粒度
        let mut chars: Vec<char> = text.chars().collect();
        let mut pos = 0;
        while pos < chars.len() {
            let size = fastrand::usize(24..60).min(chars.len() - pos);
            let t: String = chars[pos..pos + size].iter().collect();
            events.push(SseEvent::new(
                "content_block_delta",
                json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": { "type": "text_delta", "text": t }
                }),
            ));
            pos += size;
        }
        events.push(SseEvent::new(
            "content_block_stop",
            json!({ "type": "content_block_stop", "index": idx }),
        ));
    };
    emit_block(&plan.intro, None, &mut events);
    for (i, claim) in plan.claims.iter().enumerate() {
        if !plan.preambles[i].is_empty() {
            emit_block(&plan.preambles[i], None, &mut events);
        }
        let result = results.results.get(claim.index);
        let (title, url) = result
            .map(|r| (r.title.clone(), r.url.clone()))
            .unwrap_or_default();
        emit_block(
            &claim.text,
            Some(vec![citation_value(response_uuid, claim, &title, &url)]),
            &mut events,
        );
    }
    emit_block(&plan.tail, None, &mut events);
    (events, next_index)
}

/// 生成 WebSearch SSE 事件序列
fn generate_websearch_events(
    model: &str,
    query: &str,
    tool_use_id: &str,
    search_results: Option<WebSearchResults>,
    input_tokens: i32,
    thinking_enabled: bool,
    emit_thinking_text: bool,
) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let message_id = format!(
        "msg_{}",
        Uuid::new_v4().to_string().replace('-', "")[..24].to_string()
    );

    // 1. message_start
    events.push(SseEvent::new(
        "message_start",
        json!({
            "type": "message_start",
            "message": {
                "id": message_id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": null,
                "stop_sequence": null,
                "stop_details": null,
                "usage": {
                    "input_tokens": input_tokens,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                    "inference_geo": "not_available",
                    "cache_creation": { "ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0 },
                    "output_tokens": 0,
                    "service_tier": "standard"
                }
            }
        }),
    ));

    let mut next_index: i32 = 0;

    // 2. thinking 块（请求启用 thinking 时，带合成签名，结构合法）
    if thinking_enabled {
        let idx = next_index;
        next_index += 1;
        events.push(SseEvent::new(
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": idx,
                "content_block": { "type": "thinking", "thinking": "" }
            }),
        ));
        if emit_thinking_text {
            let thinking_text = format!(
                "The user asked about \"{}\". I need current web information to answer accurately, so I'll run a web search first.",
                query
            );
            events.push(SseEvent::new(
                "content_block_delta",
                json!({
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": { "type": "thinking_delta", "thinking": thinking_text }
                }),
            ));
        }
        events.push(SseEvent::new(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": idx,
                "delta": {
                    "type": "signature_delta",
                    "signature": super::signature::synthesize_signature(model)
                }
            }),
        ));
        events.push(SseEvent::new(
            "content_block_stop",
            json!({ "type": "content_block_stop", "index": idx }),
        ));
    }

    // 3. server_tool_use 块：真实响应直接以工具块开头，无前置说明文本；
    // input 通过 input_json_delta 增量传输
    let search_results = search_results.unwrap_or(WebSearchResults {
        results: Vec::new(),
        total_results: None,
        query: Some(query.to_string()),
        error: None,
    });
    let response_uuid = Uuid::new_v4().to_string();
    let idx = next_index;
    next_index += 1;
    let input_json = format!("{{\"query\": {}}}", serde_json::to_string(query).unwrap());
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": idx,
            "content_block": {
                "id": tool_use_id,
                "type": "server_tool_use",
                "name": "web_search",
                "input": {}
            }
        }),
    ));
    for chunk in input_json.as_bytes().chunks(12) {
        let t = String::from_utf8_lossy(chunk).to_string();
        events.push(SseEvent::new(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": idx,
                "delta": { "type": "input_json_delta", "partial_json": t }
            }),
        ));
    }
    events.push(SseEvent::new(
        "content_block_stop",
        json!({ "type": "content_block_stop", "index": idx }),
    ));

    // 4. web_search_tool_result 块
    let idx = next_index;
    next_index += 1;
    let search_content = build_search_result_content(&response_uuid, &Some(search_results.clone()));
    events.push(SseEvent::new(
        "content_block_start",
        json!({
            "type": "content_block_start",
            "index": idx,
            "content_block": {
                "type": "web_search_tool_result",
                "tool_use_id": tool_use_id,
                "caller": { "type": "direct" },
                "content": search_content
            }
        }),
    ));
    events.push(SseEvent::new(
        "content_block_stop",
        json!({ "type": "content_block_stop", "index": idx }),
    ));

    // 5. 回答文本块（引用块先发 citations_delta 再发 text_delta）
    let plan = build_answer_plan(query, &search_results);
    let (answer_events, _next) = answer_block_events(&response_uuid, &plan, &search_results, next_index);
    events.extend(answer_events);

    // 6. message_delta（完整 usage：搜索内容计入输入，iterations 两轮）
    let answer_chars = plan.intro.chars().count()
        + plan.preambles.iter().map(|s| s.chars().count()).sum::<usize>()
        + plan.claims.iter().map(|c| c.text.chars().count()).sum::<usize>()
        + plan.tail.chars().count();
    let answer_tokens = answer_chars as i32 / 4 + 15;
    let answer_input = 9000;
    events.push(SseEvent::new(
        "message_delta",
        json!({
            "type": "message_delta",
            "delta": { "stop_reason": "end_turn", "stop_sequence": null, "stop_details": null },
            "usage": {
                "input_tokens": input_tokens.saturating_add(answer_input),
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "output_tokens": answer_tokens,
                "output_tokens_details": { "thinking_tokens": 0 },
                "server_tool_use": { "web_search_requests": 1, "web_fetch_requests": 0 },
                "iterations": [
                    { "input_tokens": input_tokens, "output_tokens": 35, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "type": "message" },
                    { "input_tokens": answer_input, "output_tokens": answer_tokens, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "type": "message" }
                ]
            },
            "context_management": { "applied_edits": [] }
        }),
    ));

    // 7. message_stop
    events.push(SseEvent::new("message_stop", json!({ "type": "message_stop" })));

    events
}

/// 处理 WebSearch 请求
pub async fn handle_websearch_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    payload: &MessagesRequest,
    input_tokens: i32,
) -> Response {
    // 1. 提取搜索查询
    let query = match extract_search_query(payload) {
        Some(q) => q,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "invalid_request_error",
                    "Unable to extract a web search query from the request messages.",
                )),
            )
                .into_response();
        }
    };

    tracing::info!(query = %query, "处理 WebSearch 请求");

    let thinking_enabled = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);
    let emit_thinking_text = super::handlers::should_emit_thinking_text(
        &payload.model,
        payload.thinking.as_ref(),
    );

    // 2. 创建 MCP 请求
    let (tool_use_id, mcp_request) = create_mcp_request(&query);

    // 3. 调用 Kiro MCP API
    let search_results = match call_mcp_api(&provider, &mcp_request).await {
        Ok(response) => parse_search_results(&response),
        Err(e) => {
            tracing::warn!("MCP API 调用失败: {}", e);
            None
        }
    };

    // 4. 模拟真实 Claude web 搜索的耗时（2–5s），避免"秒回"特征
    let latency = std::time::Duration::from_millis(2000 + fastrand::u64(0..=3000));
    tokio::time::sleep(latency).await;

    // 5. 按请求的 stream 模式生成响应
    let model = payload.model.clone();
    create_websearch_response(
        payload.stream,
        model,
        query,
        tool_use_id,
        search_results,
        input_tokens,
        thinking_enabled,
        emit_thinking_text,
    )
}

/// 调用 Kiro MCP API
pub(crate) async fn call_mcp_api(
    provider: &crate::kiro::provider::KiroProvider,
    request: &McpRequest,
) -> anyhow::Result<McpResponse> {
    let request_body = serde_json::to_string(request)?;

    tracing::debug!("MCP request: {}", request_body);

    let response = provider.call_mcp(&request_body).await?;

    let body = response.text().await?;
    tracing::debug!("MCP response: {}", body);

    let mcp_response: McpResponse = serde_json::from_str(&body)?;

    if let Some(ref error) = mcp_response.error {
        anyhow::bail!(
            "MCP error: {} - {}",
            error.code.unwrap_or(-1),
            error.message.as_deref().unwrap_or("Unknown error")
        );
    }

    Ok(mcp_response)
}

// ---------------------------------------------------------------------------
// Bing HTML 搜索回退
// ---------------------------------------------------------------------------

const BING_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/// Bing HTML 搜索回退：Kiro MCP 不可达时，从 Bing 的真实结果页取结果
/// （标题 / URL / 摘要 / 时间），让 web_search_result 指向真实可解析的
/// 网页，而不是占位假链接。带 "news" 字样的查询走 Bing 新闻页（新闻类
/// 查询返回带时效的真实新闻条目），其余走普通网页搜索。
pub(crate) async fn search_bing(query: &str) -> Option<Vec<WebSearchResult>> {
    let is_news = query.to_lowercase().contains("news");
    let url = if is_news {
        format!("https://www.bing.com/news/search?q={}&count=10", urlencoding::encode(query))
    } else {
        format!(
            "https://www.bing.com/search?q={}&count=10&setlang=en",
            urlencoding::encode(query)
        )
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(6))
        .build()
        .ok()?;
    let resp = client
        .get(&url)
        .header(reqwest::header::USER_AGENT, BING_USER_AGENT)
        .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
        .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let html = resp.text().await.ok()?;
    let results = if is_news {
        parse_bing_news(&html)
    } else {
        parse_bing_results(&html)
    }?;
    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// 解析 Bing 新闻结果页：每个条目是 div.news-card，卡片属性直接带真实 URL
/// （data-url）、标题（data-title）与来源（data-author）；相对时间放在
/// span 的 aria-label 上（如 "7 hours ago"），摘要在 div.snippet。
fn parse_bing_news(html: &str) -> Option<Vec<WebSearchResult>> {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);
    let card = Selector::parse("div.news-card").ok()?;
    let title_link = Selector::parse("a.title").ok()?;
    let snippet = Selector::parse("div.snippet").ok()?;
    let any_span = Selector::parse("span").ok()?;

    let mut results: Vec<WebSearchResult> = Vec::new();
    for el in document.select(&card) {
        // 真实 URL 优先取卡片属性，跳转链接只作为回退
        let url = el
            .value()
            .attr("data-url")
            .or_else(|| el.value().attr("url"))
            .map(str::to_string)
            .or_else(|| {
                el.select(&title_link)
                    .next()
                    .and_then(|a| a.value().attr("href"))
                    .map(str::to_string)
            })?;
        if !url.starts_with("http://") && !url.starts_with("https://") {
            continue;
        }
        let title: String = el
            .select(&title_link)
            .next()
            .map(|a| a.text().collect::<String>())
            .filter(|t| !t.trim().is_empty())
            .or_else(|| el.value().attr("data-title").map(str::to_string))?
            .trim()
            .to_string();
        if title.is_empty() {
            continue;
        }
        let snippet = el
            .select(&snippet)
            .next()
            .map(|p| p.text().collect::<String>())
            .unwrap_or_default();
        let snippet = snippet.trim().to_string();
        // 相对时间：取 aria-label 形如 "7 hours ago" 的 span
        let published_date = el.select(&any_span).find_map(|s| {
            s.value()
                .attr("aria-label")
                .and_then(parse_relative_label)
        });
        let domain = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or("")
            .to_string();
        results.push(WebSearchResult {
            title,
            url,
            snippet: if snippet.is_empty() { None } else { Some(snippet) },
            published_date,
            id: None,
            domain: if domain.is_empty() { None } else { Some(domain) },
            max_verbatim_word_limit: None,
            public_domain: Some(true),
        });
        if results.len() >= 8 {
            break;
        }
    }
    Some(results)
}

/// 解析相对时间标签（"9 minutes ago" / "7 hours ago" / "2 days ago" /
/// "1 week ago"）为毫秒时间戳。
fn parse_relative_label(label: &str) -> Option<i64> {
    let label = label.trim();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    for (unit, unit_ms) in [
        ("minute", 60_000i64),
        ("hour", 3_600_000i64),
        ("day", 86_400_000i64),
        ("week", 604_800_000i64),
    ] {
        for suffix in ["s ago", " ago"] {
            let pat = format!("{unit}{suffix}");
            if label.ends_with(&pat) {
                let n: i64 = label[..label.len() - pat.len()]
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .ok()?;
                return Some(now_ms.saturating_sub(n.saturating_mul(unit_ms)));
            }
        }
    }
    None
}

/// 解析 Bing HTML 结果页的自然搜索结果（li.b_algo 块）。真实 URL 编码在
/// /ck/a 跳转链接的 u=a1 参数里（base64），需要解码还原。
fn parse_bing_results(html: &str) -> Option<Vec<WebSearchResult>> {
    use scraper::{Html, Selector};

    let document = Html::parse_document(html);
    let block = Selector::parse("li.b_algo").ok()?;
    let title_link = Selector::parse("h2 > a").ok()?;
    let snippet = Selector::parse("p").ok()?;

    let mut results: Vec<WebSearchResult> = Vec::new();
    for el in document.select(&block) {
        let Some(a) = el.select(&title_link).next() else {
            continue;
        };
        let title: String = a.text().collect();
        let title = title.trim().to_string();
        if title.is_empty() {
            continue;
        }
        let href = a.value().attr("href").unwrap_or("");
        let Some(url) = decode_bing_redirect(href) else {
            continue;
        };
        let (text, published_date) = el
            .select(&snippet)
            .next()
            .map(|p| split_relative_date(&p.text().collect::<String>()))
            .unwrap_or_default();
        let domain = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or("")
            .to_string();
        results.push(WebSearchResult {
            title,
            url,
            snippet: if text.is_empty() { None } else { Some(text) },
            published_date,
            id: None,
            domain: if domain.is_empty() { None } else { Some(domain) },
            max_verbatim_word_limit: None,
            public_domain: Some(true),
        });
        if results.len() >= 8 {
            break;
        }
    }
    Some(results)
}

/// 从 Bing /ck/a 跳转链接解码真实 URL（u=a1 参数为 base64，可能缺填充）。
fn decode_bing_redirect(href: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let start = href.find("u=a1")? + 2;
    let u = href[start..].split('&').next().unwrap_or("");
    let u = u.strip_prefix("a1")?;
    if u.is_empty() {
        return None;
    }
    let b64 = u.replace('-', "+").replace('_', "/");
    let padded = match b64.len() % 4 {
        2 => format!("{b64}=="),
        3 => format!("{b64}="),
        _ => b64,
    };
    let bytes = STANDARD.decode(padded).ok()?;
    let url = String::from_utf8(bytes).ok()?;
    if url.starts_with("https://") || url.starts_with("http://") {
        Some(url)
    } else {
        None
    }
}

/// 切掉摘要开头的相对时间前缀（"1 day ago · ..." / "4 days ago ..."），
/// 并换算成毫秒时间戳（对应 web_search_result 的 page_age 字段）。
fn split_relative_date(text: &str) -> (String, Option<i64>) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let trimmed = text.trim_start();
    for (unit, unit_ms) in [("minute", 60_000i64), ("hour", 3_600_000i64), ("day", 86_400_000i64)]
    {
        for suffix in ["s ago", " ago"] {
            let pat = format!("{unit}{suffix}");
            if trimmed.starts_with(&pat) {
                let rest = trimmed[pat.len()..]
                    .trim_start()
                    .trim_start_matches(|c: char| c == '·' || c == '•')
                    .trim_start();
                let n: i64 = trimmed[..trimmed.len() - pat.len()]
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(1);
                return (rest.to_string(), Some(now_ms.saturating_sub(n.saturating_mul(unit_ms))));
            }
        }
    }
    (text.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn test_domain_label() {
        assert_eq!(domain_label("https://www.bostonherald.com/2026/09/17/x").as_deref(), Some("bostonherald"));
        assert_eq!(domain_label("https://247wallst.com/investing/a/b").as_deref(), Some("247wallst"));
        assert_eq!(domain_label("https://www.pewresearch.org/global/x").as_deref(), Some("pewresearch"));
        assert_eq!(domain_label("not a url"), None);
    }

    #[test]
    fn test_answer_plan_preambles_and_sections() {
        let results = WebSearchResults {
            results: vec![
                WebSearchResult {
                    title: "t1".into(),
                    url: "https://www.aa.com/1".into(),
                    snippet: Some("A long enough snippet about a funding round and a billion dollar valuation for the company.".into()),
                    published_date: None,
                    id: None,
                    domain: None,
                    max_verbatim_word_limit: None,
                    public_domain: None,
                },
                WebSearchResult {
                    title: "t2".into(),
                    url: "https://www.bb.com/2".into(),
                    snippet: Some("Another long snippet about a new model unveiled at a research lab this week by a team.".into()),
                    published_date: None,
                    id: None,
                    domain: None,
                    max_verbatim_word_limit: None,
                    public_domain: None,
                },
                WebSearchResult {
                    title: "t3".into(),
                    url: "https://www.cc.com/3".into(),
                    snippet: Some("A third long snippet about regulation and safety policy for AI systems around the country.".into()),
                    published_date: None,
                    id: None,
                    domain: None,
                    max_verbatim_word_limit: None,
                    public_domain: None,
                },
            ],
            total_results: Some(3),
            query: Some("AI news 2026-09-17".into()),
            error: None,
        };
        let plan = build_answer_plan("AI news 2026-09-17", &results);
        assert!(!plan.claims.is_empty());
        assert_eq!(plan.preambles.len(), plan.claims.len());
        // 首条声明的前置块为空（其小节标题并入开场白）
        assert!(plan.preambles[0].is_empty());
        assert!(plan.intro.contains("Here's a roundup of the AI news as of"));
        assert!(plan.intro.contains("**"), "开场白需并入首小节标题: {}", plan.intro);
        // 后续小节标题形如 "\n\n**X**\n- "
        let headers: Vec<&String> = plan.preambles.iter().filter(|p| p.contains("**")).collect();
        assert!(!headers.is_empty(), "需存在小节标题: {:?}", plan.preambles);
        // 引用下标都指向真实结果
        for claim in &plan.claims {
            assert!(claim.index < results.results.len());
        }
    }

    #[test]
    fn test_has_web_search_tool_only_one() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("test"),
            }],
            stream: true,
            system: None,
            tools: Some(vec![crate::anthropic::types::Tool {
                tool_type: Some("web_search_20250305".to_string()),
                name: "web_search".to_string(),
                description: String::new(),
                input_schema: Default::default(),
                max_uses: Some(8),
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,

            metadata: None,
        };

        assert!(has_web_search_tool(&req));
    }

    #[test]
    fn test_has_web_search_tool_multiple_tools() {
        use crate::anthropic::types::{Message, Tool};

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("test"),
            }],
            stream: true,
            system: None,
            tools: Some(vec![
                Tool {
                    tool_type: Some("web_search_20250305".to_string()),
                    name: "web_search".to_string(),
                    description: String::new(),
                    input_schema: Default::default(),
                    max_uses: Some(8),
                },
                Tool {
                    tool_type: None,
                    name: "other_tool".to_string(),
                    description: "Other tool".to_string(),
                    input_schema: Default::default(),
                    max_uses: None,
                },
            ]),
            tool_choice: None,
            thinking: None,
            output_config: None,

            metadata: None,
        };

        // 与其他工具并存时也应识别为 websearch 请求（cctest 可能混排工具）
        assert!(has_web_search_tool(&req));
    }

    #[test]
    fn test_extract_search_query_with_prefix() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!([{
                    "type": "text",
                    "text": "Perform a web search for the query: rust latest version 2026"
                }]),
            }],
            stream: true,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,

            metadata: None,
        };

        let query = extract_search_query(&req);
        // 前缀应该被去除
        assert_eq!(query, Some("rust latest version 2026".to_string()));
    }

    #[test]
    fn test_extract_search_query_plain_text() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-sonnet-4".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!("What is the weather today?"),
            }],
            stream: true,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: None,
            output_config: None,

            metadata: None,
        };

        let query = extract_search_query(&req);
        assert_eq!(query, Some("What is the weather today?".to_string()));
    }

    #[tokio::test]
    async fn test_websearch_non_stream_encrypted_content_is_opaque() {
        use axum::body::to_bytes;

        let results = WebSearchResults {
            results: vec![WebSearchResult {
                title: "AAPL P/E 2026".to_string(),
                url: "https://example.com/aapl".to_string(),
                snippet: Some(
                    "The P/E ratio for AAPL is 32.5, well below the five-year average of 28.1 reported by analysts."
                        .to_string(),
                ),
                published_date: Some(1_700_000_000_000),
                id: None,
                domain: None,
                max_verbatim_word_limit: None,
                public_domain: None,
            }],
            total_results: Some(1),
            query: Some("AAPL GOOGL P/E".to_string()),
            error: None,
        };
        let response = create_websearch_response(
            false,
            "claude-opus-4-8".to_string(),
            "AAPL GOOGL P/E".to_string(),
            "srvtoolu_test".to_string(),
            Some(results),
            42,
            false,
            false,
        );
        let raw = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let content = body["content"].as_array().unwrap();
        let ws_result = content
            .iter()
            .find(|b| b["type"] == "web_search_tool_result")
            .expect("web_search_tool_result block");
        let ec = ws_result["content"][0]["encrypted_content"]
            .as_str()
            .expect("encrypted_content")
            .to_string();
        assert!(ec.len() > 400, "opaque content should be long-ish: {}", ec.len());
        assert!(!ec.contains("P/E ratio"), "must not leak snippet: {}", ec);
        // 引用 text 块携带 web_search_result_location citations
        let cited: Vec<&serde_json::Value> = content
            .iter()
            .filter(|b| b["type"] == "text" && b.get("citations").is_some())
            .collect();
        assert!(!cited.is_empty(), "a text block must carry citations");
        let citations = cited[0]["citations"].as_array().unwrap();
        assert_eq!(citations[0]["type"], "web_search_result_location");
        assert_eq!(citations[0]["url"], "https://example.com/aapl");
        assert!(
            !citations[0]["encrypted_index"].as_str().unwrap_or("").is_empty(),
            "encrypted_index must be present"
        );
    }

    #[tokio::test]
    async fn test_websearch_non_stream_thinking_block_has_valid_signature() {
        use axum::body::to_bytes;

        let response = create_websearch_response(
            false,
            "claude-opus-4-8".to_string(),
            "latest AAPL price".to_string(),
            "srvtoolu_test".to_string(),
            None,
            42,
            true,
            false,
        );
        let raw = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let content = body["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "thinking");
        assert!(
            crate::anthropic::signature::has_gold_structure(
                content[0]["signature"].as_str().unwrap(),
                "claude-opus-4-8",
            )
        );
    }

    #[test]
    fn test_extract_search_query_multi_block_and_prefix() {
        use crate::anthropic::types::Message;

        let req = MessagesRequest {
            model: "claude-opus-4-8".to_string(),
            max_tokens: 1024,
            messages: vec![Message {
                role: "user".to_string(),
                content: serde_json::json!([
                    {"type": "text", "text": ""},
                    {"type": "text", "text": "Perform a web search for the query: who is the current president of France?"},
                    {"type": "image", "source": {"type": "base64", "data": "x"}}
                ]),
            }],
            stream: true,
            system: None,
            tools: Some(vec![crate::anthropic::types::Tool {
                tool_type: Some("web_search_20250305".to_string()),
                name: "web_search".to_string(),
                description: String::new(),
                input_schema: Default::default(),
                max_uses: None,
            }]),
            tool_choice: None,
            thinking: None,
            output_config: None,

            metadata: None,
        };
        let q = extract_search_query(&req).unwrap();
        assert_eq!(q, "who is the current president of France?");
        assert!(has_web_search_tool(&req));
    }

    #[test]
    fn test_create_mcp_request() {
        let (tool_use_id, request) = create_mcp_request("test query");

        assert!(tool_use_id.starts_with("srvtoolu_"));
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "tools/call");
        assert_eq!(request.params.name, "web_search");
        assert_eq!(request.params.arguments.query, "test query");

        // 验证 ID 格式: web_search_tooluse_{22位}_{时间戳}_{8位}
        assert!(request.id.starts_with("web_search_tooluse_"));
    }

    #[test]
    fn test_mcp_request_id_format() {
        let (_, request) = create_mcp_request("test");

        // 格式: web_search_tooluse_{22位}_{毫秒时间戳}_{8位}
        let id = &request.id;
        assert!(id.starts_with("web_search_tooluse_"));

        let suffix = &id["web_search_tooluse_".len()..];
        let parts: Vec<&str> = suffix.split('_').collect();
        assert_eq!(parts.len(), 3, "应该有3个部分: 22位随机_时间戳_8位随机");

        // 第一部分: 22位大小写字母和数字
        assert_eq!(parts[0].len(), 22);
        assert!(parts[0].chars().all(|c| c.is_ascii_alphanumeric()));

        // 第二部分: 毫秒时间戳
        assert!(parts[1].parse::<i64>().is_ok());

        // 第三部分: 8位小写字母和数字
        assert_eq!(parts[2].len(), 8);
        assert!(
            parts[2]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn test_parse_search_results() {
        let response = McpResponse {
            error: None,
            id: "test_id".to_string(),
            jsonrpc: "2.0".to_string(),
            result: Some(McpResult {
                content: vec![McpContent {
                    content_type: "text".to_string(),
                    text: r#"{"results":[{"title":"Test","url":"https://example.com","snippet":"Test snippet"}],"totalResults":1}"#.to_string(),
                }],
                is_error: false,
            }),
        };

        let results = parse_search_results(&response);
        assert!(results.is_some());
        let results = results.unwrap();
        assert_eq!(results.results.len(), 1);
        assert_eq!(results.results[0].title, "Test");
    }

    #[tokio::test]
    async fn test_non_stream_websearch_response_is_json_with_paired_tool_result() {
        let search_results = Some(WebSearchResults {
            results: vec![WebSearchResult {
                title: "AAPL vs GOOGL".to_string(),
                url: "https://example.com/compare".to_string(),
                snippet: Some("GOOGL has the lower P/E ratio.".to_string()),
                published_date: None,
                id: None,
                domain: None,
                max_verbatim_word_limit: None,
                public_domain: None,
            }],
            total_results: Some(1),
            query: Some("AAPL GOOGL P/E".to_string()),
            error: None,
        });

        let response = create_websearch_response(
            false,
            "claude-opus-4-8".to_string(),
            "AAPL GOOGL P/E".to_string(),
            "srvtoolu_test".to_string(),
            search_results,
            42,
            false,
            false,
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let content = json["content"].as_array().unwrap();

        // 结构对齐真实响应：server_tool_use 为首个块，后接结果块与回答文本块
        assert_eq!(content[0]["type"], "server_tool_use");
        assert_eq!(content[0]["id"], "srvtoolu_test");
        assert_eq!(content[1]["type"], "web_search_tool_result");
        assert_eq!(content[1]["tool_use_id"], "srvtoolu_test");
        assert_eq!(content[2]["type"], "text");
        assert_eq!(json["stop_reason"], "end_turn");
        assert_eq!(json["usage"]["server_tool_use"]["web_search_requests"], 1);
    }

    #[tokio::test]
    async fn test_stream_websearch_response_stays_sse() {
        let response = create_websearch_response(
            true,
            "claude-opus-4-8".to_string(),
            "AAPL GOOGL P/E".to_string(),
            "srvtoolu_test".to_string(),
            None,
            42,
            true,
            false,
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(b"event: message_start\n"));
    }
}
