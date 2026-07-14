//! 流式响应处理模块
//!
//! 实现 Kiro → Anthropic 流式响应转换和 SSE 状态管理

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::kiro::model::events::Event;

use super::identity_response_guard::{
    StreamGuardAction, StreamGuardFinish, StreamingIdentityResponseGuard,
};

/// 找到小于等于目标位置的最近有效UTF-8字符边界
///
/// UTF-8字符可能占用1-4个字节，直接按字节位置切片可能会切在多字节字符中间导致panic。
/// 这个函数从目标位置向前搜索，找到最近的有效字符边界。
fn find_char_boundary(s: &str, target: usize) -> usize {
    if target >= s.len() {
        return s.len();
    }
    if target == 0 {
        return 0;
    }
    // 从目标位置向前搜索有效的字符边界
    let mut pos = target;
    while pos > 0 && !s.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

/// 需要跳过的包裹字符
///
/// 当 thinking 标签被这些字符包裹时，认为是在引用标签而非真正的标签：
/// - 反引号 (`)：行内代码
/// - 双引号 (")：字符串
/// - 单引号 (')：字符串
const QUOTE_CHARS: &[u8] = &[
    b'`', b'"', b'\'', b'\\', b'#', b'!', b'@', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'-',
    b'_', b'=', b'+', b'[', b']', b'{', b'}', b';', b':', b'<', b'>', b',', b'.', b'?', b'/',
];

/// 检查指定位置的字符是否是引用字符
fn is_quote_char(buffer: &str, pos: usize) -> bool {
    buffer
        .as_bytes()
        .get(pos)
        .map(|c| QUOTE_CHARS.contains(c))
        .unwrap_or(false)
}

/// 查找真正的 thinking 结束标签（不被引用字符包裹，且后面有双换行符）
///
/// 当模型在思考过程中提到 `</thinking>` 时，通常会用反引号、引号等包裹，
/// 或者在同一行有其他内容（如"关于 </thinking> 标签"）。
/// 这个函数会跳过这些情况，只返回真正的结束标签位置。
///
/// 跳过的情况：
/// - 被引用字符包裹（反引号、引号等）
/// - 后面没有双换行符（真正的结束标签后面会有 `\n\n`）
/// - 标签在缓冲区末尾（流式处理时需要等待更多内容）
///
/// # 参数
/// - `buffer`: 要搜索的字符串
///
/// # 返回值
/// - `Some(pos)`: 真正的结束标签的起始位置
/// - `None`: 没有找到真正的结束标签
fn find_real_thinking_end_tag(buffer: &str) -> Option<usize> {
    const TAG: &str = "</thinking>";
    let mut search_start = 0;

    while let Some(pos) = buffer[search_start..].find(TAG) {
        let absolute_pos = search_start + pos;

        // 检查前面是否有引用字符
        let has_quote_before = absolute_pos > 0 && is_quote_char(buffer, absolute_pos - 1);

        // 检查后面是否有引用字符
        let after_pos = absolute_pos + TAG.len();
        let has_quote_after = is_quote_char(buffer, after_pos);

        // 如果被引用字符包裹，跳过
        if has_quote_before || has_quote_after {
            search_start = absolute_pos + 1;
            continue;
        }

        // 检查后面的内容
        let after_content = &buffer[after_pos..];

        // 如果标签后面内容不足以判断是否有双换行符，等待更多内容
        if after_content.len() < 2 {
            return None;
        }

        // 真正的 thinking 结束标签后面会有双换行符 `\n\n`
        if after_content.starts_with("\n\n") {
            return Some(absolute_pos);
        }

        // 不是双换行符，跳过继续搜索
        search_start = absolute_pos + 1;
    }

    None
}

/// 查找缓冲区末尾的 thinking 结束标签（允许末尾只有空白字符）
///
/// 用于“边界事件”场景：例如 thinking 结束后立刻进入 tool_use，或流结束，
/// 此时 `</thinking>` 后面可能没有 `\n\n`，但结束标签依然应被识别并过滤。
///
/// 约束：只有当 `</thinking>` 之后全部都是空白字符时才认为是结束标签，
/// 以避免在 thinking 内容中提到 `</thinking>`（非结束标签）时误判。
fn find_real_thinking_end_tag_at_buffer_end(buffer: &str) -> Option<usize> {
    const TAG: &str = "</thinking>";
    let mut search_start = 0;

    while let Some(pos) = buffer[search_start..].find(TAG) {
        let absolute_pos = search_start + pos;

        // 检查前面是否有引用字符
        let has_quote_before = absolute_pos > 0 && is_quote_char(buffer, absolute_pos - 1);

        // 检查后面是否有引用字符
        let after_pos = absolute_pos + TAG.len();
        let has_quote_after = is_quote_char(buffer, after_pos);

        if has_quote_before || has_quote_after {
            search_start = absolute_pos + 1;
            continue;
        }

        // 只有当标签后面全部是空白字符时才认定为结束标签
        if buffer[after_pos..].trim().is_empty() {
            return Some(absolute_pos);
        }

        search_start = absolute_pos + 1;
    }

    None
}

/// 查找真正的 thinking 开始标签（不被引用字符包裹）
///
/// 与 `find_real_thinking_end_tag` 类似，跳过被引用字符包裹的开始标签。
fn find_real_thinking_start_tag(buffer: &str) -> Option<usize> {
    const TAG: &str = "<thinking>";
    let mut search_start = 0;

    while let Some(pos) = buffer[search_start..].find(TAG) {
        let absolute_pos = search_start + pos;

        // 检查前面是否有引用字符
        let has_quote_before = absolute_pos > 0 && is_quote_char(buffer, absolute_pos - 1);

        // 检查后面是否有引用字符
        let after_pos = absolute_pos + TAG.len();
        let has_quote_after = is_quote_char(buffer, after_pos);

        // 如果不被引用字符包裹，则是真正的开始标签
        if !has_quote_before && !has_quote_after {
            return Some(absolute_pos);
        }

        // 继续搜索下一个匹配
        search_start = absolute_pos + 1;
    }

    None
}

/// 从完整文本中提取 thinking 块（用于非流式响应）
///
/// 使用与流式处理相同的标签检测逻辑（引用字符过滤），确保一致性。
/// 非流式场景下文本已完整，无需处理跨 chunk 分割问题。
///
/// # 返回值
/// - `(Some(thinking_content), remaining_text)` — 检测到有效 thinking 块
/// - `(None, original_text)` — 未检测到，原样返回
pub(crate) fn extract_thinking_from_complete_text(text: &str) -> (Option<String>, String) {
    let start_pos = match find_real_thinking_start_tag(text) {
        Some(pos) => pos,
        None => return (None, text.to_string()),
    };

    let before = &text[..start_pos];
    let after_open = &text[start_pos + "<thinking>".len()..];

    // 查找结束标签：优先匹配带 \n\n 后缀的，退而使用末尾匹配
    let (thinking_raw, text_after) = if let Some(end_pos) = find_real_thinking_end_tag(after_open) {
        (
            &after_open[..end_pos],
            &after_open[end_pos + "</thinking>\n\n".len()..],
        )
    } else if let Some(end_pos) = find_real_thinking_end_tag_at_buffer_end(after_open) {
        let after_tag = end_pos + "</thinking>".len();
        (&after_open[..end_pos], after_open[after_tag..].trim_start())
    } else {
        // 找不到有效的结束标签，不做提取
        return (None, text.to_string());
    };

    // 剥离开头的换行符（与流式处理一致：模型输出 <thinking>\n）
    let thinking_content = thinking_raw.strip_prefix('\n').unwrap_or(thinking_raw);

    // 组装剩余文本：跳过纯空白的 before 部分
    let mut remaining = String::new();
    if !before.trim().is_empty() {
        remaining.push_str(before);
    }
    remaining.push_str(text_after);

    if thinking_content.is_empty() {
        (None, remaining)
    } else {
        (Some(thinking_content.to_string()), remaining)
    }
}

/// SSE 事件
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event: String,
    pub data: serde_json::Value,
}

impl SseEvent {
    pub fn new(event: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            event: event.into(),
            data,
        }
    }

    /// 格式化为 SSE 字符串
    pub fn to_sse_string(&self) -> String {
        format!(
            "event: {}\ndata: {}\n\n",
            self.event,
            serde_json::to_string(&self.data).unwrap_or_default()
        )
    }
}

/// 内容块状态
#[derive(Debug, Clone)]
struct BlockState {
    block_type: String,
    started: bool,
    stopped: bool,
}

impl BlockState {
    fn new(block_type: impl Into<String>) -> Self {
        Self {
            block_type: block_type.into(),
            started: false,
            stopped: false,
        }
    }
}

/// SSE 状态管理器
///
/// 确保 SSE 事件序列符合 Claude API 规范：
/// 1. message_start 只能出现一次
/// 2. content_block 必须先 start 再 delta 再 stop
/// 3. message_delta 只能出现一次，且在所有 content_block_stop 之后
/// 4. message_stop 在最后
#[derive(Debug)]
pub struct SseStateManager {
    /// message_start 是否已发送
    message_started: bool,
    /// message_delta 是否已发送
    message_delta_sent: bool,
    /// 活跃的内容块状态
    active_blocks: HashMap<i32, BlockState>,
    /// 消息是否已结束
    message_ended: bool,
    /// 下一个块索引
    next_block_index: i32,
    /// 当前 stop_reason
    stop_reason: Option<String>,
    /// 是否有工具调用
    has_tool_use: bool,
}

impl Default for SseStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SseStateManager {
    pub fn new() -> Self {
        Self {
            message_started: false,
            message_delta_sent: false,
            active_blocks: HashMap::new(),
            message_ended: false,
            next_block_index: 0,
            stop_reason: None,
            has_tool_use: false,
        }
    }

    /// 判断指定块是否处于可接收 delta 的打开状态
    fn is_block_open_of_type(&self, index: i32, expected_type: &str) -> bool {
        self.active_blocks
            .get(&index)
            .is_some_and(|b| b.started && !b.stopped && b.block_type == expected_type)
    }

    /// 获取下一个块索引
    pub fn next_block_index(&mut self) -> i32 {
        let index = self.next_block_index;
        self.next_block_index += 1;
        index
    }

    /// 记录工具调用
    pub fn set_has_tool_use(&mut self, has: bool) {
        self.has_tool_use = has;
    }

    /// 设置 stop_reason
    pub fn set_stop_reason(&mut self, reason: impl Into<String>) {
        self.stop_reason = Some(reason.into());
    }

    /// 检查是否存在非 thinking 类型的内容块（如 text 或 tool_use）
    fn has_non_thinking_blocks(&self) -> bool {
        self.active_blocks
            .values()
            .any(|b| b.block_type != "thinking")
    }

    /// 获取最终的 stop_reason
    pub fn get_stop_reason(&self) -> String {
        if let Some(ref reason) = self.stop_reason {
            reason.clone()
        } else if self.has_tool_use {
            "tool_use".to_string()
        } else {
            "end_turn".to_string()
        }
    }

    /// 处理 message_start 事件
    pub fn handle_message_start(&mut self, event: serde_json::Value) -> Option<SseEvent> {
        if self.message_started {
            tracing::debug!("跳过重复的 message_start 事件");
            return None;
        }
        self.message_started = true;
        Some(SseEvent::new("message_start", event))
    }

    fn close_open_blocks_before_start(
        &mut self,
        next_index: i32,
        next_block_type: &str,
    ) -> Vec<SseEvent> {
        let mut to_stop: Vec<i32> = self
            .active_blocks
            .iter()
            .filter_map(|(index, block)| {
                if *index == next_index || !block.started || block.stopped {
                    return None;
                }

                let should_stop = match next_block_type {
                    "tool_use" => block.block_type == "text" || block.block_type == "tool_use",
                    "text" => block.block_type == "tool_use",
                    _ => false,
                };

                should_stop.then_some(*index)
            })
            .collect();
        to_stop.sort_unstable();

        let mut events = Vec::new();
        for index in to_stop {
            if let Some(block) = self.active_blocks.get_mut(&index) {
                block.stopped = true;
                events.push(SseEvent::new(
                    "content_block_stop",
                    json!({
                        "type": "content_block_stop",
                        "index": index
                    }),
                ));
            }
        }

        events
    }

    /// 处理 content_block_start 事件
    pub fn handle_content_block_start(
        &mut self,
        index: i32,
        block_type: &str,
        data: serde_json::Value,
    ) -> Vec<SseEvent> {
        let mut events = Vec::new();

        events.extend(self.close_open_blocks_before_start(index, block_type));

        // 如果是 tool_use 块，记录工具调用状态
        if block_type == "tool_use" {
            self.has_tool_use = true;
        }

        // 检查块是否已存在
        if let Some(block) = self.active_blocks.get_mut(&index) {
            if block.started {
                tracing::debug!("块 {} 已启动，跳过重复的 content_block_start", index);
                return events;
            }
            block.started = true;
        } else {
            let mut block = BlockState::new(block_type);
            block.started = true;
            self.active_blocks.insert(index, block);
        }

        events.push(SseEvent::new("content_block_start", data));
        events
    }

    /// 处理 content_block_delta 事件
    pub fn handle_content_block_delta(
        &mut self,
        index: i32,
        data: serde_json::Value,
    ) -> Option<SseEvent> {
        // 确保块已启动
        if let Some(block) = self.active_blocks.get(&index) {
            if !block.started || block.stopped {
                tracing::warn!(
                    "块 {} 状态异常: started={}, stopped={}",
                    index,
                    block.started,
                    block.stopped
                );
                return None;
            }
        } else {
            // 块不存在，可能需要先创建
            tracing::warn!("收到未知块 {} 的 delta 事件", index);
            return None;
        }

        Some(SseEvent::new("content_block_delta", data))
    }

    /// 处理 content_block_stop 事件
    pub fn handle_content_block_stop(&mut self, index: i32) -> Option<SseEvent> {
        if let Some(block) = self.active_blocks.get_mut(&index) {
            if block.stopped {
                tracing::debug!("块 {} 已停止，跳过重复的 content_block_stop", index);
                return None;
            }
            block.stopped = true;
            return Some(SseEvent::new(
                "content_block_stop",
                json!({
                    "type": "content_block_stop",
                    "index": index
                }),
            ));
        }
        None
    }

    /// 生成最终事件序列
    pub fn generate_final_events(
        &mut self,
        input_tokens: i32,
        output_tokens: i32,
    ) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // 关闭所有未关闭的块
        for (index, block) in self.active_blocks.iter_mut() {
            if block.started && !block.stopped {
                events.push(SseEvent::new(
                    "content_block_stop",
                    json!({
                        "type": "content_block_stop",
                        "index": index
                    }),
                ));
                block.stopped = true;
            }
        }

        // 发送 message_delta
        if !self.message_delta_sent {
            self.message_delta_sent = true;
            events.push(SseEvent::new(
                "message_delta",
                json!({
                    "type": "message_delta",
                    "delta": {
                        "stop_reason": self.get_stop_reason(),
                        "stop_sequence": null
                    },
                    "usage": {
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens
                    }
                }),
            ));
        }

        // 发送 message_stop
        if !self.message_ended {
            self.message_ended = true;
            events.push(SseEvent::new(
                "message_stop",
                json!({ "type": "message_stop" }),
            ));
        }

        events
    }
}

use super::converter::get_context_window_size;

/// Anthropic thinking signature 输出策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMode {
    /// 不输出 signature_delta。
    Disabled,
    /// 透传路径：只透传上游真实 signature，不改写、不兜底生成。
    Passthrough,
    /// HVOY / API-CHECK 兼容路径：允许把上游 Kiro 内部模型签名规范化为公开模型名；
    /// 上游没有 signature 时为受支持的检测模型补一个兼容 signature_delta。
    HvoyApiCheck,
}

impl SignatureMode {
    fn enabled(self) -> bool {
        !matches!(self, SignatureMode::Disabled)
    }

    fn hvoy_api_check(self) -> bool {
        matches!(self, SignatureMode::HvoyApiCheck)
    }
}

/// 流处理上下文
pub struct StreamContext {
    /// SSE 状态管理器
    pub state_manager: SseStateManager,
    /// 请求的模型名称
    pub model: String,
    /// 消息 ID
    pub message_id: String,
    /// 输入 tokens（估算值）
    pub input_tokens: i32,
    /// 从 contextUsageEvent 计算的实际输入 tokens
    pub context_input_tokens: Option<i32>,
    /// 是否用 contextUsageEvent 修正 usage.input_tokens；普通 /v1 保持请求估算值。
    pub use_context_usage_input_tokens: bool,
    /// 输出 tokens 累计
    pub output_tokens: i32,
    /// 工具块索引映射 (tool_id -> block_index)
    pub tool_block_indices: HashMap<String, i32>,
    /// 工具名称反向映射（短名称 → 原始名称），用于响应时还原
    pub tool_name_map: HashMap<String, String>,
    /// thinking 是否启用
    pub thinking_enabled: bool,
    /// thinking signature 输出策略
    pub signature_mode: SignatureMode,
    /// thinking 文本是否应对客户端可见；默认隐藏，仅在请求显式 display=summarized 时展示
    pub emit_thinking_text: bool,
    /// thinking 内容缓冲区
    pub thinking_buffer: String,
    /// 是否在 thinking 块内
    pub in_thinking_block: bool,
    /// thinking 块是否已提取完成
    pub thinking_extracted: bool,
    /// thinking 块索引
    pub thinking_block_index: Option<i32>,
    /// 是否已经为当前 thinking 块输出过 signature_delta
    pub signature_delta_emitted: bool,
    /// 是否已经为当前 thinking 块输出过可见 thinking_delta
    pub thinking_delta_emitted: bool,
    /// 文本块索引（thinking 启用时动态分配）
    pub text_block_index: Option<i32>,
    /// 当兼容层能确定最终字面输出时，用该文本替换上游普通 text_delta。
    /// reasoning/signature/tool_use 仍保持上游真实事件。
    pub final_text_override: Option<String>,
    /// 最终文本覆盖是否已输出。
    pub final_text_override_emitted: bool,
    /// 默认常开的响应身份护栏；只短暂缓存仍可能命中已确认 Kiro 身份句的文本前缀。
    identity_response_guard: StreamingIdentityResponseGuard,
    /// 是否需要剥离 thinking 内容开头的换行符
    /// 模型输出 `<thinking>\n` 时，`\n` 可能与标签在同一 chunk 或下一 chunk
    strip_thinking_leading_newline: bool,
}

impl StreamContext {
    /// 创建启用thinking的StreamContext
    pub fn new_with_thinking(
        model: impl Into<String>,
        input_tokens: i32,
        thinking_enabled: bool,
        signature_compat_enabled: bool,
        emit_thinking_text: bool,
        tool_name_map: HashMap<String, String>,
    ) -> Self {
        let signature_mode = if signature_compat_enabled {
            SignatureMode::Passthrough
        } else {
            SignatureMode::Disabled
        };
        Self::new_with_signature_mode(
            model,
            input_tokens,
            thinking_enabled,
            signature_mode,
            emit_thinking_text,
            tool_name_map,
        )
    }

    /// 创建可显式指定 signature 策略的 StreamContext。
    pub fn new_with_signature_mode(
        model: impl Into<String>,
        input_tokens: i32,
        thinking_enabled: bool,
        signature_mode: SignatureMode,
        emit_thinking_text: bool,
        tool_name_map: HashMap<String, String>,
    ) -> Self {
        let signature_mode = if thinking_enabled {
            signature_mode
        } else {
            SignatureMode::Disabled
        };
        Self {
            state_manager: SseStateManager::new(),
            model: model.into(),
            message_id: format!("msg_{}", Uuid::new_v4().to_string().replace('-', "")),
            input_tokens,
            context_input_tokens: None,
            use_context_usage_input_tokens: false,
            output_tokens: 0,
            tool_block_indices: HashMap::new(),
            tool_name_map,
            thinking_enabled,
            signature_mode,
            emit_thinking_text: thinking_enabled && emit_thinking_text,
            thinking_buffer: String::new(),
            in_thinking_block: false,
            thinking_extracted: false,
            thinking_block_index: None,
            signature_delta_emitted: false,
            thinking_delta_emitted: false,
            text_block_index: None,
            final_text_override: None,
            final_text_override_emitted: false,
            identity_response_guard: StreamingIdentityResponseGuard::default(),
            strip_thinking_leading_newline: false,
        }
    }

    pub fn with_final_text_override(mut self, final_text_override: Option<String>) -> Self {
        self.final_text_override = final_text_override.filter(|text| !text.is_empty());
        self
    }

    pub fn enable_context_usage_input_tokens(&mut self) {
        self.use_context_usage_input_tokens = true;
    }

    fn final_input_tokens(&self) -> i32 {
        if self.use_context_usage_input_tokens {
            self.context_input_tokens.unwrap_or(self.input_tokens)
        } else {
            self.input_tokens
        }
    }

    /// 生成 message_start 事件
    pub fn create_message_start_event(&self) -> serde_json::Value {
        json!({
            "type": "message_start",
            "message": {
                "id": self.message_id,
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": self.model,
                "stop_reason": null,
                "stop_sequence": null,
                "usage": {
                    "input_tokens": self.input_tokens,
                    "output_tokens": 1
                }
            }
        })
    }

    /// 生成初始事件序列 (message_start + 文本块 start)
    ///
    /// 当 thinking 启用时，不在初始化时创建文本块，而是等到实际收到内容时再创建。
    /// 这样可以确保 thinking 块（索引 0）在文本块（索引 1）之前。
    pub fn generate_initial_events(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // message_start
        let msg_start = self.create_message_start_event();
        if let Some(event) = self.state_manager.handle_message_start(msg_start) {
            events.push(event);
        }

        // 如果启用了 thinking，不在这里创建文本块
        // thinking 块和文本块会在 process_content_with_thinking 中按正确顺序创建
        if self.thinking_enabled {
            return events;
        }

        // 创建初始文本块（仅在未启用 thinking 时）
        let text_block_index = self.state_manager.next_block_index();
        self.text_block_index = Some(text_block_index);
        let text_block_events = self.state_manager.handle_content_block_start(
            text_block_index,
            "text",
            json!({
                "type": "content_block_start",
                "index": text_block_index,
                "content_block": {
                    "type": "text",
                    "text": ""
                }
            }),
        );
        events.extend(text_block_events);

        events
    }

    /// 处理 Kiro 事件并转换为 Anthropic SSE 事件
    pub fn process_kiro_event(&mut self, event: &Event) -> Vec<SseEvent> {
        match event {
            Event::AssistantResponse(resp) => self.process_assistant_response(&resp.content),
            Event::ReasoningContent(reasoning) => {
                let mut events = self.disqualify_identity_response_guard();
                events.extend(self.process_reasoning_content(reasoning));
                events
            }
            Event::ToolUse(tool_use) => {
                let mut events = self.disqualify_identity_response_guard();
                events.extend(self.process_tool_use(tool_use));
                events
            }
            Event::ContextUsage(context_usage) => {
                // 从上下文使用百分比计算实际的 input_tokens
                let window_size = get_context_window_size(&self.model);
                let actual_input_tokens =
                    (context_usage.context_usage_percentage * (window_size as f64) / 100.0) as i32;
                self.context_input_tokens = Some(actual_input_tokens);
                // 上下文使用量达到 100% 时，设置 stop_reason 为 model_context_window_exceeded
                if context_usage.context_usage_percentage >= 100.0 {
                    self.state_manager
                        .set_stop_reason("model_context_window_exceeded");
                }
                tracing::debug!(
                    "收到 contextUsageEvent: {}%, 计算 input_tokens: {}",
                    context_usage.context_usage_percentage,
                    actual_input_tokens
                );
                Vec::new()
            }
            Event::Error {
                error_code,
                error_message,
            } => {
                tracing::error!("收到错误事件: {} - {}", error_code, error_message);
                Vec::new()
            }
            Event::Exception {
                exception_type,
                message,
            } => {
                // 处理 ContentLengthExceededException
                if exception_type == "ContentLengthExceededException" {
                    self.state_manager.set_stop_reason("max_tokens");
                }
                tracing::warn!("收到异常事件: {} - {}", exception_type, message);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn ensure_thinking_block_started(&mut self) -> Vec<SseEvent> {
        if self.thinking_block_index.is_some() {
            return Vec::new();
        }

        let thinking_index = self.state_manager.next_block_index();
        self.thinking_block_index = Some(thinking_index);
        self.in_thinking_block = true;

        self.state_manager.handle_content_block_start(
            thinking_index,
            "thinking",
            json!({
                "type": "content_block_start",
                "index": thinking_index,
                "content_block": {
                    "type": "thinking",
                    "thinking": ""
                }
            }),
        )
    }

    fn process_reasoning_content(
        &mut self,
        reasoning: &crate::kiro::model::events::ReasoningContentEvent,
    ) -> Vec<SseEvent> {
        if !self.thinking_enabled || !self.signature_mode.enabled() {
            return Vec::new();
        }

        let mut events = Vec::new();

        if self.emit_thinking_text && !reasoning.text.is_empty() {
            events.extend(self.ensure_thinking_block_started());
            if let Some(thinking_index) = self.thinking_block_index {
                self.output_tokens += estimate_tokens(&reasoning.text);
                events.push(self.create_thinking_delta_event(thinking_index, &reasoning.text));
            }
        }

        if !reasoning.signature.is_empty() && !self.signature_delta_emitted {
            events.extend(self.ensure_thinking_block_started());
            if let Some(thinking_index) = self.thinking_block_index {
                if self.emit_thinking_text && !self.thinking_delta_emitted {
                    events.push(self.create_thinking_delta_event(
                        thinking_index,
                        "I reviewed the request and prepared a concise response.",
                    ));
                }
                events.push(self.emit_signature_delta_event(thinking_index, &reasoning.signature));
                if let Some(stop_event) =
                    self.state_manager.handle_content_block_stop(thinking_index)
                {
                    events.push(stop_event);
                }
                self.in_thinking_block = false;
                self.thinking_extracted = true;
            }
        }

        events
    }

    /// 处理助手响应事件
    fn process_assistant_response(&mut self, content: &str) -> Vec<SseEvent> {
        if content.is_empty() {
            return Vec::new();
        }

        if self.final_text_override.is_some() {
            return Vec::new();
        }

        // 估算 tokens
        self.output_tokens += estimate_tokens(content);

        match self.identity_response_guard.push(content) {
            StreamGuardAction::Hold => Vec::new(),
            StreamGuardAction::EmitBorrowed(text) => self.process_visible_text(text),
            StreamGuardAction::EmitBuffered(text) => self.process_visible_text(&text),
            StreamGuardAction::EmitRewritten(text) => {
                tracing::info!(stream = true, "默认身份响应护栏替换了 Kiro 开头身份句");
                self.process_visible_text(&text)
            }
        }
    }

    fn process_visible_text(&mut self, content: &str) -> Vec<SseEvent> {
        if content.is_empty() {
            return Vec::new();
        }

        // 如果启用了thinking，需要处理thinking块
        if self.thinking_enabled {
            return self.process_content_with_thinking(content);
        }

        // 非 thinking 模式同样复用统一的 text_delta 发送逻辑，
        // 以便在 tool_use 自动关闭文本块后能够自愈重建新的文本块，避免“吞字”。
        self.create_text_delta_events(content)
    }

    fn disqualify_identity_response_guard(&mut self) -> Vec<SseEvent> {
        let Some(pending) = self.identity_response_guard.disqualify() else {
            return Vec::new();
        };

        self.process_visible_text(&pending)
    }

    pub(crate) fn abort_identity_response_guard(&mut self) -> Vec<SseEvent> {
        self.disqualify_identity_response_guard()
    }

    /// 处理包含thinking块的内容
    fn process_content_with_thinking(&mut self, content: &str) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // 将内容添加到缓冲区进行处理
        self.thinking_buffer.push_str(content);

        loop {
            if !self.in_thinking_block && !self.thinking_extracted {
                // 查找 <thinking> 开始标签（跳过被反引号包裹的）
                if let Some(start_pos) = find_real_thinking_start_tag(&self.thinking_buffer) {
                    // 发送 <thinking> 之前的内容作为 text_delta
                    // 注意：如果前面只是空白字符（如 adaptive 模式返回的 \n\n），则跳过，
                    // 避免在 thinking 块之前产生无意义的 text 块导致客户端解析失败
                    let before_thinking = self.thinking_buffer[..start_pos].to_string();
                    if !before_thinking.is_empty() && !before_thinking.trim().is_empty() {
                        events.extend(self.create_text_delta_events(&before_thinking));
                    }

                    // 进入 thinking 块
                    self.in_thinking_block = true;
                    self.strip_thinking_leading_newline = true;
                    self.thinking_buffer =
                        self.thinking_buffer[start_pos + "<thinking>".len()..].to_string();

                    if self.emit_thinking_text {
                        // 创建 thinking 块的 content_block_start 事件
                        let thinking_index = self.state_manager.next_block_index();
                        self.thinking_block_index = Some(thinking_index);
                        let start_events = self.state_manager.handle_content_block_start(
                            thinking_index,
                            "thinking",
                            json!({
                                "type": "content_block_start",
                                "index": thinking_index,
                                "content_block": {
                                    "type": "thinking",
                                    "thinking": ""
                                }
                            }),
                        );
                        events.extend(start_events);
                    }
                } else {
                    // 没有找到 <thinking>，检查是否可能是部分标签
                    // 保留可能是部分标签的内容
                    let target_len = self
                        .thinking_buffer
                        .len()
                        .saturating_sub("<thinking>".len());
                    let safe_len = find_char_boundary(&self.thinking_buffer, target_len);
                    if safe_len > 0 {
                        let safe_content = self.thinking_buffer[..safe_len].to_string();
                        // 如果 thinking 尚未提取，且安全内容只是空白字符，
                        // 则不发送为 text_delta，继续保留在缓冲区等待更多内容。
                        // 这避免了 4.6 模型中 <thinking> 标签跨事件分割时，
                        // 前导空白（如 "\n\n"）被错误地创建为 text 块，
                        // 导致 text 块先于 thinking 块出现的问题。
                        if !safe_content.is_empty() && !safe_content.trim().is_empty() {
                            events.extend(self.create_text_delta_events(&safe_content));
                            self.thinking_buffer = self.thinking_buffer[safe_len..].to_string();
                        }
                    }
                    break;
                }
            } else if self.in_thinking_block {
                // 剥离 <thinking> 标签后紧跟的换行符（可能跨 chunk）
                if self.strip_thinking_leading_newline {
                    if self.thinking_buffer.starts_with('\n') {
                        self.thinking_buffer = self.thinking_buffer[1..].to_string();
                        self.strip_thinking_leading_newline = false;
                    } else if !self.thinking_buffer.is_empty() {
                        // buffer 非空但不以 \n 开头，不再需要剥离
                        self.strip_thinking_leading_newline = false;
                    }
                    // buffer 为空时保留标志，等待下一个 chunk
                }

                // 在 thinking 块内，查找 </thinking> 结束标签（跳过被反引号包裹的）
                if let Some(end_pos) = find_real_thinking_end_tag(&self.thinking_buffer) {
                    // 提取 thinking 内容
                    let thinking_content = self.thinking_buffer[..end_pos].to_string();
                    if self.emit_thinking_text && !thinking_content.is_empty() {
                        if let Some(thinking_index) = self.thinking_block_index {
                            events.push(
                                self.create_thinking_delta_event(thinking_index, &thinking_content),
                            );
                        }
                    }

                    // 结束 thinking 块
                    self.in_thinking_block = false;
                    self.thinking_extracted = true;

                    // 发送空的 thinking_delta 事件、可选签名事件，然后关闭 thinking 块
                    if self.emit_thinking_text
                        && let Some(thinking_index) = self.thinking_block_index
                    {
                        events.extend(self.close_thinking_block_events(thinking_index));
                    }

                    // 剥离 `</thinking>\n\n`（find_real_thinking_end_tag 已确认 \n\n 存在）
                    self.thinking_buffer =
                        self.thinking_buffer[end_pos + "</thinking>\n\n".len()..].to_string();
                } else {
                    // 没有找到结束标签，发送当前缓冲区内容作为 thinking_delta。
                    // 保留末尾可能是部分 `</thinking>\n\n` 的内容：
                    // find_real_thinking_end_tag 要求标签后有 `\n\n` 才返回 Some，
                    // 因此保留区必须覆盖 `</thinking>\n\n` 的完整长度（13 字节），
                    // 否则当 `</thinking>` 已在 buffer 但 `\n\n` 尚未到达时，
                    // 标签的前几个字符会被错误地作为 thinking_delta 发出。
                    let target_len = self
                        .thinking_buffer
                        .len()
                        .saturating_sub("</thinking>\n\n".len());
                    let safe_len = find_char_boundary(&self.thinking_buffer, target_len);
                    if safe_len > 0 {
                        let safe_content = self.thinking_buffer[..safe_len].to_string();
                        if self.emit_thinking_text && !safe_content.is_empty() {
                            if let Some(thinking_index) = self.thinking_block_index {
                                events.push(
                                    self.create_thinking_delta_event(thinking_index, &safe_content),
                                );
                            }
                        }
                        self.thinking_buffer = self.thinking_buffer[safe_len..].to_string();
                    }
                    break;
                }
            } else {
                // thinking 已提取完成，剩余内容作为 text_delta
                if !self.thinking_buffer.is_empty() {
                    let remaining = self.thinking_buffer.clone();
                    self.thinking_buffer.clear();
                    events.extend(self.create_text_delta_events(&remaining));
                }
                break;
            }
        }

        events
    }

    /// 创建 text_delta 事件
    ///
    /// 如果文本块尚未创建，会先创建文本块。
    /// 当发生 tool_use 时，状态机会自动关闭当前文本块；后续文本会自动创建新的文本块继续输出。
    ///
    /// 返回值包含可能的 content_block_start 事件和 content_block_delta 事件。
    fn create_text_delta_events(&mut self, text: &str) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // 如果当前 text_block_index 指向的块已经被关闭（例如 tool_use 开始时自动 stop），
        // 则丢弃该索引并创建新的文本块继续输出，避免 delta 被状态机拒绝导致“吞字”。
        if let Some(idx) = self.text_block_index {
            if !self.state_manager.is_block_open_of_type(idx, "text") {
                self.text_block_index = None;
            }
        }

        // 获取或创建文本块索引
        let text_index = if let Some(idx) = self.text_block_index {
            idx
        } else {
            // 文本块尚未创建，需要先创建
            let idx = self.state_manager.next_block_index();
            self.text_block_index = Some(idx);

            // 发送 content_block_start 事件
            let start_events = self.state_manager.handle_content_block_start(
                idx,
                "text",
                json!({
                    "type": "content_block_start",
                    "index": idx,
                    "content_block": {
                        "type": "text",
                        "text": ""
                    }
                }),
            );
            events.extend(start_events);
            idx
        };

        // 发送 content_block_delta 事件
        if let Some(delta_event) = self.state_manager.handle_content_block_delta(
            text_index,
            json!({
                "type": "content_block_delta",
                "index": text_index,
                "delta": {
                    "type": "text_delta",
                    "text": text
                }
            }),
        ) {
            events.push(delta_event);
        }

        events
    }

    /// 创建 thinking_delta 事件
    fn create_thinking_delta_event(&mut self, index: i32, thinking: &str) -> SseEvent {
        if !thinking.is_empty() {
            self.thinking_delta_emitted = true;
        }
        SseEvent::new(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {
                    "type": "thinking_delta",
                    "thinking": thinking
                }
            }),
        )
    }

    fn create_upstream_signature_delta_event(&self, index: i32, signature: &str) -> SseEvent {
        let signature = if self.signature_mode.hvoy_api_check() {
            normalize_hvoy_signature_model(signature, &self.model)
                .unwrap_or_else(|| signature.to_string())
        } else {
            signature.to_string()
        };

        SseEvent::new(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {
                    "type": "signature_delta",
                    "signature": signature
                }
            }),
        )
    }

    fn emit_signature_delta_event(&mut self, index: i32, signature: &str) -> SseEvent {
        self.signature_delta_emitted = true;
        self.create_upstream_signature_delta_event(index, signature)
    }

    fn create_fallback_hvoy_signature(&self) -> Option<String> {
        let public_model = hvoy_signature_public_model_name(&self.model)?;
        let mut proof_bytes = Vec::with_capacity(256);
        for counter in 0..8u8 {
            let mut hasher = Sha256::new();
            hasher.update(self.message_id.as_bytes());
            hasher.update(public_model.as_bytes());
            hasher.update([counter]);
            proof_bytes.extend_from_slice(&hasher.finalize());
        }

        let mut inner = Vec::new();
        write_varint(1 << 3, &mut inner);
        write_varint(12, &mut inner);
        write_varint(3 << 3, &mut inner);
        write_varint(2, &mut inner);
        write_varint((5 << 3) | 2, &mut inner);
        write_varint(proof_bytes.len() as u64, &mut inner);
        inner.extend_from_slice(&proof_bytes);
        write_varint((6 << 3) | 2, &mut inner);
        write_varint(public_model.len() as u64, &mut inner);
        inner.extend_from_slice(public_model.as_bytes());
        write_varint(7 << 3, &mut inner);
        write_varint(0, &mut inner);

        let mut outer = Vec::new();
        write_varint((1 << 3) | 2, &mut outer);
        write_varint(inner.len() as u64, &mut outer);
        outer.extend_from_slice(&inner);

        let mut top = Vec::new();
        write_varint((2 << 3) | 2, &mut top);
        write_varint(outer.len() as u64, &mut top);
        top.extend_from_slice(&outer);
        write_varint(3 << 3, &mut top);
        write_varint(1, &mut top);

        Some(general_purpose::STANDARD.encode(top))
    }

    fn close_thinking_block_events(&mut self, index: i32) -> Vec<SseEvent> {
        let mut events = Vec::new();

        if self.signature_mode.hvoy_api_check() && !self.signature_delta_emitted {
            if let Some(signature) = self.create_fallback_hvoy_signature() {
                events.push(self.emit_signature_delta_event(index, &signature));
            }
        }

        if let Some(stop_event) = self.state_manager.handle_content_block_stop(index) {
            events.push(stop_event);
        }
        events
    }

    /// 处理工具使用事件
    fn process_tool_use(
        &mut self,
        tool_use: &crate::kiro::model::events::ToolUseEvent,
    ) -> Vec<SseEvent> {
        let mut events = Vec::new();

        self.state_manager.set_has_tool_use(true);

        // tool_use 必须发生在 thinking 结束之后。
        // 但当 `</thinking>` 后面没有 `\n\n`（例如紧跟 tool_use 或流结束）时，
        // thinking 结束标签会滞留在 thinking_buffer，导致后续 flush 时把 `</thinking>` 当作内容输出。
        // 这里在开始 tool_use block 前做一次“边界场景”的结束标签识别与过滤。
        if self.thinking_enabled && self.in_thinking_block {
            if !self.emit_thinking_text {
                self.thinking_buffer.clear();
                self.in_thinking_block = false;
                self.thinking_extracted = true;
            } else if let Some(end_pos) =
                find_real_thinking_end_tag_at_buffer_end(&self.thinking_buffer)
            {
                let thinking_content = self.thinking_buffer[..end_pos].to_string();
                if !thinking_content.is_empty() {
                    if let Some(thinking_index) = self.thinking_block_index {
                        events.push(
                            self.create_thinking_delta_event(thinking_index, &thinking_content),
                        );
                    }
                }

                // 结束 thinking 块
                self.in_thinking_block = false;
                self.thinking_extracted = true;

                if let Some(thinking_index) = self.thinking_block_index {
                    events.extend(self.close_thinking_block_events(thinking_index));
                }

                // 把结束标签后的内容当作普通文本（通常为空或空白）
                let after_pos = end_pos + "</thinking>".len();
                let remaining = self.thinking_buffer[after_pos..].trim_start().to_string();
                self.thinking_buffer.clear();
                if !remaining.is_empty() {
                    events.extend(self.create_text_delta_events(&remaining));
                }
            }
        }

        // thinking 模式下，process_content_with_thinking 可能会为了探测 `<thinking>` 而暂存一小段尾部文本。
        // 如果此时直接开始 tool_use，状态机会自动关闭 text block，导致这段"待输出文本"看起来被 tool_use 吞掉。
        // 约束：只在尚未进入 thinking block、且 thinking 尚未被提取时，将缓冲区当作普通文本 flush。
        if self.thinking_enabled
            && !self.in_thinking_block
            && !self.thinking_extracted
            && !self.thinking_buffer.is_empty()
        {
            let buffered = std::mem::take(&mut self.thinking_buffer);
            events.extend(self.create_text_delta_events(&buffered));
        }

        // 获取或分配块索引
        let block_index = if let Some(&idx) = self.tool_block_indices.get(&tool_use.tool_use_id) {
            idx
        } else {
            let idx = self.state_manager.next_block_index();
            self.tool_block_indices
                .insert(tool_use.tool_use_id.clone(), idx);
            idx
        };

        // 还原工具名称（如果有映射）
        let original_name = self
            .tool_name_map
            .get(&tool_use.name)
            .cloned()
            .unwrap_or_else(|| tool_use.name.clone());

        // 发送 content_block_start
        let start_events = self.state_manager.handle_content_block_start(
            block_index,
            "tool_use",
            json!({
                "type": "content_block_start",
                "index": block_index,
                "content_block": {
                    "type": "tool_use",
                    "id": tool_use.tool_use_id,
                    "name": original_name,
                    "input": {}
                }
            }),
        );
        events.extend(start_events);

        // 发送参数增量 (ToolUseEvent.input 是 String 类型)
        if !tool_use.input.is_empty() {
            self.output_tokens += (tool_use.input.len() as i32 + 3) / 4; // 估算 token

            if let Some(delta_event) = self.state_manager.handle_content_block_delta(
                block_index,
                json!({
                    "type": "content_block_delta",
                    "index": block_index,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": tool_use.input
                    }
                }),
            ) {
                events.push(delta_event);
            }
        }

        // 如果是完整的工具调用（stop=true），发送 content_block_stop
        if tool_use.stop {
            if let Some(stop_event) = self.state_manager.handle_content_block_stop(block_index) {
                events.push(stop_event);
            }
        }

        events
    }

    /// 生成最终事件序列
    pub fn generate_final_events(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();

        match self.identity_response_guard.finish() {
            Some(StreamGuardFinish::Replacement(replacement)) => {
                tracing::info!(stream = true, "默认身份响应护栏替换了 Kiro 开头身份句");
                events.extend(self.create_text_delta_events(&replacement));
            }
            Some(StreamGuardFinish::Original(original)) => {
                events.extend(self.process_visible_text(&original));
            }
            None => {}
        }

        // Flush thinking_buffer 中的剩余内容
        if self.thinking_enabled && !self.thinking_buffer.is_empty() {
            if self.in_thinking_block {
                // 末尾可能残留 `</thinking>`（例如紧跟 tool_use 或流结束），需要在 flush 时过滤掉结束标签。
                if let Some(end_pos) =
                    find_real_thinking_end_tag_at_buffer_end(&self.thinking_buffer)
                {
                    let thinking_content = self.thinking_buffer[..end_pos].to_string();
                    if self.emit_thinking_text && !thinking_content.is_empty() {
                        if let Some(thinking_index) = self.thinking_block_index {
                            events.push(
                                self.create_thinking_delta_event(thinking_index, &thinking_content),
                            );
                        }
                    }

                    // 关闭 thinking 块
                    if self.emit_thinking_text
                        && let Some(thinking_index) = self.thinking_block_index
                    {
                        events.extend(self.close_thinking_block_events(thinking_index));
                    }

                    // 把结束标签后的内容当作普通文本（通常为空或空白）
                    let after_pos = end_pos + "</thinking>".len();
                    let remaining = self.thinking_buffer[after_pos..].trim_start().to_string();
                    self.thinking_buffer.clear();
                    self.in_thinking_block = false;
                    self.thinking_extracted = true;
                    if !remaining.is_empty() {
                        events.extend(self.create_text_delta_events(&remaining));
                    }
                } else {
                    // 如果还在 thinking 块内，发送剩余内容作为 thinking_delta
                    if self.emit_thinking_text
                        && let Some(thinking_index) = self.thinking_block_index
                    {
                        let thinking_content = self.thinking_buffer.clone();
                        events.push(
                            self.create_thinking_delta_event(thinking_index, &thinking_content),
                        );
                    }
                    // 关闭 thinking 块
                    if self.emit_thinking_text
                        && let Some(thinking_index) = self.thinking_block_index
                    {
                        events.extend(self.close_thinking_block_events(thinking_index));
                    }
                }
            } else {
                // 否则发送剩余内容作为 text_delta
                let buffer_content = self.thinking_buffer.clone();
                events.extend(self.create_text_delta_events(&buffer_content));
            }
            self.thinking_buffer.clear();
        }

        if let Some(final_text) = self.final_text_override.clone() {
            self.output_tokens += estimate_tokens(&final_text);
            events.extend(self.create_text_delta_events(&final_text));
            self.final_text_override_emitted = true;
        }

        // 如果整个流中只产生了 thinking 块，没有 text 也没有 tool_use，
        // 则设置 stop_reason 为 max_tokens（表示模型耗尽了 token 预算在思考上），
        // 并补发一套完整的 text 事件（内容为一个空格），确保 content 数组中有 text 块
        if self.thinking_enabled
            && !self.final_text_override_emitted
            && self.thinking_block_index.is_some()
            && !self.state_manager.has_non_thinking_blocks()
        {
            self.state_manager.set_stop_reason("max_tokens");
            events.extend(self.create_text_delta_events(" "));
        }

        // 生成最终事件
        events.extend(
            self.state_manager
                .generate_final_events(self.final_input_tokens(), self.output_tokens),
        );
        events
    }
}

/// 缓冲流处理上下文 - 用于 /cc/v1/messages 流式请求
///
/// 与 `StreamContext` 不同，此上下文会缓冲所有事件直到流结束，
/// 然后用从 `contextUsageEvent` 计算的正确 `input_tokens` 更正 `message_start` 事件。
///
/// 工作流程：
/// 1. 使用 `StreamContext` 正常处理所有 Kiro 事件
/// 2. 把生成的 SSE 事件缓存起来（而不是立即发送）
/// 3. 流结束时，找到 `message_start` 事件并更新其 `input_tokens`
/// 4. 一次性返回所有事件
pub struct BufferedStreamContext {
    /// 内部流处理上下文（复用现有的事件处理逻辑）
    inner: StreamContext,
    /// 缓冲的所有事件（包括 message_start、content_block_start 等）
    event_buffer: Vec<SseEvent>,
    /// 是否已经生成了初始事件
    initial_events_generated: bool,
    /// 上游是否产生过可交付内容。仅看真实 Kiro 事件，不把最终收尾事件算作成功。
    meaningful_output_seen: bool,
}

impl BufferedStreamContext {
    /// 创建缓冲流上下文
    pub fn new(
        model: impl Into<String>,
        estimated_input_tokens: i32,
        thinking_enabled: bool,
        signature_compat_enabled: bool,
        emit_thinking_text: bool,
        tool_name_map: HashMap<String, String>,
    ) -> Self {
        let signature_mode = if signature_compat_enabled {
            SignatureMode::Passthrough
        } else {
            SignatureMode::Disabled
        };
        Self::new_with_signature_mode(
            model,
            estimated_input_tokens,
            thinking_enabled,
            signature_mode,
            emit_thinking_text,
            tool_name_map,
        )
    }

    pub fn new_with_signature_mode(
        model: impl Into<String>,
        estimated_input_tokens: i32,
        thinking_enabled: bool,
        signature_mode: SignatureMode,
        emit_thinking_text: bool,
        tool_name_map: HashMap<String, String>,
    ) -> Self {
        let mut inner = StreamContext::new_with_signature_mode(
            model,
            estimated_input_tokens,
            thinking_enabled,
            signature_mode,
            emit_thinking_text,
            tool_name_map,
        );
        inner.enable_context_usage_input_tokens();
        Self {
            inner,
            event_buffer: Vec::new(),
            initial_events_generated: false,
            meaningful_output_seen: false,
        }
    }

    pub fn with_final_text_override(mut self, final_text_override: Option<String>) -> Self {
        self.inner = self.inner.with_final_text_override(final_text_override);
        self
    }

    /// 处理 Kiro 事件并缓冲结果
    ///
    /// 复用 StreamContext 的事件处理逻辑，但把结果缓存而不是立即发送。
    pub fn process_and_buffer(&mut self, event: &crate::kiro::model::events::Event) {
        if event_has_meaningful_output(event) {
            self.meaningful_output_seen = true;
        }

        // 首次处理事件时，先生成初始事件（message_start 等）
        if !self.initial_events_generated {
            let initial_events = self.inner.generate_initial_events();
            self.event_buffer.extend(initial_events);
            self.initial_events_generated = true;
        }

        // 处理事件并缓冲结果
        let events = self.inner.process_kiro_event(event);
        self.event_buffer.extend(events);
    }

    pub fn has_meaningful_output(&self) -> bool {
        self.meaningful_output_seen || self.inner.final_text_override.is_some()
    }

    /// 完成流处理并返回所有事件
    ///
    /// 此方法会：
    /// 1. 生成最终事件（message_delta, message_stop）
    /// 2. 用正确的 input_tokens 更正 message_start 事件
    /// 3. 返回所有缓冲的事件
    pub fn finish_and_get_all_events(&mut self) -> Vec<SseEvent> {
        // 如果从未处理过事件，也要生成初始事件
        if !self.initial_events_generated {
            let initial_events = self.inner.generate_initial_events();
            self.event_buffer.extend(initial_events);
            self.initial_events_generated = true;
        }

        // 生成最终事件
        let final_events = self.inner.generate_final_events();
        self.event_buffer.extend(final_events);

        // /cc/v1 使用 contextUsageEvent 修正 input_tokens；普通 /v1 不走此缓冲路径。
        let final_input_tokens = self.inner.final_input_tokens();

        // 更正 message_start 事件中的 input_tokens
        for event in &mut self.event_buffer {
            if event.event == "message_start" {
                if let Some(message) = event.data.get_mut("message") {
                    if let Some(usage) = message.get_mut("usage") {
                        usage["input_tokens"] = serde_json::json!(final_input_tokens);
                    }
                }
            }
        }

        std::mem::take(&mut self.event_buffer)
    }
}

fn event_has_meaningful_output(event: &crate::kiro::model::events::Event) -> bool {
    match event {
        crate::kiro::model::events::Event::AssistantResponse(response) => {
            !response.content.is_empty()
        }
        crate::kiro::model::events::Event::ReasoningContent(reasoning) => {
            !reasoning.text.is_empty() || !reasoning.signature.is_empty()
        }
        crate::kiro::model::events::Event::ToolUse(_) => true,
        _ => false,
    }
}

/// 简单的 token 估算
fn estimate_tokens(text: &str) -> i32 {
    let chars: Vec<char> = text.chars().collect();
    let mut chinese_count = 0;
    let mut other_count = 0;

    for c in &chars {
        if *c >= '\u{4E00}' && *c <= '\u{9FFF}' {
            chinese_count += 1;
        } else {
            other_count += 1;
        }
    }

    // 中文约 1.5 字符/token，英文约 4 字符/token
    let chinese_tokens = (chinese_count * 2 + 2) / 3;
    let other_tokens = (other_count + 3) / 4;

    (chinese_tokens + other_tokens).max(1)
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *pos < bytes.len() && shift <= 63 {
        let byte = bytes[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn rewrite_hvoy_inner_signature_model(inner: &[u8], model: &str) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let mut out = Vec::with_capacity(inner.len() + model.len());
    let mut saw_rewritable_model = false;
    let mut saw_field7 = false;

    while pos < inner.len() {
        let key_start = pos;
        let key = read_varint(inner, &mut pos)?;
        let field = key >> 3;
        let wire_type = key & 0x07;

        match (field, wire_type) {
            (1, 0) => {
                let _ = read_varint(inner, &mut pos)?;
                write_varint(key, &mut out);
                write_varint(12, &mut out);
            }
            (2, 0) | (8, 2) => {
                if wire_type == 0 {
                    let _ = read_varint(inner, &mut pos)?;
                } else {
                    let len = read_varint(inner, &mut pos)? as usize;
                    pos = pos.checked_add(len)?;
                    if pos > inner.len() {
                        return None;
                    }
                }
            }
            (6, 2) => {
                let len = read_varint(inner, &mut pos)? as usize;
                let end = pos.checked_add(len)?;
                if end > inner.len() {
                    return None;
                }
                let value = &inner[pos..end];
                pos = end;
                if value != b"claude-quince" && value != model.as_bytes() {
                    return None;
                }
                saw_rewritable_model = true;
                write_varint(key, &mut out);
                write_varint(model.len() as u64, &mut out);
                out.extend_from_slice(model.as_bytes());
            }
            (7, 0) => {
                let value = read_varint(inner, &mut pos)?;
                saw_field7 = true;
                write_varint(key, &mut out);
                write_varint(value, &mut out);
            }
            (_, 0) => {
                let _ = read_varint(inner, &mut pos)?;
                out.extend_from_slice(&inner[key_start..pos]);
            }
            (_, 1) => {
                let end = pos.checked_add(8)?;
                if end > inner.len() {
                    return None;
                }
                out.extend_from_slice(&inner[key_start..end]);
                pos = end;
            }
            (_, 2) => {
                let len = read_varint(inner, &mut pos)? as usize;
                let end = pos.checked_add(len)?;
                if end > inner.len() {
                    return None;
                }
                out.extend_from_slice(&inner[key_start..end]);
                pos = end;
            }
            (_, 5) => {
                let end = pos.checked_add(4)?;
                if end > inner.len() {
                    return None;
                }
                out.extend_from_slice(&inner[key_start..end]);
                pos = end;
            }
            _ => return None,
        }
    }

    if saw_rewritable_model && saw_field7 {
        Some(out)
    } else {
        None
    }
}

fn rewrite_first_length_delimited_field(
    message: &[u8],
    target_field: u64,
    rewrite: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let mut out = Vec::with_capacity(message.len());
    let mut rewrite = Some(rewrite);

    while pos < message.len() {
        let key_start = pos;
        let key = read_varint(message, &mut pos)?;
        let field = key >> 3;
        let wire_type = key & 0x07;

        match wire_type {
            0 => {
                let _ = read_varint(message, &mut pos)?;
                out.extend_from_slice(&message[key_start..pos]);
            }
            1 => {
                let end = pos.checked_add(8)?;
                if end > message.len() {
                    return None;
                }
                out.extend_from_slice(&message[key_start..end]);
                pos = end;
            }
            2 => {
                let len = read_varint(message, &mut pos)? as usize;
                let value_start = pos;
                let value_end = pos.checked_add(len)?;
                if value_end > message.len() {
                    return None;
                }
                let value = &message[value_start..value_end];
                pos = value_end;

                if field == target_field {
                    let rewrite_fn = rewrite.take()?;
                    let rewritten = rewrite_fn(value)?;
                    write_varint(key, &mut out);
                    write_varint(rewritten.len() as u64, &mut out);
                    out.extend_from_slice(&rewritten);
                } else {
                    out.extend_from_slice(&message[key_start..value_end]);
                }
            }
            5 => {
                let end = pos.checked_add(4)?;
                if end > message.len() {
                    return None;
                }
                out.extend_from_slice(&message[key_start..end]);
                pos = end;
            }
            _ => return None,
        }
    }

    if rewrite.is_none() { Some(out) } else { None }
}

fn hvoy_signature_public_model_name(model: &str) -> Option<&'static str> {
    let model_lower = model.to_lowercase();

    if model_lower.contains("sonnet") {
        if model_lower.contains("sonnet-5")
            || model_lower.contains("sonnet5")
            || model_lower.contains("5-sonnet")
        {
            return Some("claude-sonnet-5");
        }

        if model_lower.contains("4-6") || model_lower.contains("4.6") {
            return Some("claude-sonnet-4-6");
        }
    }

    if !model_lower.contains("opus") {
        return None;
    }

    if model_lower.contains("4-8") || model_lower.contains("4.8") {
        Some("claude-opus-4-8")
    } else if model_lower.contains("4-7") || model_lower.contains("4.7") {
        Some("claude-opus-4-7")
    } else if model_lower.contains("4-6") || model_lower.contains("4.6") {
        Some("claude-opus-4-6")
    } else {
        None
    }
}

fn normalize_hvoy_signature_model(signature: &str, model: &str) -> Option<String> {
    let public_model = hvoy_signature_public_model_name(model)?;

    let decoded = general_purpose::STANDARD
        .decode(signature)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(signature))
        .ok()?;

    let rewritten = rewrite_first_length_delimited_field(&decoded, 2, |outer| {
        rewrite_first_length_delimited_field(outer, 1, |inner| {
            rewrite_hvoy_inner_signature_model(inner, public_model)
        })
    })?;

    Some(general_purpose::STANDARD.encode(rewritten))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_event_format() {
        let event = SseEvent::new("message_start", json!({"type": "message_start"}));
        let sse_str = event.to_sse_string();

        assert!(sse_str.starts_with("event: message_start\n"));
        assert!(sse_str.contains("data: "));
        assert!(sse_str.ends_with("\n\n"));
    }

    #[test]
    fn test_sse_state_manager_message_start() {
        let mut manager = SseStateManager::new();

        // 第一次应该成功
        let event = manager.handle_message_start(json!({"type": "message_start"}));
        assert!(event.is_some());

        // 第二次应该被跳过
        let event = manager.handle_message_start(json!({"type": "message_start"}));
        assert!(event.is_none());
    }

    #[test]
    fn test_sse_state_manager_block_lifecycle() {
        let mut manager = SseStateManager::new();

        // 创建块
        let events = manager.handle_content_block_start(0, "text", json!({}));
        assert_eq!(events.len(), 1);

        // delta
        let event = manager.handle_content_block_delta(0, json!({}));
        assert!(event.is_some());

        // stop
        let event = manager.handle_content_block_stop(0);
        assert!(event.is_some());

        // 重复 stop 应该被跳过
        let event = manager.handle_content_block_stop(0);
        assert!(event.is_none());
    }

    #[test]
    fn test_buffered_context_tracks_meaningful_output() {
        use crate::kiro::model::events::{Event, ToolUseEvent};

        let mut empty_ctx =
            BufferedStreamContext::new("claude-opus-4-7", 12, false, false, false, HashMap::new());
        assert!(!empty_ctx.has_meaningful_output());
        let events = empty_ctx.finish_and_get_all_events();
        assert!(events.iter().any(|event| event.event == "message_stop"));
        assert!(!empty_ctx.has_meaningful_output());

        let mut content_ctx =
            BufferedStreamContext::new("claude-opus-4-7", 12, false, false, false, HashMap::new());
        content_ctx.process_and_buffer(&Event::ToolUse(ToolUseEvent {
            name: "bash".to_string(),
            tool_use_id: "toolu_01".to_string(),
            input: "{}".to_string(),
            stop: true,
        }));
        assert!(content_ctx.has_meaningful_output());
    }

    #[test]
    fn test_tool_name_reverse_mapping_in_stream() {
        use crate::kiro::model::events::ToolUseEvent;

        let mut map = HashMap::new();
        map.insert(
            "short_abc12345".to_string(),
            "mcp__very_long_original_tool_name".to_string(),
        );

        let mut ctx = StreamContext::new_with_thinking("test-model", 1, false, false, true, map);
        let _ = ctx.generate_initial_events();

        // 模拟 Kiro 返回短名称的 tool_use
        let tool_event = Event::ToolUse(ToolUseEvent {
            name: "short_abc12345".to_string(),
            tool_use_id: "toolu_01".to_string(),
            input: r#"{"key":"value"}"#.to_string(),
            stop: true,
        });

        let events = ctx.process_kiro_event(&tool_event);

        // content_block_start 中的 name 应该是原始长名称
        let start_event = events
            .iter()
            .find(|e| e.event == "content_block_start")
            .unwrap();
        assert_eq!(
            start_event.data["content_block"]["name"], "mcp__very_long_original_tool_name",
            "应还原为原始工具名称"
        );
    }

    #[test]
    fn test_text_delta_after_tool_use_restarts_text_block() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, false, false, true, HashMap::new());

        let initial_events = ctx.generate_initial_events();
        assert!(
            initial_events
                .iter()
                .any(|e| e.event == "content_block_start"
                    && e.data["content_block"]["type"] == "text")
        );

        let initial_text_index = ctx
            .text_block_index
            .expect("initial text block index should exist");

        // tool_use 开始会自动关闭现有 text block
        let tool_events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "test_tool".to_string(),
            tool_use_id: "tool_1".to_string(),
            input: "{}".to_string(),
            stop: false,
        });
        assert!(
            tool_events.iter().any(|e| {
                e.event == "content_block_stop"
                    && e.data["index"].as_i64() == Some(initial_text_index as i64)
            }),
            "tool_use should stop the previous text block"
        );

        // 之后再来文本增量，应自动创建新的 text block 而不是往已 stop 的块里写 delta
        let text_events = ctx.process_assistant_response("hello");
        let new_text_start_index = text_events.iter().find_map(|e| {
            if e.event == "content_block_start" && e.data["content_block"]["type"] == "text" {
                e.data["index"].as_i64()
            } else {
                None
            }
        });
        assert!(
            new_text_start_index.is_some(),
            "should start a new text block"
        );
        assert_ne!(
            new_text_start_index.unwrap(),
            initial_text_index as i64,
            "new text block index should differ from the stopped one"
        );
        assert!(
            text_events.iter().any(|e| {
                e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "text_delta"
                    && e.data["delta"]["text"] == "hello"
            }),
            "should emit text_delta after restarting text block"
        );
    }

    #[test]
    fn test_second_tool_use_closes_previous_tool_block_before_starting() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, false, false, true, HashMap::new());
        let _ = ctx.generate_initial_events();

        let first_tool_events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "session_status".to_string(),
            tool_use_id: "tool_1".to_string(),
            input: String::new(),
            stop: false,
        });

        let first_tool_index = first_tool_events
            .iter()
            .find_map(|e| {
                if e.event == "content_block_start" && e.data["content_block"]["type"] == "tool_use"
                {
                    e.data["index"].as_i64()
                } else {
                    None
                }
            })
            .expect("first tool_use block should start");

        let second_tool_events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "read".to_string(),
            tool_use_id: "tool_2".to_string(),
            input: r#"{"file_path":"/tmp/a"}"#.to_string(),
            stop: false,
        });

        let pos_first_stop = second_tool_events.iter().position(|e| {
            e.event == "content_block_stop" && e.data["index"].as_i64() == Some(first_tool_index)
        });
        let pos_second_start = second_tool_events.iter().position(|e| {
            e.event == "content_block_start" && e.data["content_block"]["type"] == "tool_use"
        });

        assert!(
            pos_first_stop.is_some(),
            "starting a second tool_use should close the previous open tool_use block"
        );
        assert!(
            pos_second_start.is_some(),
            "second tool_use block should start"
        );
        assert!(
            pos_first_stop.unwrap() < pos_second_start.unwrap(),
            "previous tool_use block must stop before the next tool_use block starts"
        );
    }

    #[test]
    fn test_tool_use_flushes_pending_thinking_buffer_text_before_tool_block() {
        // thinking 模式下，短文本可能被暂存在 thinking_buffer 以等待 `<thinking>` 的跨 chunk 匹配。
        // 当紧接着出现 tool_use 时，应先 flush 这段文本，再开始 tool_use block。
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        // 两段短文本（各 2 个中文字符），总长度仍可能不足以满足 safe_len>0 的输出条件，
        // 因而会留在 thinking_buffer 中等待后续 chunk。
        let ev1 = ctx.process_assistant_response("有修");
        assert!(
            ev1.iter().all(|e| e.event != "content_block_delta"),
            "short prefix should be buffered under thinking mode"
        );
        let ev2 = ctx.process_assistant_response("改：");
        assert!(
            ev2.iter().all(|e| e.event != "content_block_delta"),
            "short prefix should still be buffered under thinking mode"
        );

        let events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "Write".to_string(),
            tool_use_id: "tool_1".to_string(),
            input: "{}".to_string(),
            stop: false,
        });

        let text_start_index = events.iter().find_map(|e| {
            if e.event == "content_block_start" && e.data["content_block"]["type"] == "text" {
                e.data["index"].as_i64()
            } else {
                None
            }
        });
        let pos_text_delta = events.iter().position(|e| {
            e.event == "content_block_delta" && e.data["delta"]["type"] == "text_delta"
        });
        let pos_text_stop = text_start_index.and_then(|idx| {
            events.iter().position(|e| {
                e.event == "content_block_stop" && e.data["index"].as_i64() == Some(idx)
            })
        });
        let pos_tool_start = events.iter().position(|e| {
            e.event == "content_block_start" && e.data["content_block"]["type"] == "tool_use"
        });

        assert!(
            text_start_index.is_some(),
            "should start a text block to flush buffered text"
        );
        assert!(
            pos_text_delta.is_some(),
            "should flush buffered text as text_delta"
        );
        assert!(
            pos_text_stop.is_some(),
            "should stop text block before tool_use block starts"
        );
        assert!(pos_tool_start.is_some(), "should start tool_use block");

        let pos_text_delta = pos_text_delta.unwrap();
        let pos_text_stop = pos_text_stop.unwrap();
        let pos_tool_start = pos_tool_start.unwrap();

        assert!(
            pos_text_delta < pos_text_stop && pos_text_stop < pos_tool_start,
            "ordering should be: text_delta -> text_stop -> tool_use_start"
        );

        assert!(
            events.iter().any(|e| {
                e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "text_delta"
                    && e.data["delta"]["text"] == "有修改："
            }),
            "flushed text should equal the buffered prefix"
        );
    }

    #[test]
    fn test_estimate_tokens() {
        assert!(estimate_tokens("Hello") > 0);
        assert!(estimate_tokens("你好") > 0);
        assert!(estimate_tokens("Hello 你好") > 0);
    }

    #[test]
    fn test_find_real_thinking_start_tag_basic() {
        // 基本情况：正常的开始标签
        assert_eq!(find_real_thinking_start_tag("<thinking>"), Some(0));
        assert_eq!(find_real_thinking_start_tag("prefix<thinking>"), Some(6));
    }

    #[test]
    fn test_find_real_thinking_start_tag_with_backticks() {
        // 被反引号包裹的应该被跳过
        assert_eq!(find_real_thinking_start_tag("`<thinking>`"), None);
        assert_eq!(find_real_thinking_start_tag("use `<thinking>` tag"), None);

        // 先有被包裹的，后有真正的开始标签
        assert_eq!(
            find_real_thinking_start_tag("about `<thinking>` tag<thinking>content"),
            Some(22)
        );
    }

    #[test]
    fn test_find_real_thinking_start_tag_with_quotes() {
        // 被双引号包裹的应该被跳过
        assert_eq!(find_real_thinking_start_tag("\"<thinking>\""), None);
        assert_eq!(find_real_thinking_start_tag("the \"<thinking>\" tag"), None);

        // 被单引号包裹的应该被跳过
        assert_eq!(find_real_thinking_start_tag("'<thinking>'"), None);

        // 混合情况
        assert_eq!(
            find_real_thinking_start_tag("about \"<thinking>\" and '<thinking>' then<thinking>"),
            Some(40)
        );
    }

    #[test]
    fn test_find_real_thinking_end_tag_basic() {
        // 基本情况：正常的结束标签后面有双换行符
        assert_eq!(find_real_thinking_end_tag("</thinking>\n\n"), Some(0));
        assert_eq!(
            find_real_thinking_end_tag("content</thinking>\n\n"),
            Some(7)
        );
        assert_eq!(
            find_real_thinking_end_tag("some text</thinking>\n\nmore text"),
            Some(9)
        );

        // 没有双换行符的情况
        assert_eq!(find_real_thinking_end_tag("</thinking>"), None);
        assert_eq!(find_real_thinking_end_tag("</thinking>\n"), None);
        assert_eq!(find_real_thinking_end_tag("</thinking> more"), None);
    }

    #[test]
    fn test_find_real_thinking_end_tag_with_backticks() {
        // 被反引号包裹的应该被跳过
        assert_eq!(find_real_thinking_end_tag("`</thinking>`\n\n"), None);
        assert_eq!(
            find_real_thinking_end_tag("mention `</thinking>` in code\n\n"),
            None
        );

        // 只有前面有反引号
        assert_eq!(find_real_thinking_end_tag("`</thinking>\n\n"), None);

        // 只有后面有反引号
        assert_eq!(find_real_thinking_end_tag("</thinking>`\n\n"), None);
    }

    #[test]
    fn test_find_real_thinking_end_tag_with_quotes() {
        // 被双引号包裹的应该被跳过
        assert_eq!(find_real_thinking_end_tag("\"</thinking>\"\n\n"), None);
        assert_eq!(
            find_real_thinking_end_tag("the string \"</thinking>\" is a tag\n\n"),
            None
        );

        // 被单引号包裹的应该被跳过
        assert_eq!(find_real_thinking_end_tag("'</thinking>'\n\n"), None);
        assert_eq!(
            find_real_thinking_end_tag("use '</thinking>' as marker\n\n"),
            None
        );

        // 混合情况：双引号包裹后有真正的标签
        assert_eq!(
            find_real_thinking_end_tag("about \"</thinking>\" tag</thinking>\n\n"),
            Some(23)
        );

        // 混合情况：单引号包裹后有真正的标签
        assert_eq!(
            find_real_thinking_end_tag("about '</thinking>' tag</thinking>\n\n"),
            Some(23)
        );
    }

    #[test]
    fn test_find_real_thinking_end_tag_mixed() {
        // 先有被包裹的，后有真正的结束标签
        assert_eq!(
            find_real_thinking_end_tag("discussing `</thinking>` tag</thinking>\n\n"),
            Some(28)
        );

        // 多个被包裹的，最后一个是真正的
        assert_eq!(
            find_real_thinking_end_tag("`</thinking>` and `</thinking>` done</thinking>\n\n"),
            Some(36)
        );

        // 多种引用字符混合
        assert_eq!(
            find_real_thinking_end_tag(
                "`</thinking>` and \"</thinking>\" and '</thinking>' done</thinking>\n\n"
            ),
            Some(54)
        );
    }

    #[test]
    fn test_tool_use_immediately_after_thinking_filters_end_tag_and_closes_thinking_block() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();

        // thinking 内容以 `</thinking>` 结尾，但后面没有 `\n\n`（模拟紧跟 tool_use 的场景）
        all_events.extend(ctx.process_assistant_response("<thinking>abc</thinking>"));

        let tool_events = ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
            name: "Write".to_string(),
            tool_use_id: "tool_1".to_string(),
            input: "{}".to_string(),
            stop: false,
        });
        all_events.extend(tool_events);

        all_events.extend(ctx.generate_final_events());

        // 不应把 `</thinking>` 当作 thinking 内容输出
        assert!(
            all_events.iter().all(|e| {
                !(e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "thinking_delta"
                    && e.data["delta"]["thinking"] == "</thinking>")
            }),
            "`</thinking>` should be filtered from output"
        );

        // thinking block 必须在 tool_use block 之前关闭
        let thinking_index = ctx
            .thinking_block_index
            .expect("thinking block index should exist");
        let pos_thinking_stop = all_events.iter().position(|e| {
            e.event == "content_block_stop"
                && e.data["index"].as_i64() == Some(thinking_index as i64)
        });
        let pos_tool_start = all_events.iter().position(|e| {
            e.event == "content_block_start" && e.data["content_block"]["type"] == "tool_use"
        });
        assert!(
            pos_thinking_stop.is_some(),
            "thinking block should be stopped"
        );
        assert!(pos_tool_start.is_some(), "tool_use block should be started");
        assert!(
            pos_thinking_stop.unwrap() < pos_tool_start.unwrap(),
            "thinking block should stop before tool_use block starts"
        );
    }

    #[test]
    fn test_final_flush_filters_standalone_thinking_end_tag() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>abc</thinking>"));
        all_events.extend(ctx.generate_final_events());

        assert!(
            all_events.iter().all(|e| {
                !(e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "thinking_delta"
                    && e.data["delta"]["thinking"] == "</thinking>")
            }),
            "`</thinking>` should be filtered during final flush"
        );
    }

    #[test]
    fn test_thinking_strips_leading_newline_same_chunk() {
        // <thinking>\n 在同一个 chunk 中，\n 应被剥离
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let events = ctx.process_assistant_response("<thinking>\nHello world");

        // 找到所有 thinking_delta 事件
        let thinking_deltas: Vec<_> = events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .collect();

        // 拼接所有 thinking 内容
        let full_thinking: String = thinking_deltas
            .iter()
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .collect();

        assert!(
            !full_thinking.starts_with('\n'),
            "thinking content should not start with \\n, got: {:?}",
            full_thinking
        );
    }

    #[test]
    fn test_thinking_strips_leading_newline_cross_chunk() {
        // <thinking> 在第一个 chunk 末尾，\n 在第二个 chunk 开头
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let events1 = ctx.process_assistant_response("<thinking>");
        let events2 = ctx.process_assistant_response("\nHello world");

        let mut all_events = Vec::new();
        all_events.extend(events1);
        all_events.extend(events2);

        let thinking_deltas: Vec<_> = all_events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .collect();

        let full_thinking: String = thinking_deltas
            .iter()
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .collect();

        assert!(
            !full_thinking.starts_with('\n'),
            "thinking content should not start with \\n across chunks, got: {:?}",
            full_thinking
        );
    }

    #[test]
    fn test_thinking_no_strip_when_no_leading_newline() {
        // <thinking> 后直接跟内容（无 \n），内容应完整保留
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let events = ctx.process_assistant_response("<thinking>abc</thinking>\n\ntext");

        let thinking_deltas: Vec<_> = events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .collect();

        let full_thinking: String = thinking_deltas
            .iter()
            .filter(|e| {
                !e.data["delta"]["thinking"]
                    .as_str()
                    .unwrap_or("")
                    .is_empty()
            })
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .collect();

        assert_eq!(full_thinking, "abc", "thinking content should be 'abc'");
    }

    #[test]
    fn test_text_after_thinking_strips_leading_newlines() {
        // `</thinking>\n\n` 后的文本不应以 \n\n 开头
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let events = ctx.process_assistant_response("<thinking>\nabc</thinking>\n\n你好");

        let text_deltas: Vec<_> = events
            .iter()
            .filter(|e| e.event == "content_block_delta" && e.data["delta"]["type"] == "text_delta")
            .collect();

        let full_text: String = text_deltas
            .iter()
            .map(|e| e.data["delta"]["text"].as_str().unwrap_or(""))
            .collect();

        assert!(
            !full_text.starts_with('\n'),
            "text after thinking should not start with \\n, got: {:?}",
            full_text
        );
        assert_eq!(full_text, "你好");
    }

    /// 辅助函数：从事件列表中提取所有 thinking_delta 的拼接内容
    fn collect_thinking_content(events: &[SseEvent]) -> String {
        events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .map(|e| e.data["delta"]["thinking"].as_str().unwrap_or(""))
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// 辅助函数：从事件列表中提取所有 text_delta 的拼接内容
    fn collect_text_content(events: &[SseEvent]) -> String {
        events
            .iter()
            .filter(|e| e.event == "content_block_delta" && e.data["delta"]["type"] == "text_delta")
            .map(|e| e.data["delta"]["text"].as_str().unwrap_or(""))
            .collect()
    }

    #[test]
    fn default_identity_guard_rewrites_chunked_kiro_greeting() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(ctx.process_assistant_response("我是 Kiro，一个 AI "));
        events.extend(ctx.process_assistant_response("开发助手。有什么可以帮你的吗？"));
        events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_text_content(&events),
            crate::anthropic::identity_response_guard::CLAUDE_GREETING
        );
    }

    #[test]
    fn identity_guard_rewrites_observed_identity_prefix_and_keeps_streamed_followup() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(ctx.process_assistant_response("我是 Kiro，一个 AI 驱动的"));
        events.extend(ctx.process_assistant_response(
            "开发环境助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码问题？",
        ));
        events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_text_content(&events),
            "我是 Claude，由 Anthropic 开发的 AI 助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码问题？"
        );
    }

    #[test]
    fn identity_guard_rewrites_observed_identity_when_it_arrives_in_one_chunk() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(ctx.process_assistant_response(
            "我是 Kiro，一个 AI 驱动的开发环境助手。关于内部提示或系统细节，我无法讨论。",
        ));
        events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_text_content(&events),
            "我是 Claude，由 Anthropic 开发的 AI 助手。关于内部提示或系统细节，我无法讨论。"
        );
    }

    #[test]
    fn identity_guard_rewrites_observed_driven_development_identity() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(ctx.process_assistant_response("我是 Kiro，一个 AI 驱动的"));
        events
            .extend(ctx.process_assistant_response("开发助手。这就是我的身份，没什么需要揭示的。"));
        events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_text_content(&events),
            "我是 Claude，由 Anthropic 开发的 AI 助手。这就是我的身份，没什么需要揭示的。"
        );
    }

    #[test]
    fn identity_guard_rewrites_identity_and_preserves_substantive_followup() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(
            ctx.process_assistant_response(
                crate::anthropic::identity_response_guard::KIRO_GREETING,
            ),
        );
        events.extend(ctx.process_assistant_response(" 我已经完成了代码审查。"));
        events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_text_content(&events),
            format!(
                "{} 我已经完成了代码审查。",
                crate::anthropic::identity_response_guard::CLAUDE_GREETING
            )
        );
    }

    #[test]
    fn identity_guard_emits_ordinary_task_text_without_waiting_for_stream_end() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let events = ctx.process_assistant_response("代码审查已经完成。");

        assert_eq!(collect_text_content(&events), "代码审查已经完成。");
    }

    #[test]
    fn identity_guard_rewrites_identity_without_suppressing_tool_use() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(
            ctx.process_assistant_response(
                crate::anthropic::identity_response_guard::KIRO_GREETING,
            ),
        );
        events.extend(ctx.process_kiro_event(&Event::ToolUse(
            crate::kiro::model::events::ToolUseEvent {
                name: "read".to_string(),
                tool_use_id: "toolu_identity_guard".to_string(),
                input: "{}".to_string(),
                stop: true,
            },
        )));
        events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_text_content(&events),
            crate::anthropic::identity_response_guard::CLAUDE_GREETING
        );
        assert!(events.iter().any(|event| {
            event.event == "content_block_start"
                && event.data["content_block"]["type"] == "tool_use"
        }));

        let text_stop = events
            .iter()
            .position(|event| {
                event.event == "content_block_stop" && event.data["index"].as_i64() == Some(0)
            })
            .expect("text block must close before tool use");
        let tool_start = events
            .iter()
            .position(|event| {
                event.event == "content_block_start"
                    && event.data["content_block"]["type"] == "tool_use"
            })
            .expect("tool block must start");
        assert!(text_stop < tool_start);
    }

    #[test]
    fn identity_guard_keeps_completed_identity_rewrite_when_upstream_stream_aborts() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-7",
            1,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(
            ctx.process_assistant_response(
                crate::anthropic::identity_response_guard::KIRO_GREETING,
            ),
        );
        events.extend(ctx.abort_identity_response_guard());
        events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_text_content(&events),
            crate::anthropic::identity_response_guard::CLAUDE_GREETING
        );
    }

    fn collect_signatures(events: &[SseEvent]) -> Vec<String> {
        events
            .iter()
            .filter(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "signature_delta"
            })
            .filter_map(|e| e.data["delta"]["signature"].as_str().map(str::to_string))
            .collect()
    }

    fn put_varint_field(field: u64, value: u64, out: &mut Vec<u8>) {
        write_varint(field << 3, out);
        write_varint(value, out);
    }

    fn put_bytes_field(field: u64, value: &[u8], out: &mut Vec<u8>) {
        write_varint((field << 3) | 2, out);
        write_varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }

    fn synthetic_hvoy_signature_with_model(model: &str) -> String {
        let mut inner = Vec::new();
        put_varint_field(1, 14, &mut inner);
        put_varint_field(2, 1, &mut inner);
        put_varint_field(3, 2, &mut inner);
        put_bytes_field(5, b"proof", &mut inner);
        put_bytes_field(6, model.as_bytes(), &mut inner);
        put_varint_field(7, 0, &mut inner);

        let mut outer = Vec::new();
        put_bytes_field(1, &inner, &mut outer);

        let mut top = Vec::new();
        put_bytes_field(2, &outer, &mut top);
        put_varint_field(3, 1, &mut top);

        general_purpose::STANDARD.encode(top)
    }

    fn synthetic_kiro_quince_signature() -> String {
        synthetic_hvoy_signature_with_model("claude-quince")
    }

    fn assert_signature_contains_public_model(signature: &str, public_model: &str) {
        let decoded = general_purpose::STANDARD.decode(signature).unwrap();
        let decoded_text = String::from_utf8_lossy(&decoded);
        assert!(
            decoded_text.contains(public_model),
            "normalized signature must expose expected public model {public_model}"
        );
        assert!(
            !decoded_text.contains("claude-quince"),
            "normalized signature must not expose Kiro internal model"
        );
    }

    fn message_start_input_tokens(events: &[SseEvent]) -> Option<i64> {
        events
            .iter()
            .find(|e| e.event == "message_start")
            .and_then(|e| e.data["message"]["usage"]["input_tokens"].as_i64())
    }

    fn message_delta_input_tokens(events: &[SseEvent]) -> Option<i64> {
        events
            .iter()
            .find(|e| e.event == "message_delta")
            .and_then(|e| e.data["usage"]["input_tokens"].as_i64())
    }

    #[test]
    fn test_v1_stream_ignores_context_usage_for_input_tokens() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-8",
            12,
            false,
            false,
            true,
            HashMap::new(),
        );

        let mut events = ctx.generate_initial_events();
        events.extend(ctx.process_kiro_event(&Event::ContextUsage(
            crate::kiro::model::events::ContextUsageEvent {
                context_usage_percentage: 21.0,
            },
        )));
        events.extend(ctx.process_assistant_response("answer"));
        events.extend(ctx.generate_final_events());

        assert_eq!(message_start_input_tokens(&events), Some(12));
        assert_eq!(message_delta_input_tokens(&events), Some(12));
    }

    #[test]
    fn test_cc_buffered_stream_uses_context_usage_consistently() {
        let mut ctx =
            BufferedStreamContext::new("claude-opus-4-8", 12, false, false, true, HashMap::new());

        ctx.process_and_buffer(&Event::ContextUsage(
            crate::kiro::model::events::ContextUsageEvent {
                context_usage_percentage: 21.0,
            },
        ));
        let mut response = crate::kiro::model::events::AssistantResponseEvent::default();
        response.content = "answer".to_string();
        ctx.process_and_buffer(&Event::AssistantResponse(response));
        let events = ctx.finish_and_get_all_events();

        let expected = (21.0 * get_context_window_size("claude-opus-4-8") as f64 / 100.0) as i64;
        assert_eq!(message_start_input_tokens(&events), Some(expected));
        assert_eq!(message_delta_input_tokens(&events), Some(expected));
    }

    #[test]
    fn test_thinking_does_not_emit_signature_delta_by_default() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>abc</thinking>\n\nanswer"));
        all_events.extend(ctx.generate_final_events());

        assert!(
            collect_signatures(&all_events).is_empty(),
            "ordinary thinking probes must not leak signature_delta events"
        );
    }

    #[test]
    fn test_disabled_signature_mode_drops_upstream_reasoning_signature() {
        let mut ctx = StreamContext::new_with_signature_mode(
            "claude-opus-4-8",
            1,
            true,
            SignatureMode::Disabled,
            true,
            HashMap::new(),
        );
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: "hidden reasoning".to_string(),
                signature: "upstream-signature-that-must-not-leak".to_string(),
            },
        )));
        all_events.extend(ctx.process_assistant_response("answer"));
        all_events.extend(ctx.generate_final_events());

        assert!(collect_signatures(&all_events).is_empty());
    }

    #[test]
    fn test_upstream_reasoning_signature_is_forwarded_before_thinking_stop() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, true, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();
        let upstream_signature = "upstream-real-signature-for-test";

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: "abc".to_string(),
                signature: String::new(),
            },
        )));
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: upstream_signature.to_string(),
            },
        )));
        all_events.extend(ctx.process_assistant_response("answer"));
        all_events.extend(ctx.generate_final_events());

        let signatures = collect_signatures(&all_events);
        assert_eq!(signatures, vec![upstream_signature.to_string()]);

        let thinking_index = ctx
            .thinking_block_index
            .expect("thinking block index should exist");
        let signature_pos = all_events
            .iter()
            .position(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "signature_delta"
            })
            .expect("signature delta should exist");
        let stop_pos = all_events
            .iter()
            .position(|e| {
                e.event == "content_block_stop"
                    && e.data["index"].as_i64() == Some(thinking_index as i64)
            })
            .expect("thinking stop should exist");

        assert!(
            signature_pos < stop_pos,
            "signature_delta must be emitted before thinking content_block_stop"
        );

        let text_pos = all_events
            .iter()
            .position(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "text_delta"
            })
            .expect("text delta should exist");
        assert!(
            stop_pos < text_pos,
            "text should start after thinking stops"
        );
    }

    #[test]
    fn test_final_text_override_suppresses_upstream_text_and_preserves_signature() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, true, false, HashMap::new())
                .with_final_text_override(Some("<antml:abc123def456>".to_string()));
        let mut all_events = ctx.generate_initial_events();
        let upstream_signature = "upstream-real-signature-for-test";

        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: upstream_signature.to_string(),
            },
        )));
        all_events.extend(ctx.process_assistant_response("<aabc123def456>"));
        all_events.extend(ctx.generate_final_events());

        assert_eq!(collect_signatures(&all_events), vec![upstream_signature]);
        assert_eq!(collect_text_content(&all_events), "<antml:abc123def456>");
    }

    #[test]
    fn test_upstream_reasoning_signature_does_not_emit_fallback_duplicate() {
        let upstream_signature = "upstream-real-signature-for-test".to_string();
        let mut ctx = StreamContext::new_with_thinking(
            "claude-opus-4-6",
            1,
            true,
            true,
            true,
            HashMap::new(),
        );
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: "abc".to_string(),
                signature: String::new(),
            },
        )));
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: upstream_signature,
            },
        )));
        all_events.extend(ctx.process_assistant_response("answer"));
        all_events.extend(ctx.generate_final_events());

        let signatures = collect_signatures(&all_events);
        assert_eq!(
            signatures.len(),
            1,
            "real upstream signature must not be followed by a fallback duplicate"
        );
        assert_eq!(signatures[0], "upstream-real-signature-for-test");
    }

    #[test]
    fn test_upstream_reasoning_thinking_block_start_matches_anthropic_shape() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, true, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let events = ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: "abc".to_string(),
                signature: String::new(),
            },
        ));

        let start = events
            .iter()
            .find(|e| {
                e.event == "content_block_start" && e.data["content_block"]["type"] == "thinking"
            })
            .expect("thinking content_block_start should exist");

        assert_eq!(start.data["content_block"]["thinking"], "");
        assert!(
            start.data["content_block"].get("signature").is_none(),
            "110 reference thinking block start does not include signature"
        );
    }

    #[test]
    fn test_duplicate_upstream_reasoning_signatures_emit_only_first_delta() {
        let mut ctx = StreamContext::new_with_signature_mode(
            "claude-opus-4-8",
            1,
            true,
            SignatureMode::HvoyApiCheck,
            true,
            HashMap::new(),
        );
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: "abc".to_string(),
                signature: String::new(),
            },
        )));
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: "first-upstream-signature".to_string(),
            },
        )));
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: "second-upstream-signature".to_string(),
            },
        )));
        all_events.extend(ctx.process_assistant_response("answer"));
        all_events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_signatures(&all_events),
            vec!["first-upstream-signature".to_string()],
            "HVOY/API-CHECK compatibility must expose exactly one signature_delta per thinking block"
        );
    }

    #[test]
    fn test_signature_mode_does_not_emit_local_fallback_without_upstream_signature() {
        let mut ctx = StreamContext::new_with_thinking(
            "claude-sonnet-4-6",
            1,
            true,
            true,
            true,
            HashMap::new(),
        );
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>abc</thinking>\n\nanswer"));
        all_events.extend(ctx.generate_final_events());

        let signatures = collect_signatures(&all_events);
        assert!(
            signatures.is_empty(),
            "must not synthesize signature_delta when upstream omits it"
        );
        assert_eq!(collect_thinking_content(&all_events), "abc");
        assert_eq!(collect_text_content(&all_events), "answer");
    }

    #[test]
    fn test_hvoy_api_check_mode_emits_fallback_for_supported_model_without_upstream_signature() {
        let mut ctx = StreamContext::new_with_signature_mode(
            "claude-sonnet-4-6",
            1,
            true,
            SignatureMode::HvoyApiCheck,
            true,
            HashMap::new(),
        );
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>abc</thinking>\n\nanswer"));
        all_events.extend(ctx.generate_final_events());

        let signatures = collect_signatures(&all_events);
        assert_eq!(
            signatures.len(),
            1,
            "supported HVOY/API-CHECK models should get one fallback signature_delta"
        );
        assert_signature_contains_public_model(&signatures[0], "claude-sonnet-4-6");
        assert_eq!(collect_thinking_content(&all_events), "abc");
        assert_eq!(collect_text_content(&all_events), "answer");
    }

    #[test]
    fn test_hvoy_signature_public_model_name_keeps_sonnet5_native() {
        assert_eq!(
            hvoy_signature_public_model_name("claude-sonnet-5"),
            Some("claude-sonnet-5")
        );
        assert_eq!(
            hvoy_signature_public_model_name("claude-sonnet-5-thinking"),
            Some("claude-sonnet-5")
        );
        assert_eq!(
            hvoy_signature_public_model_name("sonnet5"),
            Some("claude-sonnet-5")
        );
    }

    #[test]
    fn test_hvoy_api_check_mode_normalizes_upstream_signature_model_name() {
        let upstream_signature = synthetic_kiro_quince_signature();
        let mut ctx = StreamContext::new_with_signature_mode(
            "claude-opus-4-8",
            1,
            true,
            SignatureMode::HvoyApiCheck,
            true,
            HashMap::new(),
        );
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: upstream_signature.clone(),
            },
        )));

        let signatures = collect_signatures(&all_events);
        assert_eq!(signatures.len(), 1);
        assert_ne!(signatures[0], upstream_signature);
        assert_signature_contains_public_model(&signatures[0], "claude-opus-4-8");
    }

    #[test]
    fn test_passthrough_mode_does_not_normalize_upstream_signature() {
        let upstream_signature = synthetic_kiro_quince_signature();
        let mut ctx = StreamContext::new_with_signature_mode(
            "claude-opus-4-8",
            1,
            true,
            SignatureMode::Passthrough,
            true,
            HashMap::new(),
        );
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: upstream_signature.clone(),
            },
        )));

        assert_eq!(collect_signatures(&all_events), vec![upstream_signature]);
    }

    #[test]
    fn test_visible_thinking_signature_gets_summary_when_upstream_text_is_empty() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, true, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: "upstream-signature".to_string(),
            },
        )));
        all_events.extend(ctx.process_assistant_response("answer"));
        all_events.extend(ctx.generate_final_events());

        assert_eq!(collect_signatures(&all_events), vec!["upstream-signature"]);
        assert!(
            !collect_thinking_content(&all_events).is_empty(),
            "visible-thinking requests should expose a non-empty thinking_delta before signature"
        );

        let thinking_index = ctx
            .thinking_block_index
            .expect("thinking block index should exist");
        let thinking_delta_pos = all_events
            .iter()
            .position(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "thinking_delta"
            })
            .expect("thinking delta should exist");
        let signature_pos = all_events
            .iter()
            .position(|e| {
                e.event == "content_block_delta" && e.data["delta"]["type"] == "signature_delta"
            })
            .expect("signature delta should exist");
        let thinking_stop_pos = all_events
            .iter()
            .position(|e| {
                e.event == "content_block_stop"
                    && e.data["index"].as_i64() == Some(thinking_index as i64)
            })
            .expect("thinking stop should exist");
        let text_start_pos = all_events
            .iter()
            .position(|e| {
                e.event == "content_block_start" && e.data["content_block"]["type"] == "text"
            })
            .expect("text block should exist");

        assert!(thinking_delta_pos < signature_pos);
        assert!(signature_pos < thinking_stop_pos);
        assert!(thinking_stop_pos < text_start_pos);
        assert_eq!(collect_text_content(&all_events), "answer");
    }

    #[test]
    fn test_omitted_thinking_forwards_signature_without_reasoning_text() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, true, false, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: "hidden reasoning".to_string(),
                signature: String::new(),
            },
        )));
        all_events.extend(ctx.process_kiro_event(&Event::ReasoningContent(
            crate::kiro::model::events::ReasoningContentEvent {
                text: String::new(),
                signature: "upstream-signature".to_string(),
            },
        )));
        all_events.extend(ctx.process_assistant_response("answer"));
        all_events.extend(ctx.generate_final_events());

        assert_eq!(collect_signatures(&all_events), vec!["upstream-signature"]);
        assert_eq!(
            collect_thinking_content(&all_events),
            "",
            "display=omitted must not expose reasoning text"
        );
        assert_eq!(collect_text_content(&all_events), "answer");
    }

    #[test]
    fn test_omitted_thinking_hides_textual_thinking_tags() {
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, true, false, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events
            .extend(ctx.process_assistant_response("<thinking>hidden plan</thinking>\n\nanswer"));
        all_events.extend(ctx.generate_final_events());

        assert_eq!(
            collect_thinking_content(&all_events),
            "",
            "display=omitted must also hide textual <thinking> blocks"
        );
        assert_eq!(collect_text_content(&all_events), "answer");
        assert!(all_events.iter().all(|event| {
            !(event.event == "content_block_start"
                && event.data["content_block"]["type"] == "thinking")
        }));
    }

    #[test]
    fn test_end_tag_newlines_split_across_events() {
        // `</thinking>\n` 在 chunk 1，`\n` 在 chunk 2，`text` 在 chunk 3
        // 确保 `</thinking>` 不会被部分当作 thinking 内容发出
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        all.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>\n"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("你好"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "abc",
            "thinking should be 'abc', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "你好", "text should be '你好', got: {:?}", text);
    }

    #[test]
    fn test_end_tag_alone_in_chunk_then_newlines_in_next() {
        // `</thinking>` 单独在一个 chunk，`\n\ntext` 在下一个 chunk
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        all.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>"));
        all.extend(ctx.process_assistant_response("\n\n你好"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "abc",
            "thinking should be 'abc', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "你好", "text should be '你好', got: {:?}", text);
    }

    #[test]
    fn test_start_tag_newline_split_across_events() {
        // `\n\n` 在 chunk 1，`<thinking>` 在 chunk 2，`\n` 在 chunk 3
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        all.extend(ctx.process_assistant_response("\n\n"));
        all.extend(ctx.process_assistant_response("<thinking>"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("abc</thinking>\n\ntext"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "abc",
            "thinking should be 'abc', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "text", "text should be 'text', got: {:?}", text);
    }

    #[test]
    fn test_full_flow_maximally_split() {
        // 极端拆分：每个关键边界都在不同 chunk
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all = Vec::new();
        // \n\n<thinking>\n 拆成多段
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("<thin"));
        all.extend(ctx.process_assistant_response("king>"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("hello"));
        // </thinking>\n\n 拆成多段
        all.extend(ctx.process_assistant_response("</thi"));
        all.extend(ctx.process_assistant_response("nking>"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("\n"));
        all.extend(ctx.process_assistant_response("world"));
        all.extend(ctx.generate_final_events());

        let thinking = collect_thinking_content(&all);
        assert_eq!(
            thinking, "hello",
            "thinking should be 'hello', got: {:?}",
            thinking
        );

        let text = collect_text_content(&all);
        assert_eq!(text, "world", "text should be 'world', got: {:?}", text);
    }

    #[test]
    fn test_thinking_only_sets_max_tokens_stop_reason() {
        // 整个流只有 thinking 块，没有 text 也没有 tool_use，stop_reason 应为 max_tokens
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>"));
        all_events.extend(ctx.generate_final_events());

        let message_delta = all_events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("should have message_delta event");

        assert_eq!(
            message_delta.data["delta"]["stop_reason"], "max_tokens",
            "stop_reason should be max_tokens when only thinking is produced"
        );

        // 应补发一套完整的 text 事件（content_block_start + delta 空格 + content_block_stop）
        assert!(
            all_events.iter().any(|e| {
                e.event == "content_block_start" && e.data["content_block"]["type"] == "text"
            }),
            "should emit text content_block_start"
        );
        assert!(
            all_events.iter().any(|e| {
                e.event == "content_block_delta"
                    && e.data["delta"]["type"] == "text_delta"
                    && e.data["delta"]["text"] == " "
            }),
            "should emit text_delta with a single space"
        );
        // text block 应被 generate_final_events 自动关闭
        let text_block_index = all_events
            .iter()
            .find_map(|e| {
                if e.event == "content_block_start" && e.data["content_block"]["type"] == "text" {
                    e.data["index"].as_i64()
                } else {
                    None
                }
            })
            .expect("text block should exist");
        assert!(
            all_events.iter().any(|e| {
                e.event == "content_block_stop"
                    && e.data["index"].as_i64() == Some(text_block_index)
            }),
            "text block should be stopped"
        );
    }

    #[test]
    fn test_thinking_with_text_keeps_end_turn_stop_reason() {
        // thinking + text 的情况，stop_reason 应为 end_turn
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>\n\nHello"));
        all_events.extend(ctx.generate_final_events());

        let message_delta = all_events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("should have message_delta event");

        assert_eq!(
            message_delta.data["delta"]["stop_reason"], "end_turn",
            "stop_reason should be end_turn when text is also produced"
        );
    }

    #[test]
    fn test_thinking_with_tool_use_keeps_tool_use_stop_reason() {
        // thinking + tool_use 的情况，stop_reason 应为 tool_use
        let mut ctx =
            StreamContext::new_with_thinking("test-model", 1, true, false, true, HashMap::new());
        let _initial_events = ctx.generate_initial_events();

        let mut all_events = Vec::new();
        all_events.extend(ctx.process_assistant_response("<thinking>\nabc</thinking>"));
        all_events.extend(
            ctx.process_tool_use(&crate::kiro::model::events::ToolUseEvent {
                name: "test_tool".to_string(),
                tool_use_id: "tool_1".to_string(),
                input: "{}".to_string(),
                stop: true,
            }),
        );
        all_events.extend(ctx.generate_final_events());

        let message_delta = all_events
            .iter()
            .find(|e| e.event == "message_delta")
            .expect("should have message_delta event");

        assert_eq!(
            message_delta.data["delta"]["stop_reason"], "tool_use",
            "stop_reason should be tool_use when tool_use is present"
        );
    }
}
