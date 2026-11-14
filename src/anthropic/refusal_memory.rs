//! 对话拒绝记忆
//!
//! 某段对话被 Kiro 以「cannot continue this conversation」拒绝后，记住这段对话；之后
//! 同一段对话再发进来（原样重发，或在它后面接着追加消息），本地直接拒绝，不再送到号池
//! 账号上。原因：客户端会把同一段被拒对话自动重发几十上百次，每次都落到不同账号，
//! 每个账号都累积「内容拒绝过多」，最后把正常账号也拖进受限。
//!
//! 只认对话消息本身：system / tools 不参与（Claude Code 的 system 每次带变化的计费头）。
//! 客户回到更早的消息重新编辑、或开新对话，前缀不同，不受影响。
//!
//! 「账号已受限」那类拒绝说的是账号、不是对话，不记。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::types::Message;

/// 一段对话（前 n 条消息）的规范化哈希。
pub type ConversationKey = [u8; 32];

/// 最多记多少段对话；满了先清过期，仍满再挤掉最早到期的。
const MAX_ENTRIES: usize = 20_000;

/// Kiro 针对这段对话内容的拒绝文案片段（大小写不敏感）。
const CONVERSATION_REFUSAL_MARKER: &str = "cannot continue this conversation";

/// 这条上游拒绝说的是不是「这段对话不能继续」（而不是账号受限之类）。
pub fn is_conversation_refusal(message: &str) -> bool {
    message
        .to_ascii_lowercase()
        .contains(CONVERSATION_REFUSAL_MARKER)
}

/// 被拒对话的记忆表：对话哈希 → 到期时间。
pub struct RefusalMemory {
    entries: Mutex<HashMap<ConversationKey, Instant>>,
}

impl Default for RefusalMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl RefusalMemory {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// 记住一段被拒对话，`ttl` 后过期。
    pub fn remember(&self, key: ConversationKey, ttl: Duration) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
            entries.retain(|_, expires| *expires > now);
            if entries.len() >= MAX_ENTRIES
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, expires)| **expires)
                    .map(|(key, _)| *key)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, now + ttl);
    }

    /// 这次请求的任一前缀是否是记住的被拒对话；命中则把到期时间顺延 `ttl`
    /// （客户端一直在重发，就一直挡住）。
    pub fn matches_any(&self, keys: &[ConversationKey], ttl: Duration) -> bool {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        for key in keys {
            match entries.get(key).copied() {
                Some(expires) if expires > now => {
                    entries.insert(*key, now + ttl);
                    return true;
                }
                Some(_) => {
                    entries.remove(key);
                }
                None => {}
            }
        }
        false
    }
}

/// 逐条算出前 1、前 2 … 前 n 条消息的对话哈希（链式：每条接在前一条的哈希后面）。
///
/// 规范化：字符串内容等同于单个 text 块；所有 `cache_control` 字段忽略（客户端每轮
/// 都会挪缓存断点位置）；对象按键排序。
pub fn conversation_prefix_keys(messages: &[Message]) -> Vec<ConversationKey> {
    let mut keys = Vec::with_capacity(messages.len());
    let mut previous: ConversationKey = [0; 32];
    for message in messages {
        let mut hasher = Sha256::new();
        hasher.update(previous);
        feed_str(&mut hasher, &message.role);
        match &message.content {
            Value::String(text) => {
                // 等价于 [{"text": text, "type": "text"}]
                hasher.update(b"[");
                hasher.update(1u64.to_le_bytes());
                hasher.update(b"{");
                feed_str(&mut hasher, "text");
                feed_str(&mut hasher, text);
                feed_str(&mut hasher, "type");
                feed_str(&mut hasher, "text");
                hasher.update(b"}");
            }
            other => feed_value(&mut hasher, other),
        }
        previous = hasher.finalize().into();
        keys.push(previous);
    }
    keys
}

fn feed_str(hasher: &mut Sha256, text: &str) {
    hasher.update(b"s");
    hasher.update((text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
}

fn feed_value(hasher: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hasher.update(b"n"),
        Value::Bool(true) => hasher.update(b"t"),
        Value::Bool(false) => hasher.update(b"f"),
        Value::Number(number) => {
            hasher.update(b"#");
            feed_str(hasher, &number.to_string());
        }
        Value::String(text) => feed_str(hasher, text),
        Value::Array(items) => {
            hasher.update(b"[");
            hasher.update((items.len() as u64).to_le_bytes());
            for item in items {
                feed_value(hasher, item);
            }
        }
        // serde_json 未开 preserve_order，Map 是 BTreeMap，遍历即按键排序。
        Value::Object(map) => {
            hasher.update(b"{");
            for (key, item) in map {
                if key == "cache_control" {
                    continue;
                }
                feed_str(hasher, key);
                feed_value(hasher, item);
            }
            hasher.update(b"}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(role: &str, content: Value) -> Message {
        Message {
            role: role.to_string(),
            content,
        }
    }

    const TTL: Duration = Duration::from_secs(3600);

    #[test]
    fn recognises_only_conversation_refusals() {
        assert!(is_conversation_refusal(
            "I'm sorry, but I Cannot Continue This Conversation."
        ));
        assert!(!is_conversation_refusal(
            "Your account has been temporarily restricted due to excessive content refusals"
        ));
        assert!(!is_conversation_refusal(""));
    }

    #[test]
    fn resend_and_continuation_match_but_edits_do_not() {
        let memory = RefusalMemory::new();
        let refused = vec![
            msg("user", json!("帮我写个脚本")),
            msg("assistant", json!([{"type": "text", "text": "好的"}])),
            msg("user", json!([{"type": "text", "text": "被拒的那句"}])),
        ];
        let refused_keys = conversation_prefix_keys(&refused);
        memory.remember(*refused_keys.last().unwrap(), TTL);

        // 原样重发
        assert!(memory.matches_any(&conversation_prefix_keys(&refused), TTL));

        // 接着追加（客户端打「继续」）
        let mut continued = refused.clone();
        continued.push(msg("assistant", json!("")));
        continued.push(msg("user", json!("继续")));
        assert!(memory.matches_any(&conversation_prefix_keys(&continued), TTL));

        // 缓存断点挪位置、字符串写成 text 块：仍算同一段
        let reshaped = vec![
            msg("user", json!([{"type": "text", "text": "帮我写个脚本", "cache_control": {"type": "ephemeral"}}])),
            msg("assistant", json!("好的")),
            msg("user", json!("被拒的那句")),
        ];
        assert!(memory.matches_any(&conversation_prefix_keys(&reshaped), TTL));

        // 回到被拒那句之前改写：放行
        let edited = vec![
            msg("user", json!("帮我写个脚本")),
            msg("assistant", json!([{"type": "text", "text": "好的"}])),
            msg("user", json!("换个说法")),
        ];
        assert!(!memory.matches_any(&conversation_prefix_keys(&edited), TTL));

        // 只发了被拒对话的前半段：放行（那时还没被拒）
        assert!(!memory.matches_any(&conversation_prefix_keys(&refused[..2]), TTL));
    }

    #[test]
    fn role_is_part_of_the_key() {
        let a = conversation_prefix_keys(&[msg("user", json!("x"))]);
        let b = conversation_prefix_keys(&[msg("assistant", json!("x"))]);
        assert_ne!(a, b);
    }

    #[test]
    fn expired_entries_do_not_match_and_hits_extend_expiry() {
        let memory = RefusalMemory::new();
        let key = conversation_prefix_keys(&[msg("user", json!("x"))])[0];
        memory.remember(key, Duration::from_millis(0));
        assert!(!memory.matches_any(&[key], TTL));
        assert!(memory.is_empty());

        memory.remember(key, Duration::from_millis(50));
        assert!(memory.matches_any(&[key], TTL));
        std::thread::sleep(Duration::from_millis(80));
        // 命中时顺延成 TTL，所以 80ms 后仍记得
        assert!(memory.matches_any(&[key], TTL));
    }

    #[test]
    fn full_table_evicts_earliest_expiry() {
        let memory = RefusalMemory::new();
        for index in 0..MAX_ENTRIES {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let ttl = if index == 0 { Duration::from_secs(1) } else { TTL };
            memory.remember(key, ttl);
        }
        let newcomer = [0xffu8; 32];
        memory.remember(newcomer, TTL);
        assert_eq!(memory.entries.lock().len(), MAX_ENTRIES);
        assert!(memory.matches_any(&[newcomer], TTL));
        assert!(!memory.matches_any(&[[0u8; 32]], TTL));
    }
}
