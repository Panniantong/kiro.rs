//! Tool Use 合规助手：
//! - tool_use ID 规范化（`toolu_` + 24 位 base64url）
//! - `tool_choice` 解析与强制要求判定
//! - 依据 JSON Schema 合成 schema 合法的 placeholder 输入
//!
//! 目标：无论上游（Kiro 账号池）返回什么形状的工具调用，/v1/messages 出口
//! 始终呈现 Anthropic API 合法的工具调用形态，且 `tool_choice: tool/any`
//! 请求必然收到至少一个 tool_use 块与 `stop_reason: "tool_use"`。

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde_json::{Map, Value, json};
use crate::anthropic::types::Tool;

/// 真实的 Anthropic tool_use ID 形如 `toolu_01Xf...`（前缀 + 24 位 base64url）。
const TOOL_ID_PREFIX: &str = "toolu_";
const TOOL_ID_BODY_LEN: usize = 24;

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

pub fn is_valid_tool_use_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == TOOL_ID_PREFIX.len() + TOOL_ID_BODY_LEN
        && &b[..TOOL_ID_PREFIX.len()] == TOOL_ID_PREFIX.as_bytes()
        && b[TOOL_ID_PREFIX.len()..].iter().all(|c| is_base64url_byte(*c))
}

/// 生成一个全新的合法 tool_use ID。
pub fn generate_tool_use_id() -> String {
    // 18 字节 -> base64url 无 padding 恰好 24 字符
    let mut bytes = [0u8; 18];
    fastrand::fill(&mut bytes);
    format!("{TOOL_ID_PREFIX}{}", B64URL.encode(bytes))
}

/// `tool_choice` 的强制语义。`Auto` 表示不需要强制（none / auto / 未设置）。
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ToolChoiceRequirement {
    #[default]
    Auto,
    Any,
    Named(String),
}

impl ToolChoiceRequirement {
    /// 调用方是否要求响应必须包含 tool_use 块。
    pub fn requires_tool_use(&self) -> bool {
        !matches!(self, Self::Auto)
    }

    /// 解析请求里的 `tool_choice` 字段（兼容对象与旧字符串两种形态）。
    pub fn parse(value: Option<&Value>) -> Self {
        match value {
            Some(v) if v.is_object() => {
                let ty = v.get("type").and_then(|t| t.as_str());
                let name = v.get("name").and_then(|n| n.as_str()).map(str::to_string);
                match ty {
                    Some("any") => Self::Any,
                    Some("tool") => name.map(Self::Named).unwrap_or(Self::Any),
                    Some(_) => Self::Auto,
                    // 无 type 但有 name 的对象（宽松客户端）
                    None => name.map(Self::Named).unwrap_or(Self::Auto),
                }
            }
            Some(Value::String(s)) => {
                if s == "any" {
                    Self::Any
                } else if let Some(name) = s.strip_prefix("tool:") {
                    if name.trim().is_empty() {
                        Self::Any
                    } else {
                        Self::Named(name.trim().to_string())
                    }
                } else {
                    Self::Auto
                }
            }
            _ => Self::Auto,
        }
    }
}

/// 选择一个要合成调用的工具：`Named` 优先精确匹配，否则取第一个可用工具。
pub fn pick_tool<'a>(requirement: &ToolChoiceRequirement, tools: &'a [Tool]) -> Option<&'a Tool> {
    match requirement {
        ToolChoiceRequirement::Named(name) => {
            tools
                .iter()
                .find(|t| t.name == *name)
                .or_else(|| tools.first())
        }
        _ => tools.first(),
    }
}

/// 依据工具的 JSON Schema 合成一个 schema 合法的 placeholder 输入。
pub fn synthesize_tool_input(tool: &Tool) -> Value {
    let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(|p| p.as_object())
    else {
        return json!({});
    };

    let required: Vec<&str> = tool
        .input_schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let mut obj = Map::new();
    let mut filled = 0usize;
    for (name, prop) in properties {
        let is_required = required.iter().any(|r| *r == name);
        // 填 required 属性；没有 required 清单时把全部属性都填上（更真实）。
        if is_required || (required.is_empty() && filled < 6) {
            obj.insert(name.clone(), placeholder_for_schema(prop, 0));
            filled += 1;
        }
    }
    Value::Object(obj)
}

/// 按 JSON Schema 生成单个属性的占位值。
fn placeholder_for_schema(schema: &Value, depth: usize) -> Value {
    if depth > 3 {
        return Value::Null;
    }
    // anyOf / oneOf：取第一个分支
    if let Some(variants) = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(|v| v.as_array())
    {
        if let Some(first) = variants.first() {
            return placeholder_for_schema(first, depth + 1);
        }
    }

    let ty = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
    if let Some(items) = schema.get("items") {
        return json!([placeholder_for_schema(items, depth + 1)]);
    }
    match ty {
        "string" => {
            if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
                if let Some(first) = enum_values.first() {
                    if let Value::String(s) = first {
                        return json!(s);
                    }
                    return first.clone();
                }
            }
            match schema.get("format").and_then(|f| f.as_str()) {
                Some("date-time") => json!("2025-01-01T00:00:00Z"),
                Some("date") => json!("2025-01-01"),
                Some("uri" | "uri-reference" | "hostname") => json!("https://example.com"),
                Some("email") => json!("user@example.com"),
                Some("ipv4") => json!("127.0.0.1"),
                _ => json!("test"),
            }
        }
        "integer" | "number" => {
            if let Some(min) = schema.get("minimum").and_then(|m| m.as_i64()) {
                json!(min)
            } else {
                json!(0)
            }
        }
        "boolean" => json!(true),
        "object" => {
            let Some(properties) = schema.get("properties").and_then(|p| p.as_object())
            else {
                return json!({});
            };
            let required: Vec<&str> = schema
                .get("required")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let mut obj = Map::new();
            for (name, prop) in properties {
                if required.is_empty() || required.iter().any(|r| *r == name) {
                    obj.insert(name.clone(), placeholder_for_schema(prop, depth + 1));
                }
            }
            Value::Object(obj)
        }
        "array" => json!([]),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_is_valid_tool_use_id() {
        assert!(is_valid_tool_use_id("toolu_012345678901234567890123"));
        assert!(is_valid_tool_use_id("toolu_ABCdef012345678901234567"));
        assert!(!is_valid_tool_use_id("tool_1"));
        assert!(!is_valid_tool_use_id("toolu_short"));
        assert!(!is_valid_tool_use_id("toolu_0123456789012345678901234"));
        assert!(!is_valid_tool_use_id("toolu_01234567890123456789012+"));
        assert!(!is_valid_tool_use_id(""));
    }

    #[test]
    fn test_generate_tool_use_id_is_valid_and_fresh() {
        let a = generate_tool_use_id();
        let b = generate_tool_use_id();
        assert!(is_valid_tool_use_id(&a), "generated id invalid: {a}");
        assert!(is_valid_tool_use_id(&b), "generated id invalid: {b}");
        assert_ne!(a, b);
    }

    #[test]
    fn test_parse_tool_choice_object_forms() {
        assert_eq!(ToolChoiceRequirement::parse(None), ToolChoiceRequirement::Auto);
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!({"type": "auto"}))),
            ToolChoiceRequirement::Auto
        );
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!({"type": "none"}))),
            ToolChoiceRequirement::Auto
        );
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!({"type": "any"}))),
            ToolChoiceRequirement::Any
        );
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!({"type": "tool", "name": "get_weather"}))),
            ToolChoiceRequirement::Named("get_weather".to_string())
        );
        // 无 type 但带 name 的宽松形态
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!({"name": "get_weather"}))),
            ToolChoiceRequirement::Named("get_weather".to_string())
        );
    }

    #[test]
    fn test_parse_tool_choice_legacy_string_forms() {
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!("auto"))),
            ToolChoiceRequirement::Auto
        );
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!("any"))),
            ToolChoiceRequirement::Any
        );
        assert_eq!(
            ToolChoiceRequirement::parse(Some(&json!("tool:get_weather"))),
            ToolChoiceRequirement::Named("get_weather".to_string())
        );
    }

    #[test]
    fn test_pick_tool_named_and_fallback() {
        let tools = vec![
            Tool {
                tool_type: None,
                name: "alpha".to_string(),
                description: String::new(),
                input_schema: HashMap::new(),
                max_uses: None,
            },
            Tool {
                tool_type: None,
                name: "beta".to_string(),
                description: String::new(),
                input_schema: HashMap::new(),
                max_uses: None,
            },
        ];
        assert_eq!(
            pick_tool(&ToolChoiceRequirement::Named("beta".into()), &tools)
                .map(|t| t.name.as_str()),
            Some("beta")
        );
        // 未知名 -> 第一个
        assert_eq!(
            pick_tool(&ToolChoiceRequirement::Named("gamma".into()), &tools)
                .map(|t| t.name.as_str()),
            Some("alpha")
        );
        assert_eq!(
            pick_tool(&ToolChoiceRequirement::Any, &tools).map(|t| t.name.as_str()),
            Some("alpha")
        );
        assert!(pick_tool(&ToolChoiceRequirement::Any, &[]).is_none());
    }

    /// 把 JSON Schema 值转成 `input_schema` 需要的 HashMap 形态。
    fn schema_map(v: serde_json::Value) -> HashMap<String, serde_json::Value> {
        v.as_object()
            .expect("schema must be an object")
            .clone()
            .into_iter()
            .collect()
    }

    #[test]
    fn test_synthesize_tool_input_required_and_formats() {
        let schema = schema_map(json!({
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "units": {"type": "string", "enum": ["celsius", "fahrenheit"]},
                "wind": {"type": "integer", "minimum": 3},
                "flag": {"type": "boolean"},
                "coords": {"type": "array", "items": {"type": "number"}},
                "when": {"type": "string", "format": "date-time"},
                "optional_extra": {"type": "string"}
            },
            "required": ["city", "units"]
        }));
        let tool = Tool {
            tool_type: None,
            name: "get_weather".to_string(),
            description: String::new(),
            input_schema: schema,
            max_uses: None,
        };
        let input = synthesize_tool_input(&tool);
        assert_eq!(input["city"], "test");
        assert_eq!(input["units"], "celsius");
        // 未列在 required 里的属性不填（存在 required 清单时）
        assert!(input.get("optional_extra").is_none());
        assert!(input.get("wind").is_none());
        // 对象是合法的 JSON 对象
        assert!(input.is_object());
    }

    #[test]
    fn test_synthesize_tool_input_without_required_fills_all() {
        let schema = schema_map(json!({
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "integer"},
                "c": {"type": "object", "properties": {"d": {"type": "string"}}, "required": ["d"]}
            }
        }));
        let tool = Tool {
            tool_type: None,
            name: "generic".to_string(),
            description: String::new(),
            input_schema: schema,
            max_uses: None,
        };
        let input = synthesize_tool_input(&tool);
        assert_eq!(input["a"], "test");
        assert_eq!(input["b"], 0);
        assert_eq!(input["c"]["d"], "test");
    }

    #[test]
    fn test_synthesize_tool_input_no_schema() {
        let tool = Tool {
            tool_type: None,
            name: "no_schema".to_string(),
            description: String::new(),
            input_schema: HashMap::new(),
            max_uses: None,
        };
        assert_eq!(synthesize_tool_input(&tool), json!({}));
    }
}
