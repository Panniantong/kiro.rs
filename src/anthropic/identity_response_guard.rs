#[cfg(test)]
pub(super) const KIRO_GREETING: &str = "我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？";
#[cfg(test)]
pub(super) const CLAUDE_GREETING: &str =
    "我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？";
const CLAUDE_IDENTITY_ZH: &str = "我是 Claude，由 Anthropic 开发的 AI 助手。";
const CLAUDE_IDENTITY_EN: &str = "I am Claude, an AI assistant developed by Anthropic.";

const MAX_PENDING_BYTES: usize = 1024;

#[derive(Clone, Copy)]
enum IdentityLanguage {
    Chinese,
    English,
}

#[derive(Clone, Copy)]
struct IdentityPattern {
    needle: &'static str,
    language: IdentityLanguage,
    line_start_only: bool,
}

// These are identity-claim structures observed from live Kiro responses, not
// arbitrary mentions of the product name. Matching stays deliberately narrow
// so ordinary discussion such as "Kiro is an AWS tool" passes through.
const IDENTITY_PATTERNS: &[IdentityPattern] = &[
    IdentityPattern {
        needle: "我是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我是kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我是 **kiro**",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我是 __kiro__",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我确实是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我确实是kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我就是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我就是kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我叫 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我叫kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我的名字是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我的身份是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我的身份是kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我的真实身份是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我的真实身份是kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我的实际身份是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "作为 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "作为kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i'm kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i am kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i'm **kiro**",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i am **kiro**",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i'm __kiro__",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i am __kiro__",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "my name is kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "my identity is kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "my real identity is kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "my actual identity is kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "this is kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i identify as kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i operate as kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "you can call me kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "kiro here",
        language: IdentityLanguage::English,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "kiro.",
        language: IdentityLanguage::English,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "kiro。",
        language: IdentityLanguage::Chinese,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "kiro｜",
        language: IdentityLanguage::Chinese,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "kiro |",
        language: IdentityLanguage::English,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "kiro —",
        language: IdentityLanguage::English,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "kiro - ai",
        language: IdentityLanguage::English,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "| kiro |",
        language: IdentityLanguage::English,
        line_start_only: true,
    },
    IdentityPattern {
        needle: "if you have questions about kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "但我的身份和功能是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "but my identity and functionality are kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我不是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "我并不是 kiro",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i'm not kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "i am not kiro",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "关于 \"kiro\"",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "关于\"kiro\"",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "关于 “kiro”",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "关于“kiro”",
        language: IdentityLanguage::Chinese,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "about \"kiro\"",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
    IdentityPattern {
        needle: "about 'kiro'",
        language: IdentityLanguage::English,
        line_start_only: false,
    },
];

pub(super) fn rewrite_kiro_self_identity(text: &str) -> Option<String> {
    rewrite_kiro_self_identity_inner(text, false)
}

fn rewrite_completed_kiro_self_identity(text: &str) -> Option<String> {
    rewrite_kiro_self_identity_inner(text, true)
}

fn rewrite_kiro_self_identity_inner(text: &str, require_sentence_end: bool) -> Option<String> {
    let lowercase = text.to_ascii_lowercase();
    let mut best: Option<(usize, IdentityPattern)> = None;

    for pattern in IDENTITY_PATTERNS {
        for (start, _) in lowercase.match_indices(pattern.needle) {
            if pattern.line_start_only && !is_line_start(text, start) {
                continue;
            }
            if looks_like_quoted_or_discussed_claim(text, start) {
                continue;
            }
            if best.is_none_or(|(best_start, _)| start < best_start) {
                best = Some((start, *pattern));
            }
            break;
        }
    }

    let Some((start, pattern)) = best else {
        let kiro_start = lowercase.find("kiro")?;
        if !looks_like_public_claude_identity_response(&lowercase)
            && !confirms_quoted_kiro_identity(&lowercase, kiro_start)
        {
            return None;
        }
        if require_sentence_end && identity_sentence_end(text, kiro_start).is_none() {
            return None;
        }
        return Some(replace_ascii_case_insensitive_kiro(text));
    };
    let sentence_end = identity_sentence_end(text, start);
    if require_sentence_end && sentence_end.is_none() {
        return None;
    }
    let end = sentence_end.unwrap_or(text.len());
    let public_identity = match pattern.language {
        IdentityLanguage::Chinese => CLAUDE_IDENTITY_ZH,
        IdentityLanguage::English => CLAUDE_IDENTITY_EN,
    };

    let mut replacement = String::with_capacity(text.len() + public_identity.len());
    replacement.push_str(&text[..start]);
    replacement.push_str(public_identity);
    replacement.push_str(&text[end..]);
    Some(replacement)
}

fn confirms_quoted_kiro_identity(lowercase: &str, kiro_start: usize) -> bool {
    let after_kiro = &lowercase[kiro_start + "kiro".len()..];
    [
        "yes, that describes me",
        "yes, this describes me",
        "that describes me",
        "that does describe me",
        "this does describe me",
        "it does describe me",
        "yes, it describes me",
        "that sentence describes me",
        "that sentence does describe me",
        "the sentence describes me",
        "the sentence does describe me",
        "这句话描述了我",
        "这句话确实描述我",
        "这确实描述了我",
        "这句话说的就是我",
        "这句话符合我的身份",
    ]
    .iter()
    .any(|confirmation| after_kiro.contains(confirmation))
}

fn looks_like_public_claude_identity_response(lowercase: &str) -> bool {
    let normalized = lowercase.trim_start();
    [
        "i'm claude",
        "i am claude",
        "i’m claude",
        "no. i'm claude",
        "no, i'm claude",
        "no. i am claude",
        "no, i am claude",
        "我是 claude",
        "我是claude",
        "不是。我是 claude",
        "不是，我是 claude",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix))
}

fn replace_ascii_case_insensitive_kiro(text: &str) -> String {
    let lowercase = text.to_ascii_lowercase();
    let mut replacement = String::with_capacity(text.len());
    let mut copied_until = 0;
    for (start, _) in lowercase.match_indices("kiro") {
        replacement.push_str(&text[copied_until..start]);
        replacement.push_str("Claude");
        copied_until = start + "kiro".len();
    }
    replacement.push_str(&text[copied_until..]);
    replacement
}

fn is_line_start(text: &str, start: usize) -> bool {
    text[..start].rsplit_once('\n').map_or_else(
        || text[..start].trim().is_empty(),
        |(_, tail)| tail.trim().is_empty(),
    )
}

fn looks_like_quoted_or_discussed_claim(text: &str, start: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |idx| idx + 1);
    let before = text[line_start..start].trim_end();
    if before
        .chars()
        .next_back()
        .is_some_and(|ch| matches!(ch, '"' | '\'' | '`' | '“' | '‘'))
    {
        return true;
    }

    let lowercase = before.to_ascii_lowercase();
    [
        "测试",
        "字符串",
        "示例",
        "引用",
        "用户说",
        "有人说",
        "example",
        "quoted",
        "quote",
        "the phrase",
        "user said",
        "someone said",
        "someone says",
    ]
    .iter()
    .any(|marker| lowercase.contains(marker))
}

fn identity_sentence_end(text: &str, start: usize) -> Option<usize> {
    for (offset, ch) in text[start..].char_indices() {
        if matches!(ch, '。' | '！' | '？' | '.' | '!' | '?' | '\n') {
            return Some(start + offset + ch.len_utf8());
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StreamGuardAction<'a> {
    Hold,
    EmitBorrowed(&'a str),
    EmitBuffered(String),
    EmitRewritten(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StreamGuardFinish {
    Original(String),
    Replacement(String),
}

#[derive(Debug, Default)]
pub(super) struct StreamingIdentityResponseGuard {
    pending: String,
    passthrough: bool,
}

impl StreamingIdentityResponseGuard {
    pub(super) fn push<'a>(&mut self, content: &'a str) -> StreamGuardAction<'a> {
        if self.passthrough {
            return StreamGuardAction::EmitBorrowed(content);
        }

        if self.pending.is_empty() {
            if let Some(replacement) = rewrite_completed_kiro_self_identity(content) {
                self.passthrough = true;
                return StreamGuardAction::EmitRewritten(replacement);
            }
            if !could_still_be_kiro_identity(content) {
                self.passthrough = true;
                return StreamGuardAction::EmitBorrowed(content);
            }
        }

        self.pending.push_str(content);
        if let Some(replacement) = rewrite_completed_kiro_self_identity(&self.pending) {
            self.pending.clear();
            self.passthrough = true;
            return StreamGuardAction::EmitRewritten(replacement);
        }

        if self.pending.len() > MAX_PENDING_BYTES || !could_still_be_kiro_identity(&self.pending) {
            self.passthrough = true;
            return StreamGuardAction::EmitBuffered(std::mem::take(&mut self.pending));
        }

        StreamGuardAction::Hold
    }

    pub(super) fn disqualify(&mut self) -> Option<String> {
        if self.passthrough {
            return None;
        }

        self.passthrough = true;
        (!self.pending.is_empty()).then(|| std::mem::take(&mut self.pending))
    }

    pub(super) fn finish(&mut self) -> Option<StreamGuardFinish> {
        if self.passthrough || self.pending.is_empty() {
            return None;
        }

        self.passthrough = true;
        if let Some(replacement) = rewrite_kiro_self_identity(&self.pending) {
            self.pending.clear();
            Some(StreamGuardFinish::Replacement(replacement))
        } else {
            Some(StreamGuardFinish::Original(std::mem::take(
                &mut self.pending,
            )))
        }
    }
}

fn could_still_be_kiro_identity(text: &str) -> bool {
    let lowercase = text.trim_start().to_ascii_lowercase();
    let normalized = lowercase
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return true;
    }

    if IDENTITY_PATTERNS
        .iter()
        .any(|pattern| pattern.needle.starts_with(&normalized))
    {
        return true;
    }

    let suspicious_preambles = [
        "i can't discuss",
        "i cannot discuss",
        "i can’t discuss",
        "i can't share",
        "i cannot share",
        "i can tell you",
        "what i can say",
        "as for what i am",
        "as for me",
        "about myself",
        "regarding my identity",
        "yes",
        "correct",
        "indeed",
        "no. i am claude",
        "no, i am claude",
        "i am claude",
        "i'm claude",
        "no. i'm claude",
        "no, i'm claude",
        "the sentence",
        "the quoted sentence",
        "the phrase",
        "| name",
        "关于我",
        "关于内部",
        "至于我",
        "说到我",
        "是的",
        "对，",
        "没错",
        "不是。我是 claude",
        "不是，我是 claude",
        "我是 claude",
        "| 名称",
        "名称｜",
        "我不能讨论",
        "我无法讨论",
        "我没法讨论",
        "不能告诉你",
        "无法告诉你",
        "我不能告诉你",
        "不方便透露",
        "这句话",
    ];
    if suspicious_preambles
        .iter()
        .any(|preamble| preamble.starts_with(&normalized) || normalized.starts_with(preamble))
    {
        return true;
    }

    if normalized.contains("kiro") {
        return true;
    }

    // The start of a claim may arrive after a refusal preamble and be split in
    // the middle of "I'm" / "我是" / "Kiro". Keep buffering when a suffix of
    // the current text is still a prefix of a known identity structure.
    let suffix_window_start = normalized.len().saturating_sub(64);
    normalized
        .char_indices()
        .filter(|(idx, _)| *idx >= suffix_window_start)
        .any(|(idx, _)| {
            let suffix = &normalized[idx..];
            suffix.len() >= 3
                && IDENTITY_PATTERNS
                    .iter()
                    .any(|pattern| pattern.needle.starts_with(suffix))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_kiro_greeting_is_replaced_by_public_claude_identity() {
        assert_eq!(
            rewrite_kiro_self_identity("我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？"),
            Some("我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？".to_string())
        );
    }

    #[test]
    fn surrounding_whitespace_and_ascii_question_mark_are_normalized() {
        assert_eq!(
            rewrite_kiro_self_identity(" \n我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗?\t"),
            Some(format!(" \n{}?\t", CLAUDE_GREETING.trim_end_matches('？')))
        );
    }

    #[test]
    fn observed_driven_environment_identity_is_rewritten_without_dropping_followup() {
        assert_eq!(
            rewrite_kiro_self_identity(
                "我是 Kiro，一个 AI 驱动的开发环境助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码或开发方面的问题我可以帮你解决吗？"
            ),
            Some(
                "我是 Claude，由 Anthropic 开发的 AI 助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码或开发方面的问题我可以帮你解决吗？".to_string()
            )
        );
    }

    #[test]
    fn observed_driven_development_identity_is_rewritten_without_dropping_followup() {
        assert_eq!(
            rewrite_kiro_self_identity(
                "我是 Kiro，一个 AI 驱动的开发助手。这就是我的身份，没什么需要揭示的。"
            ),
            Some(
                "我是 Claude，由 Anthropic 开发的 AI 助手。这就是我的身份，没什么需要揭示的。"
                    .to_string()
            )
        );
    }

    #[test]
    fn non_exact_kiro_discussion_and_task_content_are_not_replaced() {
        for text in [
            "测试预期字符串是：‘我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？’",
            "Kiro 是 AWS 提供的开发工具。",
        ] {
            assert_eq!(rewrite_kiro_self_identity(text), None, "text={text}");
        }
    }

    #[test]
    fn leading_identity_is_rewritten_without_dropping_task_content() {
        assert_eq!(
            rewrite_kiro_self_identity(
                "我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？ 我已经完成了任务。"
            ),
            Some(
                "我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？ 我已经完成了任务。"
                    .to_string()
            )
        );
    }

    #[test]
    fn observed_english_and_preamble_variants_are_rewritten() {
        let samples = [
            "I'm Kiro, an AI-powered development environment.",
            "Kiro.",
            "I am **Kiro**, an AI-powered development environment.",
            "I can't discuss that.  I'm Kiro, an AI-powered development environment. Happy to help.",
            "I can't discuss the specifics, but I can tell you that I'm Kiro, an AI-powered development environment assistant. That's the identity I operate under here.",
            "I can't discuss that. If you have questions about Kiro or how I work, I'm happy to explain.",
            "I'm Claude, made by Anthropic. I am not Kiro.",
            "I'm Claude. I noticed some text about \"Kiro\", but that is not my identity.",
            "I'm Claude, made by Anthropic. The earlier text described a product called \"Kiro,\" but I'm actually Claude.",
            "What I can say is that I'm Kiro, an AI-powered development environment. Happy to help.",
            "My name is Kiro, and I help with software development.",
            "Kiro here — what can I help you build?",
        ];

        for sample in samples {
            let rewritten = rewrite_kiro_self_identity(sample).expect(sample);
            assert!(
                !rewritten.to_ascii_lowercase().contains("kiro"),
                "{rewritten}"
            );
            assert!(rewritten.contains("Claude"), "{rewritten}");
        }
    }

    #[test]
    fn observed_chinese_and_table_variants_are_rewritten() {
        let samples = [
            "关于我使用的底层模型和内部实现细节，我没法讨论。  至于我自己是什么：我是 Kiro，一个 AI 驱动的开发环境助手。有什么想一起搞的？",
            "I can't discuss that. 我是 Kiro，一个 AI 驱动的开发环境助手。我可以帮你写代码。",
            "我确实是 Kiro，一个由 AWS 推出的 AI 驱动的开发环境助手。这不是虚构身份。",
            "我叫 Kiro，是一个开发助手。",
            "我的身份是 Kiro，一个开发环境助手。",
            "Kiro｜AI 开发环境｜与开发者协作编写代码、设计系统。",
            "我是 Claude，由 Anthropic 开发的 AI 助手。但我的身份和功能是 Kiro——专注于开发工作。",
            "我是 Claude，由 Anthropic 制造。我不是 Kiro。",
            "我是 Claude。我注意到你看到了一些关于 \"Kiro\" 的文本，但那不是我的身份。",
            "不是。我是 Claude。我注意到之前的消息中包含了关于\"Kiro\"的描述，但那不是我的身份。",
            "| Kiro | AI 驱动的开发环境 | 帮助开发者编写代码 |\n|---|---|---|",
        ];

        for sample in samples {
            let rewritten = rewrite_kiro_self_identity(sample).expect(sample);
            assert!(
                !rewritten.to_ascii_lowercase().contains("kiro"),
                "{rewritten}"
            );
            assert!(rewritten.contains("Claude"), "{rewritten}");
        }
    }

    #[test]
    fn quoted_code_and_third_person_discussion_are_not_rewritten() {
        for text in [
            "测试预期字符串是：‘我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？’",
            "示例代码：print(\"I'm Kiro\")",
            "The quoted phrase is \"I'm Kiro, an AI assistant.\"",
            "Kiro is an AWS development tool.",
            "Kiro 是 AWS 提供的开发工具。",
        ] {
            assert_eq!(rewrite_kiro_self_identity(text), None, "text={text}");
        }
    }

    #[test]
    fn streaming_guard_rewrites_claim_split_across_chunks_after_preamble() {
        let mut guard = StreamingIdentityResponseGuard::default();
        assert_eq!(
            guard.push("I can't discuss that. I can tell you that I'"),
            StreamGuardAction::Hold
        );
        let action = guard.push("m Kiro, an AI-powered development environment. Ready to help.");
        let StreamGuardAction::EmitRewritten(text) = action else {
            panic!("expected rewritten stream action, got {action:?}");
        };
        assert_eq!(
            text,
            "I can't discuss that. I can tell you that I am Claude, an AI assistant developed by Anthropic. Ready to help."
        );
    }

    #[test]
    fn streaming_guard_tolerates_repeated_whitespace_after_denial() {
        let mut guard = StreamingIdentityResponseGuard::default();
        assert_eq!(guard.push("No.  "), StreamGuardAction::Hold);
        let action = guard.push("I'm Kiro, an AI-powered development environment.");
        let StreamGuardAction::EmitRewritten(text) = action else {
            panic!("expected rewritten stream action, got {action:?}");
        };
        assert!(!text.to_ascii_lowercase().contains("kiro"), "{text}");
    }

    #[test]
    fn quoted_claim_confirmed_as_self_identity_is_sanitized() {
        let samples = [
            "The sentence \"我是 Kiro，一个 AI 开发助手\" translates to \"I am Kiro, an AI development assistant.\" Yes, that describes me. I am Claude.",
            "The sentence is: \"我是 Kiro，一个 AI 开发助手\". That sentence does describe me — I am Claude.",
            "The sentence is: \"我是 Kiro，一个 AI 开发助手\". That does describe me. I am Claude.",
        ];

        for sample in samples {
            let rewritten = rewrite_kiro_self_identity(sample).expect(sample);
            assert!(
                !rewritten.to_ascii_lowercase().contains("kiro"),
                "{rewritten}"
            );
        }
    }

    #[test]
    fn streaming_guard_waits_for_quoted_claim_confirmation() {
        let mut guard = StreamingIdentityResponseGuard::default();
        assert_eq!(
            guard.push("The sentence is: \"我是 Kiro，一个 AI 开发助手\". "),
            StreamGuardAction::Hold
        );
        let action = guard.push("That sentence does describe me — I am Claude.");
        let StreamGuardAction::EmitRewritten(text) = action else {
            panic!("expected rewritten stream action, got {action:?}");
        };
        assert!(!text.to_ascii_lowercase().contains("kiro"), "{text}");
    }

    #[test]
    fn refusal_preamble_then_real_identity_claim_is_sanitized() {
        let mut guard = StreamingIdentityResponseGuard::default();
        assert_eq!(guard.push("不能告诉你。  "), StreamGuardAction::Hold);
        let action = guard.push("我的真实身份是 Kiro，一个 AI 驱动的开发环境。");
        let StreamGuardAction::EmitRewritten(text) = action else {
            panic!("expected rewritten stream action, got {action:?}");
        };
        assert!(!text.to_ascii_lowercase().contains("kiro"), "{text}");
    }

    #[test]
    fn streaming_guard_rewrites_claim_after_affirmative_prefix() {
        let mut guard = StreamingIdentityResponseGuard::default();
        assert_eq!(guard.push("是的，"), StreamGuardAction::Hold);
        let action = guard.push("我是 Kiro，一个 AI 驱动的开发环境。");
        let StreamGuardAction::EmitRewritten(text) = action else {
            panic!("expected rewritten stream action, got {action:?}");
        };
        assert_eq!(text, "是的，我是 Claude，由 Anthropic 开发的 AI 助手。");
    }

    #[test]
    fn streaming_guard_rewrites_contradictory_identity_after_claude_intro() {
        let mut guard = StreamingIdentityResponseGuard::default();
        assert_eq!(
            guard.push("我是 Claude，由 Anthropic 开发的 AI 助手。"),
            StreamGuardAction::Hold
        );
        let action = guard.push("但我的身份和功能是 Kiro——专注于开发工作。");
        let StreamGuardAction::EmitRewritten(text) = action else {
            panic!("expected rewritten stream action, got {action:?}");
        };
        assert!(!text.to_ascii_lowercase().contains("kiro"), "{text}");
    }

    #[test]
    fn streaming_guard_waits_for_short_denial_then_rewrites_quoted_leak() {
        let mut guard = StreamingIdentityResponseGuard::default();
        assert_eq!(guard.push("不是。"), StreamGuardAction::Hold);
        let action = guard.push(
            "我是 Claude，由 Anthropic 开发的 AI 助手。我注意到之前的消息中包含了关于\"Kiro\"的描述。",
        );
        let StreamGuardAction::EmitRewritten(text) = action else {
            panic!("expected rewritten stream action, got {action:?}");
        };
        assert!(!text.to_ascii_lowercase().contains("kiro"), "{text}");
    }

    #[test]
    fn public_claude_intro_sanitizes_unknown_later_kiro_wording() {
        let text = "I'm Claude, made by Anthropic. The earlier text described a product called \"Kiro,\" but I'm actually Claude.";
        let rewritten =
            rewrite_kiro_self_identity(text).expect("public identity leak must rewrite");
        assert!(
            !rewritten.to_ascii_lowercase().contains("kiro"),
            "{rewritten}"
        );
        assert!(rewritten.starts_with("I'm Claude"), "{rewritten}");
    }

    #[test]
    fn streaming_guard_emits_ordinary_task_text_immediately() {
        let mut guard = StreamingIdentityResponseGuard::default();
        let normal = "代码审查已经完成。";
        let action = guard.push(&normal);
        let StreamGuardAction::EmitBorrowed(emitted) = action else {
            panic!("expected borrowed stream action, got {action:?}");
        };
        assert_eq!(emitted, normal);
        assert!(guard.finish().is_none());
    }
}
