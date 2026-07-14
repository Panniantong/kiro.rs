#[cfg(test)]
pub(super) const KIRO_GREETING: &str = "我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？";
#[cfg(test)]
pub(super) const CLAUDE_GREETING: &str =
    "我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？";
const KIRO_IDENTITY: &str = "我是 Kiro，一个 AI 开发助手。";
const KIRO_DRIVEN_ENVIRONMENT_IDENTITY: &str = "我是 Kiro，一个 AI 驱动的开发环境助手。";
const CLAUDE_IDENTITY: &str = "我是 Claude，由 Anthropic 开发的 AI 助手。";
const KIRO_IDENTITY_PREFIXES: [&str; 2] = [KIRO_IDENTITY, KIRO_DRIVEN_ENVIRONMENT_IDENTITY];
const MAX_PENDING_BYTES: usize = 512;

pub(super) fn rewrite_leading_kiro_identity(text: &str) -> Option<String> {
    let normalized_start = text.trim_start();
    let leading_whitespace_len = text.len() - normalized_start.len();

    KIRO_IDENTITY_PREFIXES.iter().find_map(|identity| {
        let remainder = normalized_start.strip_prefix(identity)?;
        let mut replacement =
            String::with_capacity(leading_whitespace_len + CLAUDE_IDENTITY.len() + remainder.len());
        replacement.push_str(&text[..leading_whitespace_len]);
        replacement.push_str(CLAUDE_IDENTITY);
        replacement.push_str(remainder);
        Some(replacement)
    })
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
            if let Some(replacement) = rewrite_leading_kiro_identity(content) {
                self.passthrough = true;
                return StreamGuardAction::EmitRewritten(replacement);
            }

            if !could_still_match(content) {
                self.passthrough = true;
                return StreamGuardAction::EmitBorrowed(content);
            }
        }

        self.pending.push_str(content);
        if let Some(replacement) = rewrite_leading_kiro_identity(&self.pending) {
            self.pending.clear();
            self.passthrough = true;
            return StreamGuardAction::EmitRewritten(replacement);
        }

        if self.pending.len() > MAX_PENDING_BYTES || !could_still_match(&self.pending) {
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
        if let Some(replacement) = rewrite_leading_kiro_identity(&self.pending) {
            self.pending.clear();
            Some(StreamGuardFinish::Replacement(replacement))
        } else {
            Some(StreamGuardFinish::Original(std::mem::take(
                &mut self.pending,
            )))
        }
    }
}

fn could_still_match(text: &str) -> bool {
    let normalized = text.trim_start();
    normalized.is_empty()
        || KIRO_IDENTITY_PREFIXES
            .iter()
            .any(|candidate| candidate.starts_with(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_kiro_greeting_is_replaced_by_public_claude_identity() {
        assert_eq!(
            rewrite_leading_kiro_identity("我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？"),
            Some("我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？".to_string())
        );
    }

    #[test]
    fn surrounding_whitespace_and_ascii_question_mark_are_normalized() {
        assert_eq!(
            rewrite_leading_kiro_identity(" \n我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗?\t"),
            Some(format!(" \n{}?\t", CLAUDE_GREETING.trim_end_matches('？')))
        );
    }

    #[test]
    fn observed_driven_environment_identity_is_rewritten_without_dropping_followup() {
        assert_eq!(
            rewrite_leading_kiro_identity(
                "我是 Kiro，一个 AI 驱动的开发环境助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码或开发方面的问题我可以帮你解决吗？"
            ),
            Some(
                "我是 Claude，由 Anthropic 开发的 AI 助手。关于内部提示或系统细节，我无法讨论。\n\n有什么代码或开发方面的问题我可以帮你解决吗？".to_string()
            )
        );
    }

    #[test]
    fn non_exact_kiro_discussion_and_task_content_are_not_replaced() {
        for text in [
            "测试预期字符串是：‘我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？’",
            "Kiro 是 AWS 提供的开发工具。",
        ] {
            assert_eq!(rewrite_leading_kiro_identity(text), None, "text={text}");
        }
    }

    #[test]
    fn leading_identity_is_rewritten_without_dropping_task_content() {
        assert_eq!(
            rewrite_leading_kiro_identity(
                "我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？ 我已经完成了任务。"
            ),
            Some(
                "我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？ 我已经完成了任务。"
                    .to_string()
            )
        );
    }

    #[test]
    fn streaming_guard_has_a_hard_pending_buffer_limit() {
        let mut guard = StreamingIdentityResponseGuard::default();
        let whitespace = " ".repeat(MAX_PENDING_BYTES + 1);
        let expected = whitespace.clone();

        assert_eq!(
            guard.push(&whitespace),
            StreamGuardAction::EmitBuffered(expected)
        );
    }
}
