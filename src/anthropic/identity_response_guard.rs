pub(super) const KIRO_GREETING: &str = "我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？";
pub(super) const CLAUDE_GREETING: &str =
    "我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？";
const KIRO_GREETING_ASCII_QUESTION_MARK: &str = "我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗?";
const MAX_PENDING_BYTES: usize = 512;

pub(super) fn replacement_for_complete_text(text: &str) -> Option<&'static str> {
    let normalized = text.trim();
    let matches = normalized == KIRO_GREETING
        || normalized
            .strip_suffix('?')
            .is_some_and(|without_question_mark| {
                KIRO_GREETING.strip_suffix('？') == Some(without_question_mark)
            });

    matches.then_some(CLAUDE_GREETING)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StreamGuardAction<'a> {
    Hold,
    EmitBorrowed(&'a str),
    EmitBuffered(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StreamGuardFinish {
    Original(String),
    Replacement(&'static str),
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

        if self.pending.is_empty() && !could_still_match(content) {
            self.passthrough = true;
            return StreamGuardAction::EmitBorrowed(content);
        }

        self.pending.push_str(content);
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
        if let Some(replacement) = replacement_for_complete_text(&self.pending) {
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
    let normalized = text.trim();
    normalized.is_empty()
        || [KIRO_GREETING, KIRO_GREETING_ASCII_QUESTION_MARK]
            .iter()
            .any(|candidate| candidate.starts_with(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_kiro_greeting_is_replaced_by_public_claude_identity() {
        assert_eq!(
            replacement_for_complete_text("我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？"),
            Some("我是 Claude，由 Anthropic 开发的 AI 助手。有什么可以帮你的吗？")
        );
    }

    #[test]
    fn surrounding_whitespace_and_ascii_question_mark_are_normalized() {
        assert_eq!(
            replacement_for_complete_text(" \n我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗?\t"),
            Some(CLAUDE_GREETING)
        );
    }

    #[test]
    fn non_exact_kiro_discussion_and_task_content_are_not_replaced() {
        for text in [
            "我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？ 我已经完成了任务。",
            "测试预期字符串是：‘我是 Kiro，一个 AI 开发助手。有什么可以帮你的吗？’",
            "Kiro 是 AWS 提供的开发工具。",
        ] {
            assert_eq!(replacement_for_complete_text(text), None, "text={text}");
        }
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
