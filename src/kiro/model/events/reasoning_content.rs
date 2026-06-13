//! Reasoning content events

use serde::Deserialize;

use crate::kiro::parser::error::ParseResult;
use crate::kiro::parser::frame::Frame;

use super::base::EventPayload;

/// Kiro upstream reasoning stream payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReasoningContentEvent {
    /// Reasoning text chunk.
    #[serde(default)]
    pub text: String,
    /// Upstream thinking signature. Must be forwarded verbatim.
    #[serde(default)]
    pub signature: String,
}

impl EventPayload for ReasoningContentEvent {
    fn from_frame(frame: &Frame) -> ParseResult<Self> {
        frame.payload_as_json()
    }
}
